import { createPublicKey, verify as verifySignature } from "node:crypto";

const REQUIRED_SCOPE = "mcp";
const JWKS_CACHE_TTL_MS = 10 * 60 * 1000;
const JWKS_FETCH_TIMEOUT_MS = 5_000;
const CLOCK_SKEW_SECONDS = 30;

type Env = Record<string, string | undefined>;

type JwtPayload = Record<string, unknown>;

type RsaJwk = {
  kty: "RSA";
  kid: string;
  n: string;
  e: string;
  alg?: string;
  use?: string;
};

type JwksCacheEntry = {
  keys: RsaJwk[];
  expiresAt: number;
};

const jwksCache = new Map<string, JwksCacheEntry>();

export type OAuthConfig = {
  issuer: string;
  resource: string;
  allowedSubject: string;
  requiredScopes: readonly string[];
};

export class OAuthTokenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OAuthTokenError";
  }
}

function requiredEnv(env: Env, name: string): string {
  const value = env[name]?.trim();
  if (!value) throw new Error(`${name} is required for the remote HTTP server.`);
  return value;
}

function normalizeIssuer(raw: string): string {
  const url = new URL(raw);
  if (url.protocol !== "https:") {
    throw new Error("AUTH0_ISSUER must use https://.");
  }
  if (url.search || url.hash) {
    throw new Error("AUTH0_ISSUER must not contain a query string or fragment.");
  }
  url.pathname = `${url.pathname.replace(/\/+$/, "")}/`;
  return url.toString();
}

function normalizeResource(raw: string): string {
  const url = new URL(raw);
  if (url.protocol !== "https:") {
    throw new Error("MCP_RESOURCE_URL must use https://.");
  }
  if (url.search || url.hash) {
    throw new Error("MCP_RESOURCE_URL must not contain a query string or fragment.");
  }
  return url.toString();
}

export function loadOAuthConfig(env: Env = process.env): OAuthConfig {
  return {
    issuer: normalizeIssuer(requiredEnv(env, "AUTH0_ISSUER")),
    resource: normalizeResource(requiredEnv(env, "MCP_RESOURCE_URL")),
    allowedSubject: requiredEnv(env, "AUTH0_ALLOWED_SUB"),
    requiredScopes: [REQUIRED_SCOPE],
  };
}

export function protectedResourceMetadata(config: OAuthConfig) {
  return {
    resource: config.resource,
    authorization_servers: [config.issuer],
    scopes_supported: [...config.requiredScopes],
    bearer_methods_supported: ["header"],
  };
}

export function protectedResourceMetadataUrl(config: OAuthConfig): string {
  const resource = new URL(config.resource);
  return `${resource.origin}/.well-known/oauth-protected-resource`;
}

export function protectedResourceMetadataPaths(config: OAuthConfig): string[] {
  const resource = new URL(config.resource);
  const resourcePath = resource.pathname.replace(/\/+$/, "");
  const paths = ["/.well-known/oauth-protected-resource"];

  if (resourcePath && resourcePath !== "/") {
    paths.push(`/.well-known/oauth-protected-resource${resourcePath}`);
  }

  return [...new Set(paths)];
}

export function wwwAuthenticateChallenge(
  config: OAuthConfig,
  error?: "invalid_token" | "insufficient_scope",
): string {
  const parts = [
    `resource_metadata="${protectedResourceMetadataUrl(config)}"`,
    `scope="${config.requiredScopes.join(" ")}"`,
  ];

  if (error) {
    parts.push(`error="${error}"`);
    parts.push(
      `error_description="The access token is missing, invalid, expired, or not authorized for this server"`,
    );
  }

  return `Bearer ${parts.join(", ")}`;
}

function decodeJsonSegment(segment: string, label: string): Record<string, unknown> {
  try {
    const decoded = Buffer.from(segment, "base64url").toString("utf8");
    const value: unknown = JSON.parse(decoded);
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error(`${label} is not an object`);
    }
    return value as Record<string, unknown>;
  } catch {
    throw new OAuthTokenError(`Malformed JWT ${label}.`);
  }
}

function parseJwt(token: string) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new OAuthTokenError("Malformed JWT.");

  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  if (!encodedHeader || !encodedPayload || !encodedSignature) {
    throw new OAuthTokenError("Malformed JWT.");
  }

  const header = decodeJsonSegment(encodedHeader, "header");
  const payload = decodeJsonSegment(encodedPayload, "payload");

  return {
    header,
    payload,
    signingInput: `${encodedHeader}.${encodedPayload}`,
    signature: Buffer.from(encodedSignature, "base64url"),
  };
}

function parseRsaKeys(value: unknown): RsaJwk[] {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new OAuthTokenError("Auth0 JWKS response is invalid.");
  }

  const keys = (value as { keys?: unknown }).keys;
  if (!Array.isArray(keys)) {
    throw new OAuthTokenError("Auth0 JWKS response does not contain keys.");
  }

  return keys.flatMap((key): RsaJwk[] => {
    if (!key || typeof key !== "object" || Array.isArray(key)) return [];
    const candidate = key as Record<string, unknown>;
    if (
      candidate.kty !== "RSA" ||
      typeof candidate.kid !== "string" ||
      typeof candidate.n !== "string" ||
      typeof candidate.e !== "string"
    ) {
      return [];
    }

    return [
      {
        kty: "RSA",
        kid: candidate.kid,
        n: candidate.n,
        e: candidate.e,
        ...(typeof candidate.alg === "string" ? { alg: candidate.alg } : {}),
        ...(typeof candidate.use === "string" ? { use: candidate.use } : {}),
      },
    ];
  });
}

async function fetchJwks(issuer: string, forceRefresh = false): Promise<RsaJwk[]> {
  const cached = jwksCache.get(issuer);
  if (!forceRefresh && cached && cached.expiresAt > Date.now()) return cached.keys;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), JWKS_FETCH_TIMEOUT_MS);

  try {
    const response = await fetch(new URL(".well-known/jwks.json", issuer), {
      signal: controller.signal,
      headers: { accept: "application/json" },
    });

    if (!response.ok) {
      throw new OAuthTokenError(`Unable to fetch Auth0 JWKS (${response.status}).`);
    }

    const keys = parseRsaKeys(await response.json());
    if (keys.length === 0) {
      throw new OAuthTokenError("Auth0 JWKS does not contain an RSA signing key.");
    }

    jwksCache.set(issuer, {
      keys,
      expiresAt: Date.now() + JWKS_CACHE_TTL_MS,
    });

    return keys;
  } catch (error) {
    if (error instanceof OAuthTokenError) throw error;
    throw new OAuthTokenError("Unable to fetch Auth0 signing keys.");
  } finally {
    clearTimeout(timeout);
  }
}

async function findSigningKey(issuer: string, kid: string): Promise<RsaJwk> {
  let keys = await fetchJwks(issuer);
  let key = keys.find((candidate) => candidate.kid === kid);

  // Auth0 may rotate signing keys. Refresh once before rejecting an unknown kid.
  if (!key) {
    keys = await fetchJwks(issuer, true);
    key = keys.find((candidate) => candidate.kid === kid);
  }

  if (!key) throw new OAuthTokenError("JWT signing key is unknown.");
  if (key.alg && key.alg !== "RS256") {
    throw new OAuthTokenError("JWT signing key uses an unsupported algorithm.");
  }
  if (key.use && key.use !== "sig") {
    throw new OAuthTokenError("JWT key is not a signing key.");
  }

  return key;
}

function audienceMatches(aud: unknown, expected: string): boolean {
  if (typeof aud === "string") return aud === expected;
  return Array.isArray(aud) && aud.some((value) => value === expected);
}

function scopesFromPayload(payload: JwtPayload): Set<string> {
  if (typeof payload.scope !== "string") return new Set();
  return new Set(payload.scope.split(/\s+/).filter(Boolean));
}

function validateClaims(payload: JwtPayload, config: OAuthConfig): void {
  const now = Math.floor(Date.now() / 1000);

  if (payload.iss !== config.issuer) {
    throw new OAuthTokenError("JWT issuer does not match AUTH0_ISSUER.");
  }
  if (!audienceMatches(payload.aud, config.resource)) {
    throw new OAuthTokenError("JWT audience does not match MCP_RESOURCE_URL.");
  }
  if (payload.sub !== config.allowedSubject) {
    throw new OAuthTokenError("JWT subject is not authorized for this server.");
  }
  if (typeof payload.exp !== "number" || payload.exp <= now - CLOCK_SKEW_SECONDS) {
    throw new OAuthTokenError("JWT is expired or has no valid exp claim.");
  }
  if (typeof payload.nbf === "number" && payload.nbf > now + CLOCK_SKEW_SECONDS) {
    throw new OAuthTokenError("JWT is not valid yet.");
  }

  const grantedScopes = scopesFromPayload(payload);
  const missingScope = config.requiredScopes.find((scope) => !grantedScopes.has(scope));
  if (missingScope) {
    throw new OAuthTokenError(`JWT is missing required scope: ${missingScope}.`);
  }
}

export async function verifyAccessToken(
  token: string,
  config: OAuthConfig,
): Promise<JwtPayload> {
  const parsed = parseJwt(token);

  if (parsed.header.alg !== "RS256") {
    throw new OAuthTokenError("JWT must use RS256.");
  }
  if (typeof parsed.header.kid !== "string" || !parsed.header.kid) {
    throw new OAuthTokenError("JWT is missing a kid header.");
  }

  const jwk = await findSigningKey(config.issuer, parsed.header.kid);
  const publicKey = createPublicKey({ key: jwk, format: "jwk" });
  const signatureValid = verifySignature(
    "RSA-SHA256",
    Buffer.from(parsed.signingInput, "utf8"),
    publicKey,
    parsed.signature,
  );

  if (!signatureValid) throw new OAuthTokenError("JWT signature is invalid.");

  validateClaims(parsed.payload, config);
  return parsed.payload;
}
