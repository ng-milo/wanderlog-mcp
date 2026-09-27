import { generateKeyPairSync, sign } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  loadOAuthConfig,
  protectedResourceMetadata,
  protectedResourceMetadataPaths,
  verifyAccessToken,
  wwwAuthenticateChallenge,
} from "../../src/oauth.js";

const issuer = "https://tenant.example.com/";
const resource = "https://mcp.example.com/mcp";
const allowedSubject = "google-oauth2|milo";

const { publicKey, privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
});

const exportedJwk = publicKey.export({ format: "jwk" });
const jwk = {
  ...exportedJwk,
  kid: "test-key",
  alg: "RS256",
  use: "sig",
};

const config = loadOAuthConfig({
  AUTH0_ISSUER: issuer,
  MCP_RESOURCE_URL: resource,
  AUTH0_ALLOWED_SUB: allowedSubject,
});

function encode(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function makeToken(overrides: Record<string, unknown> = {}): string {
  const now = Math.floor(Date.now() / 1000);
  const header = encode({ alg: "RS256", typ: "JWT", kid: "test-key" });
  const payload = encode({
    iss: issuer,
    aud: resource,
    sub: allowedSubject,
    scope: "openid profile mcp",
    iat: now,
    exp: now + 300,
    ...overrides,
  });
  const signingInput = `${header}.${payload}`;
  const signature = sign("RSA-SHA256", Buffer.from(signingInput), privateKey).toString("base64url");
  return `${signingInput}.${signature}`;
}

beforeEach(() => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () =>
      new Response(JSON.stringify({ keys: [jwk] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    ),
  );
});

describe("OAuth configuration", () => {
  it("normalizes the issuer and publishes protected-resource metadata", () => {
    const loaded = loadOAuthConfig({
      AUTH0_ISSUER: "https://tenant.example.com",
      MCP_RESOURCE_URL: resource,
      AUTH0_ALLOWED_SUB: allowedSubject,
    });

    expect(loaded.issuer).toBe(issuer);
    expect(protectedResourceMetadata(loaded)).toEqual({
      resource,
      authorization_servers: [issuer],
      scopes_supported: ["mcp"],
      bearer_methods_supported: ["header"],
    });
    expect(protectedResourceMetadataPaths(loaded)).toEqual([
      "/.well-known/oauth-protected-resource",
      "/.well-known/oauth-protected-resource/mcp",
    ]);
    expect(wwwAuthenticateChallenge(loaded)).toContain(
      'resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"',
    );
  });
});

describe("verifyAccessToken", () => {
  it("accepts a correctly signed token for the one allowed user", async () => {
    await expect(verifyAccessToken(makeToken(), config)).resolves.toMatchObject({
      sub: allowedSubject,
      aud: resource,
    });
  });

  it("rejects a token for another Auth0 user", async () => {
    await expect(
      verifyAccessToken(makeToken({ sub: "google-oauth2|someone-else" }), config),
    ).rejects.toThrow("not authorized");
  });

  it("rejects a token minted for another audience", async () => {
    await expect(
      verifyAccessToken(makeToken({ aud: "https://some-other-api.example.com" }), config),
    ).rejects.toThrow("audience");
  });

  it("rejects a token without the mcp scope", async () => {
    await expect(
      verifyAccessToken(makeToken({ scope: "openid profile" }), config),
    ).rejects.toThrow("missing required scope");
  });

  it("rejects expired tokens", async () => {
    const now = Math.floor(Date.now() / 1000);
    await expect(
      verifyAccessToken(makeToken({ exp: now - 120 }), config),
    ).rejects.toThrow("expired");
  });
});
