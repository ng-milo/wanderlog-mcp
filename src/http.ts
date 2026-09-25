#!/usr/bin/env node
import { createHash, timingSafeEqual } from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { normalizeCookie, type Config } from "./config.js";
import { RestClient } from "./transport/rest.js";
import { ShareDBPool } from "./transport/sharedb.js";
import { TripCache } from "./cache/trip-cache.js";
import type { AppContext } from "./context.js";
import { WanderlogError } from "./errors.js";
import { buildServer } from "./server.js";

// --- per-user context cache keyed by cookie hash ---

type CachedContext = { ctx: AppContext; lastUsed: number };

const CTX_TTL_MS = 10 * 60 * 1000; // 10 minutes
const ctxCache = new Map<string, CachedContext>();
const ctxPending = new Map<string, Promise<AppContext>>();

function hashCookie(cookie: string): string {
  return createHash("sha256").update(cookie).digest("hex").slice(0, 16);
}

function evictStaleContexts() {
  const now = Date.now();
  for (const [key, entry] of ctxCache) {
    if (now - entry.lastUsed > CTX_TTL_MS) {
      entry.ctx.pool.closeAll();
      ctxCache.delete(key);
    }
  }
}

// Run eviction every 2 minutes
setInterval(evictStaleContexts, 2 * 60 * 1000).unref();

async function getOrCreateContext(cookieRaw: string): Promise<AppContext> {
  const cookie = normalizeCookie(cookieRaw);
  const key = hashCookie(cookie);

  const cached = ctxCache.get(key);
  if (cached) {
    cached.lastUsed = Date.now();
    return cached.ctx;
  }

  // Deduplicate concurrent requests for the same cookie
  const pending = ctxPending.get(key);
  if (pending) return pending;

  const promise = (async () => {
    const config: Config = {
      cookieHeader: cookie,
      baseUrl: process.env.WANDERLOG_BASE_URL ?? "https://wanderlog.com",
      wsBaseUrl: process.env.WANDERLOG_WS_BASE_URL ?? "wss://wanderlog.com",
      userAgent:
        process.env.WANDERLOG_USER_AGENT ??
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
    };
    const rest = new RestClient(config);
    const pool = new ShareDBPool(config);
    const tripCache = new TripCache(rest, pool);

    const user = await rest.getUser();
    const ctx: AppContext = { config, rest, pool, tripCache, userId: user.id, authenticated: true };

    ctxCache.set(key, { ctx, lastUsed: Date.now() });
    return ctx;
  })();

  ctxPending.set(key, promise);
  try {
    return await promise;
  } finally {
    ctxPending.delete(key);
  }
}

// --- MCP authentication ---

function extractBearerToken(req: { headers: Record<string, string | string[] | undefined> }): string | null {
  const auth = req.headers.authorization;

  if (typeof auth !== "string") {
    return null;
  }

  const match = auth.match(/^Bearer\s+(.+)$/i);
  return match?.[1]?.trim() || null;
}

function tokensMatch(actual: string, expected: string): boolean {
  // Hash both values first so timingSafeEqual always receives equal-length buffers.
  const actualHash = createHash("sha256").update(actual).digest();
  const expectedHash = createHash("sha256").update(expected).digest();

  return timingSafeEqual(actualHash, expectedHash);
}

// --- HTTP server ---
async function main() {
  // The Wanderlog session stays server-side and is never used as the public
  // MCP authentication credential.
  const wanderlogCookie = process.env.WANDERLOG_COOKIE?.trim();

  if (!wanderlogCookie) {
    throw new Error(
      "WANDERLOG_COOKIE is required. Set it to your Wanderlog connect.sid value.",
    );
  }

  // Fail fast if the cookie has the wrong format.
  normalizeCookie(wanderlogCookie);

  const mcpAuthToken = process.env.MCP_AUTH_TOKEN?.trim();

  if (!mcpAuthToken) {
    throw new Error(
      "MCP_AUTH_TOKEN is required. Generate a separate random token; do not reuse your Wanderlog connect.sid.",
    );
  }

  if (mcpAuthToken.length < 32) {
    throw new Error(
      "MCP_AUTH_TOKEN must be at least 32 characters long.",
    );
  }

  const app = createMcpExpressApp({ host: "0.0.0.0" });

  // All MCP methods (POST, GET, DELETE) go through auth + transport so
  // the transport itself decides what's allowed per the spec.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const handleMcp = async (req: any, res: any) => {
  const bearerToken = extractBearerToken(req);
  
  if (!bearerToken || !tokensMatch(bearerToken, mcpAuthToken)) {
    res.status(401).json({
      jsonrpc: "2.0",
      error: {
        code: -32000,
        message:
          "Missing or invalid Authorization header. Use MCP_AUTH_TOKEN as the Bearer token.",
      },
      id: null,
    });
    return;
  }

    let ctx: AppContext;
    try {
      ctx = await getOrCreateContext(wanderlogCookie);
    } catch (err) {
      const msg =
        err instanceof WanderlogError
          ? err.toUserMessage()
          : (err as Error).message;
      console.error(`[wanderdog] Wanderlog auth failed: ${msg}`);
      res.status(403).json({
        jsonrpc: "2.0",
        error: { code: -32000, message: `Wanderlog authentication failed: ${msg}` },
        id: null,
      });
      return;
    }

    const server = buildServer(ctx);
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
    });

    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      console.error("[wanderdog] error handling request:", error);
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: "2.0",
          error: { code: -32603, message: "Internal server error" },
          id: null,
        });
      }
    }

    res.on("close", () => {
      transport.close();
      server.close();
    });
  };

  app.post("/mcp", handleMcp);
  app.get("/mcp", handleMcp);
  app.delete("/mcp", handleMcp);

  // Health check for fly.io
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  app.get("/health", (_req: any, res: any) => {
    res.status(200).json({ status: "ok" });
  });

  const port = parseInt(process.env.PORT ?? "3000", 10);
  app.listen(port, "0.0.0.0", () => {
    console.log(`[wanderdog] HTTP server listening on 0.0.0.0:${port}`);
  });

  const shutdown = async (signal: string) => {
    console.log(`[wanderdog] ${signal} received, shutting down`);
    for (const [, entry] of ctxCache) {
      entry.ctx.pool.closeAll();
    }
    process.exit(0);
  };
  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
}

main().catch((err) => {
  console.error(`[wanderdog] fatal: ${(err as Error).stack ?? err}`);
  process.exit(1);
});
