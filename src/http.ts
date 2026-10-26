import { randomUUID } from "node:crypto";
import express, { type Request, type Response } from "express";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { config } from "./config.js";
import { healthz, readyz } from "./health.js";
import {
  WELL_KNOWN_BASE,
  challengeHeader,
  requireBearer,
  resourceMetadataUrl,
  serveProtectedResourceMetadata,
} from "./mcp-auth.js";
import { createServer } from "./server.js";

/**
 * Streamable HTTP entrypoint.
 *
 * One MCP session == one Server + one transport, held in memory and keyed by
 * the Mcp-Session-Id the transport issues on initialize. That makes this
 * process single-replica by construction: scaling the Deployment past one pod
 * without sticky sessions produces intermittent "session not found" errors,
 * because a follow-up request can land on a pod that never saw the
 * initialize. See the deployment notes before changing replicas.
 *
 * Each session also remembers the subject that opened it. The MCP spec
 * requires a token on every request, so every request is validated -- but a
 * valid token is not the same as the token this session belongs to, and
 * without that check one user's session id would be a handle anyone else
 * with a token could pick up.
 */

interface Session {
  transport: StreamableHTTPServerTransport;
  subject?: string;
}

const sessions = new Map<string, Session>();

function sessionIdOf(req: Request): string | undefined {
  const header = req.headers["mcp-session-id"];
  return Array.isArray(header) ? header[0] : header;
}

/** Rejects a session id that belongs to a different subject. */
function ownsSession(req: Request, session: Session): boolean {
  if (!config.auth.enabled) return true;
  return session.subject === req.mcpAuth?.token.subject;
}

export function buildApp(): express.Express {
  const app = express();

  // Health endpoints are registered before the JSON body parser and carry no
  // auth: kubelet probes must not depend on either.
  app.get("/healthz", healthz);
  app.get("/readyz", readyz);

  // RFC 9728 metadata. Public by definition -- a client reads it to learn
  // how to authenticate -- and registered before the bearer middleware so
  // it stays reachable from a 401. RFC 9728 puts the resource's path after
  // the well-known segment; clients in the wild also try the bare path, so
  // both are served.
  const metadataSuffix = new URL(resourceMetadataUrl()).pathname;
  app.get(WELL_KNOWN_BASE, serveProtectedResourceMetadata);
  if (metadataSuffix !== WELL_KNOWN_BASE) {
    app.get(metadataSuffix, serveProtectedResourceMetadata);
  }

  // Before the body parser, deliberately: an unauthenticated caller should
  // not get 4MB of JSON parsed on their behalf.
  app.use("/mcp", requireBearer);

  app.use(express.json({ limit: "4mb" }));

  // ── POST /mcp: JSON-RPC in, JSON or SSE out ────────────────────────────────
  app.post("/mcp", async (req: Request, res: Response) => {
    const sessionId = sessionIdOf(req);

    if (sessionId) {
      const existing = sessions.get(sessionId);
      if (!existing || !ownsSession(req, existing)) {
        // Deliberately the same 404 either way: whether a session id exists
        // is not something a different caller should be able to probe.
        res.status(404).json(rpcError(-32001, "Session not found", req.body?.id));
        return;
      }
      await existing.transport.handleRequest(req, res, req.body);
      return;
    }

    // No session yet: only an initialize request may open one.
    if (!isInitializeRequest(req.body)) {
      res
        .status(400)
        .json(rpcError(-32000, "Bad Request: no session, and body is not an initialize request", req.body?.id));
      return;
    }

    const auth = req.mcpAuth;
    const subject = auth?.token.subject;

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (id) => {
        sessions.set(id, { transport, subject });
        console.error(
          `[http] session opened: ${id} sub=${subject ?? "-"} ` +
            `scopes=[${auth?.scopes.join(" ") ?? ""}] (${sessions.size} open)`
        );
      },
      onsessionclosed: (id) => {
        sessions.delete(id);
        console.error(`[http] session closed: ${id} (${sessions.size} open)`);
      },
    });

    transport.onclose = () => {
      if (transport.sessionId) sessions.delete(transport.sessionId);
    };

    await createServer({
      scopes: auth?.scopes ?? [],
      subject,
      clientId: auth?.token.clientId,
    }).connect(transport);
    await transport.handleRequest(req, res, req.body);
  });

  // ── GET /mcp: the SSE stream the client opens after initialize ─────────────
  app.get("/mcp", async (req: Request, res: Response) => {
    const session = requireSession(req, res);
    if (!session) return;
    await session.transport.handleRequest(req, res);
  });

  // ── DELETE /mcp: explicit session teardown ─────────────────────────────────
  app.delete("/mcp", async (req: Request, res: Response) => {
    const session = requireSession(req, res);
    if (!session) return;
    await session.transport.handleRequest(req, res);
  });

  // Anything else under /mcp, and any unknown path, gets a challenge rather
  // than an express HTML 404: a client probing for the auth story should
  // find it here too.
  app.use((req: Request, res: Response) => {
    if (config.auth.enabled) res.set("WWW-Authenticate", challengeHeader());
    res.status(404).json({ error: "not_found", path: req.path });
  });

  return app;
}

function requireSession(req: Request, res: Response): Session | null {
  const sessionId = sessionIdOf(req);
  if (!sessionId) {
    res.status(400).json(rpcError(-32000, "Bad Request: Mcp-Session-Id header is required"));
    return null;
  }
  const session = sessions.get(sessionId);
  if (!session || !ownsSession(req, session)) {
    res.status(404).json(rpcError(-32001, "Session not found"));
    return null;
  }
  return session;
}

function rpcError(code: number, message: string, id: unknown = null) {
  return { jsonrpc: "2.0" as const, error: { code, message }, id: id ?? null };
}

export function startHttpServer(): void {
  const app = buildApp();
  const { host, port } = config.server;

  const httpServer = app.listen(port, host, () => {
    console.error(`[http] MCP server listening on http://${host}:${port}/mcp`);
    console.error(`[http] FHIR ${config.fhir.version} base: ${config.fhir.baseUrl}`);
    if (config.auth.enabled) {
      console.error(`[http] protected resource: ${config.auth.resource}`);
      console.error(`[http] authorization server: ${config.auth.issuer}`);
      console.error(`[http] key set: ${config.auth.jwksUri}`);
      console.error(`[http] metadata: ${resourceMetadataUrl()}`);
      console.error(
        `[http] required scope: ${config.auth.readScope} (toolset=${config.auth.toolset})`
      );
    } else {
      console.error("[http] WARNING: MCP_AUTH=disabled -- /mcp is unauthenticated.");
    }
  });

  // SSE streams are long-lived; do not let Node time them out mid-stream.
  httpServer.headersTimeout = 0;
  httpServer.requestTimeout = 0;

  const shutdown = (signal: string) => {
    console.error(`[http] ${signal} received, closing ${sessions.size} session(s)`);
    for (const session of sessions.values()) void session.transport.close();
    sessions.clear();
    httpServer.close(() => process.exit(0));
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}
