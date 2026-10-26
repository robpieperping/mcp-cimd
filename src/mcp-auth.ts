import type { NextFunction, Request, Response } from "express";
import { config } from "./config.js";
import { TokenError, verifyAccessToken, type VerifiedToken } from "./jwt.js";

/**
 * This server as an OAuth 2.0 protected resource: RFC 9728 metadata, RFC
 * 6750 challenges, and the middleware that turns a bearer token into an
 * authorization decision.
 *
 * Every externally visible string here is derived from MCP_RESOURCE, never
 * from the request's Host header -- a resource identifier an attacker can
 * set is a resource identifier that proves nothing.
 */

export interface AuthContext {
  token: VerifiedToken;
  scopes: string[];
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      mcpAuth?: AuthContext;
    }
  }
}

/**
 * The path RFC 9728 §3.1 puts the metadata at. For a resource with a path
 * component the well-known segment is inserted after the host and the
 * resource path follows, so `https://h/mcp` is advertised at
 * `https://h/.well-known/oauth-protected-resource/mcp`. Clients in the wild
 * also try the bare path, so both are served (see src/http.ts).
 */
export const WELL_KNOWN_BASE = "/.well-known/oauth-protected-resource";

export function resourceMetadataUrl(): string {
  const resource = config.auth.resource;
  if (!resource) return WELL_KNOWN_BASE;
  const url = new URL(resource);
  const suffix = url.pathname === "/" ? "" : url.pathname;
  return `${url.origin}${WELL_KNOWN_BASE}${suffix}`;
}

export function protectedResourceMetadata(): Record<string, unknown> {
  return {
    resource: config.auth.resource,
    authorization_servers: [config.auth.issuer],
    scopes_supported: config.auth.scopesSupported,
    bearer_methods_supported: ["header"],
    resource_name: "BxHealth FHIR MCP",
    resource_documentation: "https://github.com/robpieperping/mcp-cimd",
  };
}

export function serveProtectedResourceMetadata(_req: Request, res: Response): void {
  // Public and unauthenticated by definition: a client reads this to find
  // out how to authenticate.
  res.status(200).type("application/json").json(protectedResourceMetadata());
}

/** RFC 7230 quoted-string. An unescaped `"` here silently truncates the header. */
function quoted(value: string): string {
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

interface ChallengeOptions {
  error?: "invalid_token" | "invalid_request" | "insufficient_scope";
  description?: string;
  scope?: string;
}

/**
 * The `WWW-Authenticate` value. `resource_metadata` is what makes a 401
 * actionable rather than terminal: it is how ChatGPT discovers which
 * authorization server to send the user to, so it is present on every
 * challenge.
 */
export function challengeHeader({ error, description, scope }: ChallengeOptions = {}): string {
  const params = [`resource_metadata=${quoted(resourceMetadataUrl())}`];
  if (error) params.push(`error=${quoted(error)}`);
  // Collapse newlines: a header value cannot contain them.
  if (description) params.push(`error_description=${quoted(description.replace(/\s+/g, " ").trim())}`);
  if (scope) params.push(`scope=${quoted(scope)}`);
  return `Bearer ${params.join(", ")}`;
}

function deny(
  res: Response,
  status: 401 | 403,
  options: ChallengeOptions,
  logLine: string
): void {
  console.error(`[auth] ${status} ${logLine}`);
  res
    .status(status)
    .set("WWW-Authenticate", challengeHeader(options))
    .json({
      error: options.error ?? "invalid_token",
      error_description: options.description,
      resource_metadata: resourceMetadataUrl(),
    });
}

function bearerFrom(req: Request): string | undefined | null {
  const header = req.headers.authorization;
  if (!header) return undefined;
  const match = /^Bearer[ ]+([^ ]+)$/i.exec(header.trim());
  // null distinguishes "sent something, but not a bearer token" from
  // "sent nothing" -- the first is a protocol error, the second is normal.
  return match ? match[1] : null;
}

/**
 * Requires a valid, in-audience token on the request, and records it on
 * `req.mcpAuth`. Scope is enforced per tool rather than here, so that a
 * read-scoped token gets a usable session instead of a blanket 403.
 */
export async function requireBearer(req: Request, res: Response, next: NextFunction): Promise<void> {
  if (!config.auth.enabled) {
    next();
    return;
  }

  const token = bearerFrom(req);

  if (token === undefined) {
    // RFC 6750 §3: no credentials means no error code, just the challenge.
    deny(res, 401, {}, `${req.method} ${req.originalUrl}: no Authorization header`);
    return;
  }
  if (token === null) {
    deny(
      res,
      401,
      { error: "invalid_request", description: "Use the Bearer authorization scheme." },
      `${req.method} ${req.originalUrl}: Authorization header is not a Bearer token`
    );
    return;
  }

  let verified: VerifiedToken;
  try {
    verified = await verifyAccessToken(token);
  } catch (error: unknown) {
    if (error instanceof TokenError) {
      deny(res, 401, { error: "invalid_token", description: error.description }, error.reason);
      return;
    }
    const detail = error instanceof Error ? error.message : String(error);
    console.error(`[auth] token validation failed unexpectedly: ${detail}`);
    res.status(500).json({ error: "server_error" });
    return;
  }

  const required = config.auth.readScope;
  if (!verified.scopes.includes(required)) {
    deny(
      res,
      403,
      {
        error: "insufficient_scope",
        description: `The access token must carry the ${required} scope.`,
        scope: required,
      },
      `sub=${verified.subject ?? "?"} client=${verified.clientId ?? "?"} ` +
        `has [${verified.scopes.join(" ")}], needs ${required}`
    );
    return;
  }

  req.mcpAuth = { token: verified, scopes: verified.scopes };
  next();
}
