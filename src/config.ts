import { readFileSync } from "node:fs";
import { resolve } from "node:path";

// Load .env from the project root (one level up from src/ or dist/) into
// process.env, without pulling in a dependency. Values already present in the
// environment win, so an MCP host or shell export can override the file.
function loadDotEnv(): void {
  const projectRoot = resolve(__dirname, "..");

  let contents: string;
  try {
    contents = readFileSync(resolve(projectRoot, ".env"), "utf8");
  } catch {
    return;
  }

  for (const line of contents.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    const separator = trimmed.indexOf("=");
    if (separator === -1) continue;

    const key = trimmed.slice(0, separator).trim();
    const value = trimmed.slice(separator + 1).trim().replace(/^["']|["']$/g, "");

    if (!(key in process.env)) {
      process.env[key] = value;
    }
  }
}

loadDotEnv();

function required(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(
      `Missing required environment variable ${name}. ` +
        `Copy .env.example to .env and fill in the values.`
    );
  }
  return value;
}

function optional(name: string): string | undefined {
  const value = process.env[name];
  return value && value.length > 0 ? value : undefined;
}

function optionalNumber(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new Error(`Environment variable ${name} must be a non-negative integer, got "${raw}".`);
  }
  return parsed;
}

function oneOf<T extends string>(name: string, allowed: readonly T[], fallback: T): T {
  const raw = process.env[name];
  if (!raw) return fallback;
  if (!(allowed as readonly string[]).includes(raw)) {
    throw new Error(`Environment variable ${name} must be one of ${allowed.join(", ")}, got "${raw}".`);
  }
  return raw as T;
}

function splitList(raw: string | undefined, fallback: string[]): string[] {
  if (!raw) return fallback;
  return raw
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

// stdio keeps the original MCP-host registration working (see mcp.json);
// http is what ChatGPT connects to.
const transport = oneOf("MCP_TRANSPORT", ["stdio", "http"] as const, "stdio");

// Inbound authorization. Over HTTP this server is an OAuth 2.0 protected
// resource and defaults to requiring a token: a demo that silently serves
// patient data unauthenticated is worse than one that fails loudly. stdio
// has no HTTP layer to authorize, so the switch is ignored there.
const authMode = oneOf("MCP_AUTH", ["required", "disabled"] as const, "required");
const authEnabled = transport === "http" && authMode === "required";

const issuer = optional("OAUTH_ISSUER");
const resource = optional("MCP_RESOURCE");

if (authEnabled) {
  if (!issuer) throw new Error("OAUTH_ISSUER is required unless MCP_AUTH=disabled.");
  if (!resource) throw new Error("MCP_RESOURCE is required unless MCP_AUTH=disabled.");
  // The resource identifier is compared to the token's `aud` as an exact
  // string, and it is also what the client sends as RFC 8707 `resource`.
  // A trailing slash or a missing scheme here is an audience mismatch that
  // presents as a flat 401 with no clue why.
  if (!/^https:\/\/[^\s]+$/.test(resource)) {
    throw new Error(`MCP_RESOURCE must be an absolute https URL, got "${resource}".`);
  }
  if (resource.endsWith("/")) {
    throw new Error(`MCP_RESOURCE must not end in a slash, got "${resource}".`);
  }
}

// PingFederate publishes its key set at /pf/JWKS, not the RFC-conventional
// /.well-known/jwks.json, so the default is derived from the issuer but
// stays overridable for any other AS.
const jwksUri = optional("OAUTH_JWKS_URI") ?? (issuer ? `${issuer.replace(/\/$/, "")}/pf/JWKS` : undefined);

const readScope = process.env.OAUTH_READ_SCOPE ?? "fhir.read";
const writeScope = process.env.OAUTH_WRITE_SCOPE ?? "fhir.write";

export const config = {
  server: {
    transport,
    port: optionalNumber("PORT", 3000),
    host: process.env.HOST ?? "0.0.0.0",
  },
  /**
   * Inbound: what this server requires of ChatGPT's bearer token.
   */
  auth: {
    enabled: authEnabled,
    issuer,
    jwksUri,
    /** The RFC 8707 resource identifier; must equal the token's `aud`. */
    resource,
    readScope,
    writeScope,
    /** Scopes advertised in protected-resource metadata. Every one must be grantable. */
    scopesSupported: splitList(process.env.OAUTH_SCOPES_SUPPORTED, [readScope]),
    /** Tolerance for clock drift between PF and this pod, in seconds. */
    clockSkewSeconds: optionalNumber("OAUTH_CLOCK_SKEW_SECONDS", 60),
    jwksCacheSeconds: optionalNumber("OAUTH_JWKS_CACHE_SECONDS", 300),
    /**
     * Which tools ChatGPT may see. `read` is the default on the strength of
     * §6.2 of the plan: the demo's value is retrieval, and a destructive
     * FHIR tool reachable from a chat client is a far larger blast radius
     * than the demo needs. `all` additionally exposes the mutating tools,
     * and those still require OAUTH_WRITE_SCOPE in the token.
     */
    toolset: oneOf("MCP_TOOLSET", ["read", "all"] as const, "read"),
  },
  /**
   * Serve Phase A's CIMD client metadata document from this origin. Off by
   * default and test-only -- see src/test-client-doc.ts for why a resource
   * server is hosting a client's document at all.
   */
  serveTestClientDoc: oneOf(
    "SERVE_TEST_CLIENT_DOC",
    ["true", "false"] as const,
    "false",
  ) === "true",
  /**
   * Outbound: the service account this server uses to call FHIR. Optional,
   * and when it is absent the FHIR hop is anonymous -- see README, "The
   * upstream FHIR hop is unauthenticated".
   */
  pingone: (() => {
    const environmentId = optional("PINGONE_ENV_ID");
    const clientId = optional("PINGONE_CLIENT_ID");
    const clientSecret = optional("PINGONE_CLIENT_SECRET");
    if (!environmentId || !clientId || !clientSecret) return null;
    return {
      environmentId,
      clientId,
      clientSecret,
      tokenUrl: `https://auth.pingone.com/${environmentId}/as/token`,
    };
  })(),
  fhir: {
    baseUrl: required("FHIR_BASE_URL"),
    version: "R4" as const,
  },
};
