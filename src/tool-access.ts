import { config } from "./config.js";
import { tools, type ToolDefinition } from "./tools.js";

/**
 * Which tools need which scope, and which ChatGPT is allowed to see.
 *
 * Kept in one place rather than spread across the 19 tool definitions so
 * that the read/write boundary can be reviewed in a single screen -- it is
 * the only thing standing between a chat client and a DELETE against a FHIR
 * server. assertToolAccessIsExhaustive() below makes the list unable to
 * drift from tools.ts.
 */

/**
 * Tools that can change data upstream.
 *
 * `fhir_execute_operation` is here despite not being a plain write: it
 * invokes arbitrary FHIR `$operations`, and plenty of those mutate. It
 * cannot be classified safely from its arguments, so it is classified
 * pessimistically.
 *
 * `fhir_search_resources` is deliberately NOT here. It takes an arbitrary
 * resource type and query, which §6.2 of the plan rightly flags as a broad
 * surface, but every path through it is a GET -- it is a confidentiality
 * question, not an integrity one, and `fhir.read` is the scope that governs
 * confidentiality here.
 */
const WRITE_TOOLS: ReadonlySet<string> = new Set([
  "fhir_create_resource",
  "fhir_update_resource",
  "fhir_patch_resource",
  "fhir_delete_resource",
  "fhir_transaction",
  "fhir_execute_operation",
]);

/** Tools that destroy or overwrite rather than add. Surfaced as a hint to the client. */
const DESTRUCTIVE_TOOLS: ReadonlySet<string> = new Set([
  "fhir_delete_resource",
  "fhir_update_resource",
  "fhir_patch_resource",
  "fhir_transaction",
  "fhir_execute_operation",
]);

export function mutates(toolName: string): boolean {
  return WRITE_TOOLS.has(toolName);
}

export function requiredScopeFor(toolName: string): string {
  return mutates(toolName) ? config.auth.writeScope : config.auth.readScope;
}

/**
 * The `securitySchemes` array ChatGPT reads to decide whether a tool needs a
 * linked account, and which scopes to ask for. Shape per the Apps SDK:
 * `[{ "type": "oauth2", "scopes": [...] }]`, with `noauth` meaning the tool
 * is callable anonymously.
 */
export function securitySchemesFor(toolName: string): Array<Record<string, unknown>> {
  if (!config.auth.enabled) return [{ type: "noauth" }];
  return [{ type: "oauth2", scopes: [requiredScopeFor(toolName)] }];
}

/**
 * Tool list for one session.
 *
 * Two filters, and they are not the same thing. MCP_TOOLSET is a deployment
 * decision -- read-only by default, so the mutating tools are not merely
 * ungranted but absent. Scope is then a per-token decision: a read-scoped
 * token does not see write tools it could not call, because a listed tool
 * that always fails is worse than a tool that was never offered.
 */
export function visibleTools(grantedScopes: string[]): ToolDefinition[] {
  return tools.filter((tool) => {
    if (!mutates(tool.name)) return true;
    if (config.auth.toolset !== "all") return false;
    if (!config.auth.enabled) return true;
    return grantedScopes.includes(config.auth.writeScope);
  });
}

export function toolAnnotations(toolName: string): Record<string, unknown> {
  const write = mutates(toolName);
  return {
    readOnlyHint: !write,
    destructiveHint: DESTRUCTIVE_TOOLS.has(toolName),
    idempotentHint: toolName === "fhir_update_resource" || toolName === "fhir_delete_resource",
    openWorldHint: true,
  };
}

/**
 * Fails fast if the classification above names a tool that no longer
 * exists. A renamed tool would otherwise silently fall back to read scope,
 * which is exactly the wrong direction to fail in.
 */
export function assertToolAccessIsExhaustive(): void {
  const known = new Set(tools.map((tool) => tool.name));
  const unknown = [...WRITE_TOOLS, ...DESTRUCTIVE_TOOLS].filter((name) => !known.has(name));
  if (unknown.length > 0) {
    throw new Error(
      `src/tool-access.ts classifies tools that do not exist: ${unknown.join(", ")}. ` +
        `A write tool that falls through to the read scope is a privilege escalation.`
    );
  }
}
