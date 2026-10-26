import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import { config } from "./config.js";
import { challengeHeader } from "./mcp-auth.js";
import {
  assertToolAccessIsExhaustive,
  requiredScopeFor,
  securitySchemesFor,
  toolAnnotations,
  visibleTools,
} from "./tool-access.js";
import { tools } from "./tools.js";

export const SERVER_NAME = "mcp-cimd";
export const SERVER_VERSION = "1.0.0";

assertToolAccessIsExhaustive();

/** What the session's token turned out to carry. Empty when auth is disabled. */
export interface SessionAuth {
  scopes: string[];
  subject?: string;
  clientId?: string;
}

/**
 * Builds a fresh MCP Server with the FHIR tool set wired up.
 *
 * A Server instance can only be connected to one transport, and the
 * Streamable HTTP transport is per-session, so the HTTP entrypoint calls
 * this once per session rather than sharing a single module-level server.
 *
 * `auth` is the validated token for that session. It shapes the tool list
 * and gates every call, so authorization is decided from the token that
 * opened the session rather than from anything the model asks for.
 */
export function createServer(auth: SessionAuth = { scopes: [] }): Server {
  const server = new Server(
    { name: SERVER_NAME, version: SERVER_VERSION },
    { capabilities: { tools: {} } }
  );

  // ── List Tools ──────────────────────────────────────────────────────────────

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: visibleTools(auth.scopes).map((tool) => ({
        name: tool.name,
        description: tool.description,
        inputSchema: zodSchemaToJsonSchema(tool.inputSchema),
        annotations: toolAnnotations(tool.name),
        // Read by ChatGPT to decide whether the tool needs a linked
        // account and which scopes to ask for.
        securitySchemes: securitySchemesFor(tool.name),
      })),
    };
  });

  // ── Call Tool ───────────────────────────────────────────────────────────────

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    const tool = tools.find((t) => t.name === name);
    if (!tool) {
      throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
    }

    // Re-check on every call, not just at list time. The tool list is a
    // hint to the model; this is the control. A tool hidden by MCP_TOOLSET
    // is unreachable even with a write-scoped token.
    if (!visibleTools(auth.scopes).some((t) => t.name === name)) {
      const needed = requiredScopeFor(name);
      if (config.auth.enabled && !auth.scopes.includes(needed)) {
        return insufficientScope(name, needed);
      }
      throw new McpError(
        ErrorCode.MethodNotFound,
        `Tool '${name}' is not exposed by this server (MCP_TOOLSET=${config.auth.toolset}).`
      );
    }

    // Validate input
    const parseResult = tool.inputSchema.safeParse(args ?? {});
    if (!parseResult.success) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `Invalid parameters for tool '${name}': ${parseResult.error.message}`
      );
    }

    try {
      const result = await tool.handler(parseResult.data);
      return {
        content: [{ type: "text" as const, text: result }],
      };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        content: [{ type: "text" as const, text: `Error: ${message}` }],
        isError: true,
      };
    }
  });

  return server;
}

/**
 * A tool-level authorization failure.
 *
 * This is a tool *result*, not a transport error: the session's token is
 * valid, it just does not carry the scope this tool needs. ChatGPT reads
 * `_meta["mcp/www_authenticate"]` to offer a step-up re-link, and the Apps
 * SDK requires that value to carry both `error` and `error_description`.
 */
function insufficientScope(toolName: string, scope: string) {
  const description = `The ${toolName} tool requires the ${scope} scope.`;
  console.error(`[auth] tool ${toolName} refused: token lacks ${scope}`);
  return {
    content: [{ type: "text" as const, text: `Error: ${description}` }],
    isError: true,
    _meta: {
      "mcp/www_authenticate": challengeHeader({
        error: "insufficient_scope",
        description,
        scope,
      }),
    },
  };
}

// ── Zod → JSON Schema (simple conversion for MCP) ────────────────────────────

function zodSchemaToJsonSchema(schema: import("zod").ZodTypeAny): Record<string, unknown> {
  // Use the Zod schema's _def to build a minimal JSON Schema
  return buildJsonSchema(schema);
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function buildJsonSchema(schema: any): Record<string, unknown> {
  const typeName = schema._def?.typeName as string | undefined;

  switch (typeName) {
    case "ZodObject": {
      const shape = schema._def.shape();
      const properties: Record<string, unknown> = {};
      const required: string[] = [];
      for (const [key, value] of Object.entries(shape)) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const fieldSchema = value as any;
        properties[key] = buildJsonSchema(fieldSchema);
        // If not optional/default, mark as required
        if (
          fieldSchema._def?.typeName !== "ZodOptional" &&
          fieldSchema._def?.typeName !== "ZodDefault"
        ) {
          required.push(key);
        }
      }
      const result: Record<string, unknown> = { type: "object", properties };
      if (required.length > 0) result.required = required;
      return result;
    }
    case "ZodOptional":
      return buildJsonSchema(schema._def.innerType);
    case "ZodDefault": {
      const inner = buildJsonSchema(schema._def.innerType);
      inner.default = schema._def.defaultValue();
      return inner;
    }
    case "ZodString":
      return { type: "string", description: schema.description };
    case "ZodNumber":
      return { type: "number", description: schema.description };
    case "ZodBoolean":
      return { type: "boolean", description: schema.description };
    case "ZodArray":
      return {
        type: "array",
        items: buildJsonSchema(schema._def.type),
        description: schema.description,
      };
    case "ZodRecord":
      return {
        type: "object",
        additionalProperties: buildJsonSchema(schema._def.valueType),
        description: schema.description,
      };
    case "ZodEnum":
      return { type: "string", enum: schema._def.values, description: schema.description };
    case "ZodUnion":
      return { oneOf: schema._def.options.map(buildJsonSchema), description: schema.description };
    case "ZodUnknown":
    case "ZodAny":
      return { description: schema.description };
    default:
      return { description: schema.description };
  }
}
