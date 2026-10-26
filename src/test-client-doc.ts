/**
 * A CIMD client metadata document, served by the resource server.
 *
 * This is a layering wart and it is deliberate, so it is worth saying why.
 * A CIMD `client_id` *is* the URL its document is served from, so the
 * document can only live at the exact URL baked into it. Phase A's test
 * client was supposed to sit on the PingFederate host beside `cimd.json`,
 * which needs access to that deployment. This server already has a public
 * HTTPS origin with a valid certificate, so it can host the document
 * instead and unblock the flow without touching PF.
 *
 * It is off unless SERVE_TEST_CLIENT_DOC=true, it is never on in a
 * configuration that matters, and nothing else in the server reads it.
 * Delete this file and its route once a real client exists.
 *
 * The document is deliberately shaped like ChatGPT's where it matters and
 * like the facile demo's where it has to be:
 *
 *   - no `scope` key, so the FHIR MCP CIMD policy's defaults govern, which
 *     is the only way this client can request fhir.read. A document that
 *     declares a scope list is restricted to it.
 *   - token_endpoint_auth_method "none", so a code can be redeemed without
 *     a client secret we do not have. ChatGPT uses private_key_jwt, which
 *     needs OpenAI's signing key.
 */

import type { Request, Response } from "express";
import { config } from "./config.js";

export const TEST_CLIENT_DOC_PATH = "/mcp-test-client.json";

/**
 * Both URLs are derived rather than written down: the client_id must equal
 * the URL this is served from or PF rejects it, and the redirect must be one
 * PF already accepts. `/callback` on the issuer is a token-display page that
 * is already registered there -- a loopback redirect was refused with
 * "400 Invalid redirect_uri".
 */
export function testClientDocument(): Record<string, unknown> {
  const resource = config.auth.resource;
  const issuer = config.auth.issuer;
  if (!resource || !issuer) {
    throw new Error(
      "SERVE_TEST_CLIENT_DOC needs MCP_RESOURCE and OAUTH_ISSUER to derive " +
        "the client_id and redirect_uri.",
    );
  }
  const origin = new URL(resource).origin;
  return {
    client_id: `${origin}${TEST_CLIENT_DOC_PATH}`,
    client_name: "FHIR MCP Phase A Test Client",
    client_uri: "https://github.com/robpieperping/mcp-cimd",
    redirect_uris: [`${issuer.replace(/\/$/, "")}/callback`],
    response_types: ["code"],
    grant_types: ["authorization_code", "refresh_token"],
    token_endpoint_auth_method: "none",
    application_type: "web",
    subject_type: "public",
  };
}

export function serveTestClientDocument(_req: Request, res: Response): void {
  // PF fetches this, so it must be application/json and must not be cached
  // long enough to outlive an edit during testing.
  res
    .status(200)
    .type("application/json")
    .set("Cache-Control", "public, max-age=60")
    .json(testClientDocument());
}
