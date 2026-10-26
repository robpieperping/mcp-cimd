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
export const TEST_CALLBACK_PATH = "/callback";

/**
 * Both URLs are derived rather than written down, because the client_id must
 * equal the URL this is served from or PF rejects the client outright.
 *
 * The redirect deliberately points back here rather than at `/callback` on
 * the PingFederate host. That page looked like a passive token display, but
 * it performs the token exchange itself, server-side, using a verifier from
 * a flow it started. Landing our authorization response there made it
 * redeem our code with the wrong verifier: it failed with
 * "invalid_grant: the code_verifier sent does not match code_challenge", and
 * spent the single-use code before anyone could copy it out of the address
 * bar -- an error that reads as a PKCE bug in our own client and is not one.
 * Our callback exchanges nothing.
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
    redirect_uris: [`${origin}${TEST_CALLBACK_PATH}`],
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

/**
 * The landing page for the authorization response. It renders the query
 * parameters and does nothing else -- no token exchange, so the code is
 * still unspent when it reaches `flow.sh token`.
 */
export function serveTestCallback(req: Request, res: Response): void {
  const q = req.query as Record<string, string | undefined>;
  const row = (k: string) =>
    q[k] ? `<div class="k">${k}</div><pre>${escapeHtml(q[k]!)}</pre>` : "";
  const failed = Boolean(q.error);
  res
    .status(200)
    .type("html")
    .send(
      `<!doctype html><meta charset="utf-8"><title>Authorization response</title>
<style>body{font-family:system-ui,sans-serif;max-width:760px;margin:48px auto;
padding:0 24px;color:#222}h1{font-size:1.3rem;margin-bottom:4px}
.sub{color:#666;font-size:.9rem;margin-bottom:24px}
.k{font-size:.75rem;font-weight:600;text-transform:uppercase;color:#888;
margin:14px 0 4px}pre{margin:0;background:#f7f8fa;border:1px solid #e0e0e0;
border-radius:6px;padding:12px;white-space:pre-wrap;word-break:break-all;
font-size:.85rem}.err{color:#c0392b}
@media(prefers-color-scheme:dark){body{background:#1a1a1a;color:#eee}
pre{background:#242424;border-color:#3a3a3a}}</style>
<h1 class="${failed ? "err" : ""}">${
        failed ? "Authorization failed" : "Authorization response received"
      }</h1>
<div class="sub">Nothing was exchanged here. ${
        failed
          ? "There is no code to redeem."
          : "Copy this page's full URL from the address bar and pass it to <code>./flow.sh token</code>."
      }</div>
${row("code")}${row("state")}${row("iss")}${row("error")}${row("error_description")}`,
    );
}

function escapeHtml(s: string): string {
  return s.replace(
    /[&<>"']/g,
    (c) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[c]!,
  );
}
