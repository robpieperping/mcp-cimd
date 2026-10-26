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
 *     a client secret we do not have.
 *
 * A second variant is served at /mcp-test-client-jwt[-suffix].json. It
 * declares private_key_jwt against a jwks_uri on this same origin, and it
 * exists to reproduce ChatGPT's client authentication with a key we hold.
 * PingFederate 13.1 rejects ChatGPT's assertion on two rules -- RFC 7523
 * `aud` and rfc7523bis `typ` -- and that rejection is only reachable after
 * PF has resolved the signing key and verified the signature. Signing with
 * OpenAI's key is impossible; signing with ours is, so the rules can be
 * measured directly and a fix confirmed without spending a ChatGPT connect
 * attempt. See MCP-CIMD/cimd/probe-client-auth.sh.
 */

import type { Request, Response } from "express";
import { config } from "./config.js";

export const TEST_CLIENT_DOC_PATH = "/mcp-test-client.json";

/**
 * The document is served at any `/mcp-test-client[-suffix].json`, and its
 * client_id is whichever of those paths was actually requested.
 *
 * That exists because PingFederate never re-reads a document it has already
 * seen. It is not a cache, which is how it was first misread: on first use PF
 * *registers* the resolved client into its own client store, keyed by
 * client_id, and fetches the document no further. After the redirect_uri
 * inside the document changed, PF went on validating against the registered
 * copy indefinitely -- waiting does not help, and no refetch ever appears in
 * the ingress log. A client_id *is* the document URL, so serving at a
 * suffixed path is a different client and PF registers it fresh. See
 * MCP-CIMD/cimd/README.md.
 *
 * The pattern is deliberately narrow rather than "serve a document for any
 * path": this is a public, unauthenticated endpoint.
 */
const DOC_PATH = /^\/mcp-test-client(-[a-z0-9]{1,16})?\.json$/;

/**
 * The private_key_jwt variant. Checked before DOC_PATH, because `-jwt` also
 * satisfies DOC_PATH's generic suffix and would otherwise serve a document
 * claiming "none" at a path whose whole purpose is to claim private_key_jwt.
 */
const JWT_DOC_PATH = /^\/mcp-test-client-jwt(-[a-z0-9]{1,16})?\.json$/;

export const TEST_CALLBACK_PATH = "/callback";

/**
 * Deliberately not `/mcp-test-client-jwks.json`: `-jwks` matches DOC_PATH's
 * generic suffix, so that spelling would collide with the document route.
 */
export const TEST_CLIENT_JWKS_PATH = "/mcp-test-client.jwks.json";

/**
 * The public half of the probe signing key. Public by construction -- it is
 * published at TEST_CLIENT_JWKS_PATH for PingFederate to fetch, so there is
 * nothing here to protect. The private half is held outside this repository,
 * at MCP-CIMD/cimd/.probe-key.jwk.json, and is used only by the probe script.
 *
 * Rotating it means generating a new pair, replacing this constant, and
 * serving the document at a fresh `-jwt-<suffix>` path: PF registered the old
 * client against the old jwks_uri contents and will not look again.
 */
const PROBE_JWKS = {
  keys: [
    {
      kty: "RSA",
      n: "34ibsjD1Wf5yrHstbqi1MVcDWHYU7S50st64bIZZhIFUbtPBJHrDe4fqvk5QCfc1lBY6aKbgaUbsziIt4x8g5nOzBG_ClSij0ZXRjg-iTiM_kpRelrUucHtEBTZF0xoQegpXpEh2nWBGUFisj_L-OkJg7vgI2UdoCHNxjrr0nZ6yXcTxEyWvarLfw3Yq_fkHOyCSvCg8wAcnguvfx7A2vZ5W9anhP3LzZeH2qq5Ejl3MtGQEBtkSvZAzo82izkWXKh1MJjY0Og9_Ohnv3zoo_ZIDXVZaaAXO1Z7gOn94qlGtU8HkW5VASQiN7XgM6l5TP41u7hkvhp29KhBv4wJC8w",
      e: "AQAB",
      kid: "probe-20261026",
      alg: "RS256",
      use: "sig",
    },
  ],
} as const;

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
export function testClientDocument(
  docPath: string = TEST_CLIENT_DOC_PATH,
): Record<string, unknown> {
  const resource = config.auth.resource;
  const issuer = config.auth.issuer;
  if (!resource || !issuer) {
    throw new Error(
      "SERVE_TEST_CLIENT_DOC needs MCP_RESOURCE and OAUTH_ISSUER to derive " +
        "the client_id and redirect_uri.",
    );
  }
  const privateKeyJwt = JWT_DOC_PATH.test(docPath);
  if (!privateKeyJwt && !DOC_PATH.test(docPath)) {
    throw new Error(`Refusing to mint a client document for ${docPath}.`);
  }
  const origin = new URL(resource).origin;
  // ChatGPT names the signing algorithm explicitly and so do we, so PF
  // registers the same constraint it registered for ChatGPT.
  const auth = privateKeyJwt
    ? {
        token_endpoint_auth_method: "private_key_jwt",
        token_endpoint_auth_signing_alg: "RS256",
        jwks_uri: `${origin}${TEST_CLIENT_JWKS_PATH}`,
      }
    : { token_endpoint_auth_method: "none" };
  return {
    client_id: `${origin}${docPath}`,
    client_name: "FHIR MCP Phase A Test Client",
    client_uri: "https://github.com/robpieperping/mcp-cimd",
    redirect_uris: [`${origin}${TEST_CALLBACK_PATH}`],
    response_types: ["code"],
    grant_types: ["authorization_code", "refresh_token"],
    ...auth,
    application_type: "web",
    subject_type: "public",
  };
}

export function serveTestClientDocument(req: Request, res: Response): void {
  if (!JWT_DOC_PATH.test(req.path) && !DOC_PATH.test(req.path)) {
    res.status(404).json({ error: "not_found" });
    return;
  }
  // PF fetches this, so it must be application/json and must not be cached
  // long enough to outlive an edit during testing.
  res
    .status(200)
    .type("application/json")
    .set("Cache-Control", "public, max-age=60")
    .json(testClientDocument(req.path));
}

/**
 * PingFederate fetches this when it registers the private_key_jwt variant,
 * then keeps the keys it found. Confirmed behaviour, not assumption: PF was
 * observed resolving ChatGPT's `kid` out of chatgpt.com/oauth/jwks.json and
 * verifying a signature with it before it reported any claim error.
 */
export function serveTestClientJwks(_req: Request, res: Response): void {
  res
    .status(200)
    .type("application/json")
    .set("Cache-Control", "public, max-age=60")
    .json(PROBE_JWKS);
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
