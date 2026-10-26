// The document's value is in what it does NOT say, so that is what this
// pins. Config is read once per process, so this file sets its own env.
import { strict as assert } from "node:assert";
import { test, before } from "node:test";

const RESOURCE = "https://mcp-cimd.example.com/mcp";
const ISSUER = "https://as.example.com";

let testClientDocument, TEST_CLIENT_DOC_PATH, buildApp;

before(async () => {
  Object.assign(process.env, {
    MCP_TRANSPORT: "http",
    MCP_AUTH: "required",
    MCP_RESOURCE: RESOURCE,
    OAUTH_ISSUER: ISSUER,
    FHIR_BASE_URL: "https://fhir.example.com/fhir",
    SERVE_TEST_CLIENT_DOC: "true",
  });
  ({ testClientDocument, TEST_CLIENT_DOC_PATH } = await import(
    "../dist/test-client-doc.js"
  ));
  ({ buildApp } = await import("../dist/http.js"));
});

test("declares no scope key, so the CIMD policy's defaults govern", () => {
  // A document that declares a scope list is restricted to it, which is
  // exactly how the facile demo client became unable to request fhir.read.
  assert.equal("scope" in testClientDocument(), false);
});

test("client_id equals the URL it is served from", () => {
  // CIMD identity: if these disagree, PF rejects the client outright.
  assert.equal(
    testClientDocument().client_id,
    `https://mcp-cimd.example.com${TEST_CLIENT_DOC_PATH}`,
  );
});

test("redirects to our own callback, not the AS's", () => {
  // The PF host's /callback performs the token exchange itself, server-side,
  // with a verifier from a flow it started. Pointing our authorization
  // response there made it spend our single-use code and fail with
  // "code_verifier does not match code_challenge" -- which reads as a PKCE
  // bug in this client and is not one. Ours exchanges nothing.
  assert.deepEqual(testClientDocument().redirect_uris, [
    "https://mcp-cimd.example.com/callback",
  ]);
});

test("the callback does not exchange anything", async () => {
  const app = buildApp();
  const server = app.listen(0);
  await new Promise((r) => server.once("listening", r));
  try {
    const res = await fetch(
      `http://127.0.0.1:${server.address().port}/callback?code=abc123&state=xyz`,
    );
    const body = await res.text();
    assert.equal(res.status, 200);
    assert.match(body, /abc123/);
    assert.match(body, /Nothing was exchanged here/);
  } finally {
    server.close();
  }
});

test("can redeem a code without a secret", () => {
  assert.equal(testClientDocument().token_endpoint_auth_method, "none");
});

test("is served as JSON, unauthenticated", async () => {
  const app = buildApp();
  const server = app.listen(0);
  await new Promise((r) => server.once("listening", r));
  try {
    const res = await fetch(
      `http://127.0.0.1:${server.address().port}${TEST_CLIENT_DOC_PATH}`,
    );
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type"), /application\/json/);
    assert.equal((await res.json()).client_id, testClientDocument().client_id);
  } finally {
    server.close();
  }
});
