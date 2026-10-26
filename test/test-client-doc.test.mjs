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

test("a suffixed path serves a document whose client_id is that path", async () => {
  // PF registers a client by client_id and never re-reads its document, and
  // a client_id IS the document URL -- so a suffixed path is a new client,
  // which is the only way to revise one. The document must own the URL it is
  // served from or PF rejects the client outright.
  const app = buildApp();
  const server = app.listen(0);
  await new Promise((r) => server.once("listening", r));
  try {
    const res = await fetch(
      `http://127.0.0.1:${server.address().port}/mcp-test-client-v2.json`,
    );
    assert.equal(res.status, 200);
    const d = await res.json();
    assert.equal(d.client_id, "https://mcp-cimd.example.com/mcp-test-client-v2.json");
    assert.equal("scope" in d, false);
  } finally {
    server.close();
  }
});

test("refuses to mint a document for an unexpected path", async () => {
  // This endpoint is public and unauthenticated; it should not hand out a
  // client document for any path a caller invents.
  const app = buildApp();
  const server = app.listen(0);
  await new Promise((r) => server.once("listening", r));
  try {
    for (const p of ["/anything.json", "/mcp-test-client-WAYTOOLONGSUFFIXHERE.json"]) {
      const res = await fetch(`http://127.0.0.1:${server.address().port}${p}`);
      assert.equal(res.status, 404, `${p} should not be served`);
    }
  } finally {
    server.close();
  }
});

// ── the private_key_jwt variant ─────────────────────────────────────────────
// It exists to measure PingFederate 13.1's client-assertion rules with a key
// we hold. PF rejected ChatGPT's assertion on `aud` and on the `typ` header,
// and neither complaint is reachable until PF has resolved the signing key
// and verified the signature -- so an unverifiable key tells us nothing.

test("the -jwt document authenticates with private_key_jwt", async () => {
  const { testClientDocument: doc, TEST_CLIENT_JWKS_PATH } = await import(
    "../dist/test-client-doc.js"
  );
  const d = doc("/mcp-test-client-jwt.json");
  assert.equal(d.token_endpoint_auth_method, "private_key_jwt");
  assert.equal(d.token_endpoint_auth_signing_alg, "RS256");
  assert.equal(
    d.jwks_uri,
    `https://mcp-cimd.example.com${TEST_CLIENT_JWKS_PATH}`,
  );
  assert.equal(d.client_id, "https://mcp-cimd.example.com/mcp-test-client-jwt.json");
  // Same reason as the plain document: a declared scope list would restrict
  // the client and cost it fhir.read.
  assert.equal("scope" in d, false);
});

test("the plain document is untouched by the jwt branch", () => {
  const d = testClientDocument();
  assert.equal(d.token_endpoint_auth_method, "none");
  assert.equal("jwks_uri" in d, false);
  assert.equal("token_endpoint_auth_signing_alg" in d, false);
});

test("the published JWKS carries no private material", async () => {
  // The whole point of the split is that the private half lives outside this
  // repository. If `d` ever appears here, the signing key has been published.
  const { TEST_CLIENT_JWKS_PATH } = await import("../dist/test-client-doc.js");
  const app = buildApp();
  const server = app.listen(0);
  await new Promise((r) => server.once("listening", r));
  try {
    const res = await fetch(
      `http://127.0.0.1:${server.address().port}${TEST_CLIENT_JWKS_PATH}`,
    );
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type"), /application\/json/);
    const jwks = await res.json();
    assert.equal(jwks.keys.length, 1);
    assert.equal(jwks.keys[0].kty, "RSA");
    assert.equal(jwks.keys[0].alg, "RS256");
    assert.ok(jwks.keys[0].kid);
    for (const secret of ["d", "p", "q", "dp", "dq", "qi"]) {
      assert.equal(secret in jwks.keys[0], false, `JWKS leaked ${secret}`);
    }
  } finally {
    server.close();
  }
});

test("the jwks path is not served as a client document", async () => {
  // `-jwks` would satisfy the document pattern's generic suffix, which is
  // why the path is spelled with a dot. Pin that it stays a JWKS.
  const app = buildApp();
  const server = app.listen(0);
  await new Promise((r) => server.once("listening", r));
  try {
    const res = await fetch(
      `http://127.0.0.1:${server.address().port}/mcp-test-client.jwks.json`,
    );
    const body = await res.json();
    assert.equal("client_id" in body, false);
    assert.ok(Array.isArray(body.keys));
  } finally {
    server.close();
  }
});
