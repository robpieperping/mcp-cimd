// Phase B exit criteria, as executable checks.
//
//   npm test
//
// The plan's exit is: "locally, a hand-minted PF token gets tools/list; no
// token and a wrong-audience token each get 401 with a well-formed
// challenge." A PF-signed token cannot be minted without PF's private key,
// so this stands up a local authorization server instead: a key pair, a
// JWKS endpoint, and tokens signed with it. Everything on this server's
// side of the boundary -- signature, iss, aud, exp, scope, the challenge,
// the tool gate -- is the real code path.
//
// No test framework: node:test and node:assert only, matching the repo's
// zero-dependency habit.

import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import { after, before, describe, it } from "node:test";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

const ISSUER = "https://as.test.invalid";
const RESOURCE = "https://mcp-cimd.ping-devops.com/mcp";
const READ_SCOPE = "fhir.read";
const WRITE_SCOPE = "fhir.write";
const TOTAL_TOOLS = 19;
const READ_TOOLS = 13; // 19 minus the 6 classified in src/tool-access.ts

// ── A local authorization server ─────────────────────────────────────────────

const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const ec = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const impostor = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });

function publicJwk(pair, kid) {
  return { ...pair.publicKey.export({ format: "jwk" }), kid, use: "sig" };
}

const jwks = { keys: [publicJwk(rsa, "rsa-1"), publicJwk(ec, "ec-1")] };
let jwksRequests = 0;

const jwksServer = http.createServer((req, res) => {
  jwksRequests += 1;
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify(jwks));
});

await new Promise((resolve) => jwksServer.listen(0, "127.0.0.1", resolve));
const jwksUri = `http://127.0.0.1:${jwksServer.address().port}/jwks`;

// ── Boot the server under test ───────────────────────────────────────────────
// config.ts reads the environment once, at require time, so this has to come
// before the require below.

Object.assign(process.env, {
  MCP_TRANSPORT: "http",
  MCP_AUTH: "required",
  MCP_TOOLSET: "read",
  OAUTH_ISSUER: ISSUER,
  OAUTH_JWKS_URI: jwksUri,
  MCP_RESOURCE: RESOURCE,
  OAUTH_READ_SCOPE: READ_SCOPE,
  OAUTH_WRITE_SCOPE: WRITE_SCOPE,
  FHIR_BASE_URL: "https://fhir.test.invalid/fhir",
  PINGONE_ENV_ID: "",
  PINGONE_CLIENT_ID: "",
  PINGONE_CLIENT_SECRET: "",
});

const { buildApp } = require("../dist/http.js");
const app = buildApp();
let base;
let appServer;

before(async () => {
  appServer = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => appServer.once("listening", resolve));
  base = `http://127.0.0.1:${appServer.address().port}`;
});

after(async () => {
  await new Promise((resolve) => appServer.close(resolve));
  await new Promise((resolve) => jwksServer.close(resolve));
});

// ── Minting ──────────────────────────────────────────────────────────────────

const b64u = (input) => Buffer.from(input).toString("base64url");

function sign(alg, key, signingInput) {
  if (alg === "none") return "";
  const digest = { 256: "sha256", 384: "sha384", 512: "sha512" }[alg.slice(2)];
  if (alg.startsWith("HS")) return crypto.createHmac(digest, key).update(signingInput).digest("base64url");
  const options = { key };
  if (alg.startsWith("ES")) options.dsaEncoding = "ieee-p1363";
  return crypto.sign(digest, Buffer.from(signingInput), options).toString("base64url");
}

function mint({ alg = "RS256", kid = "rsa-1", key = rsa.privateKey, ...overrides } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    iss: ISSUER,
    aud: RESOURCE,
    sub: "user-a",
    client_id: "https://chatgpt.com/oauth/client.json",
    scope: READ_SCOPE,
    iat: now,
    exp: now + 300,
    ...overrides,
  };
  for (const [name, value] of Object.entries(overrides)) {
    if (value === undefined) delete claims[name];
  }
  const header = b64u(JSON.stringify(kid ? { alg, kid, typ: "at+jwt" } : { alg, typ: "at+jwt" }));
  const payload = b64u(JSON.stringify(claims));
  return `${header}.${payload}.${sign(alg, key, `${header}.${payload}`)}`;
}

// ── Transport helpers ────────────────────────────────────────────────────────

const MCP_ACCEPT = "application/json, text/event-stream";

async function rpc(method, params, { token, sessionId } = {}) {
  const headers = { "content-type": "application/json", accept: MCP_ACCEPT };
  if (token) headers.authorization = `Bearer ${token}`;
  if (sessionId) headers["mcp-session-id"] = sessionId;
  const response = await fetch(`${base}/mcp`, {
    method: "POST",
    headers,
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  return { response, body: await readRpcBody(response) };
}

/** The streamable transport may answer either as JSON or as a one-event SSE stream. */
async function readRpcBody(response) {
  const text = await response.text();
  if (!text) return null;
  if ((response.headers.get("content-type") ?? "").includes("text/event-stream")) {
    const data = text
      .split("\n")
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice(5).trim())
      .join("");
    return data ? JSON.parse(data) : null;
  }
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

/** Opens a real MCP session and returns its id. */
async function openSession(token) {
  const { response, body } = await rpc(
    "initialize",
    {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "phase-b-test", version: "0" },
    },
    { token }
  );
  assert.equal(response.status, 200, `initialize failed: ${JSON.stringify(body)}`);
  const sessionId = response.headers.get("mcp-session-id");
  assert.ok(sessionId, "initialize returned no Mcp-Session-Id");

  await fetch(`${base}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: MCP_ACCEPT,
      authorization: `Bearer ${token}`,
      "mcp-session-id": sessionId,
    },
    body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
  });
  return sessionId;
}

/** Parses a WWW-Authenticate Bearer challenge into its parameters. */
function parseChallenge(header) {
  assert.ok(header, "no WWW-Authenticate header");
  assert.ok(header.startsWith("Bearer "), `challenge is not Bearer: ${header}`);
  const params = {};
  for (const [, key, value] of header.slice(7).matchAll(/([a-z_]+)="((?:[^"\\]|\\.)*)"/g)) {
    params[key] = value.replace(/\\(.)/g, "$1");
  }
  return params;
}

// ── Protected resource metadata ──────────────────────────────────────────────

describe("protected resource metadata", () => {
  it("is served unauthenticated at the well-known path", async () => {
    const response = await fetch(`${base}/.well-known/oauth-protected-resource`);
    assert.equal(response.status, 200);
    assert.match(response.headers.get("content-type"), /application\/json/);
    const body = await response.json();
    assert.equal(body.resource, RESOURCE);
    assert.deepEqual(body.authorization_servers, [ISSUER]);
    assert.deepEqual(body.scopes_supported, [READ_SCOPE]);
    assert.deepEqual(body.bearer_methods_supported, ["header"]);
  });

  it("is also served at the RFC 9728 path-suffixed location", async () => {
    const response = await fetch(`${base}/.well-known/oauth-protected-resource/mcp`);
    assert.equal(response.status, 200);
    assert.equal((await response.json()).resource, RESOURCE);
  });

  it("advertises no scope this server would refuse to honour", async () => {
    const body = await (await fetch(`${base}/.well-known/oauth-protected-resource`)).json();
    // Every advertised scope must be grantable, or linking fails at consent.
    assert.ok(body.scopes_supported.includes(READ_SCOPE));
    assert.ok(!body.scopes_supported.includes("offline_access"));
  });
});

describe("health endpoints", () => {
  it("answer without a token, so kubelet probes do not need one", async () => {
    const response = await fetch(`${base}/healthz`);
    assert.equal(response.status, 200);
    assert.equal((await response.json()).status, "ok");
  });
});

// ── 401s, and whether the challenge is usable ────────────────────────────────

describe("rejects a request with no usable token", () => {
  it("401s a request with no Authorization header, pointing at the metadata", async () => {
    const { response } = await rpc("tools/list", {});
    assert.equal(response.status, 401);
    const challenge = parseChallenge(response.headers.get("www-authenticate"));
    assert.equal(
      challenge.resource_metadata,
      "https://mcp-cimd.ping-devops.com/.well-known/oauth-protected-resource/mcp"
    );
    // RFC 6750 §3: absent credentials are not an error condition to report.
    assert.equal(challenge.error, undefined);
  });

  it("401s a non-Bearer Authorization header", async () => {
    const response = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: MCP_ACCEPT, authorization: "Basic abc" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    assert.equal(response.status, 401);
    assert.equal(parseChallenge(response.headers.get("www-authenticate")).error, "invalid_request");
  });

  const rejected = {
    "an opaque reference token": () => "e1e02f0a-not-a-jwt",
    "a token signed by an unpublished key": () => mint({ key: impostor.privateKey }),
    "a token with alg=none": () => mint({ alg: "none", key: null }),
    "an HMAC-signed token": () => mint({ alg: "HS256", key: "shared-secret", kid: "rsa-1" }),
    "a token from another issuer": () => mint({ iss: "https://evil.test.invalid" }),
    "a token with no aud": () => mint({ aud: undefined }),
    "a token for another resource": () => mint({ aud: "https://someone-else.example.com/mcp" }),
    "an expired token": () => mint({ exp: Math.floor(Date.now() / 1000) - 3600 }),
    "a not-yet-valid token": () => mint({ nbf: Math.floor(Date.now() / 1000) + 3600 }),
    "a token with no exp": () => mint({ exp: undefined }),
    "a tampered payload": () => {
      const parts = mint().split(".");
      const claims = JSON.parse(Buffer.from(parts[1], "base64url").toString());
      claims.scope = `${READ_SCOPE} ${WRITE_SCOPE}`;
      return `${parts[0]}.${b64u(JSON.stringify(claims))}.${parts[2]}`;
    },
  };

  for (const [name, make] of Object.entries(rejected)) {
    it(`401s ${name}`, async () => {
      const { response } = await rpc("tools/list", {}, { token: make() });
      assert.equal(response.status, 401, `expected 401 for ${name}`);
      const challenge = parseChallenge(response.headers.get("www-authenticate"));
      assert.equal(challenge.error, "invalid_token");
      assert.ok(challenge.error_description, "challenge carried no error_description");
      assert.ok(challenge.resource_metadata, "challenge carried no resource_metadata");
    });
  }

  it("names the audience mismatch in the 401, rather than failing blankly", async () => {
    const { response } = await rpc("tools/list", {}, { token: mint({ aud: "https://wrong.example.com/mcp" }) });
    const { error_description } = parseChallenge(response.headers.get("www-authenticate"));
    assert.match(error_description, /not issued for this resource/i);
  });

  it("403s an in-audience token that lacks the read scope", async () => {
    const { response } = await rpc("tools/list", {}, { token: mint({ scope: "openid email" }) });
    assert.equal(response.status, 403);
    const challenge = parseChallenge(response.headers.get("www-authenticate"));
    assert.equal(challenge.error, "insufficient_scope");
    assert.equal(challenge.scope, READ_SCOPE);
    assert.ok(challenge.resource_metadata);
  });
});

// ── The happy path ───────────────────────────────────────────────────────────

describe("accepts a valid token", () => {
  it("lists tools for an RS256 token", async () => {
    const token = mint();
    const sessionId = await openSession(token);
    const { response, body } = await rpc("tools/list", {}, { token, sessionId });
    assert.equal(response.status, 200);
    assert.equal(body.result.tools.length, READ_TOOLS);
  });

  it("lists tools for an ES256 token too", async () => {
    const token = mint({ alg: "ES256", kid: "ec-1", key: ec.privateKey });
    const sessionId = await openSession(token);
    const { body } = await rpc("tools/list", {}, { token, sessionId });
    assert.equal(body.result.tools.length, READ_TOOLS);
  });

  it("tags every tool with the oauth2 scope it needs", async () => {
    const token = mint();
    const sessionId = await openSession(token);
    const { body } = await rpc("tools/list", {}, { token, sessionId });
    for (const tool of body.result.tools) {
      assert.deepEqual(
        tool.securitySchemes,
        [{ type: "oauth2", scopes: [READ_SCOPE] }],
        `${tool.name} carried the wrong securitySchemes`
      );
      assert.equal(tool.annotations.readOnlyHint, true, `${tool.name} is listed but not read-only`);
    }
  });

  it("exposes no mutating tool under MCP_TOOLSET=read", async () => {
    const token = mint({ scope: `${READ_SCOPE} ${WRITE_SCOPE}` });
    const sessionId = await openSession(token);
    const { body } = await rpc("tools/list", {}, { token, sessionId });
    const names = body.result.tools.map((tool) => tool.name);
    assert.equal(names.length, READ_TOOLS);
    for (const name of ["fhir_create_resource", "fhir_update_resource", "fhir_delete_resource",
                        "fhir_patch_resource", "fhir_transaction", "fhir_execute_operation"]) {
      assert.ok(!names.includes(name), `${name} is exposed and should not be`);
    }
    assert.equal(READ_TOOLS + 6, TOTAL_TOOLS, "the read/write split no longer accounts for every tool");
  });

  it("refuses a hidden write tool even when asked for by name", async () => {
    const token = mint();
    const sessionId = await openSession(token);
    const { body } = await rpc(
      "tools/call",
      { name: "fhir_delete_resource", arguments: { resourceType: "Patient", id: "1" } },
      { token, sessionId }
    );
    const refused = body.error ?? body.result;
    assert.ok(refused, "the call was neither answered nor refused");
    if (body.result) {
      assert.equal(body.result.isError, true);
      // The Apps SDK reads this to offer a re-link, and requires both
      // error and error_description in the value.
      const challenge = parseChallenge(body.result._meta["mcp/www_authenticate"]);
      assert.equal(challenge.error, "insufficient_scope");
      assert.equal(challenge.scope, WRITE_SCOPE);
      assert.ok(challenge.error_description);
    }
  });
});

// ── Session binding ──────────────────────────────────────────────────────────

describe("session binding", () => {
  it("does not let a different subject drive someone else's session", async () => {
    const sessionId = await openSession(mint({ sub: "user-a" }));
    const { response } = await rpc("tools/list", {}, { token: mint({ sub: "user-b" }), sessionId });
    assert.equal(response.status, 404);
  });

  it("still serves the subject the session belongs to", async () => {
    const token = mint({ sub: "user-a" });
    const sessionId = await openSession(token);
    const { response } = await rpc("tools/list", {}, { token, sessionId });
    assert.equal(response.status, 200);
  });
});

// ── Key set handling ─────────────────────────────────────────────────────────

describe("key set handling", () => {
  it("caches the key set rather than fetching it per request", async () => {
    const token = mint();
    const before = jwksRequests;
    for (let i = 0; i < 5; i += 1) await rpc("tools/list", {}, { token });
    assert.ok(jwksRequests - before <= 1, `fetched JWKS ${jwksRequests - before} times for 5 requests`);
  });

  it("does not refetch the key set for every unknown kid", async () => {
    const before = jwksRequests;
    for (let i = 0; i < 5; i += 1) {
      await rpc("tools/list", {}, { token: mint({ kid: `rotated-${i}` }) });
    }
    assert.ok(jwksRequests - before <= 1, `an unknown kid cost ${jwksRequests - before} fetches`);
  });
});
