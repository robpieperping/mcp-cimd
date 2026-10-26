// A brief authorization-server outage must not become an outage of this
// server. Separate file because config.ts reads the environment once per
// process and this needs a zero-second key set TTL.

import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import { after, before, describe, it } from "node:test";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

const ISSUER = "https://as.test.invalid";
const RESOURCE = "https://mcp-cimd.ping-devops.com/mcp";

const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwks = { keys: [{ ...rsa.publicKey.export({ format: "jwk" }), kid: "rsa-1", use: "sig" }] };

let asHealthy = true;

const jwksServer = http.createServer((req, res) => {
  if (!asHealthy) {
    res.writeHead(503).end("the authorization server is having a bad day");
    return;
  }
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify(jwks));
});
await new Promise((resolve) => jwksServer.listen(0, "127.0.0.1", resolve));

Object.assign(process.env, {
  MCP_TRANSPORT: "http",
  MCP_AUTH: "required",
  OAUTH_ISSUER: ISSUER,
  OAUTH_JWKS_URI: `http://127.0.0.1:${jwksServer.address().port}/jwks`,
  MCP_RESOURCE: RESOURCE,
  // Every request re-reads the key set, so the outage is hit immediately.
  OAUTH_JWKS_CACHE_SECONDS: "0",
  FHIR_BASE_URL: "https://fhir.test.invalid/fhir",
  PINGONE_ENV_ID: "",
  PINGONE_CLIENT_ID: "",
  PINGONE_CLIENT_SECRET: "",
});

const { buildApp } = require("../dist/http.js");
let base;
let appServer;

before(async () => {
  appServer = buildApp().listen(0, "127.0.0.1");
  await new Promise((resolve) => appServer.once("listening", resolve));
  base = `http://127.0.0.1:${appServer.address().port}`;
});

after(async () => {
  await new Promise((resolve) => appServer.close(resolve));
  await new Promise((resolve) => jwksServer.close(resolve));
});

const b64u = (input) => Buffer.from(input).toString("base64url");

function mint({ kid = "rsa-1", key = rsa.privateKey } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const header = b64u(JSON.stringify({ alg: "RS256", kid }));
  const payload = b64u(
    JSON.stringify({ iss: ISSUER, aud: RESOURCE, sub: "user-a", scope: "fhir.read", exp: now + 300 })
  );
  return `${header}.${payload}.${crypto
    .sign("sha256", Buffer.from(`${header}.${payload}`), key)
    .toString("base64url")}`;
}

async function listTools(token) {
  return fetch(`${base}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  });
}

describe("when the authorization server goes down", () => {
  it("accepts a valid token while the key set is reachable", async () => {
    assert.notEqual((await listTools(mint())).status, 401);
  });

  it("keeps accepting a valid token from the cached key set", async () => {
    asHealthy = false;
    try {
      assert.notEqual((await listTools(mint())).status, 401, "a brief AS outage became our outage");
    } finally {
      asHealthy = true;
    }
  });

  it("still refuses a token the cached key set cannot verify", async () => {
    const impostor = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    asHealthy = false;
    try {
      const response = await listTools(mint({ key: impostor.privateKey }));
      assert.equal(response.status, 401, "the stale cache was treated as permission");
    } finally {
      asHealthy = true;
    }
  });
});
