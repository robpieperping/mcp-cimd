# mcp-cimd

A FHIR R4 MCP server that is **its own OAuth 2.1 protected resource**. It
validates the bearer token ChatGPT presents against PingFederate's published
key set, publishes the metadata a client needs to find that authorization
server, and refuses anything it cannot audience-bind to itself.

Clean copy of [`bxhealth-fhir-mcp`](https://github.com/robpieperping/bxhealth-fhir-mcp)
with no shared history. The 19 FHIR tools and both transports are unchanged;
what is new is the authorization layer, and one architectural reversal:
**there is no PingGateway in front of this server.** The reasoning is in
plan §3 of the program folder — in short, OpenAI's connector requirements
*are* the MCP authorization spec, so implementing them here is a contained
amount of code, while pointing the existing gateway at PingFederate means a
second host, a second issuer, and re-litigating the audience problem that
cost the earlier Phase 4 its exit criterion.

Local checkout is `mcp-cimd-server`, not `mcp-cimd`: macOS is
case-insensitive, and `~/mywork/MCP-CIMD` (the program folder) already owns
that name. The git remote is `mcp-cimd` as planned.

## How a request is authorized

```
  ChatGPT                                        this server
     │                                                │
     │  POST /mcp  (no token)                         │
     │───────────────────────────────────────────────►│
     │  401 + WWW-Authenticate: Bearer                │
     │       resource_metadata="…/.well-known/…"      │  src/mcp-auth.ts
     │◄───────────────────────────────────────────────│
     │  GET /.well-known/oauth-protected-resource/mcp │
     │───────────────────────────────────────────────►│
     │  { resource, authorization_servers: [PF] }     │
     │◄───────────────────────────────────────────────│
     │                                                │
     │  auth-code + PKCE + resource=…/mcp             │
     ├────────────► PingFederate ────────────┐        │
     │              client_id = a CIMD URL   │        │
     │◄─────────── access token (JWT) ───────┘        │
     │                                                │
     │  POST /mcp  Authorization: Bearer …            │
     │───────────────────────────────────────────────►│  src/jwt.ts
     │                                                │   signature → PF JWKS
     │                                                │   iss  exact match
     │                                                │   aud  contains MCP_RESOURCE
     │                                                │   exp/nbf within skew
     │                                                │   scope ⊇ fhir.read
     │  200 — tools, scoped to the token              │  src/tool-access.ts
     │◄───────────────────────────────────────────────│
```

Validation is **stateless**: one cached fetch of `/pf/JWKS`, no
introspection call, nothing for a second replica to disagree about.

### The audience check is the point

`MCP_RESOURCE` has to be the same byte string in four places — this server's
config, the `resource` parameter ChatGPT sends on both the authorization and
token requests, the `Audience Claim Value` on PingFederate's access token
manager, and the `resource` field in the metadata document this server
publishes. A trailing slash in any one of them produces a 401 with no other
symptom, so the config rejects a trailing slash at startup and the 401's
`error_description` names both the audience it got and the one it wanted.

Phase A of the program established that PingFederate does implement RFC 8707
resource indicators and that `resource` selects the access token manager
whose `Audience Claim Value` becomes `aud`. That is what makes this design
viable; see `MCP-CIMD/phase-a/README.md`.

## Configuration

```bash
cp .env.example .env
```

`.env` is read at startup from the project root; variables already in the
environment win, so a host or shell export overrides the file. `.env` is
gitignored.

### Inbound — what ChatGPT's token must satisfy

| Variable | Default | Description |
| --- | --- | --- |
| `MCP_RESOURCE` | — | Canonical https identifier for this server. Exact-matched against `aud`. No trailing slash. Required when auth is on. |
| `OAUTH_ISSUER` | — | PingFederate's issuer, exactly as its `openid-configuration` reports it. Required when auth is on. |
| `OAUTH_JWKS_URI` | `$OAUTH_ISSUER/pf/JWKS` | PingFederate publishes keys there rather than at the RFC-conventional path. It is also what PF's own `openid-configuration` reports as `jwks_uri`. |
| `OAUTH_READ_SCOPE` | `fhir.read` | Required on every request. |
| `OAUTH_WRITE_SCOPE` | `fhir.write` | Additionally required by the mutating tools. |
| `OAUTH_SCOPES_SUPPORTED` | the read scope | Advertised in metadata. Every scope listed must be grantable in PF, or linking fails at consent. |
| `MCP_TOOLSET` | `read` | `read` hides the six mutating tools; `all` exposes them, still gated on the write scope. |
| `MCP_AUTH` | `required` | `disabled` turns off inbound validation. Local development only. |
| `OAUTH_CLOCK_SKEW_SECONDS` | `60` | Tolerance on `exp`/`nbf`. |
| `OAUTH_JWKS_CACHE_SECONDS` | `300` | Key set TTL. An unknown `kid` also triggers one rate-limited refetch, so rotation is picked up without waiting out the TTL. |

Auth applies to the **http** transport only. stdio has no HTTP layer to
authorize, and the MCP spec says stdio servers should take credentials from
the environment instead.

### Outbound — this server's own call to FHIR

| Variable | Description |
| --- | --- |
| `FHIR_BASE_URL` | FHIR R4 base URL, including `/fhir`. Required. |
| `PINGONE_ENV_ID` / `PINGONE_CLIENT_ID` / `PINGONE_CLIENT_SECRET` | Optional. A `client_credentials` app for the upstream call. |

### Transport

| Variable | Default |
| --- | --- |
| `MCP_TRANSPORT` | `stdio`; `http` for the cluster and ChatGPT |
| `PORT` | `3000` |
| `HOST` | `0.0.0.0` |

## Build, test, run

```bash
npm install
npm test           # build, then the authorization suite
npm start          # stdio
npm run start:http # Streamable HTTP on PORT
```

`npm test` is the Phase B exit criterion, executable. It stands up a local
authorization server — a key pair and a JWKS endpoint — and drives the real
express app over real HTTP, because a PingFederate-signed token cannot be
minted without PingFederate's private key. Everything on this server's side
of the boundary is the code that runs in production.

31 checks, including: an opaque reference token, a token signed by an
unpublished key, `alg=none`, an HMAC-signed token (the JWKS confusion
attack), another issuer, a missing `aud`, another resource's `aud`, expired,
not-yet-valid, no `exp`, a tampered payload, a valid token with the wrong
scope, RS256 and ES256 happy paths, the `securitySchemes` on every listed
tool, the mutating tools' absence under `MCP_TOOLSET=read`, one subject
trying to drive another's session, that the key set is cached rather than
fetched per request, and that a brief authorization-server outage is
served from the cached key set rather than becoming an outage here.

## HTTP routes

| Route | Auth | Purpose |
| --- | --- | --- |
| `POST /mcp` | required | JSON-RPC. No `Mcp-Session-Id` means it must be an `initialize`; the response carries the new id. |
| `GET /mcp` | required | SSE stream for an established session. |
| `DELETE /mcp` | required | Ends a session. |
| `GET /.well-known/oauth-protected-resource` | none | RFC 9728 metadata. Public by definition — a client reads it to learn how to authenticate. |
| `GET /.well-known/oauth-protected-resource/mcp` | none | The same document at the path-suffixed location RFC 9728 §3.1 specifies for a resource with a path. Both are served because clients in the wild try both. |
| `GET /healthz` | none | Liveness. Never touches FHIR, so a FHIR outage cannot restart the pod. |
| `GET /readyz` | none | Readiness. Pings the CapabilityStatement and reports the advertised `fhirVersion`, the cheapest way to catch an R4/R5 mismatch. |

Sessions are held in memory and keyed by `Mcp-Session-Id`, so the service is
**single-replica** until there is a shared store or sticky sessions. Each
session also remembers the subject that opened it: a valid token is not the
same as the token a session belongs to, and without that check a session id
would be a handle any other token holder could pick up.

Smoke test the challenge, which is the one thing a misconfigured deployment
gets wrong invisibly:

```bash
curl -isS -X POST http://localhost:3000/mcp \
  -H 'content-type: application/json' -d '{}' | grep -i www-authenticate
```

## Tool exposure

`MCP_TOOLSET=read` is the default, on the strength of plan §6.2: the demo's
value is retrieval, and a destructive FHIR tool reachable from a chat client
is a far larger blast radius than the demo needs. The six tools it hides are
classified in `src/tool-access.ts`:

| Tool | Why |
| --- | --- |
| `fhir_create_resource` | writes |
| `fhir_update_resource` | writes |
| `fhir_patch_resource` | writes |
| `fhir_delete_resource` | writes |
| `fhir_transaction` | writes, in bulk |
| `fhir_execute_operation` | invokes arbitrary `$operations`, plenty of which mutate, and cannot be classified safely from its arguments |

`fhir_search_resources` is deliberately *not* in that list. It takes an
arbitrary resource type and query, which is a broad surface, but every path
through it is a GET — a confidentiality question, which `fhir.read` is the
scope that governs.

Each listed tool carries `securitySchemes: [{ type: "oauth2", scopes: [...] }]`,
which is how ChatGPT decides whether a tool needs a linked account and which
scopes to request. Scope is re-checked on every call, not just at list time:
the tool list is a hint to the model, the check is the control. A refusal
comes back as a tool result carrying `_meta["mcp/www_authenticate"]`, which
is what lets ChatGPT offer a step-up re-link rather than just reporting an
error.

### The 19 tools

Generic FHIR operations:

- `fhir_get_metadata` — fetch the server CapabilityStatement
- `fhir_read_resource` / `fhir_vread_resource` — read a resource, optionally at a version
- `fhir_search_resources` — search any resource type
- `fhir_create_resource` / `fhir_update_resource` / `fhir_patch_resource` / `fhir_delete_resource`
- `fhir_resource_history` / `fhir_type_history` — history for one resource or a whole type
- `fhir_validate_resource` — validate against the server's profiles
- `fhir_execute_operation` — invoke an arbitrary `$operation`
- `fhir_transaction` — submit a transaction or batch Bundle
- `fhir_patient_everything` — `Patient/$everything`

Convenience searches: `fhir_search_patients`, `fhir_search_observations`,
`fhir_search_conditions`, `fhir_search_medication_requests`,
`fhir_search_encounters`.

## Container

```bash
docker build -f infra/Dockerfile -t mcp-cimd .
docker run --rm -p 3000:3000 --env-file .env mcp-cimd
```

Defaults to `MCP_TRANSPORT=http`. Runs as UID 1000 stated numerically, not
as `USER node` — Kubernetes verifies `runAsNonRoot` from the numeric UID and
cannot resolve a name inside the image.

CI builds `linux/arm64`: every node on the target cluster is Graviton. An
amd64 image fails as `exec format error` in CrashLoopBackOff, which reads
like an application bug.

## Registering with an MCP host over stdio

```json
{
  "mcpServers": {
    "mcp-cimd": {
      "command": "node",
      "args": ["/absolute/path/to/mcp-cimd-server/dist/index.js"]
    }
  }
}
```

## Known gaps

**The upstream FHIR hop is unauthenticated.** Inherited from the earlier
work, where the PingOne token request failed and the FHIR client silently
fell back to no `Authorization` header. The fallback is now explicit — with
no PingOne configuration the server logs that FHIR calls go out
unauthenticated, rather than looking like it tried — but the gap is real:
the user authenticates to *this* server, and per-patient scoping is not
enforced upstream. Either fix it (a token exchange, which would make this
server a CIMD client in its own right) or state it in the demo narrative.

**`fhir.write` is grantable in PingFederate today.** Phase A measured that.
`MCP_TOOLSET=read` means it buys nothing here, but the two settings should
agree before the demo is shown.

**`securitySchemes` is not in the MCP core specification.** It comes from
OpenAI's Apps SDK, and the MCP SDK's types do not know the field — it is
attached to the tool descriptor and passes through untouched. A client that
does not read it falls back to the server-level requirement, which is the
same answer.

## Where this sits

| | |
| --- | --- |
| Program plan | `~/mywork/MCP-CIMD/plan.md` |
| Phase A findings and PF runbook | `~/mywork/MCP-CIMD/phase-a/README.md` |
| CIMD documents | `~/mywork/MCP-CIMD/cimd/README.md` |
| Deployment | `infra/k8s/README.md` |
| One-time cluster + CI setup | `./infra/k8s/bootstrap.sh` |
| Check a deployment | `./infra/verify-deploy.sh` |
