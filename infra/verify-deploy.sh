#!/usr/bin/env bash
# Phase C exit criteria against the deployed server, as a pass/fail report.
#
#   ./infra/verify-deploy.sh                      # everything that needs no token
#   ./infra/verify-deploy.sh "$ACCESS_TOKEN"      # also drives a real session
#
# Exits non-zero unless every required check passes. Safe to re-run: it only
# reads, and the one write it performs is opening and closing an MCP session.
set -uo pipefail

HOST="${MCP_HOST:-mcp-cimd.ping-devops.com}"
RESOURCE="${MCP_RESOURCE:-https://$HOST/mcp}"
TOKEN="${1:-${MCP_TOKEN:-}}"

for tool in curl openssl python3 dig; do
  command -v "$tool" >/dev/null || { echo "verify-deploy.sh needs $tool on PATH." >&2; exit 2; }
done

pass=0 fail=0
ok()   { printf '  PASS  %-52s %s\n' "$1" "${2:-}"; pass=$((pass+1)); }
no()   { printf '  FAIL  %-52s %s\n' "$1" "${2:-}"; fail=$((fail+1)); }
note() { printf '  ----  %-52s %s\n' "$1" "${2:-}"; }

jqish() { python3 -c "import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit(1)
import functools
v=d
for k in sys.argv[1].split('.'):
    if k=='': continue
    v = v[int(k)] if k.isdigit() else v.get(k) if isinstance(v,dict) else None
    if v is None: sys.exit(1)
print(v if not isinstance(v,(list,dict)) else json.dumps(v))" "$1"; }

echo
echo "--- $HOST ---"
echo

# ── DNS and TLS ──────────────────────────────────────────────────────────────

if addr=$(dig +short "$HOST" 2>/dev/null | head -1) && [ -n "$addr" ]; then
  ok "DNS resolves" "$addr"
else
  no "DNS resolves" "no A/CNAME record for $HOST"
fi

# The wildcard certificate is the thing most likely to be silently wrong: a
# host outside *.ping-devops.com gets no cert at all, and ChatGPT will not
# talk to a server it cannot verify.
cert=$(echo | openssl s_client -servername "$HOST" -connect "$HOST:443" 2>/dev/null \
       | openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null)
if [ -n "$cert" ]; then
  subject=$(printf '%s' "$cert" | sed -n 's/^subject=//p')
  issuer=$(printf '%s' "$cert" | sed -n 's/^issuer=.*CN *= *//p' | head -1)
  notafter=$(printf '%s' "$cert" | sed -n 's/^notAfter=//p')
  ok "TLS certificate presented" "$subject"
  note "issued by" "${issuer:-unknown}, expires $notafter"
  if printf '%s' "$cert" | grep -q "DNS:\*\.ping-devops\.com\|DNS:$HOST"; then
    ok "certificate covers this host" ""
  else
    no "certificate covers this host" "SAN lists neither $HOST nor *.ping-devops.com"
  fi
else
  no "TLS certificate presented" "no TLS handshake on $HOST:443"
fi

# ── Protected resource metadata: the Phase C exit ────────────────────────────

meta_body=$(curl -sS --max-time 15 "https://$HOST/.well-known/oauth-protected-resource" 2>/dev/null)
meta_code=$(curl -sS --max-time 15 -o /dev/null -w '%{http_code}' \
            "https://$HOST/.well-known/oauth-protected-resource" 2>/dev/null)
meta_type=$(curl -sS --max-time 15 -o /dev/null -w '%{content_type}' \
            "https://$HOST/.well-known/oauth-protected-resource" 2>/dev/null)

if [ "$meta_code" = "200" ]; then
  ok "metadata returns 200 over TLS" ""
else
  no "metadata returns 200 over TLS" "got $meta_code"
fi
case "$meta_type" in
  application/json*) ok "metadata is application/json" "" ;;
  *)                 no "metadata is application/json" "got ${meta_type:-nothing}" ;;
esac

advertised=$(printf '%s' "$meta_body" | jqish resource 2>/dev/null)
if [ "$advertised" = "$RESOURCE" ]; then
  ok "advertised resource is correct" "$advertised"
else
  # Almost always a stale MCP_RESOURCE in the Deployment env, and the symptom
  # downstream is a flat 401 with no other clue.
  no "advertised resource is correct" "advertises '${advertised:-nothing}', expected '$RESOURCE'"
fi

as=$(printf '%s' "$meta_body" | jqish authorization_servers.0 2>/dev/null)
if [ -n "$as" ]; then
  ok "names an authorization server" "$as"
else
  no "names an authorization server" "authorization_servers is missing or empty"
fi

scopes=$(printf '%s' "$meta_body" | jqish scopes_supported 2>/dev/null)
if [ -n "$scopes" ]; then
  ok "advertises scopes" "$scopes"
else
  no "advertises scopes" "every advertised scope must be grantable in PF"
fi

# RFC 9728 §3.1 puts the resource's path after the well-known segment.
suffixed=$(curl -sS --max-time 15 -o /dev/null -w '%{http_code}' \
           "https://$HOST/.well-known/oauth-protected-resource/mcp" 2>/dev/null)
if [ "$suffixed" = "200" ]; then
  ok "metadata at the path-suffixed location too" ""
else
  no "metadata at the path-suffixed location too" "got $suffixed"
fi

# ── The challenge, and whether it is actionable ───────────────────────────────

challenge=$(curl -sS --max-time 15 -i -X POST "https://$HOST/mcp" \
            -H 'content-type: application/json' -d '{}' 2>/dev/null)
status=$(printf '%s' "$challenge" | head -1 | tr -d '\r')
header=$(printf '%s' "$challenge" | grep -i '^www-authenticate:' | tr -d '\r')

case "$status" in
  *401*) ok "unauthenticated POST /mcp is refused" "$status" ;;
  *)     no "unauthenticated POST /mcp is refused" "${status:-no response}" ;;
esac

if [ -n "$header" ]; then
  ok "challenge carries WWW-Authenticate" ""
  rm_url=$(printf '%s' "$header" | sed -n 's/.*resource_metadata="\([^"]*\)".*/\1/p')
  if [ -n "$rm_url" ]; then
    ok "challenge carries resource_metadata" "$rm_url"
    # This is how ChatGPT discovers PingFederate. A URL that does not
    # resolve is the whole flow dead at step one.
    rm_code=$(curl -sS --max-time 15 -o /dev/null -w '%{http_code}' "$rm_url" 2>/dev/null)
    if [ "$rm_code" = "200" ]; then
      ok "the advertised metadata URL resolves" ""
    else
      no "the advertised metadata URL resolves" "got $rm_code from $rm_url"
    fi
  else
    no "challenge carries resource_metadata" "ChatGPT cannot discover the AS without it"
  fi
else
  no "challenge carries WWW-Authenticate" ""
fi

# A garbage bearer must be refused as invalid_token, which also proves the
# pod can reach the key set -- a pod that cannot would fail the same way, so
# check the server log if this one is the only failure.
bad=$(curl -sS --max-time 20 -i -X POST "https://$HOST/mcp" \
      -H 'content-type: application/json' -H 'authorization: Bearer not.a.jwt' \
      -d '{}' 2>/dev/null | grep -i '^www-authenticate:' | tr -d '\r')
case "$bad" in
  *invalid_token*) ok "a bad token is refused as invalid_token" "" ;;
  *)               no "a bad token is refused as invalid_token" "${bad:-no challenge}" ;;
esac

# ── The authorization server chain ChatGPT walks ─────────────────────────────

if [ -n "$as" ]; then
  found_metadata=no
  for path in .well-known/oauth-authorization-server .well-known/openid-configuration; do
    body=$(curl -sS --max-time 15 "$as/$path" 2>/dev/null)
    iss=$(printf '%s' "$body" | jqish issuer 2>/dev/null)
    if [ -n "$iss" ]; then
      found_metadata=yes
      # Exact string comparison, per RFC 9207. No normalisation.
      if [ "$iss" = "$as" ]; then
        ok "$path issuer matches" "$iss"
      else
        no "$path issuer matches" "reports '$iss', we advertise '$as'"
      fi
      if printf '%s' "$body" | grep -q '"authorization_response_iss_parameter_supported": *true'; then
        ok "$path advertises RFC 9207 iss" ""
      else
        note "$path RFC 9207 iss" "not advertised; ChatGPT then issues a per-connector client_id"
      fi
    else
      note "$path" "not served (one of the two is enough)"
    fi
  done
  if [ "$found_metadata" = yes ]; then
    ok "the AS serves discovery metadata" ""
  else
    no "the AS serves discovery metadata" "neither RFC 8414 nor OIDC discovery answered"
  fi
fi

# ── What must NOT be public ──────────────────────────────────────────────────

for path in healthz readyz; do
  code=$(curl -sS --max-time 15 -o /dev/null -w '%{http_code}' "https://$HOST/$path" 2>/dev/null)
  case "$code" in
    200)
      # /readyz reports the FHIR base URL. The Ingress routes only /mcp and
      # the well-known path for exactly this reason.
      no "/$path is not internet-reachable" "returns 200; the Ingress routes more than /mcp" ;;
    000|"")
      # Nothing answered at all, so this proves nothing: an undeployed host
      # would otherwise "pass" for not exposing anything.
      note "/$path reachability" "inconclusive -- no response from $HOST" ;;
    *)
      ok "/$path is not internet-reachable" "$code" ;;
  esac
done

# ── With a token ─────────────────────────────────────────────────────────────

if [ -n "$TOKEN" ]; then
  echo
  init=$(curl -sS --max-time 30 -i -X POST "https://$HOST/mcp" \
    -H 'content-type: application/json' \
    -H 'accept: application/json, text/event-stream' \
    -H "authorization: Bearer $TOKEN" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"verify-deploy","version":"1"}}}' 2>/dev/null)
  sid=$(printf '%s' "$init" | grep -i '^mcp-session-id:' | tr -d '\r' | awk '{print $2}')
  if [ -n "$sid" ]; then
    ok "the token opens an MCP session" "$sid"
    list=$(curl -sS --max-time 30 -X POST "https://$HOST/mcp" \
      -H 'content-type: application/json' \
      -H 'accept: application/json, text/event-stream' \
      -H "authorization: Bearer $TOKEN" -H "mcp-session-id: $sid" \
      -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' 2>/dev/null \
      | sed -n 's/^data: //p;/^{/p' | tail -1)
    count=$(printf '%s' "$list" | python3 -c "import json,sys
try: print(len(json.load(sys.stdin)['result']['tools']))
except Exception: print(0)" 2>/dev/null)
    if [ "${count:-0}" -gt 0 ]; then
      ok "tools/list over the public URL" "$count tools"
      note "" "13 is the expected count with MCP_TOOLSET=read; 19 with =all"
    else
      no "tools/list over the public URL" "returned no tools"
    fi
    curl -sS --max-time 15 -o /dev/null -X DELETE "https://$HOST/mcp" \
      -H "authorization: Bearer $TOKEN" -H "mcp-session-id: $sid" 2>/dev/null
  else
    no "the token opens an MCP session" "no Mcp-Session-Id; check aud and scope"
  fi
else
  echo
  note "no token supplied" "pass one to also drive a session: ./infra/verify-deploy.sh \$TOKEN"
  note "" "mint one with ~/mywork/MCP-CIMD/phase-a/flow.sh"
fi

# ── Report ───────────────────────────────────────────────────────────────────

echo
if [ "$fail" -eq 0 ]; then
  echo "  $pass passed, 0 failed."
  [ -z "$TOKEN" ] && echo "  Phase C's token-bearing half still needs a real access token."
  exit 0
fi
echo "  $pass passed, $fail FAILED."
exit 1
