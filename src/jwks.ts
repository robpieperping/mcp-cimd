import { createPublicKey, type KeyObject } from "node:crypto";
import { config } from "./config.js";

/**
 * The authorization server's key set, cached.
 *
 * No dependency: the same ~100 lines of node:crypto that validated the
 * Phase A exit token (MCP-CIMD/phase-a/verify-token.mjs, 12 self-tests)
 * validate tokens here, so the code path that proved the audience binding
 * is the code path that enforces it.
 */

export interface JwkEntry {
  kid?: string;
  kty?: string;
  use?: string;
  alg?: string;
  [claim: string]: unknown;
}

export class JwksError extends Error {}

interface CacheEntry {
  keys: JwkEntry[];
  fetchedAt: number;
}

let cache: CacheEntry | null = null;
let inFlight: Promise<CacheEntry> | null = null;
let lastForcedRefreshAt = 0;

/**
 * How long after a cache miss on `kid` we are willing to refetch. Key
 * rotation must be picked up without waiting out the TTL, but an attacker
 * can put any `kid` they like in an unsigned header, so an unknown kid must
 * not be a free round trip to the AS.
 */
const FORCED_REFRESH_INTERVAL_MS = 10_000;
const FETCH_TIMEOUT_MS = 5_000;

export function resetJwksCache(): void {
  cache = null;
  inFlight = null;
  lastForcedRefreshAt = 0;
}

async function fetchJwks(): Promise<CacheEntry> {
  const uri = config.auth.jwksUri;
  if (!uri) throw new JwksError("No JWKS URI is configured (set OAUTH_JWKS_URI or OAUTH_ISSUER).");

  let response: Response;
  try {
    response = await fetch(uri, {
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
  } catch (error: unknown) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new JwksError(`Could not reach the JWKS endpoint ${uri}: ${detail}`);
  }

  if (!response.ok) {
    throw new JwksError(`JWKS endpoint ${uri} returned HTTP ${response.status}.`);
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new JwksError(`JWKS endpoint ${uri} did not return JSON.`);
  }

  const keys = (body as { keys?: unknown })?.keys;
  if (!Array.isArray(keys)) {
    throw new JwksError(`JWKS endpoint ${uri} returned no "keys" array.`);
  }

  return { keys: keys as JwkEntry[], fetchedAt: Date.now() };
}

/** Coalesces concurrent refreshes, so a burst of requests makes one fetch. */
function refresh(): Promise<CacheEntry> {
  if (inFlight) return inFlight;
  inFlight = fetchJwks()
    .then((entry) => {
      cache = entry;
      return entry;
    })
    .finally(() => {
      inFlight = null;
    });
  return inFlight;
}

function selectCandidates(keys: JwkEntry[], kid: string | undefined): JwkEntry[] {
  return keys.filter((key) => {
    // A key published for encryption cannot validate a signature; a key with
    // no `use` is unrestricted and therefore a candidate.
    if (key.use && key.use !== "sig") return false;
    // `oct` is a symmetric secret. PingFederate never publishes one, and if
    // it did, holding it would let anyone mint tokens.
    if (key.kty === "oct") return false;
    if (kid && key.kid && key.kid !== kid) return false;
    return true;
  });
}

/**
 * Public keys that could have signed a token with this `kid`, newest view of
 * the key set first. An unknown `kid` triggers at most one rate-limited
 * refetch before giving up.
 */
export async function verificationKeys(kid: string | undefined): Promise<KeyObject[]> {
  const ttlMs = config.auth.jwksCacheSeconds * 1000;
  let entry = cache;

  if (!entry || Date.now() - entry.fetchedAt > ttlMs) {
    entry = await refresh();
  } else if (selectCandidates(entry.keys, kid).length === 0) {
    const now = Date.now();
    if (now - lastForcedRefreshAt > FORCED_REFRESH_INTERVAL_MS) {
      lastForcedRefreshAt = now;
      entry = await refresh();
    }
  }

  const candidates = selectCandidates(entry.keys, kid);
  if (candidates.length === 0) {
    throw new JwksError(
      `No signing key in ${config.auth.jwksUri} matches kid=${kid ?? "(absent)"}. ` +
        `If the access token manager was just reconfigured, check that ` +
        `"Publish Keys to the PingFederate JWKS Endpoint" is enabled for it.`
    );
  }

  const parsed: KeyObject[] = [];
  for (const jwk of candidates) {
    try {
      parsed.push(createPublicKey({ key: jwk as never, format: "jwk" }));
    } catch {
      // A key this Node build cannot represent is simply not a candidate.
    }
  }
  if (parsed.length === 0) {
    throw new JwksError(`kid=${kid ?? "(absent)"} matched ${candidates.length} key(s), none usable.`);
  }
  return parsed;
}
