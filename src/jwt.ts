import { constants, verify as cryptoVerify } from "node:crypto";
import { config } from "./config.js";
import { JwksError, verificationKeys } from "./jwks.js";

/**
 * Validation of the bearer token ChatGPT presents, against the AS's
 * published key set. Stateless: no introspection call, no shared session
 * store, nothing for a second replica to disagree about.
 *
 * Checked, in this order: it is a JWS; the algorithm is asymmetric; the
 * signature verifies against a published key; `iss` matches exactly; `aud`
 * contains this resource exactly; `exp`/`nbf` hold within the configured
 * skew. Scope is checked separately, because an in-date token with the
 * wrong scope is a 403, not a 401.
 */

export interface TokenClaims {
  iss?: string;
  aud?: string | string[];
  sub?: string;
  scope?: string | string[];
  client_id?: string;
  exp?: number;
  nbf?: number;
  iat?: number;
  [claim: string]: unknown;
}

export interface VerifiedToken {
  claims: TokenClaims;
  scopes: string[];
  subject?: string;
  clientId?: string;
}

/** Why a token was rejected. `reason` is for our logs; `description` is safe to return. */
export class TokenError extends Error {
  constructor(
    readonly description: string,
    readonly reason: string = description
  ) {
    super(reason);
    this.name = "TokenError";
  }
}

const DIGEST_FOR_LENGTH: Record<string, string> = { "256": "sha256", "384": "sha384", "512": "sha512" };

function decodeSegment(segment: string): Buffer {
  return Buffer.from(segment.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

function parseJson(segment: string, label: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(decodeSegment(segment).toString("utf8"));
  } catch {
    throw new TokenError("The access token is malformed.", `${label} is not valid JSON`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new TokenError("The access token is malformed.", `${label} is not a JSON object`);
  }
  return parsed as Record<string, unknown>;
}

export function scopesOf(claims: TokenClaims): string[] {
  const { scope } = claims;
  if (typeof scope === "string") return scope.split(/\s+/).filter(Boolean);
  if (Array.isArray(scope)) return scope.filter((s): s is string => typeof s === "string");
  return [];
}

export async function verifyAccessToken(token: string): Promise<VerifiedToken> {
  const segments = token.split(".");

  if (segments.length !== 3) {
    // Almost always an internally-managed ("reference") access token manager:
    // PF issued an opaque handle, which cannot be validated locally at all.
    throw new TokenError(
      "The access token is not a JWT. This resource requires a JWT access token.",
      `token has ${segments.length} segment(s); the access token manager is probably ` +
        `internally managed rather than JWT`
    );
  }

  const header = parseJson(segments[0], "JWS header");
  const claims = parseJson(segments[1], "JWS payload") as TokenClaims;
  const alg = typeof header.alg === "string" ? header.alg : undefined;

  if (!alg || alg === "none") {
    throw new TokenError("The access token is not signed.", `alg=${alg ?? "(absent)"}`);
  }
  if (alg.startsWith("HS")) {
    // Accepting HMAC here would mean treating a published key as a shared
    // secret -- the classic JWKS confusion attack.
    throw new TokenError(
      "The access token uses an unsupported signing algorithm.",
      `alg=${alg} is symmetric; configure the access token manager for RS256, ES256 or PS256`
    );
  }
  const digest = DIGEST_FOR_LENGTH[alg.slice(2)];
  if (!digest || !/^(RS|ES|PS)(256|384|512)$/.test(alg)) {
    throw new TokenError("The access token uses an unsupported signing algorithm.", `alg=${alg}`);
  }

  const signedInput = Buffer.from(`${segments[0]}.${segments[1]}`);
  const signature = decodeSegment(segments[2]);
  const kid = typeof header.kid === "string" ? header.kid : undefined;

  let keys;
  try {
    keys = await verificationKeys(kid);
  } catch (error: unknown) {
    if (error instanceof JwksError) {
      throw new TokenError("The access token signature could not be verified.", error.message);
    }
    throw error;
  }

  const verified = keys.some((key) => {
    const options: Parameters<typeof cryptoVerify>[2] = { key } as never;
    if (alg.startsWith("ES")) {
      // JWS packs ECDSA signatures as raw r||s, not the DER that node
      // defaults to; without this every ES* token fails to verify.
      (options as { dsaEncoding?: string }).dsaEncoding = "ieee-p1363";
    }
    if (alg.startsWith("PS")) {
      (options as { padding?: number; saltLength?: number }).padding = constants.RSA_PKCS1_PSS_PADDING;
      (options as { padding?: number; saltLength?: number }).saltLength = constants.RSA_PSS_SALTLEN_DIGEST;
    }
    try {
      return cryptoVerify(digest, signedInput, options, signature);
    } catch {
      return false;
    }
  });

  if (!verified) {
    throw new TokenError(
      "The access token signature is invalid.",
      `${alg} did not verify against any key published for kid=${kid ?? "(absent)"}`
    );
  }

  // ── Claims ────────────────────────────────────────────────────────────────
  const expectedIssuer = config.auth.issuer;
  if (claims.iss !== expectedIssuer) {
    throw new TokenError(
      "The access token was issued by a different authorization server.",
      `iss=${claims.iss ?? "(absent)"}, expected exactly ${expectedIssuer}`
    );
  }

  const audiences = claims.aud === undefined ? [] : ([] as string[]).concat(claims.aud as string | string[]);
  const resource = config.auth.resource;
  if (!audiences.includes(resource!)) {
    // The failure Phase A existed to rule out. Say which value was wrong:
    // a flat 401 here costs hours.
    throw new TokenError(
      "The access token was not issued for this resource.",
      `aud=${JSON.stringify(claims.aud) ?? "(absent)"}, expected to contain ${resource}. ` +
        `The client must send resource=${resource} on the authorization and token ` +
        `requests, and the selected access token manager's Audience Claim Value must match.`
    );
  }

  const now = Math.floor(Date.now() / 1000);
  const skew = config.auth.clockSkewSeconds;

  if (typeof claims.exp !== "number") {
    throw new TokenError("The access token has no expiry.", "exp claim absent or not a number");
  }
  if (claims.exp + skew <= now) {
    throw new TokenError(
      "The access token has expired.",
      `exp=${new Date(claims.exp * 1000).toISOString()}, ${now - claims.exp}s ago`
    );
  }
  if (typeof claims.nbf === "number" && claims.nbf - skew > now) {
    throw new TokenError(
      "The access token is not valid yet.",
      `nbf=${new Date(claims.nbf * 1000).toISOString()}`
    );
  }

  return {
    claims,
    scopes: scopesOf(claims),
    subject: typeof claims.sub === "string" ? claims.sub : undefined,
    clientId: typeof claims.client_id === "string" ? claims.client_id : undefined,
  };
}
