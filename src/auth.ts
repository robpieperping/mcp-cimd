import axios from "axios";
import { config } from "./config.js";

interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  scope?: string;
}

interface CachedToken {
  accessToken: string;
  expiresAt: number;
}

let cachedToken: CachedToken | null = null;
let warnedUnconfigured = false;

/**
 * Retrieves a valid access token for the UPSTREAM FHIR call, using the
 * PingOne client_credentials flow with client_secret_basic authentication
 * (credentials in the Authorization header). Caches the token and refreshes
 * it 30 seconds before expiry.
 *
 * Returns null when no token can be obtained -- either because PingOne is
 * not configured at all, or because the token request failed. Callers then
 * call FHIR without an Authorization header.
 *
 * This is NOT the token ChatGPT presents to us; that one is validated in
 * src/mcp-auth.ts. The two are unrelated, and today there is no exchange
 * between them: see README, "The upstream FHIR hop is unauthenticated".
 */
export async function getAccessToken(): Promise<string | null> {
  if (!config.pingone) {
    if (!warnedUnconfigured) {
      warnedUnconfigured = true;
      console.error(
        "[auth] PingOne is not configured; FHIR requests go out unauthenticated. " +
          "Set PINGONE_ENV_ID, PINGONE_CLIENT_ID and PINGONE_CLIENT_SECRET to change that."
      );
    }
    return null;
  }

  const now = Date.now();

  if (cachedToken && cachedToken.expiresAt > now + 30_000) {
    return cachedToken.accessToken;
  }

  const { clientId, clientSecret, tokenUrl } = config.pingone;

  // PingOne requires client_secret_basic: credentials go in the Authorization header,
  // not in the POST body (client_secret_post is not supported for this app).
  const basicCredentials = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");

  try {
    const response = await axios.post<TokenResponse>(
      tokenUrl,
      "grant_type=client_credentials",
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Basic ${basicCredentials}`,
        },
      }
    );

    const { access_token, expires_in } = response.data;

    cachedToken = {
      accessToken: access_token,
      expiresAt: now + expires_in * 1000,
    };

    return access_token;
  } catch (err: unknown) {
    // Log the auth failure but allow callers to proceed without a token.
    // This supports FHIR servers that permit unauthenticated access.
    const detail = axios.isAxiosError(err)
      ? JSON.stringify(err.response?.data ?? err.message)
      : String(err);
    console.error(`[auth] Failed to obtain access token (will proceed without auth): ${detail}`);
    return null;
  }
}

/** Clears the cached token, forcing a fresh token on the next request. */
export function clearTokenCache(): void {
  cachedToken = null;
}
