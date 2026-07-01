// @hlao-adapter/google-sso-directory — verify actors by checking whether
// an email is a real user in a Google Workspace domain. Uses the Admin
// SDK Directory API with a service account exercising domain-wide
// delegation to impersonate a Workspace admin.
//
// The verifyActor(actorId) function returns true iff the actorId (email)
// exists in the configured workspace domain and is not suspended.
//
// Auth flow (JWT bearer, RFC 7523):
//   1. Build a JWT with iss = service account email, sub = admin to
//      impersonate, aud = https://oauth2.googleapis.com/token,
//      scope = admin.directory.user.readonly.
//   2. Sign it with the service account private key.
//   3. POST to Google's token endpoint; receive an access token.
//   4. GET https://admin.googleapis.com/admin/directory/v1/users/{email}
//      with Authorization: Bearer <access_token>.
//   5. Return true on 200, false on 404, throw on any other error.
//
// Access tokens are cached in-memory until 60s before expiry. User
// lookups are cached with a configurable TTL (default 60 seconds) to
// keep API pressure sane.

import { SignJWT, importPKCS8 } from "jose";
import { z } from "zod";

const TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
const DIRECTORY_BASE = "https://admin.googleapis.com/admin/directory/v1/users";
const DIRECTORY_SCOPE = "https://www.googleapis.com/auth/admin.directory.user.readonly";
const TOKEN_TTL_SECONDS = 3600;
const TOKEN_REFRESH_MARGIN_MS = 60_000;

export const ServiceAccountKeySchema = z.object({
  type: z.literal("service_account"),
  client_email: z.string().email(),
  private_key: z.string().min(1),
  token_uri: z.string().url().optional(),
});

export type ServiceAccountKey = z.infer<typeof ServiceAccountKeySchema>;

export const GoogleDirectoryConfigSchema = z.object({
  /** Workspace domain to check membership against. e.g. "example.edu". */
  workspaceDomain: z.string().min(1),
  /**
   * The service account key JSON, either as a parsed object or as a
   * raw JSON string (which will be parsed).
   */
  serviceAccountKey: z.union([ServiceAccountKeySchema, z.string().min(1)]),
  /**
   * The admin email in the workspace to impersonate. Domain-wide
   * delegation must be authorized for this account.
   */
  adminEmailToImpersonate: z.string().email(),
  /**
   * How long to cache user-lookup results before re-fetching. Default
   * 60 seconds. Cache is per-verifier instance.
   */
  cacheTtlMs: z.number().int().positive().default(60_000),
});

export type GoogleDirectoryConfig = z.input<typeof GoogleDirectoryConfigSchema>;

export interface GoogleDirectoryVerifier {
  /**
   * Returns true iff the actorId (email) is a real, non-suspended user
   * in the configured workspace domain.
   */
  verifyActor(actorId: string): Promise<boolean>;
}

export interface GoogleDirectoryVerifierOptions {
  /**
   * Test seam. Production callers omit this; the default is native
   * fetch. Tests pass a mock.
   */
  fetchFn?: typeof fetch;
  /**
   * Test seam for time. Default is Date.now().
   */
  nowMs?: () => number;
}

interface CachedToken {
  token: string;
  expiresAt: number;
}

interface CachedUser {
  exists: boolean;
  expiresAt: number;
}

export function createGoogleDirectoryVerifier(
  rawConfig: GoogleDirectoryConfig,
  options: GoogleDirectoryVerifierOptions = {},
): GoogleDirectoryVerifier {
  const config = GoogleDirectoryConfigSchema.parse(rawConfig);
  const fetchFn = options.fetchFn ?? fetch;
  const now = options.nowMs ?? Date.now;

  const key: ServiceAccountKey =
    typeof config.serviceAccountKey === "string"
      ? ServiceAccountKeySchema.parse(JSON.parse(config.serviceAccountKey))
      : config.serviceAccountKey;

  let tokenCache: CachedToken | undefined;
  const userCache = new Map<string, CachedUser>();

  async function getAccessToken(): Promise<string> {
    if (tokenCache !== undefined && tokenCache.expiresAt > now() + TOKEN_REFRESH_MARGIN_MS) {
      return tokenCache.token;
    }

    const privateKey = await importPKCS8(key.private_key, "RS256");
    const nowSec = Math.floor(now() / 1000);
    const jwt = await new SignJWT({
      iss: key.client_email,
      sub: config.adminEmailToImpersonate,
      aud: key.token_uri ?? TOKEN_ENDPOINT,
      scope: DIRECTORY_SCOPE,
      iat: nowSec,
      exp: nowSec + TOKEN_TTL_SECONDS,
    })
      .setProtectedHeader({ alg: "RS256", typ: "JWT" })
      .sign(privateKey);

    const body = new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: jwt,
    });

    const response = await fetchFn(key.token_uri ?? TOKEN_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    if (!response.ok) {
      const text = await safeText(response);
      throw new Error(
        `Google token exchange failed: ${response.status} ${response.statusText}: ${text}`,
      );
    }
    const json = (await response.json()) as { access_token?: string; expires_in?: number };
    if (typeof json.access_token !== "string") {
      throw new Error("Google token response is missing access_token");
    }
    const ttlMs = (json.expires_in ?? TOKEN_TTL_SECONDS) * 1000;
    tokenCache = { token: json.access_token, expiresAt: now() + ttlMs };
    return json.access_token;
  }

  async function lookupUser(email: string): Promise<boolean> {
    const cached = userCache.get(email);
    if (cached !== undefined && cached.expiresAt > now()) return cached.exists;

    const token = await getAccessToken();
    const url = `${DIRECTORY_BASE}/${encodeURIComponent(email)}`;
    const response = await fetchFn(url, {
      method: "GET",
      headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
    });

    let exists: boolean;
    if (response.status === 200) {
      const json = (await response.json()) as {
        primaryEmail?: string;
        suspended?: boolean;
        archived?: boolean;
      };
      exists =
        typeof json.primaryEmail === "string" && json.suspended !== true && json.archived !== true;
    } else if (response.status === 404) {
      exists = false;
    } else if (response.status === 401 || response.status === 403) {
      const text = await safeText(response);
      throw new Error(
        `Directory API auth failed (${response.status}): ${text}. Check that domain-wide delegation is granted to the service account for the admin.directory.user.readonly scope.`,
      );
    } else {
      const text = await safeText(response);
      throw new Error(
        `Directory API unexpected response ${response.status} ${response.statusText}: ${text}`,
      );
    }

    userCache.set(email, { exists, expiresAt: now() + config.cacheTtlMs });
    return exists;
  }

  return {
    async verifyActor(actorId: string): Promise<boolean> {
      if (typeof actorId !== "string" || actorId.length === 0) return false;
      // Only look up emails that end with the configured domain. Emails
      // in other domains are refused immediately without an API call
      // (defense in depth for typo'd/forged actor ids).
      if (!actorId.toLowerCase().endsWith(`@${config.workspaceDomain.toLowerCase()}`)) {
        return false;
      }
      return lookupUser(actorId);
    },
  };
}

async function safeText(response: Response): Promise<string> {
  try {
    const text = await response.text();
    return text.length > 500 ? `${text.slice(0, 500)}…` : text;
  } catch {
    return "(response body unreadable)";
  }
}
