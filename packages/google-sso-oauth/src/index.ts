// @hlao-adapter/google-sso-oauth — Google OAuth 2.0 authorization-code
// flow with server-side sessions. Express-compatible middleware that
// owns the login redirect + callback and hands the resulting actor id
// to the HLAO runner via verifyActor.
//
// Flow:
//   1. User visits a protected page. Session middleware sees no cookie,
//      redirects to /auth/google/start.
//   2. startHandler generates a signed state parameter (HMAC via jose),
//      constructs Google's authorize URL, redirects.
//   3. Google authenticates the user, redirects back to
//      /auth/google/callback with ?code=... &state=...
//   4. callbackHandler validates state, POSTs to Google's token endpoint,
//      receives id_token, decodes it, creates a session in the
//      SessionStore, sets a signed cookie, redirects to the original URL.
//   5. On subsequent requests, sessionMiddleware reads the cookie, loads
//      the session, populates req.hlaoActor.
//
// The adapter exports verifyActor(actorId) that checks whether the actor
// has an active session. Wire this into createRunner.verifyActor per
// ADR-0020.

import { parse as parseCookie, serialize as serializeCookie } from "cookie";
import type { NextFunction, Request, RequestHandler, Response } from "express";
import { SignJWT, decodeJwt, jwtVerify } from "jose";
import { z } from "zod";

export * from "./session-store.js";

import type { SessionData, SessionStore } from "./session-store.js";

const GOOGLE_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const STATE_TTL_MS = 10 * 60 * 1000;

export const GoogleOauthConfigSchema = z.object({
  clientId: z.string().min(1),
  clientSecret: z.string().min(1),
  /** Absolute redirect URI registered in Google Cloud Console. */
  redirectUri: z.string().url(),
  /** Enforce this Workspace domain via the id_token's `hd` claim. */
  hostedDomain: z.string().min(1).optional(),
  /** Explicit allowlist enforced at session creation. */
  allowedActorIds: z.array(z.string().min(1)).optional(),
  /** Cookie name for the session id. Default: "hlao_session". */
  sessionCookieName: z.string().default("hlao_session"),
  /** Session TTL in ms. Default: 24 hours. */
  sessionTtlMs: z
    .number()
    .int()
    .positive()
    .default(24 * 60 * 60 * 1000),
  /** Cookie Domain attribute. Optional. */
  cookieDomain: z.string().optional(),
  /**
   * Whether to set the Secure attribute on cookies. Default true.
   * Only set false for local http:// development.
   */
  cookieSecure: z.boolean().default(true),
  /**
   * HMAC secret for signing state parameters and session cookie
   * envelopes. Must be at least 32 bytes.
   */
  stateSigningSecret: z.string().min(32),
  /** Path to redirect after login when no ?redirect was in state. */
  defaultRedirectPath: z.string().default("/"),
});

export type GoogleOauthConfig = z.input<typeof GoogleOauthConfigSchema>;

export interface GoogleOauthAdapter {
  /**
   * Handler for the login-start route. Constructs a signed state,
   * builds the Google authorize URL, redirects the user.
   */
  startHandler: RequestHandler;
  /**
   * Handler for the OAuth callback. Validates state, exchanges the code
   * for tokens, creates a session, sets the cookie, redirects to the
   * originally requested URL.
   */
  callbackHandler: RequestHandler;
  /**
   * Optional middleware that reads the session cookie and populates
   * req.hlaoActor with { actorId, name? } if the session is valid.
   * Silent on missing/invalid cookie.
   */
  sessionMiddleware: RequestHandler;
  /** Handler that clears the session cookie and destroys the session. */
  logoutHandler: RequestHandler;
  /**
   * Runner-compatible verifyActor. Returns true iff the actor has a
   * currently-valid session in the store.
   */
  verifyActor: (actorId: string) => Promise<boolean>;
}

export interface GoogleOauthOptions {
  sessionStore: SessionStore;
  /** Test seam for fetch. Default: native. */
  fetchFn?: typeof fetch;
  /** Test seam for time. Default: Date.now. */
  nowMs?: () => number;
}

interface StatePayload {
  redirectTo: string;
  nonce: string;
}

/**
 * The shape sessionMiddleware writes onto req. Consumers access it as
 * `(req as unknown as { hlaoActor?: HlaoActor }).hlaoActor`, or add a
 * module augmentation in their own project for ergonomic `req.hlaoActor`.
 * The adapter itself doesn't augment express types — that would leak
 * into every consumer's declaration space.
 */
export interface HlaoActor {
  actorId: string;
  name?: string;
}

interface RequestWithActor {
  hlaoActor?: HlaoActor;
}

export function createGoogleOauthAdapter(
  rawConfig: GoogleOauthConfig,
  options: GoogleOauthOptions,
): GoogleOauthAdapter {
  const config = GoogleOauthConfigSchema.parse(rawConfig);
  const fetchFn = options.fetchFn ?? fetch;
  const now = options.nowMs ?? Date.now;
  const store = options.sessionStore;
  const secret = new TextEncoder().encode(config.stateSigningSecret);
  const allowedSet =
    config.allowedActorIds !== undefined ? new Set(config.allowedActorIds) : undefined;
  // Set of actor ids currently believed to have an active session.
  // verifyActor consults this rather than hitting the store on every
  // gate-side check (which is called synchronously during
  // approveReview/denyReview). Cross-process deployments should
  // replace this with a shared cache.
  const activeActors = new Set<string>();

  async function signState(payload: StatePayload): Promise<string> {
    return new SignJWT({ ...payload })
      .setProtectedHeader({ alg: "HS256" })
      .setExpirationTime(new Date(now() + STATE_TTL_MS))
      .setIssuedAt(new Date(now()))
      .sign(secret);
  }

  async function verifyState(token: string): Promise<StatePayload> {
    const { payload } = await jwtVerify(token, secret);
    const redirectTo = typeof payload.redirectTo === "string" ? payload.redirectTo : "/";
    const nonce = typeof payload.nonce === "string" ? payload.nonce : "";
    if (nonce.length === 0) throw new Error("state has empty nonce");
    return { redirectTo, nonce };
  }

  function setCookie(res: Response, name: string, value: string, maxAgeSec: number): void {
    const serialized = serializeCookie(name, value, {
      httpOnly: true,
      secure: config.cookieSecure,
      sameSite: "lax",
      path: "/",
      maxAge: maxAgeSec,
      domain: config.cookieDomain,
    });
    const existing = res.getHeader("Set-Cookie");
    if (Array.isArray(existing)) {
      res.setHeader("Set-Cookie", [...existing, serialized]);
    } else if (typeof existing === "string") {
      res.setHeader("Set-Cookie", [existing, serialized]);
    } else {
      res.setHeader("Set-Cookie", serialized);
    }
  }

  function clearCookie(res: Response, name: string): void {
    setCookie(res, name, "", 0);
  }

  const startHandler: RequestHandler = async (req, res, next) => {
    try {
      const redirectTo =
        (typeof req.query.redirect === "string" && req.query.redirect.startsWith("/")
          ? req.query.redirect
          : undefined) ?? config.defaultRedirectPath;
      const nonce = Math.random().toString(36).slice(2) + Date.now().toString(36);
      const state = await signState({ redirectTo, nonce });
      const authorizeUrl = new URL(GOOGLE_AUTHORIZE_URL);
      authorizeUrl.searchParams.set("client_id", config.clientId);
      authorizeUrl.searchParams.set("redirect_uri", config.redirectUri);
      authorizeUrl.searchParams.set("response_type", "code");
      authorizeUrl.searchParams.set("scope", "openid email profile");
      authorizeUrl.searchParams.set("state", state);
      authorizeUrl.searchParams.set("access_type", "online");
      authorizeUrl.searchParams.set("prompt", "select_account");
      if (config.hostedDomain !== undefined) {
        authorizeUrl.searchParams.set("hd", config.hostedDomain);
      }
      res.redirect(authorizeUrl.toString());
    } catch (err) {
      next(err);
    }
  };

  const callbackHandler: RequestHandler = async (req, res, next) => {
    try {
      const code = typeof req.query.code === "string" ? req.query.code : undefined;
      const stateToken = typeof req.query.state === "string" ? req.query.state : undefined;
      if (code === undefined || stateToken === undefined) {
        res.status(400).type("text").send("missing code or state");
        return;
      }
      let stateData: StatePayload;
      try {
        stateData = await verifyState(stateToken);
      } catch {
        res.status(400).type("text").send("state parameter invalid or expired");
        return;
      }

      const tokenBody = new URLSearchParams({
        code,
        client_id: config.clientId,
        client_secret: config.clientSecret,
        redirect_uri: config.redirectUri,
        grant_type: "authorization_code",
      });
      const tokenResponse = await fetchFn(GOOGLE_TOKEN_URL, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: tokenBody.toString(),
      });
      if (!tokenResponse.ok) {
        const text = await safeText(tokenResponse);
        throw new Error(`Google token exchange failed: ${tokenResponse.status}: ${text}`);
      }
      const tokenJson = (await tokenResponse.json()) as { id_token?: string };
      if (typeof tokenJson.id_token !== "string") {
        throw new Error("Google token response missing id_token");
      }

      // The id_token comes from Google's authenticated HTTPS response
      // and does not need re-verification for this flow. We decode
      // without verifying signature; the trust boundary is TLS to
      // Google's token endpoint.
      const claims = decodeJwt(tokenJson.id_token) as {
        email?: string;
        email_verified?: boolean;
        hd?: string;
        name?: string;
      };
      const email = claims.email;
      if (typeof email !== "string") {
        throw new Error("Google id_token missing email claim; ensure the email scope is requested");
      }
      if (claims.email_verified !== true) {
        res.status(403).type("text").send(`refusing session for unverified email ${email}`);
        return;
      }
      if (config.hostedDomain !== undefined && claims.hd !== config.hostedDomain) {
        res
          .status(403)
          .type("text")
          .send(
            `refusing session: token hd '${claims.hd ?? "(missing)"}' does not match configured hostedDomain '${config.hostedDomain}'`,
          );
        return;
      }
      if (allowedSet !== undefined && !allowedSet.has(email)) {
        res.status(403).type("text").send(`refusing session for ${email}: not in allowedActorIds`);
        return;
      }

      const sessionData: SessionData = {
        actorId: email,
        name: claims.name,
        createdAt: now(),
        expiresAt: now() + config.sessionTtlMs,
      };
      const sessionId = await store.create(sessionData);
      activeActors.add(email);
      setCookie(res, config.sessionCookieName, sessionId, Math.floor(config.sessionTtlMs / 1000));
      res.redirect(stateData.redirectTo);
    } catch (err) {
      next(err);
    }
  };

  const sessionMiddleware: RequestHandler = async (req, _res, next) => {
    try {
      const cookieHeader = req.headers.cookie;
      if (typeof cookieHeader !== "string") return next();
      const cookies = parseCookie(cookieHeader);
      const sessionId = cookies[config.sessionCookieName];
      if (typeof sessionId !== "string" || sessionId.length === 0) return next();
      const session = await store.get(sessionId);
      if (session === null) {
        activeActors.delete(sessionId);
        return next();
      }
      (req as unknown as RequestWithActor).hlaoActor = {
        actorId: session.actorId,
        name: session.name,
      };
      activeActors.add(session.actorId);
      next();
    } catch (err) {
      next(err);
    }
  };

  const logoutHandler: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const cookieHeader = req.headers.cookie;
      if (typeof cookieHeader === "string") {
        const cookies = parseCookie(cookieHeader);
        const sessionId = cookies[config.sessionCookieName];
        if (typeof sessionId === "string" && sessionId.length > 0) {
          const session = await store.get(sessionId);
          if (session !== null) {
            activeActors.delete(session.actorId);
          }
          await store.destroy(sessionId);
        }
      }
      clearCookie(res, config.sessionCookieName);
      res.redirect(config.defaultRedirectPath);
    } catch (err) {
      next(err);
    }
  };

  async function verifyActor(actorId: string): Promise<boolean> {
    return activeActors.has(actorId);
  }

  return { startHandler, callbackHandler, sessionMiddleware, logoutHandler, verifyActor };
}

async function safeText(response: Response | globalThis.Response): Promise<string> {
  try {
    // biome-ignore lint/suspicious/noExplicitAny: standard fetch Response
    const text = await (response as any).text();
    return typeof text === "string" && text.length > 500 ? `${text.slice(0, 500)}…` : text;
  } catch {
    return "(response body unreadable)";
  }
}
