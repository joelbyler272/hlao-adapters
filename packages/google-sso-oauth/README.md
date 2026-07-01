# @hlao-adapter/google-sso-oauth

Reference implementation of an HLAO `verifyActor` source using **Google
OAuth 2.0 authorization-code flow** with server-side sessions.
Express-compatible middleware for HLAO deployments where the app owns
the login flow itself.

## When to reach for this shape

Your app is server-rendered (like `@hlao/oversight`) and the browser
navigates through your app's own login redirect. You want cookies +
sessions, not bearer tokens on every request.

**Not the right shape if:**
- Your frontend already logs users into Google and passes an ID token
  to the backend — use [`@hlao-adapter/google-sso-oidc`](../google-sso-oidc/README.md).
- You just want to check "is this email a real Workspace user" without
  running the login yourself — use [`@hlao-adapter/google-sso-directory`](../google-sso-directory/README.md).

## Install

```bash
npm install @hlao-adapter/google-sso-oauth
# express is a peer dep; you provide the version
```

## Wire it up

```ts
import express from "express";
import {
  InMemorySessionStore,
  createGoogleOauthAdapter,
} from "@hlao-adapter/google-sso-oauth";

const adapter = createGoogleOauthAdapter(
  {
    clientId: process.env.GOOGLE_OAUTH_CLIENT_ID!,
    clientSecret: process.env.GOOGLE_OAUTH_CLIENT_SECRET!,
    redirectUri: process.env.GOOGLE_OAUTH_REDIRECT_URI!,
    stateSigningSecret: process.env.GOOGLE_OAUTH_STATE_SIGNING_SECRET!,
    hostedDomain: process.env.GOOGLE_OAUTH_HOSTED_DOMAIN,
  },
  { sessionStore: new InMemorySessionStore() },
);

const app = express();
app.use(adapter.sessionMiddleware);

app.get("/auth/google/start", adapter.startHandler);
app.get("/auth/google/callback", adapter.callbackHandler);
app.post("/auth/logout", adapter.logoutHandler);

// Protect a route: redirect to /auth/google/start if no session.
app.get("/reviews", (req, res, next) => {
  if (req.hlaoActor === undefined) {
    return res.redirect(`/auth/google/start?redirect=${encodeURIComponent(req.originalUrl)}`);
  }
  next();
});

// Wire runner:
const runner = createRunner({
  gate,
  sink,
  artifactStore,
  verifyPassport,
  verifyActor: adapter.verifyActor, // <-- ADR-0020 seam
});

// In the approve/deny handler:
app.post("/reviews/:id/action", async (req, res) => {
  if (req.hlaoActor === undefined) return res.status(401).send("no session");
  await runner.approveReview({
    workspaceRunId: req.params.id,
    actorHumanId: req.hlaoActor.actorId,
    reason: req.body.reason,
  });
  res.redirect("/reviews");
});
```

## Handlers exported

| Handler              | Route                               | What it does                                                                              |
| -------------------- | ----------------------------------- | ----------------------------------------------------------------------------------------- |
| `startHandler`       | `GET /auth/google/start`            | Signs a state parameter, builds Google's authorize URL, redirects.                        |
| `callbackHandler`    | `GET /auth/google/callback`         | Validates state, exchanges code, creates a session, sets a signed cookie, redirects.      |
| `sessionMiddleware`  | Global                              | Reads the session cookie, populates `req.hlaoActor` if valid. Silent on missing.          |
| `logoutHandler`      | `POST /auth/logout`                 | Destroys the session, clears the cookie, redirects to `defaultRedirectPath`.              |
| `verifyActor`        | Runner dep                          | Returns true iff the actor id has an active session.                                      |

## What the callback checks

- `state` parameter is a valid HMAC-signed JWT that has not expired.
  Prevents CSRF and forged callbacks.
- Google's token endpoint returned a 200 with an `id_token`.
- `email` claim exists.
- `email_verified` is `true`.
- `hd` claim matches `hostedDomain` (if configured).
- `email` is in `allowedActorIds` (if configured).

Failing any check aborts the callback with 403 or 400, no session
created.

## Session store

Ships an in-memory reference. For multi-process / durable deployments:

```ts
import type { SessionStore, SessionData } from "@hlao-adapter/google-sso-oauth";

class RedisSessionStore implements SessionStore {
  async create(data: SessionData): Promise<string> { ... }
  async get(sessionId: string): Promise<SessionData | null> { ... }
  async destroy(sessionId: string): Promise<void> { ... }
}
```

Pass it as `sessionStore` in the adapter options.

## Configuration

| Field                    | Purpose                                                                | Required |
| ------------------------ | ---------------------------------------------------------------------- | -------- |
| `clientId`               | Google OAuth 2.0 web client id                                         | Yes      |
| `clientSecret`           | Google OAuth 2.0 web client secret                                     | Yes      |
| `redirectUri`            | Absolute callback URL registered in Google Cloud Console               | Yes      |
| `stateSigningSecret`     | 32+ byte HMAC secret for signing state parameters and session cookies  | Yes      |
| `hostedDomain`           | Enforce Workspace domain via `hd` claim                                | No       |
| `allowedActorIds`        | Explicit email allowlist enforced at session creation                  | No       |
| `sessionCookieName`      | Cookie name. Default `hlao_session`.                                   | No       |
| `sessionTtlMs`           | Session lifetime. Default 24h.                                         | No       |
| `cookieDomain`           | Cookie Domain attribute. Default browser-inferred.                     | No       |
| `cookieSecure`           | Secure cookie attribute. Default true (only false for local http dev). | No       |
| `defaultRedirectPath`    | Path to redirect after login when state has no explicit target.        | No       |

### How to obtain credentials

1. **Google Cloud Console → APIs & Services → OAuth consent screen**:
   configure. Add `email` and `profile` scopes.
2. **APIs & Services → Credentials → Create credentials → OAuth client
   ID → Web application**. Add your redirect URI as an authorized
   redirect URI.
3. Copy the client ID and client secret to your `.env`.
4. Generate a 32-byte HMAC secret:
   ```
   openssl rand -hex 32
   ```
   Store it as `GOOGLE_OAUTH_STATE_SIGNING_SECRET`.

## Local development

For local http:// testing, set `cookieSecure: false` to allow cookies
over http.

```bash
cp .env.example .env
pnpm install
pnpm --filter @hlao-adapter/google-sso-oauth build
pnpm --filter @hlao-adapter/google-sso-oauth test
```
