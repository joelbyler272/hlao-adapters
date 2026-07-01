# @hlao-adapter/google-sso-oidc

Reference implementation of an HLAO `verifyActor` source using **Google
OIDC ID-token verification**. Validates a Google-issued JWT against
Google's JWKS, checks the audience/issuer/expiry/hosted-domain claims,
extracts the verified email, and provides a runner-compatible
`verifyActor` allowlist function.

## When to reach for this shape

Your backend receives an ID token from a client (SPA, mobile app,
first-party integration) that already logged the user in via Google.
The token is passed to the backend on every request (typically as an
`Authorization: Bearer <token>` header, though the header name is your
choice). The backend needs to verify the token, extract the user's
identity, and pass it to `runner.approveReview` / `runner.denyReview`
as `actorHumanId`.

**Not the right shape if:** your app owns the login flow itself
(server-rendered app with `/auth/google/start` and `/callback`
handlers). Reach for [`@hlao-adapter/google-sso-oauth`](../google-sso-oauth/README.md)
instead.

## Install

```bash
npm install @hlao-adapter/google-sso-oidc
# or: pnpm add @hlao-adapter/google-sso-oidc
```

## Wire it up

Two functions, wired in two places:

```ts
// Anywhere in your deployment startup (e.g. wiring.ts):
import { createGoogleOidcVerifier } from "@hlao-adapter/google-sso-oidc";

export const googleOidc = createGoogleOidcVerifier({
  clientId: process.env.GOOGLE_OIDC_CLIENT_ID!,
  hostedDomain: process.env.GOOGLE_OIDC_HOSTED_DOMAIN,          // optional
  allowedActorIds: process.env.GOOGLE_OIDC_ALLOWED_ACTOR_IDS
    ?.split(",")
    .map((s) => s.trim()),                                       // optional
});
```

In your HTTP handler for approve/deny — verify the token, extract the
actor id:

```ts
app.post("/reviews/:id/action", async (req, res) => {
  const idToken = req.headers["x-google-id-token"] as string | undefined;
  if (idToken === undefined) return res.status(401).send("missing id token");

  let actorId: string;
  try {
    const result = await googleOidc.verifyToken(idToken);
    actorId = result.actorId;
  } catch (err) {
    return res.status(401).send(`id token invalid: ${(err as Error).message}`);
  }

  await runner.approveReview({
    workspaceRunId: req.params.id,
    actorHumanId: actorId,
    reason: req.body.reason,
  });
  res.redirect("/reviews");
});
```

Wire `verifyActor` into the runner's `CreateRunnerDeps`:

```ts
const runner = createRunner({
  gate,
  sink,
  artifactStore,
  verifyPassport,
  verifyActor: googleOidc.verifyActor,   // <-- ADR-0020 seam
});
```

The split reflects a deliberate separation of concerns:

- `verifyToken` is **authentication** (credential → identity), done in
  the HTTP handler.
- `verifyActor` is **authorization** (identity → allowed), done in the
  runner's own audit path per ADR-0020.

## What the verifier checks

`verifyToken(idToken)` fails closed on any of:

- JWT signature does not verify against Google's JWKS
- `aud` claim does not match the configured `clientId`
- `iss` claim is not `https://accounts.google.com` or `accounts.google.com`
- Token is expired or not yet valid
- Token has no `email` claim (ensure your OAuth request includes the
  `email` scope)
- `email_verified` is not `true`
- `hostedDomain` was configured and the `hd` claim does not equal it
- `allowedActorIds` was configured and the `email` is not in the set

## Configuration

| Variable / field    | What it is                                                     | Required |
| ------------------- | -------------------------------------------------------------- | -------- |
| `clientId`          | Google OAuth 2.0 client id (matches token's `aud` claim)       | Yes      |
| `hostedDomain`      | Workspace domain to enforce via the token's `hd` claim         | No       |
| `allowedActorIds`   | Explicit email allowlist enforced by both `verifyToken` and `verifyActor` | No |
| `jwksUri`           | Override Google's JWKS URI. Only for testing/pinning.          | No       |

### How to obtain credentials

1. Create a Google Cloud project (or pick one).
2. **APIs & Services → OAuth consent screen**: configure your consent
   screen. Add the `email` scope.
3. **APIs & Services → Credentials → Create credentials → OAuth client
   ID** (Web application). Copy the client ID.
4. Store it in your `.env` as `GOOGLE_OIDC_CLIENT_ID`.

No plan upgrade is required; the OIDC verification path is free.

## Local development

```bash
cp .env.example .env
pnpm install
pnpm --filter @hlao-adapter/google-sso-oidc build
pnpm --filter @hlao-adapter/google-sso-oidc test
```

## How this composes with the HLAO engine

```
[client with Google login]
      |
      | ID token in header
      v
[HTTP handler]  ---calls verifyToken()---> [@hlao-adapter/google-sso-oidc]
      |
      | actorHumanId = verified email
      v
[runner.approveReview({actorHumanId: ...})]
      |
      | calls verifyActor(actorHumanId)      <-- ADR-0020 seam
      v
[@hlao-adapter/google-sso-oidc verifyActor]
      |
      | true (in allowlist / trust upstream)
      v
[Escalation lifecycle continues, resolved with resolvedBy: actorHumanId]
```

Both boundaries — the HTTP handler and the runner — call into the same
adapter so authentication and authorization use one source of truth.
