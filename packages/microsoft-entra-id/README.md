# @hlao-adapter/microsoft-entra-id

OIDC ID-token verification against Microsoft Entra ID (formerly Azure Active
Directory). Reference implementation of an HLAO `verifyActor` source: a
deployment uses `verifyToken` to authenticate the caller and `verifyActor` in
the runner's `CreateRunnerDeps` to gate approvals.

## What this adapter does

Verifies the JWT signature of an Entra ID token against the tenant's public
JWKs, checks audience (`aud`), issuer (`iss`), expiry, and (optionally) an
explicit allowlist of principals. Returns `{ actorId, claims }` where
`actorId` is either the verified `preferred_username`, `email`, or `oid`
claim (in that order), ready to pass as `actorHumanId`.

The two-function shape matches the verifyActor seam defined by ADR-0020: the
adapter authenticates (credential → identity) via `verifyToken`, and
authorizes (identity → allowed?) via `verifyActor`. See `@hlao-adapter/google-sso-oidc`
for the parallel Google implementation.

## Configuration

| Field             | What it is                                                            |
| ----------------- | --------------------------------------------------------------------- |
| `tenantId`        | Entra tenant id GUID or `contoso.onmicrosoft.com` suffix. Required.   |
| `clientId`        | Registered app's Application (client) ID. Required.                   |
| `allowedActorIds` | Optional allowlist of principals; verifyToken and verifyActor enforce.|
| `jwksUri`         | Advanced override; defaults to the tenant's public discovery keys.    |

## Usage

```ts
import { createEntraOidcVerifier } from "@hlao-adapter/microsoft-entra-id";

const entra = createEntraOidcVerifier({
  tenantId: process.env.ENTRA_TENANT_ID!,
  clientId: process.env.ENTRA_CLIENT_ID!,
  allowedActorIds: (process.env.ENTRA_ALLOWED_ACTOR_IDS ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean),
});

// Web handler: authenticate the incoming token.
app.post("/reviews/:id/approve", async (req, res) => {
  const { actorId } = await entra.verifyToken(req.headers["x-entra-id-token"] as string);
  await runner.approveReview({ actorHumanId: actorId, ... });
});

// Runner deps: gate approvals on the same identity.
const runner = createRunner({ verifyActor: entra.verifyActor, ... });
```

## Dependencies

- `jose` for JWKS + JWT verification (already used across the adapter fleet).
- `zod` for config validation.

## Testing

Unit tests use a local RSA keypair via `jose.generateKeyPair` and inject
`createLocalJWKSet` through the `jwksGetKey` option; no network calls are
made. Run with `pnpm --filter @hlao-adapter/microsoft-entra-id test`.
