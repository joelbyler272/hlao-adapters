# @hlao-adapter/jwt

Provider-agnostic JWT verifier for HLAO `verifyActor`. Use it when your IdP
issues a signed JWT and there's no dedicated adapter for it (e.g. Auth0,
Okta, Keycloak, a custom in-house issuer, a webhook signed by an upstream
service).

Prefer a dedicated adapter (`@hlao-adapter/google-sso-oidc`,
`@hlao-adapter/microsoft-entra-id`, etc.) when one exists. This adapter is
the escape hatch for everything else.

## What it does

Verifies a JWT via `jose` against either a JWKS URI or a static PEM public
key, enforces `iss` and `aud`, and extracts a configurable claim as
`actorId`. Optional allowlist enforcement is built in.

## Usage

```ts
import { createJwtVerifier } from "@hlao-adapter/jwt";

// JWKS-backed:
const auth0 = createJwtVerifier({
  issuer: "https://your-tenant.auth0.com/",
  audience: "hlao-review-api",
  jwksUri: "https://your-tenant.auth0.com/.well-known/jwks.json",
  actorClaim: "email",
});

// Static-key deployment:
const custom = createJwtVerifier({
  issuer: "https://auth.example.com/",
  audience: "hlao-review-api",
  publicKeyPem: process.env.JWT_PUBLIC_KEY_PEM!,
  actorClaim: "sub",
});

const { actorId } = await auth0.verifyToken(bearerToken);
```

## Configuration

| Field              | What it is                                                        |
| ------------------ | ----------------------------------------------------------------- |
| `issuer`           | Expected `iss` claim. Required.                                   |
| `audience`         | Expected `aud` claim. Required.                                   |
| `jwksUri`          | JWKS URI, mutually exclusive with `publicKeyPem`.                 |
| `publicKeyPem`     | Static PEM public key, mutually exclusive with `jwksUri`.         |
| `actorClaim`       | Claim used as actor id. Default `sub`.                            |
| `allowedActorIds`  | Optional allowlist enforced by both verifyToken and verifyActor.  |
| `algorithms`       | Advanced; default `['RS256','ES256','EdDSA']`.                    |

## Dependencies

- `jose` for JWT verification.
- `zod` for config validation.

## Testing

Unit tests use `jose.generateKeyPair` + `SignJWT` with `createLocalJWKSet` for
JWKS-backed and `importSPKI` for PEM-backed. No network.
