# @hlao-adapter/google-sso-directory

Reference implementation of an HLAO `verifyActor` source using **Google
Workspace Directory API lookup**. Checks whether an email is a real,
non-suspended user in a configured Workspace domain via a service
account with domain-wide delegation.

## When to reach for this shape

You already have an actor id (an email) from some upstream authentication
step and want to enforce "is this a real employee/student in our
Workspace domain?" without maintaining a hand-maintained allowlist.
Typical wiring: an upstream proxy or reverse-proxy authenticates the
user (SSO, mTLS, etc.) and passes the verified email in a request
header; `verifyActor` confirms directory membership.

**Not the right shape if:**
- Your app owns the OAuth flow itself — use
  [`@hlao-adapter/google-sso-oauth`](../google-sso-oauth/README.md).
- Your app receives a Google ID token — use
  [`@hlao-adapter/google-sso-oidc`](../google-sso-oidc/README.md), then
  optionally chain this adapter for additional directory verification.

## Install

```bash
npm install @hlao-adapter/google-sso-directory
```

## Wire it up

```ts
import { readFileSync } from "node:fs";
import { createGoogleDirectoryVerifier } from "@hlao-adapter/google-sso-directory";

const directory = createGoogleDirectoryVerifier({
  workspaceDomain: process.env.GOOGLE_DIRECTORY_WORKSPACE_DOMAIN!,
  serviceAccountKey: readFileSync(
    process.env.GOOGLE_DIRECTORY_SERVICE_ACCOUNT_KEY_FILE!,
    "utf8",
  ),
  adminEmailToImpersonate: process.env.GOOGLE_DIRECTORY_ADMIN_EMAIL!,
});

const runner = createRunner({
  gate,
  sink,
  artifactStore,
  verifyPassport,
  verifyActor: directory.verifyActor, // <-- ADR-0020 seam
});
```

## What the verifier checks

`verifyActor(actorId)` returns:

- **`false`** immediately (no API call) if `actorId` is empty, non-string,
  or does not end in `@<workspaceDomain>` (defense in depth: refuse
  cross-domain actors before spending an API call).
- **`true`** if the Directory API returns 200 with the user active
  (`suspended !== true` and `archived !== true`).
- **`false`** if the Directory API returns 404.
- **Throws** with an actionable message on 401/403 (usually means
  domain-wide delegation is misconfigured) or any other 5xx / network
  failure. Fail-closed at the runner boundary per ADR-0008.

## Caching

Two caches, both in-memory per verifier instance:

- **Access token cache**: keeps the OAuth2 access token until 60s
  before its stated expiry. One JWT-signing + token exchange per hour
  in steady state.
- **User lookup cache**: default TTL 60 seconds per email. Tune with
  `cacheTtlMs`. Higher TTL means faster verifyActor calls but slower
  reaction to a user being disabled/deleted in the directory.

## Configuration

| Field                     | What it is                                                    | Required |
| ------------------------- | ------------------------------------------------------------- | -------- |
| `workspaceDomain`         | Domain to check against, e.g. `example.edu`                   | Yes      |
| `serviceAccountKey`       | Parsed service account JSON, or raw JSON string               | Yes      |
| `adminEmailToImpersonate` | Admin in the workspace the service account impersonates       | Yes      |
| `cacheTtlMs`              | User lookup cache TTL in ms. Default 60000.                   | No       |

### How to obtain credentials

This is the highest-friction adapter of the three because it requires
Workspace admin actions.

1. Create a Google Cloud project (or pick one).
2. **APIs & Services → Library → Admin SDK API**: enable it.
3. **APIs & Services → Credentials → Create credentials → Service
   account**: create a service account. Download the JSON key.
4. On the service account's page → **Advanced settings** → copy the
   **Client ID** (a long numeric string).
5. Ask a Workspace admin to visit **admin.google.com → Security → API
   controls → Domain-wide delegation → Add new**, paste the service
   account Client ID, and grant this OAuth scope:
   `https://www.googleapis.com/auth/admin.directory.user.readonly`
6. Pick a Workspace admin whose email you'll impersonate (any
   super-admin will do; a role-scoped admin with directory read is
   safer).
7. Store the JSON key file, workspace domain, and admin email in your
   `.env`.

## Local development

```bash
cp .env.example .env
pnpm install
pnpm --filter @hlao-adapter/google-sso-directory build
pnpm --filter @hlao-adapter/google-sso-directory test
```

Tests use a mock `fetch` — no real Google credentials needed.

## Composition with other adapters

Directory can chain BEHIND another verifier. Common pattern:

```ts
const oidc = createGoogleOidcVerifier({ clientId, hostedDomain });
const directory = createGoogleDirectoryVerifier({ workspaceDomain, ... });

// Runner-wired verifyActor: check the allowlist first (fast), fall
// back to directory (slower, network call).
const verifyActor = async (actorId: string) => {
  if (!oidc.verifyActor(actorId)) return false;
  return directory.verifyActor(actorId);
};
```

This chains cheap allowlist check + authoritative directory check.
