# hlao-adapters

Reference implementations of the [HLAO engine](https://github.com/joelbyler272/hlao)'s
required-dependency contracts. Adapter packages are workflow-agnostic — every
adopter of the engine that reaches for the same identity provider or auth
pattern needs the same adapter code — so they live one layer above the engine
substrate and below per-org deployment kits.

## The three-layer model

```
+-----------------------------------------------------------+
|  HLAO Deployment Kit  (per-org)                           |
|  workflows, agents, config, deploy shape                  |
+-----------------------------------------------------------+
|  HLAO Adapters  (this repo)                               |
|  verifyActor sources, verifyPassport sources,             |
|  MCP connectors (in the sibling hlao-mcp-servers repo)    |
+-----------------------------------------------------------+
|  HLAO Engine  (~/hlao)                                    |
|  contracts + primitives (@hlao/*)                         |
+-----------------------------------------------------------+
```

The engine ships `verifyActor` as a required dep on `CreateRunnerDeps` (per
ADR-0020) but is agnostic about the auth mechanism. Every deployment supplies
its own. Adapters in this repo let deployments consume the common patterns
without re-implementing them.

## Package families

### `@hlao-adapter/google-sso-*`

Google identity in three shapes:

- **`google-sso-oidc`** — OIDC ID-token verification against Google's JWKs.
  For backends that receive an ID token from a client (SPA, mobile).
- **`google-sso-oauth`** — OAuth authorization-code flow with server-side
  sessions. Express middleware for `/start` and `/callback`. For
  server-rendered apps like `@hlao/oversight`.
- **`google-sso-directory`** — Workspace Directory API lookup via service
  account with domain-wide delegation. For header-based email checks
  without a per-user login.

Each package exports a `verifyActor` function compatible with
`@hlao/orchestrator`'s `CreateRunnerDeps.verifyActor`, plus any additional
helpers the pattern needs.

### Future package families (empty today)

- `@hlao-adapter/authority-signer-*` — KMS/HSM implementations of the
  `AuthoritySigner` interface reserved in ADR-0023 (AWS KMS, GCP KMS,
  Vault Transit, YubiHSM).
- `@hlao-adapter/verify-actor-*` — non-Google identity providers (SAML,
  Okta, Azure AD, Auth0, HTTP basic, static allowlist).

## Conventions every package follows

- Every package is `@hlao-adapter/<name>` in npm scope.
- Every package's README lists exactly the config surface, the credentials
  needed, and how to obtain them.
- Every package that touches secrets ships an `.env.example`; `.env` is
  gitignored.
- Every package exposes a `verifyActor` function typed against
  `@hlao/orchestrator`'s expected signature so wiring is drop-in.
- Every package validates all incoming config with Zod at construction
  time; misconfiguration throws at wire time, not at first call.
- Tests use mocked HTTP responses; integration tests against real providers
  are out of scope (that's a deployment concern).

## Build and test

```bash
pnpm install
pnpm -r build
pnpm -r typecheck
pnpm lint
pnpm -r test
```

## Layer discipline

Adapters do NOT depend on `@hlao-mcp/*` (the MCP connector fleet) or on any
per-org code. They depend only on the engine's public interface (`@hlao/*`)
and on third-party libraries appropriate to their pattern (`jose` for JWT,
`googleapis` for Directory API, etc.).

Any adapter that grows an assumption about a specific org's workflow or
data shape has drifted into the wrong layer — surface it as a deployment
kit concern instead.
