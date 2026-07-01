# @hlao-adapter/saml

SAML 2.0 assertion verification for HLAO `verifyActor`. Validates the XML
signature of a base64-encoded SAML Response, extracts `NameID` as the actor
id, and optionally enforces an allowlist.

## What this adapter does

Parses a base64-encoded SAML Response XML, verifies the XML-DSig signature
against the IdP's X.509 certificate, validates issuer and audience, checks
`NotBefore`/`NotOnOrAfter` timing constraints, and extracts the `NameID`
element as `actorId`.

This adapter does NOT implement the SP-initiated SAML flow (AuthnRequest,
ACS endpoint, RelayState). It verifies an already-received SAML Response.
For the full flow, pair this with Express middleware in your deployment
(parallel to how `@hlao-adapter/google-sso-oauth` handles the full OAuth
dance).

## Usage

```ts
import { createSamlVerifier } from "@hlao-adapter/saml";

const saml = createSamlVerifier({
  idpCertPem: process.env.SAML_IDP_CERT_PEM!,
  expectedIssuer: process.env.SAML_EXPECTED_ISSUER!,
  expectedAudience: process.env.SAML_EXPECTED_AUDIENCE!,
});

// ACS endpoint: verify the POSTed SAMLResponse.
app.post("/saml/acs", async (req, res) => {
  const { actorId, attributes } = await saml.verifySamlResponse(req.body.SAMLResponse);
  await runner.approveReview({ actorHumanId: actorId, ... });
});

// Runner deps:
const runner = createRunner({ verifyActor: saml.verifyActor, ... });
```

## Configuration

| Field              | What it is                                                        |
| ------------------ | ----------------------------------------------------------------- |
| `idpCertPem`       | IdP's X.509 signing certificate in PEM format. Required.          |
| `expectedIssuer`   | Expected Issuer/EntityID. Required.                               |
| `expectedAudience` | Expected AudienceRestriction value (your SP entity ID). Required. |
| `allowedActorIds`  | Optional allowlist of NameID values.                              |
| `clockSkewMs`      | Tolerance for NotBefore/NotOnOrAfter checks. Default 60000 (1m). |

## Dependencies

- `zod` for config validation.
- `node:crypto` for X.509 signature verification. No external deps beyond zod.

## Testing

Unit tests build synthetic SAML responses with `node:crypto` signing.
Run with `pnpm --filter @hlao-adapter/saml test`.
