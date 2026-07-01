// @hlao-adapter/microsoft-entra-id — verify Microsoft Entra ID (Azure AD)
// OIDC ID tokens against the tenant's JWKS, then expose the two-function
// shape ADR-0020 defined: verifyToken (authentication) and verifyActor
// (authorization). Parallel to @hlao-adapter/google-sso-oidc.

import { type JWTPayload, type JWTVerifyGetKey, createRemoteJWKSet, jwtVerify } from "jose";
import { z } from "zod";

export const EntraOidcConfigSchema = z.object({
  /**
   * Entra tenant id (a GUID like '00000000-0000-0000-0000-000000000000') or
   * a verified domain suffix (like 'contoso.onmicrosoft.com'). Do NOT use
   * 'common' unless you deliberately want to accept sign-ins from any
   * Microsoft tenant.
   */
  tenantId: z.string().min(1),
  /**
   * The registered application's Application (client) ID that the token's
   * `aud` claim must match. Portal: App registrations → your app → Overview.
   */
  clientId: z.string().min(1),
  /**
   * Optional explicit allowlist of actor ids (the verified principal from
   * the token). When set, verifyToken rejects unknown principals and
   * verifyActor enforces the same set.
   */
  allowedActorIds: z.array(z.string().min(1)).optional(),
  /**
   * JWKS URI. Default is the tenant's public v2.0 keys endpoint. Override
   * only for tests or when Microsoft has provisioned a sovereign-cloud
   * endpoint you need to pin (e.g. Azure Government, Azure China).
   */
  jwksUri: z.string().url().optional(),
});

export type EntraOidcConfig = z.input<typeof EntraOidcConfigSchema>;

export interface EntraOidcClaims extends JWTPayload {
  oid?: string;
  preferred_username?: string;
  email?: string;
  name?: string;
  tid?: string;
  ver?: string;
}

export interface VerifyTokenResult {
  actorId: string;
  claims: EntraOidcClaims;
}

export interface EntraOidcVerifier {
  verifyToken(idToken: string): Promise<VerifyTokenResult>;
  verifyActor(actorId: string): boolean;
}

export interface EntraOidcVerifierOptions {
  /**
   * Advanced: override the JWKS resolver. Production callers omit this;
   * the default is createRemoteJWKSet against the tenant's public v2.0
   * discovery endpoint. Tests pass createLocalJWKSet(...) to avoid network.
   */
  jwksGetKey?: JWTVerifyGetKey;
}

const defaultJwksUri = (tenantId: string): string =>
  `https://login.microsoftonline.com/${encodeURIComponent(tenantId)}/discovery/v2.0/keys`;

const validIssuers = (tenantId: string): string[] => [
  `https://login.microsoftonline.com/${tenantId}/v2.0`,
  `https://sts.windows.net/${tenantId}/`,
];

const extractActorId = (claims: EntraOidcClaims): string | undefined =>
  claims.preferred_username ?? claims.email ?? claims.oid;

export function createEntraOidcVerifier(
  rawConfig: EntraOidcConfig,
  options: EntraOidcVerifierOptions = {},
): EntraOidcVerifier {
  const config = EntraOidcConfigSchema.parse(rawConfig);
  const jwksUri = config.jwksUri ?? defaultJwksUri(config.tenantId);
  const getKey = options.jwksGetKey ?? createRemoteJWKSet(new URL(jwksUri));
  const allowedSet =
    config.allowedActorIds !== undefined ? new Set(config.allowedActorIds) : undefined;

  async function verifyToken(idToken: string): Promise<VerifyTokenResult> {
    if (typeof idToken !== "string" || idToken.length === 0) {
      throw new Error("verifyToken called with an empty or non-string id token");
    }

    const { payload } = await jwtVerify(idToken, getKey, {
      audience: config.clientId,
      issuer: validIssuers(config.tenantId),
    });

    const claims = payload as EntraOidcClaims;
    const actorId = extractActorId(claims);
    if (typeof actorId !== "string" || actorId.length === 0) {
      throw new Error(
        "Entra ID token has no preferred_username, email, or oid claim; cannot derive actor id",
      );
    }
    if (allowedSet !== undefined && !allowedSet.has(actorId)) {
      throw new Error(`Entra ID token principal '${actorId}' is not in the allowedActorIds set`);
    }

    return { actorId, claims };
  }

  function verifyActor(actorId: string): boolean {
    if (allowedSet === undefined) return true;
    return allowedSet.has(actorId);
  }

  return { verifyToken, verifyActor };
}
