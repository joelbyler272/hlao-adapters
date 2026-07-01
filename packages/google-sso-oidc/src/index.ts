// @hlao-adapter/google-sso-oidc — verify Google OIDC ID tokens against
// Google's JWKS, then expose two functions the deployment composes:
//
//   verifyToken(idToken) -- production entry point. Validates the JWT
//     signature via jose against Google's public keys, checks audience,
//     issuer, expiry, email_verified, and (optionally) the hd claim
//     against a configured Workspace domain. Returns { actorId, claims }
//     where actorId is the verified email string, ready to pass to
//     runner.approveReview / runner.denyReview as actorHumanId.
//
//   verifyActor(actorId) -- runner-compatible allowlist check. Called by
//     @hlao/orchestrator's runner via CreateRunnerDeps.verifyActor. Returns
//     true if actorId is in the configured allowedActorIds set, or if no
//     set is configured (trusting the upstream verifyToken call did the
//     real work). The deployment wires this into createRunner.
//
// The two-function shape reflects a deliberate separation: verifyToken is
// the AUTHENTICATION step (credential → identity); verifyActor is the
// AUTHORIZATION step (identity → allowed?). They are typically called in
// different places in the deployment:
//
//   Web layer (POST /reviews/:id/action handler):
//     const { actorId } = await oidc.verifyToken(req.headers['x-google-id-token']);
//     await runner.approveReview({ actorHumanId: actorId, ... });
//
//   Runner deps (createRunner):
//     verifyActor: oidc.verifyActor
//
// This split is what ADR-0020's verifyActor was designed to accept: the
// engine ships the seam, the deployment picks the auth mechanism, the
// adapter provides the concrete implementation.

import { type JWTPayload, type JWTVerifyGetKey, createRemoteJWKSet, jwtVerify } from "jose";
import { z } from "zod";

export const GoogleOidcConfigSchema = z.object({
  /**
   * The Google OAuth 2.0 client ID that the ID token's `aud` claim must
   * match. Get this from Google Cloud Console → APIs & Services →
   * Credentials → OAuth 2.0 Client IDs.
   */
  clientId: z.string().min(1),
  /**
   * Optional Workspace hosted-domain check. When set, the token's `hd`
   * claim must equal this exactly. Use this to enforce "only users in
   * example.edu may approve reviews."
   */
  hostedDomain: z.string().min(1).optional(),
  /**
   * Optional explicit allowlist of actor ids (email addresses). When
   * set, both verifyToken and verifyActor enforce membership. When
   * unset, verifyActor returns true for any actor id (trusting the
   * upstream verifyToken).
   */
  allowedActorIds: z.array(z.string().min(1)).optional(),
  /**
   * Google's JWKS URI. Default is the public endpoint. Override only
   * for testing (see jwksGetKey) or if Google publishes a
   * regional/enterprise endpoint you need to pin.
   */
  jwksUri: z.string().url().default("https://www.googleapis.com/oauth2/v3/certs"),
});

export type GoogleOidcConfig = z.input<typeof GoogleOidcConfigSchema>;

export interface GoogleOidcClaims extends JWTPayload {
  email: string;
  email_verified: boolean;
  hd?: string;
  name?: string;
  picture?: string;
  sub: string;
}

export interface VerifyTokenResult {
  /** The verified email, ready to pass as actorHumanId. */
  actorId: string;
  claims: GoogleOidcClaims;
}

export interface GoogleOidcVerifier {
  /**
   * Verify a Google ID token. Returns the extracted actor id (email) on
   * success; throws with an actionable message on any failure.
   */
  verifyToken(idToken: string): Promise<VerifyTokenResult>;
  /**
   * Runner-compatible verifyActor. Returns true if actorId is in the
   * configured allowedActorIds set, or if no set is configured.
   */
  verifyActor(actorId: string): boolean;
}

export interface GoogleOidcVerifierOptions {
  /**
   * Advanced: override the JWKS resolver. Production callers omit this;
   * the default is createRemoteJWKSet against config.jwksUri. Tests can
   * pass createLocalJWKSet(...) to avoid network calls.
   */
  jwksGetKey?: JWTVerifyGetKey;
}

const GOOGLE_ISSUERS = ["https://accounts.google.com", "accounts.google.com"];

export function createGoogleOidcVerifier(
  rawConfig: GoogleOidcConfig,
  options: GoogleOidcVerifierOptions = {},
): GoogleOidcVerifier {
  const config = GoogleOidcConfigSchema.parse(rawConfig);
  const getKey = options.jwksGetKey ?? createRemoteJWKSet(new URL(config.jwksUri));
  const allowedSet =
    config.allowedActorIds !== undefined ? new Set(config.allowedActorIds) : undefined;

  async function verifyToken(idToken: string): Promise<VerifyTokenResult> {
    if (typeof idToken !== "string" || idToken.length === 0) {
      throw new Error("verifyToken called with an empty or non-string id token");
    }

    const { payload } = await jwtVerify(idToken, getKey, {
      audience: config.clientId,
      issuer: GOOGLE_ISSUERS,
    });

    const email = payload.email;
    if (typeof email !== "string" || email.length === 0) {
      throw new Error("Google ID token has no email claim; ensure the 'email' scope was requested");
    }
    if (payload.email_verified !== true) {
      throw new Error(
        `Google ID token email_verified is not true for ${email}; refusing to accept an unverified email`,
      );
    }
    if (config.hostedDomain !== undefined) {
      if (payload.hd !== config.hostedDomain) {
        throw new Error(
          `Google ID token hd claim '${payload.hd ?? "(missing)"}' does not match configured hostedDomain '${config.hostedDomain}'`,
        );
      }
    }
    if (allowedSet !== undefined && !allowedSet.has(email)) {
      throw new Error(`Google ID token email '${email}' is not in the allowedActorIds set`);
    }

    return {
      actorId: email,
      claims: payload as GoogleOidcClaims,
    };
  }

  function verifyActor(actorId: string): boolean {
    if (allowedSet === undefined) return true;
    return allowedSet.has(actorId);
  }

  return { verifyToken, verifyActor };
}
