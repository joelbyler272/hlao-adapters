// @hlao-adapter/jwt — generic JWT verifier for HLAO verifyActor.
//
// Provider-agnostic. Use a dedicated adapter (google-sso-oidc,
// microsoft-entra-id, ...) when one exists; this is the escape hatch for
// custom or otherwise-uncovered issuers.

import {
  type JWTPayload,
  type JWTVerifyGetKey,
  type KeyLike,
  createRemoteJWKSet,
  importSPKI,
  jwtVerify,
} from "jose";
import { z } from "zod";

const DEFAULT_ALGORITHMS = ["RS256", "ES256", "EdDSA"] as const;

export const JwtVerifierConfigSchema = z
  .object({
    issuer: z.string().min(1),
    audience: z.string().min(1),
    jwksUri: z.string().url().optional(),
    publicKeyPem: z.string().min(1).optional(),
    actorClaim: z.string().min(1).default("sub"),
    allowedActorIds: z.array(z.string().min(1)).optional(),
    algorithms: z.array(z.string().min(1)).nonempty().optional(),
  })
  .refine((v) => Boolean(v.jwksUri) !== Boolean(v.publicKeyPem), {
    message: "Exactly one of jwksUri or publicKeyPem must be set",
  });

export type JwtVerifierConfig = z.input<typeof JwtVerifierConfigSchema>;

export interface JwtClaims extends JWTPayload {
  [claim: string]: unknown;
}

export interface VerifyTokenResult {
  actorId: string;
  claims: JwtClaims;
}

export interface JwtVerifier {
  verifyToken(token: string): Promise<VerifyTokenResult>;
  verifyActor(actorId: string): boolean;
}

export interface JwtVerifierOptions {
  /**
   * Advanced: pre-resolved JWKS resolver. Tests inject this via
   * createLocalJWKSet to avoid network.
   */
  jwksGetKey?: JWTVerifyGetKey;
  /**
   * Advanced: pre-resolved public key. When set (with publicKeyPem in
   * config), used directly instead of importing the PEM at each call.
   */
  publicKey?: KeyLike;
}

const isString = (v: unknown): v is string => typeof v === "string" && v.length > 0;

export function createJwtVerifier(
  rawConfig: JwtVerifierConfig,
  options: JwtVerifierOptions = {},
): JwtVerifier {
  const config = JwtVerifierConfigSchema.parse(rawConfig);
  const algorithms = (config.algorithms ?? DEFAULT_ALGORITHMS) as string[];
  const allowedSet =
    config.allowedActorIds !== undefined ? new Set(config.allowedActorIds) : undefined;

  let jwksGetKey: JWTVerifyGetKey | undefined = options.jwksGetKey;
  if (!jwksGetKey && config.jwksUri) {
    jwksGetKey = createRemoteJWKSet(new URL(config.jwksUri));
  }

  let cachedPublicKey: KeyLike | undefined = options.publicKey;
  const resolvePublicKey = async (): Promise<KeyLike> => {
    if (cachedPublicKey) return cachedPublicKey;
    if (!config.publicKeyPem) {
      throw new Error("Invariant: publicKeyPem verifier called without a PEM");
    }
    const alg = algorithms[0] ?? "RS256";
    cachedPublicKey = await importSPKI(config.publicKeyPem, alg);
    return cachedPublicKey;
  };

  async function verifyToken(token: string): Promise<VerifyTokenResult> {
    if (!isString(token)) {
      throw new Error("verifyToken called with an empty or non-string token");
    }

    const opts = { audience: config.audience, issuer: config.issuer, algorithms };
    const { payload } = jwksGetKey
      ? await jwtVerify(token, jwksGetKey, opts)
      : await jwtVerify(token, await resolvePublicKey(), opts);

    const raw = (payload as JwtClaims)[config.actorClaim];
    if (!isString(raw)) {
      throw new Error(
        `JWT claim '${config.actorClaim}' is missing or not a non-empty string; cannot derive actor id`,
      );
    }
    if (allowedSet !== undefined && !allowedSet.has(raw)) {
      throw new Error(`JWT actor '${raw}' is not in the allowedActorIds set`);
    }

    return { actorId: raw, claims: payload as JwtClaims };
  }

  function verifyActor(actorId: string): boolean {
    if (allowedSet === undefined) return true;
    return allowedSet.has(actorId);
  }

  return { verifyToken, verifyActor };
}
