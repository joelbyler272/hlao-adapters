import { SignJWT, createLocalJWKSet, exportJWK, exportSPKI, generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { createJwtVerifier } from "../src/index.js";

const ISSUER = "https://auth.example.com/";
const AUDIENCE = "hlao-review-api";

let privateKey: CryptoKey;
let publicKeyPem: string;
// biome-ignore lint/suspicious/noExplicitAny: jose JWKSet shape
let jwks: any;

beforeAll(async () => {
  const keyPair = await generateKeyPair("RS256");
  privateKey = keyPair.privateKey;
  publicKeyPem = await exportSPKI(keyPair.publicKey);
  const publicJwk = await exportJWK(keyPair.publicKey);
  publicJwk.alg = "RS256";
  publicJwk.kid = "test-jwt-key-1";
  publicJwk.use = "sig";
  jwks = { keys: [publicJwk] };
});

async function signToken(
  claims: Record<string, unknown>,
  overrides: { issuer?: string; audience?: string } = {},
): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: "test-jwt-key-1" })
    .setIssuedAt()
    .setIssuer(overrides.issuer ?? ISSUER)
    .setAudience(overrides.audience ?? AUDIENCE)
    .setExpirationTime("5m")
    .sign(privateKey);
}

describe("createJwtVerifier (JWKS)", () => {
  it("accepts a signed token and extracts the default sub claim", async () => {
    const token = await signToken({ sub: "user-123" });
    const v = createJwtVerifier(
      { issuer: ISSUER, audience: AUDIENCE, jwksUri: "https://example.com/jwks" },
      { jwksGetKey: createLocalJWKSet(jwks) },
    );
    const result = await v.verifyToken(token);
    expect(result.actorId).toBe("user-123");
  });

  it("extracts a custom actorClaim", async () => {
    const token = await signToken({ sub: "user-123", email: "alice@example.com" });
    const v = createJwtVerifier(
      {
        issuer: ISSUER,
        audience: AUDIENCE,
        jwksUri: "https://example.com/jwks",
        actorClaim: "email",
      },
      { jwksGetKey: createLocalJWKSet(jwks) },
    );
    expect((await v.verifyToken(token)).actorId).toBe("alice@example.com");
  });

  it("rejects wrong issuer / audience", async () => {
    const badIss = await signToken({ sub: "u" }, { issuer: "https://other/" });
    const badAud = await signToken({ sub: "u" }, { audience: "other-api" });
    const v = createJwtVerifier(
      { issuer: ISSUER, audience: AUDIENCE, jwksUri: "https://example.com/jwks" },
      { jwksGetKey: createLocalJWKSet(jwks) },
    );
    await expect(v.verifyToken(badIss)).rejects.toThrow();
    await expect(v.verifyToken(badAud)).rejects.toThrow();
  });

  it("rejects tokens missing the configured actorClaim", async () => {
    const token = await signToken({ other: "value" });
    const v = createJwtVerifier(
      {
        issuer: ISSUER,
        audience: AUDIENCE,
        jwksUri: "https://example.com/jwks",
        actorClaim: "email",
      },
      { jwksGetKey: createLocalJWKSet(jwks) },
    );
    await expect(v.verifyToken(token)).rejects.toThrow(/claim 'email' is missing/);
  });

  it("enforces allowedActorIds", async () => {
    const good = await signToken({ sub: "alice" });
    const bad = await signToken({ sub: "eve" });
    const v = createJwtVerifier(
      {
        issuer: ISSUER,
        audience: AUDIENCE,
        jwksUri: "https://example.com/jwks",
        allowedActorIds: ["alice"],
      },
      { jwksGetKey: createLocalJWKSet(jwks) },
    );
    expect((await v.verifyToken(good)).actorId).toBe("alice");
    await expect(v.verifyToken(bad)).rejects.toThrow(/allowedActorIds/);
  });
});

describe("createJwtVerifier (static PEM)", () => {
  it("verifies with a static PEM public key", async () => {
    const token = await signToken({ sub: "user-pem" });
    const v = createJwtVerifier({
      issuer: ISSUER,
      audience: AUDIENCE,
      publicKeyPem,
    });
    expect((await v.verifyToken(token)).actorId).toBe("user-pem");
  });
});

describe("config validation", () => {
  it("requires exactly one of jwksUri or publicKeyPem", () => {
    expect(() => createJwtVerifier({ issuer: ISSUER, audience: AUDIENCE } as never)).toThrow(
      /Exactly one/,
    );
    expect(() =>
      createJwtVerifier({
        issuer: ISSUER,
        audience: AUDIENCE,
        jwksUri: "https://example.com/jwks",
        publicKeyPem: "-----BEGIN-----\n",
      }),
    ).toThrow(/Exactly one/);
  });
});

describe("verifyActor", () => {
  it("returns true for any actor when allowedActorIds is unset", () => {
    const v = createJwtVerifier(
      { issuer: ISSUER, audience: AUDIENCE, jwksUri: "https://example.com/jwks" },
      { jwksGetKey: createLocalJWKSet(jwks) },
    );
    expect(v.verifyActor("anyone")).toBe(true);
  });
  it("enforces membership when set", () => {
    const v = createJwtVerifier(
      {
        issuer: ISSUER,
        audience: AUDIENCE,
        jwksUri: "https://example.com/jwks",
        allowedActorIds: ["alice"],
      },
      { jwksGetKey: createLocalJWKSet(jwks) },
    );
    expect(v.verifyActor("alice")).toBe(true);
    expect(v.verifyActor("eve")).toBe(false);
  });
});
