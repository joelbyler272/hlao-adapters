import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { createEntraOidcVerifier } from "../src/index.js";

const TENANT = "00000000-0000-0000-0000-000000000000";
const CLIENT_ID = "11111111-1111-1111-1111-111111111111";
const ISSUER = `https://login.microsoftonline.com/${TENANT}/v2.0`;

let privateKey: CryptoKey;
// biome-ignore lint/suspicious/noExplicitAny: jose JWKSet shape
let jwks: any;

beforeAll(async () => {
  const keyPair = await generateKeyPair("RS256");
  privateKey = keyPair.privateKey;
  const publicJwk = await exportJWK(keyPair.publicKey);
  publicJwk.alg = "RS256";
  publicJwk.kid = "test-entra-key-1";
  publicJwk.use = "sig";
  jwks = { keys: [publicJwk] };
});

async function signTestToken(
  claims: Record<string, unknown>,
  overrides: { issuer?: string; audience?: string } = {},
): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: "test-entra-key-1" })
    .setIssuedAt()
    .setIssuer(overrides.issuer ?? ISSUER)
    .setAudience(overrides.audience ?? CLIENT_ID)
    .setExpirationTime("5m")
    .sign(privateKey);
}

describe("createEntraOidcVerifier.verifyToken", () => {
  it("accepts a well-formed token and extracts preferred_username", async () => {
    const token = await signTestToken({
      preferred_username: "alice@contoso.com",
      oid: "abc-123",
      tid: TENANT,
    });
    const verifier = createEntraOidcVerifier(
      { tenantId: TENANT, clientId: CLIENT_ID },
      { jwksGetKey: createLocalJWKSet(jwks) },
    );
    const result = await verifier.verifyToken(token);
    expect(result.actorId).toBe("alice@contoso.com");
    expect(result.claims.oid).toBe("abc-123");
  });

  it("falls back to email then oid when preferred_username is missing", async () => {
    const emailOnly = await signTestToken({ email: "bob@contoso.com", oid: "b-1" });
    const oidOnly = await signTestToken({ oid: "c-1" });
    const verifier = createEntraOidcVerifier(
      { tenantId: TENANT, clientId: CLIENT_ID },
      { jwksGetKey: createLocalJWKSet(jwks) },
    );
    expect((await verifier.verifyToken(emailOnly)).actorId).toBe("bob@contoso.com");
    expect((await verifier.verifyToken(oidOnly)).actorId).toBe("c-1");
  });

  it("rejects tokens with the wrong audience", async () => {
    const token = await signTestToken(
      { preferred_username: "alice@contoso.com" },
      {
        audience: "different-client-id",
      },
    );
    const verifier = createEntraOidcVerifier(
      { tenantId: TENANT, clientId: CLIENT_ID },
      { jwksGetKey: createLocalJWKSet(jwks) },
    );
    await expect(verifier.verifyToken(token)).rejects.toThrow();
  });

  it("rejects tokens with the wrong issuer", async () => {
    const token = await signTestToken(
      { preferred_username: "alice@contoso.com" },
      {
        issuer: "https://malicious.example.com",
      },
    );
    const verifier = createEntraOidcVerifier(
      { tenantId: TENANT, clientId: CLIENT_ID },
      { jwksGetKey: createLocalJWKSet(jwks) },
    );
    await expect(verifier.verifyToken(token)).rejects.toThrow();
  });

  it("rejects tokens missing all principal claims", async () => {
    const token = await signTestToken({ tid: TENANT });
    const verifier = createEntraOidcVerifier(
      { tenantId: TENANT, clientId: CLIENT_ID },
      { jwksGetKey: createLocalJWKSet(jwks) },
    );
    await expect(verifier.verifyToken(token)).rejects.toThrow(/no preferred_username/);
  });

  it("enforces allowedActorIds when configured", async () => {
    const good = await signTestToken({ preferred_username: "alice@contoso.com" });
    const bad = await signTestToken({ preferred_username: "eve@contoso.com" });
    const verifier = createEntraOidcVerifier(
      { tenantId: TENANT, clientId: CLIENT_ID, allowedActorIds: ["alice@contoso.com"] },
      { jwksGetKey: createLocalJWKSet(jwks) },
    );
    expect((await verifier.verifyToken(good)).actorId).toBe("alice@contoso.com");
    await expect(verifier.verifyToken(bad)).rejects.toThrow(/allowedActorIds/);
  });

  it("throws on empty input", async () => {
    const verifier = createEntraOidcVerifier(
      { tenantId: TENANT, clientId: CLIENT_ID },
      { jwksGetKey: createLocalJWKSet(jwks) },
    );
    await expect(verifier.verifyToken("")).rejects.toThrow(/empty or non-string/);
  });
});

describe("createEntraOidcVerifier.verifyActor", () => {
  it("returns true for any actor when allowedActorIds is unset", () => {
    const verifier = createEntraOidcVerifier(
      { tenantId: TENANT, clientId: CLIENT_ID },
      { jwksGetKey: createLocalJWKSet(jwks) },
    );
    expect(verifier.verifyActor("anyone@anywhere.com")).toBe(true);
  });

  it("enforces membership when allowedActorIds is set", () => {
    const verifier = createEntraOidcVerifier(
      { tenantId: TENANT, clientId: CLIENT_ID, allowedActorIds: ["alice@contoso.com"] },
      { jwksGetKey: createLocalJWKSet(jwks) },
    );
    expect(verifier.verifyActor("alice@contoso.com")).toBe(true);
    expect(verifier.verifyActor("eve@contoso.com")).toBe(false);
  });
});
