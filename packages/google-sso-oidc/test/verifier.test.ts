// Unit tests for @hlao-adapter/google-sso-oidc. Uses jose's local key
// generation + SignJWT to produce test tokens, then verifies them via
// createLocalJWKSet passed as jwksGetKey. No network calls; the crypto
// path is fully exercised.

import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { createGoogleOidcVerifier } from "../src/index.js";

const CLIENT_ID = "test-client-id.apps.googleusercontent.com";

// Test keypair and JWKS shared across tests.
let privateKey: CryptoKey;
// biome-ignore lint/suspicious/noExplicitAny: jose types are strict about JWKSet shape
let jwks: any;

beforeAll(async () => {
  const keyPair = await generateKeyPair("RS256");
  privateKey = keyPair.privateKey;
  const publicJwk = await exportJWK(keyPair.publicKey);
  publicJwk.alg = "RS256";
  publicJwk.kid = "test-key-1";
  publicJwk.use = "sig";
  jwks = { keys: [publicJwk] };
});

async function signTestToken(claims: Record<string, unknown>): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: "test-key-1" })
    .setIssuedAt()
    .setIssuer("https://accounts.google.com")
    .setAudience(CLIENT_ID)
    .setExpirationTime("5m")
    .sign(privateKey);
}

describe("createGoogleOidcVerifier.verifyToken", () => {
  it("accepts a well-formed Google ID token and extracts the email as actorId", async () => {
    const token = await signTestToken({
      email: "alice@example.com",
      email_verified: true,
      sub: "1234567890",
      name: "Alice",
    });
    const verifier = createGoogleOidcVerifier(
      { clientId: CLIENT_ID },
      { jwksGetKey: createLocalJWKSet(jwks) },
    );
    const result = await verifier.verifyToken(token);
    expect(result.actorId).toBe("alice@example.com");
    expect(result.claims.sub).toBe("1234567890");
    expect(result.claims.name).toBe("Alice");
  });

  it("rejects a token whose signature was made with a different key", async () => {
    // Sign with a fresh keypair; verifier uses the original jwks.
    const otherPair = await generateKeyPair("RS256");
    const bogusToken = await new SignJWT({
      email: "alice@example.com",
      email_verified: true,
      sub: "1234567890",
    })
      .setProtectedHeader({ alg: "RS256", kid: "test-key-1" })
      .setIssuedAt()
      .setIssuer("https://accounts.google.com")
      .setAudience(CLIENT_ID)
      .setExpirationTime("5m")
      .sign(otherPair.privateKey);
    const verifier = createGoogleOidcVerifier(
      { clientId: CLIENT_ID },
      { jwksGetKey: createLocalJWKSet(jwks) },
    );
    await expect(verifier.verifyToken(bogusToken)).rejects.toThrow();
  });

  it("rejects a token whose audience does not match the configured clientId", async () => {
    const token = await new SignJWT({
      email: "alice@example.com",
      email_verified: true,
      sub: "1234567890",
    })
      .setProtectedHeader({ alg: "RS256", kid: "test-key-1" })
      .setIssuedAt()
      .setIssuer("https://accounts.google.com")
      .setAudience("someone-else.apps.googleusercontent.com")
      .setExpirationTime("5m")
      .sign(privateKey);
    const verifier = createGoogleOidcVerifier(
      { clientId: CLIENT_ID },
      { jwksGetKey: createLocalJWKSet(jwks) },
    );
    await expect(verifier.verifyToken(token)).rejects.toThrow();
  });

  it("rejects a token whose issuer is not Google", async () => {
    const token = await new SignJWT({
      email: "alice@example.com",
      email_verified: true,
      sub: "1234567890",
    })
      .setProtectedHeader({ alg: "RS256", kid: "test-key-1" })
      .setIssuedAt()
      .setIssuer("https://malicious.example.com")
      .setAudience(CLIENT_ID)
      .setExpirationTime("5m")
      .sign(privateKey);
    const verifier = createGoogleOidcVerifier(
      { clientId: CLIENT_ID },
      { jwksGetKey: createLocalJWKSet(jwks) },
    );
    await expect(verifier.verifyToken(token)).rejects.toThrow();
  });

  it("rejects a token missing the email claim with an actionable message", async () => {
    const token = await signTestToken({
      email_verified: true,
      sub: "1234567890",
    });
    const verifier = createGoogleOidcVerifier(
      { clientId: CLIENT_ID },
      { jwksGetKey: createLocalJWKSet(jwks) },
    );
    await expect(verifier.verifyToken(token)).rejects.toThrow(/no email claim/);
  });

  it("rejects a token with email_verified: false", async () => {
    const token = await signTestToken({
      email: "alice@example.com",
      email_verified: false,
      sub: "1234567890",
    });
    const verifier = createGoogleOidcVerifier(
      { clientId: CLIENT_ID },
      { jwksGetKey: createLocalJWKSet(jwks) },
    );
    await expect(verifier.verifyToken(token)).rejects.toThrow(/email_verified/);
  });

  it("enforces hostedDomain when configured", async () => {
    const goodToken = await signTestToken({
      email: "alice@example.edu",
      email_verified: true,
      hd: "example.edu",
      sub: "1234567890",
    });
    const badToken = await signTestToken({
      email: "eve@evil.com",
      email_verified: true,
      hd: "evil.com",
      sub: "9999",
    });
    const verifier = createGoogleOidcVerifier(
      { clientId: CLIENT_ID, hostedDomain: "example.edu" },
      { jwksGetKey: createLocalJWKSet(jwks) },
    );
    const good = await verifier.verifyToken(goodToken);
    expect(good.actorId).toBe("alice@example.edu");
    await expect(verifier.verifyToken(badToken)).rejects.toThrow(/hd claim/);
  });

  it("enforces hostedDomain rejection when the hd claim is missing entirely", async () => {
    const token = await signTestToken({
      email: "alice@example.com",
      email_verified: true,
      sub: "1234567890",
    });
    const verifier = createGoogleOidcVerifier(
      { clientId: CLIENT_ID, hostedDomain: "example.edu" },
      { jwksGetKey: createLocalJWKSet(jwks) },
    );
    await expect(verifier.verifyToken(token)).rejects.toThrow(/hd claim/);
  });

  it("enforces allowedActorIds when configured", async () => {
    const goodToken = await signTestToken({
      email: "alice@example.com",
      email_verified: true,
      sub: "1234567890",
    });
    const badToken = await signTestToken({
      email: "eve@example.com",
      email_verified: true,
      sub: "9999",
    });
    const verifier = createGoogleOidcVerifier(
      { clientId: CLIENT_ID, allowedActorIds: ["alice@example.com", "bob@example.com"] },
      { jwksGetKey: createLocalJWKSet(jwks) },
    );
    const good = await verifier.verifyToken(goodToken);
    expect(good.actorId).toBe("alice@example.com");
    await expect(verifier.verifyToken(badToken)).rejects.toThrow(/allowedActorIds/);
  });

  it("throws on empty/non-string input to verifyToken", async () => {
    const verifier = createGoogleOidcVerifier(
      { clientId: CLIENT_ID },
      { jwksGetKey: createLocalJWKSet(jwks) },
    );
    await expect(verifier.verifyToken("")).rejects.toThrow(/empty or non-string/);
  });
});

describe("createGoogleOidcVerifier.verifyActor", () => {
  it("returns true for any actor when allowedActorIds is unset (trust upstream)", () => {
    const verifier = createGoogleOidcVerifier(
      { clientId: CLIENT_ID },
      { jwksGetKey: createLocalJWKSet(jwks) },
    );
    expect(verifier.verifyActor("anyone@anywhere.com")).toBe(true);
  });

  it("returns membership check when allowedActorIds is set", () => {
    const verifier = createGoogleOidcVerifier(
      { clientId: CLIENT_ID, allowedActorIds: ["alice@example.com"] },
      { jwksGetKey: createLocalJWKSet(jwks) },
    );
    expect(verifier.verifyActor("alice@example.com")).toBe(true);
    expect(verifier.verifyActor("eve@example.com")).toBe(false);
  });
});
