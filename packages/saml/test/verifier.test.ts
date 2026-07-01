import { createSign, generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createSamlVerifier } from "../src/index.js";

const ISSUER = "https://idp.example.com/saml/metadata";
const AUDIENCE = "https://sp.example.com/saml/sp";

const { publicKey, privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

function buildSamlResponse(opts: {
  issuer?: string;
  audience?: string;
  nameId?: string;
  nameIdFormat?: string;
  notBefore?: string;
  notOnOrAfter?: string;
  attributes?: Record<string, string[]>;
  signingKey?: string;
}): string {
  const iss = opts.issuer ?? ISSUER;
  const aud = opts.audience ?? AUDIENCE;
  const nameId = opts.nameId ?? "alice@example.com";
  const fmt = opts.nameIdFormat ?? "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
  const now = new Date();
  const nb = opts.notBefore ?? new Date(now.getTime() - 60_000).toISOString();
  const na = opts.notOnOrAfter ?? new Date(now.getTime() + 300_000).toISOString();

  let attrBlock = "";
  if (opts.attributes) {
    for (const [name, values] of Object.entries(opts.attributes)) {
      const vals = values.map((v) => `<saml:AttributeValue>${v}</saml:AttributeValue>`).join("");
      attrBlock += `<saml:Attribute Name="${name}">${vals}</saml:Attribute>`;
    }
    attrBlock = `<saml:AttributeStatement>${attrBlock}</saml:AttributeStatement>`;
  }

  const assertion = [
    `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">`,
    `<saml:Issuer>${iss}</saml:Issuer>`,
    `<saml:Subject><saml:NameID Format="${fmt}">${nameId}</saml:NameID></saml:Subject>`,
    `<saml:Conditions NotBefore="${nb}" NotOnOrAfter="${na}">`,
    `<saml:AudienceRestriction><saml:Audience>${aud}</saml:Audience></saml:AudienceRestriction>`,
    "</saml:Conditions>",
    attrBlock,
    "</saml:Assertion>",
  ].join("");

  const signedInfo = [
    '<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">',
    '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>',
    '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>',
    '<ds:Reference><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>',
    "<ds:DigestValue>test</ds:DigestValue></ds:Reference>",
    "</ds:SignedInfo>",
  ].join("");

  const signer = createSign("RSA-SHA256");
  signer.update(signedInfo);
  const signatureValue = signer.sign(opts.signingKey ?? privateKey, "base64");

  const sig = [
    `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">`,
    signedInfo,
    `<ds:SignatureValue>${signatureValue}</ds:SignatureValue>`,
    "</ds:Signature>",
  ].join("");

  const response = [
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">`,
    sig,
    assertion,
    "</samlp:Response>",
  ].join("");

  return Buffer.from(response).toString("base64");
}

describe("createSamlVerifier.verifySamlResponse", () => {
  it("accepts a well-formed signed SAML response", async () => {
    const resp = buildSamlResponse({});
    const v = createSamlVerifier({
      idpCertPem: publicKey,
      expectedIssuer: ISSUER,
      expectedAudience: AUDIENCE,
    });
    const result = await v.verifySamlResponse(resp);
    expect(result.actorId).toBe("alice@example.com");
    expect(result.issuer).toBe(ISSUER);
    expect(result.nameIdFormat).toBe("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
  });

  it("extracts SAML attributes", async () => {
    const resp = buildSamlResponse({
      attributes: {
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": ["alice@example.com"],
        "http://schemas.xmlsoap.org/claims/Group": ["admins", "users"],
      },
    });
    const v = createSamlVerifier({
      idpCertPem: publicKey,
      expectedIssuer: ISSUER,
      expectedAudience: AUDIENCE,
    });
    const result = await v.verifySamlResponse(resp);
    expect(result.attributes["http://schemas.xmlsoap.org/claims/Group"]).toEqual([
      "admins",
      "users",
    ]);
  });

  it("rejects a response with a bad signature", async () => {
    const { privateKey: otherKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    const resp = buildSamlResponse({ signingKey: otherKey });
    const v = createSamlVerifier({
      idpCertPem: publicKey,
      expectedIssuer: ISSUER,
      expectedAudience: AUDIENCE,
    });
    await expect(v.verifySamlResponse(resp)).rejects.toThrow(/signature verification failed/);
  });

  it("rejects a response with wrong issuer", async () => {
    const resp = buildSamlResponse({ issuer: "https://evil.com/saml" });
    const v = createSamlVerifier({
      idpCertPem: publicKey,
      expectedIssuer: ISSUER,
      expectedAudience: AUDIENCE,
    });
    await expect(v.verifySamlResponse(resp)).rejects.toThrow(/Issuer/);
  });

  it("rejects a response with wrong audience", async () => {
    const resp = buildSamlResponse({ audience: "https://wrong.com" });
    const v = createSamlVerifier({
      idpCertPem: publicKey,
      expectedIssuer: ISSUER,
      expectedAudience: AUDIENCE,
    });
    await expect(v.verifySamlResponse(resp)).rejects.toThrow(/Audience/);
  });

  it("enforces allowedActorIds", async () => {
    const good = buildSamlResponse({ nameId: "alice@example.com" });
    const bad = buildSamlResponse({ nameId: "eve@example.com" });
    const v = createSamlVerifier({
      idpCertPem: publicKey,
      expectedIssuer: ISSUER,
      expectedAudience: AUDIENCE,
      allowedActorIds: ["alice@example.com"],
    });
    expect((await v.verifySamlResponse(good)).actorId).toBe("alice@example.com");
    await expect(v.verifySamlResponse(bad)).rejects.toThrow(/allowedActorIds/);
  });

  it("throws on empty input", async () => {
    const v = createSamlVerifier({
      idpCertPem: publicKey,
      expectedIssuer: ISSUER,
      expectedAudience: AUDIENCE,
    });
    await expect(v.verifySamlResponse("")).rejects.toThrow(/empty or non-string/);
  });
});

describe("createSamlVerifier.verifyActor", () => {
  it("returns true for any actor when allowedActorIds is unset", () => {
    const v = createSamlVerifier({
      idpCertPem: publicKey,
      expectedIssuer: ISSUER,
      expectedAudience: AUDIENCE,
    });
    expect(v.verifyActor("anyone@anywhere.com")).toBe(true);
  });

  it("enforces membership when set", () => {
    const v = createSamlVerifier({
      idpCertPem: publicKey,
      expectedIssuer: ISSUER,
      expectedAudience: AUDIENCE,
      allowedActorIds: ["alice@example.com"],
    });
    expect(v.verifyActor("alice@example.com")).toBe(true);
    expect(v.verifyActor("eve@example.com")).toBe(false);
  });
});
