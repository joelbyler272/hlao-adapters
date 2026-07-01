// @hlao-adapter/saml — SAML 2.0 assertion verifier for HLAO verifyActor.
//
// Validates the XML-DSig signature of a base64-encoded SAML Response against
// the IdP's X.509 cert, extracts NameID, and optionally enforces an allowlist.
// Uses only node:crypto (no external XML/SAML libs).

import { createVerify } from "node:crypto";
import { z } from "zod";

export const SamlVerifierConfigSchema = z.object({
  idpCertPem: z.string().min(1),
  expectedIssuer: z.string().min(1),
  expectedAudience: z.string().min(1),
  allowedActorIds: z.array(z.string().min(1)).optional(),
  clockSkewMs: z.number().int().min(0).default(60_000),
});

export type SamlVerifierConfig = z.input<typeof SamlVerifierConfigSchema>;

export interface SamlAttributes {
  [key: string]: string[];
}

export interface VerifySamlResult {
  actorId: string;
  issuer: string;
  attributes: SamlAttributes;
  nameIdFormat?: string;
}

export interface SamlVerifier {
  verifySamlResponse(base64Response: string): Promise<VerifySamlResult>;
  verifyActor(actorId: string): boolean;
}

const extractTag = (xml: string, tag: string): string | undefined => {
  const nsPattern = new RegExp(
    `<(?:[\\w]+:)?${tag}(?=[>\\s/])[^>]*>([\\s\\S]*?)</(?:[\\w]+:)?${tag}>`,
  );
  const match = nsPattern.exec(xml);
  return match?.[1]?.trim();
};

const extractTagWithAttr = (
  xml: string,
  tag: string,
  attrName: string,
): { value: string; attr: string | undefined } | undefined => {
  const nsPattern = new RegExp(
    `<(?:[\\w]+:)?${tag}(?=[>\\s/])([^>]*)>([\\s\\S]*?)</(?:[\\w]+:)?${tag}>`,
  );
  const match = nsPattern.exec(xml);
  if (!match) return undefined;
  const attrs = match[1] ?? "";
  const attrMatch = new RegExp(`${attrName}="([^"]*)"`).exec(attrs);
  return { value: match[2]?.trim() ?? "", attr: attrMatch?.[1] };
};

const extractAllAttributes = (xml: string): SamlAttributes => {
  const attrs: SamlAttributes = {};
  const attrPattern =
    /<(?:[\w]+:)?Attribute\s+Name="([^"]*)"[^>]*>([\s\S]*?)<\/(?:[\w]+:)?Attribute>/g;
  for (;;) {
    const match = attrPattern.exec(xml);
    if (match === null) break;
    const name = match[1] ?? "";
    const block = match[2] ?? "";
    const values: string[] = [];
    const valPattern = /<(?:[\w]+:)?AttributeValue[^>]*>([\s\S]*?)<\/(?:[\w]+:)?AttributeValue>/g;
    for (;;) {
      const vm = valPattern.exec(block);
      if (vm === null) break;
      values.push(vm[1]?.trim() ?? "");
    }
    attrs[name] = values;
  }
  return attrs;
};

const extractSignedInfo = (xml: string): string | undefined => {
  const match = /<(?:[\w]+:)?SignedInfo[\s\S]*?<\/(?:[\w]+:)?SignedInfo>/i.exec(xml);
  return match?.[0];
};

const extractSignatureValue = (xml: string): string | undefined => {
  const match = /<(?:[\w]+:)?SignatureValue[^>]*>([\s\S]*?)<\/(?:[\w]+:)?SignatureValue>/i.exec(
    xml,
  );
  return match?.[1]?.replace(/\s/g, "");
};

export function createSamlVerifier(rawConfig: SamlVerifierConfig): SamlVerifier {
  const config = SamlVerifierConfigSchema.parse(rawConfig);
  const allowedSet =
    config.allowedActorIds !== undefined ? new Set(config.allowedActorIds) : undefined;

  async function verifySamlResponse(base64Response: string): Promise<VerifySamlResult> {
    if (typeof base64Response !== "string" || base64Response.length === 0) {
      throw new Error("verifySamlResponse called with an empty or non-string SAMLResponse");
    }

    const xml = Buffer.from(base64Response, "base64").toString("utf-8");

    const signedInfo = extractSignedInfo(xml);
    const signatureValue = extractSignatureValue(xml);
    if (!signedInfo || !signatureValue) {
      throw new Error("SAML Response does not contain a valid XML-DSig Signature element");
    }

    const verifier = createVerify("RSA-SHA256");
    verifier.update(signedInfo);
    const valid = verifier.verify(config.idpCertPem, signatureValue, "base64");
    if (!valid) {
      throw new Error(
        "SAML Response signature verification failed; the response was not signed by the configured IdP certificate",
      );
    }

    const issuer = extractTag(xml, "Issuer");
    if (issuer !== config.expectedIssuer) {
      throw new Error(
        `SAML Issuer '${issuer ?? "(missing)"}' does not match expected '${config.expectedIssuer}'`,
      );
    }

    const audience = extractTag(xml, "Audience");
    if (audience !== config.expectedAudience) {
      throw new Error(
        `SAML Audience '${audience ?? "(missing)"}' does not match expected '${config.expectedAudience}'`,
      );
    }

    const conditionsBlock = /<(?:[\w]+:)?Conditions([^>]*)>/i.exec(xml);
    if (conditionsBlock?.[1]) {
      const now = Date.now();
      const nbMatch = /NotBefore="([^"]*)"/.exec(conditionsBlock[1]);
      const naMatch = /NotOnOrAfter="([^"]*)"/.exec(conditionsBlock[1]);
      if (nbMatch?.[1]) {
        const notBefore = new Date(nbMatch[1]).getTime();
        if (now < notBefore - config.clockSkewMs) {
          throw new Error(`SAML assertion is not yet valid (NotBefore: ${nbMatch[1]})`);
        }
      }
      if (naMatch?.[1]) {
        const notOnOrAfter = new Date(naMatch[1]).getTime();
        if (now >= notOnOrAfter + config.clockSkewMs) {
          throw new Error(`SAML assertion has expired (NotOnOrAfter: ${naMatch[1]})`);
        }
      }
    }

    const nameIdResult = extractTagWithAttr(xml, "NameID", "Format");
    if (!nameIdResult || !nameIdResult.value) {
      throw new Error("SAML assertion does not contain a NameID element");
    }

    const actorId = nameIdResult.value;
    if (allowedSet !== undefined && !allowedSet.has(actorId)) {
      throw new Error(`SAML NameID '${actorId}' is not in the allowedActorIds set`);
    }

    return {
      actorId,
      issuer: issuer ?? "",
      attributes: extractAllAttributes(xml),
      nameIdFormat: nameIdResult.attr,
    };
  }

  function verifyActor(actorId: string): boolean {
    if (allowedSet === undefined) return true;
    return allowedSet.has(actorId);
  }

  return { verifySamlResponse, verifyActor };
}
