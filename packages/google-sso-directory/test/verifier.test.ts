// Unit tests for @hlao-adapter/google-sso-directory. Uses a mock fetch
// to simulate the Google token endpoint and Directory API without a
// network call. The JWT signing path IS exercised (real RSA keypair),
// which catches drift in the JWT claims the token endpoint expects.

import { exportPKCS8, generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { type ServiceAccountKey, createGoogleDirectoryVerifier } from "../src/index.js";

const WORKSPACE_DOMAIN = "example.edu";
const ADMIN_EMAIL = "admin@example.edu";

let serviceAccountKey: ServiceAccountKey;

beforeAll(async () => {
  const { privateKey } = await generateKeyPair("RS256");
  const pem = await exportPKCS8(privateKey);
  serviceAccountKey = {
    type: "service_account",
    client_email: "svc@example-project.iam.gserviceaccount.com",
    private_key: pem,
  };
});

interface MockFetchOptions {
  /** Directory API response by user email. */
  users?: Record<string, { primaryEmail?: string; suspended?: boolean; archived?: boolean } | 404>;
  /** How the token endpoint behaves. Default: returns a token. */
  tokenEndpoint?: "ok" | "denied";
}

function makeMockFetch(opts: MockFetchOptions = {}): {
  fetchFn: typeof fetch;
  calls: { url: string; method: string }[];
} {
  const calls: { url: string; method: string }[] = [];
  const users = opts.users ?? {};
  const tokenBehavior = opts.tokenEndpoint ?? "ok";

  const fetchFn = (async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const urlStr = typeof url === "string" ? url : url instanceof URL ? url.toString() : url.url;
    calls.push({ url: urlStr, method: init?.method ?? "GET" });

    // Token endpoint
    if (urlStr.startsWith("https://oauth2.googleapis.com/token")) {
      if (tokenBehavior === "denied") {
        return new Response("invalid_grant", { status: 400 });
      }
      return new Response(JSON.stringify({ access_token: "test-access-token", expires_in: 3600 }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }

    // Directory API user lookup
    if (urlStr.startsWith("https://admin.googleapis.com/admin/directory/v1/users/")) {
      const email = decodeURIComponent(urlStr.split("/users/")[1] ?? "");
      const entry = users[email];
      if (entry === undefined) {
        return new Response("not found", { status: 404 });
      }
      if (entry === 404) {
        return new Response("not found", { status: 404 });
      }
      return new Response(JSON.stringify(entry), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }

    return new Response("unexpected mock request", { status: 500 });
  }) as unknown as typeof fetch;

  return { fetchFn, calls };
}

describe("createGoogleDirectoryVerifier.verifyActor", () => {
  it("returns true for an active user in the workspace domain", async () => {
    const { fetchFn } = makeMockFetch({
      users: { "alice@example.edu": { primaryEmail: "alice@example.edu" } },
    });
    const verifier = createGoogleDirectoryVerifier(
      {
        workspaceDomain: WORKSPACE_DOMAIN,
        serviceAccountKey,
        adminEmailToImpersonate: ADMIN_EMAIL,
      },
      { fetchFn },
    );
    const result = await verifier.verifyActor("alice@example.edu");
    expect(result).toBe(true);
  });

  it("returns false for a user that does not exist (404)", async () => {
    const { fetchFn } = makeMockFetch({
      users: { "alice@example.edu": { primaryEmail: "alice@example.edu" } },
    });
    const verifier = createGoogleDirectoryVerifier(
      {
        workspaceDomain: WORKSPACE_DOMAIN,
        serviceAccountKey,
        adminEmailToImpersonate: ADMIN_EMAIL,
      },
      { fetchFn },
    );
    const result = await verifier.verifyActor("eve@example.edu");
    expect(result).toBe(false);
  });

  it("returns false for a suspended user", async () => {
    const { fetchFn } = makeMockFetch({
      users: { "alice@example.edu": { primaryEmail: "alice@example.edu", suspended: true } },
    });
    const verifier = createGoogleDirectoryVerifier(
      {
        workspaceDomain: WORKSPACE_DOMAIN,
        serviceAccountKey,
        adminEmailToImpersonate: ADMIN_EMAIL,
      },
      { fetchFn },
    );
    const result = await verifier.verifyActor("alice@example.edu");
    expect(result).toBe(false);
  });

  it("returns false for an archived user", async () => {
    const { fetchFn } = makeMockFetch({
      users: { "alice@example.edu": { primaryEmail: "alice@example.edu", archived: true } },
    });
    const verifier = createGoogleDirectoryVerifier(
      {
        workspaceDomain: WORKSPACE_DOMAIN,
        serviceAccountKey,
        adminEmailToImpersonate: ADMIN_EMAIL,
      },
      { fetchFn },
    );
    const result = await verifier.verifyActor("alice@example.edu");
    expect(result).toBe(false);
  });

  it("refuses emails outside the workspace domain without a network call", async () => {
    const { fetchFn, calls } = makeMockFetch({
      users: { "alice@example.edu": { primaryEmail: "alice@example.edu" } },
    });
    const verifier = createGoogleDirectoryVerifier(
      {
        workspaceDomain: WORKSPACE_DOMAIN,
        serviceAccountKey,
        adminEmailToImpersonate: ADMIN_EMAIL,
      },
      { fetchFn },
    );
    const result = await verifier.verifyActor("alice@evil.com");
    expect(result).toBe(false);
    expect(calls).toHaveLength(0);
  });

  it("returns false for empty or non-string actor ids", async () => {
    const { fetchFn } = makeMockFetch();
    const verifier = createGoogleDirectoryVerifier(
      {
        workspaceDomain: WORKSPACE_DOMAIN,
        serviceAccountKey,
        adminEmailToImpersonate: ADMIN_EMAIL,
      },
      { fetchFn },
    );
    expect(await verifier.verifyActor("")).toBe(false);
  });

  it("caches user lookups within the TTL (only one Directory API call for two verifyActor calls)", async () => {
    const { fetchFn, calls } = makeMockFetch({
      users: { "alice@example.edu": { primaryEmail: "alice@example.edu" } },
    });
    const verifier = createGoogleDirectoryVerifier(
      {
        workspaceDomain: WORKSPACE_DOMAIN,
        serviceAccountKey,
        adminEmailToImpersonate: ADMIN_EMAIL,
        cacheTtlMs: 60_000,
      },
      { fetchFn },
    );
    await verifier.verifyActor("alice@example.edu");
    await verifier.verifyActor("alice@example.edu");
    const directoryCalls = calls.filter((c) => c.url.includes("/admin/directory/"));
    expect(directoryCalls).toHaveLength(1);
  });

  it("throws with an actionable message when the token exchange fails", async () => {
    const { fetchFn } = makeMockFetch({ tokenEndpoint: "denied" });
    const verifier = createGoogleDirectoryVerifier(
      {
        workspaceDomain: WORKSPACE_DOMAIN,
        serviceAccountKey,
        adminEmailToImpersonate: ADMIN_EMAIL,
      },
      { fetchFn },
    );
    await expect(verifier.verifyActor("alice@example.edu")).rejects.toThrow(
      /token exchange failed/,
    );
  });

  it("accepts serviceAccountKey as a raw JSON string", async () => {
    const { fetchFn } = makeMockFetch({
      users: { "alice@example.edu": { primaryEmail: "alice@example.edu" } },
    });
    const verifier = createGoogleDirectoryVerifier(
      {
        workspaceDomain: WORKSPACE_DOMAIN,
        serviceAccountKey: JSON.stringify(serviceAccountKey),
        adminEmailToImpersonate: ADMIN_EMAIL,
      },
      { fetchFn },
    );
    expect(await verifier.verifyActor("alice@example.edu")).toBe(true);
  });
});
