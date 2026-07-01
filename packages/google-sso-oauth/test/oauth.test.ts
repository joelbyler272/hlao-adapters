// Unit tests for the OAuth adapter. Uses a mock fetch for Google's
// token endpoint and drives Express handlers directly with mock req/res
// objects. Covers: start-handler redirect, callback state validation,
// callback happy path with session creation, hosted-domain rejection,
// allowlist rejection, unverified-email rejection.

import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { createGoogleOauthAdapter } from "../src/index.js";
import { InMemorySessionStore } from "../src/session-store.js";

const CLIENT_ID = "test-client.apps.googleusercontent.com";
const CLIENT_SECRET = "test-secret";
const REDIRECT_URI = "https://example.com/auth/google/callback";
const STATE_SECRET = "0123456789abcdef0123456789abcdef";

function makeIdToken(claims: Record<string, unknown>): string {
  // Not verified; the callback decodes without verifying. Use plain
  // base64url segments.
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const signature = "unsigned";
  return `${header}.${payload}.${signature}`;
}

function mockTokenExchange(idToken: string): typeof fetch {
  return (async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const urlStr = typeof url === "string" ? url : url instanceof URL ? url.toString() : url.url;
    if (urlStr.startsWith("https://oauth2.googleapis.com/token") && init?.method === "POST") {
      return new Response(JSON.stringify({ id_token: idToken, access_token: "atok" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    return new Response("unexpected mock", { status: 500 });
  }) as unknown as typeof fetch;
}

// Minimal req/res mocks for driving express-style handlers.
interface MockRes {
  status: (code: number) => MockRes;
  type: (t: string) => MockRes;
  send: (body: string) => void;
  redirect: (url: string) => void;
  setHeader: (name: string, value: string | string[]) => void;
  getHeader: (name: string) => string | string[] | undefined;
  statusCode: number;
  sent: string | undefined;
  redirected: string | undefined;
  headers: Record<string, string | string[]>;
}

function mockRes(): MockRes {
  const res: MockRes = {
    statusCode: 200,
    sent: undefined,
    redirected: undefined,
    headers: {},
    status(code) {
      res.statusCode = code;
      return res;
    },
    type() {
      return res;
    },
    send(body) {
      res.sent = body;
    },
    redirect(url) {
      res.redirected = url;
    },
    setHeader(name, value) {
      res.headers[name] = value;
    },
    getHeader(name) {
      return res.headers[name];
    },
  };
  return res;
}

async function signState(payload: Record<string, unknown>, secret: string): Promise<string> {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setExpirationTime("10m")
    .setIssuedAt()
    .sign(new TextEncoder().encode(secret));
}

describe("createGoogleOauthAdapter.startHandler", () => {
  it("redirects to Google's authorize URL with the expected query", async () => {
    const adapter = createGoogleOauthAdapter(
      {
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        redirectUri: REDIRECT_URI,
        stateSigningSecret: STATE_SECRET,
      },
      { sessionStore: new InMemorySessionStore() },
    );
    // biome-ignore lint/suspicious/noExplicitAny: minimal req mock
    const req = { query: {}, headers: {} } as any;
    const res = mockRes();
    // biome-ignore lint/suspicious/noExplicitAny: express next mock
    await adapter.startHandler(req, res as any, (() => {}) as any);
    expect(res.redirected).toBeDefined();
    const url = new URL(res.redirected as string);
    expect(url.origin + url.pathname).toBe("https://accounts.google.com/o/oauth2/v2/auth");
    expect(url.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(url.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("scope")).toBe("openid email profile");
    expect(url.searchParams.get("state")).toBeTruthy();
  });

  it("includes hd parameter when hostedDomain is configured", async () => {
    const adapter = createGoogleOauthAdapter(
      {
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        redirectUri: REDIRECT_URI,
        stateSigningSecret: STATE_SECRET,
        hostedDomain: "example.edu",
      },
      { sessionStore: new InMemorySessionStore() },
    );
    // biome-ignore lint/suspicious/noExplicitAny: minimal req mock
    const req = { query: {}, headers: {} } as any;
    const res = mockRes();
    // biome-ignore lint/suspicious/noExplicitAny: express next mock
    await adapter.startHandler(req, res as any, (() => {}) as any);
    const url = new URL(res.redirected as string);
    expect(url.searchParams.get("hd")).toBe("example.edu");
  });
});

describe("createGoogleOauthAdapter.callbackHandler", () => {
  it("rejects a callback with no code", async () => {
    const adapter = createGoogleOauthAdapter(
      {
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        redirectUri: REDIRECT_URI,
        stateSigningSecret: STATE_SECRET,
      },
      { sessionStore: new InMemorySessionStore() },
    );
    // biome-ignore lint/suspicious/noExplicitAny: minimal req mock
    const req = { query: { state: "x" }, headers: {} } as any;
    const res = mockRes();
    // biome-ignore lint/suspicious/noExplicitAny: express next mock
    await adapter.callbackHandler(req, res as any, (() => {}) as any);
    expect(res.statusCode).toBe(400);
  });

  it("rejects a callback with an invalid state parameter", async () => {
    const adapter = createGoogleOauthAdapter(
      {
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        redirectUri: REDIRECT_URI,
        stateSigningSecret: STATE_SECRET,
      },
      { sessionStore: new InMemorySessionStore() },
    );
    // biome-ignore lint/suspicious/noExplicitAny: minimal req mock
    const req = { query: { code: "c", state: "invalid-state" }, headers: {} } as any;
    const res = mockRes();
    // biome-ignore lint/suspicious/noExplicitAny: express next mock
    await adapter.callbackHandler(req, res as any, (() => {}) as any);
    expect(res.statusCode).toBe(400);
    expect(res.sent).toContain("state");
  });

  it("happy path: creates a session, sets a cookie, redirects to the state's redirectTo", async () => {
    const store = new InMemorySessionStore();
    const adapter = createGoogleOauthAdapter(
      {
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        redirectUri: REDIRECT_URI,
        stateSigningSecret: STATE_SECRET,
      },
      {
        sessionStore: store,
        fetchFn: mockTokenExchange(
          makeIdToken({
            email: "alice@example.com",
            email_verified: true,
            sub: "1234",
            name: "Alice",
          }),
        ),
      },
    );
    const state = await signState({ redirectTo: "/dashboard", nonce: "n1" }, STATE_SECRET);
    // biome-ignore lint/suspicious/noExplicitAny: minimal req mock
    const req = { query: { code: "authcode", state }, headers: {} } as any;
    const res = mockRes();
    // biome-ignore lint/suspicious/noExplicitAny: express next mock
    await adapter.callbackHandler(req, res as any, (() => {}) as any);
    expect(res.redirected).toBe("/dashboard");
    expect(store.size()).toBe(1);
    const setCookieHeader = res.headers["Set-Cookie"];
    expect(setCookieHeader).toBeDefined();
    expect(String(setCookieHeader)).toContain("hlao_session=");
    expect(await adapter.verifyActor("alice@example.com")).toBe(true);
  });

  it("rejects a callback whose id_token has email_verified: false", async () => {
    const adapter = createGoogleOauthAdapter(
      {
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        redirectUri: REDIRECT_URI,
        stateSigningSecret: STATE_SECRET,
      },
      {
        sessionStore: new InMemorySessionStore(),
        fetchFn: mockTokenExchange(
          makeIdToken({ email: "alice@example.com", email_verified: false, sub: "1234" }),
        ),
      },
    );
    const state = await signState({ redirectTo: "/", nonce: "n1" }, STATE_SECRET);
    // biome-ignore lint/suspicious/noExplicitAny: minimal req mock
    const req = { query: { code: "c", state }, headers: {} } as any;
    const res = mockRes();
    // biome-ignore lint/suspicious/noExplicitAny: express next mock
    await adapter.callbackHandler(req, res as any, (() => {}) as any);
    expect(res.statusCode).toBe(403);
    expect(res.sent).toContain("unverified");
  });

  it("rejects a callback whose hd does not match configured hostedDomain", async () => {
    const adapter = createGoogleOauthAdapter(
      {
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        redirectUri: REDIRECT_URI,
        stateSigningSecret: STATE_SECRET,
        hostedDomain: "example.edu",
      },
      {
        sessionStore: new InMemorySessionStore(),
        fetchFn: mockTokenExchange(
          makeIdToken({
            email: "eve@evil.com",
            email_verified: true,
            hd: "evil.com",
            sub: "9999",
          }),
        ),
      },
    );
    const state = await signState({ redirectTo: "/", nonce: "n1" }, STATE_SECRET);
    // biome-ignore lint/suspicious/noExplicitAny: minimal req mock
    const req = { query: { code: "c", state }, headers: {} } as any;
    const res = mockRes();
    // biome-ignore lint/suspicious/noExplicitAny: express next mock
    await adapter.callbackHandler(req, res as any, (() => {}) as any);
    expect(res.statusCode).toBe(403);
  });

  it("rejects a callback for an actor not in allowedActorIds", async () => {
    const adapter = createGoogleOauthAdapter(
      {
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        redirectUri: REDIRECT_URI,
        stateSigningSecret: STATE_SECRET,
        allowedActorIds: ["alice@example.com"],
      },
      {
        sessionStore: new InMemorySessionStore(),
        fetchFn: mockTokenExchange(
          makeIdToken({ email: "bob@example.com", email_verified: true, sub: "2" }),
        ),
      },
    );
    const state = await signState({ redirectTo: "/", nonce: "n1" }, STATE_SECRET);
    // biome-ignore lint/suspicious/noExplicitAny: minimal req mock
    const req = { query: { code: "c", state }, headers: {} } as any;
    const res = mockRes();
    // biome-ignore lint/suspicious/noExplicitAny: express next mock
    await adapter.callbackHandler(req, res as any, (() => {}) as any);
    expect(res.statusCode).toBe(403);
    expect(res.sent).toContain("allowedActorIds");
  });
});

describe("createGoogleOauthAdapter.verifyActor", () => {
  it("returns false for an actor without an active session", async () => {
    const adapter = createGoogleOauthAdapter(
      {
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        redirectUri: REDIRECT_URI,
        stateSigningSecret: STATE_SECRET,
      },
      { sessionStore: new InMemorySessionStore() },
    );
    expect(await adapter.verifyActor("nobody@nowhere.com")).toBe(false);
  });
});
