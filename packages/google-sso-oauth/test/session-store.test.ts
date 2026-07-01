import { describe, expect, it } from "vitest";
import { InMemorySessionStore } from "../src/session-store.js";

describe("InMemorySessionStore", () => {
  it("stores, retrieves, and destroys a session", async () => {
    const store = new InMemorySessionStore();
    const id = await store.create({
      actorId: "alice@example.com",
      createdAt: Date.now(),
      expiresAt: Date.now() + 60_000,
    });
    expect(id.length).toBeGreaterThan(20);
    const session = await store.get(id);
    expect(session?.actorId).toBe("alice@example.com");
    await store.destroy(id);
    expect(await store.get(id)).toBeNull();
  });

  it("returns null and self-cleans an expired session", async () => {
    const store = new InMemorySessionStore();
    const id = await store.create({
      actorId: "alice@example.com",
      createdAt: Date.now() - 120_000,
      expiresAt: Date.now() - 60_000,
    });
    expect(store.size()).toBe(1);
    expect(await store.get(id)).toBeNull();
    expect(store.size()).toBe(0);
  });

  it("returns null for an unknown session id", async () => {
    const store = new InMemorySessionStore();
    expect(await store.get("unknown")).toBeNull();
  });

  it("destroy is silent on unknown session id", async () => {
    const store = new InMemorySessionStore();
    await expect(store.destroy("unknown")).resolves.toBeUndefined();
  });
});
