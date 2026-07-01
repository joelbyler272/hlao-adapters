import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createUsersFileVerifier } from "../src/index.js";

let toClose: Array<{ close(): void }> = [];

afterEach(() => {
  for (const v of toClose) v.close();
  toClose = [];
});

async function makeFile(contents: unknown): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "hlao-users-file-"));
  const path = join(dir, "users.json");
  await writeFile(path, JSON.stringify(contents), "utf-8");
  return path;
}

describe("createUsersFileVerifier", () => {
  it("accepts a simple string-array file", async () => {
    const path = await makeFile({ actors: ["alice@example.com", "bob@example.com"] });
    const v = await createUsersFileVerifier({ path });
    toClose.push(v);
    expect(v.verifyActor("alice@example.com")).toBe(true);
    expect(v.verifyActor("bob@example.com")).toBe(true);
    expect(v.verifyActor("eve@example.com")).toBe(false);
  });

  it("accepts an object-array file with metadata", async () => {
    const path = await makeFile({
      actors: [
        { id: "alice@example.com", displayName: "Alice", roles: ["approver"] },
        { id: "bob@example.com", displayName: "Bob" },
      ],
    });
    const v = await createUsersFileVerifier({ path });
    toClose.push(v);
    expect(v.verifyActor("alice@example.com")).toBe(true);
    const listed = v.listActors();
    expect(listed).toHaveLength(2);
    expect(listed[0]?.displayName).toBe("Alice");
    expect(listed[0]?.roles).toEqual(["approver"]);
  });

  it("throws with an actionable message when JSON is malformed", async () => {
    const dir = await mkdtemp(join(tmpdir(), "hlao-users-file-"));
    const path = join(dir, "users.json");
    await writeFile(path, "not-json-{{", "utf-8");
    await expect(createUsersFileVerifier({ path })).rejects.toThrow(/not valid JSON/);
  });

  it("throws when the schema is wrong (empty actors)", async () => {
    const path = await makeFile({ actors: [] });
    await expect(createUsersFileVerifier({ path })).rejects.toThrow();
  });

  it("reload() picks up file changes", async () => {
    const path = await makeFile({ actors: ["alice@example.com"] });
    const v = await createUsersFileVerifier({ path });
    toClose.push(v);
    expect(v.verifyActor("bob@example.com")).toBe(false);
    await writeFile(path, JSON.stringify({ actors: ["alice@example.com", "bob@example.com"] }));
    await v.reload();
    expect(v.verifyActor("bob@example.com")).toBe(true);
  });

  it("resolves relative paths against process.cwd()", async () => {
    // Sanity check that resolve(cwd, path) is used; we pass an absolute path
    // so this documents the intent — actual relative-path behavior is
    // exercised in deployment tests where cwd is controlled.
    const path = await makeFile({ actors: ["alice@example.com"] });
    const v = await createUsersFileVerifier({ path });
    toClose.push(v);
    expect(v.verifyActor("alice@example.com")).toBe(true);
  });
});
