// @hlao-adapter/users-file — file-backed verifyActor source.
//
// Reads a JSON file describing an allowlist of principals, exposes
// verifyActor for the runner, and optionally reloads on file change.

import { readFile, watch } from "node:fs/promises";
import { resolve } from "node:path";
import { z } from "zod";

export const ActorEntrySchema = z.union([
  z.string().min(1),
  z.object({
    id: z.string().min(1),
    displayName: z.string().min(1).optional(),
    roles: z.array(z.string().min(1)).optional(),
    email: z.string().email().optional(),
  }),
]);

export const UsersFileSchema = z.object({
  actors: z.array(ActorEntrySchema).min(1),
});

export type UsersFile = z.infer<typeof UsersFileSchema>;

export interface Actor {
  id: string;
  displayName?: string;
  roles?: string[];
  email?: string;
}

export interface UsersFileVerifierConfig {
  /** Path to the JSON file. Resolved against process.cwd() if relative. */
  path: string;
  /**
   * When true, reload the file on change. Uses fs.watch; the watcher is
   * detached and never blocks process shutdown. Default false.
   */
  watch?: boolean;
}

export interface UsersFileVerifier {
  verifyActor(actorId: string): boolean;
  listActors(): Actor[];
  /** Reload the file synchronously; useful in tests. */
  reload(): Promise<void>;
  /** Stop the watcher, if one was started. */
  close(): void;
}

const normalize = (entry: z.infer<typeof ActorEntrySchema>): Actor =>
  typeof entry === "string" ? { id: entry } : entry;

export async function createUsersFileVerifier(
  config: UsersFileVerifierConfig,
): Promise<UsersFileVerifier> {
  const absolute = resolve(process.cwd(), config.path);

  let actors: Actor[] = [];
  let index: Set<string> = new Set();

  const load = async (): Promise<void> => {
    const raw = await readFile(absolute, "utf-8");
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new Error(`users-file at ${absolute} is not valid JSON: ${message}`);
    }
    const file = UsersFileSchema.parse(parsed);
    actors = file.actors.map(normalize);
    index = new Set(actors.map((a) => a.id));
  };

  await load();

  let abort: AbortController | undefined;
  if (config.watch) {
    abort = new AbortController();
    (async () => {
      try {
        const watcher = watch(absolute, { signal: abort.signal });
        for await (const _ of watcher) {
          try {
            await load();
          } catch {
            // ignore; keep prior state
          }
        }
      } catch {
        // watcher aborted or file removed; keep prior state
      }
    })();
  }

  return {
    verifyActor(actorId: string): boolean {
      return index.has(actorId);
    },
    listActors(): Actor[] {
      return actors.slice();
    },
    reload: load,
    close(): void {
      abort?.abort();
    },
  };
}
