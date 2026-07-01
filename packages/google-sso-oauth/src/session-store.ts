// Session store interface + reference in-memory implementation.
//
// Production deployments swap InMemorySessionStore for a durable one
// (Redis, Postgres, encrypted-cookie, etc.) by implementing the
// SessionStore interface. The adapter itself stays store-agnostic.

import { randomBytes } from "node:crypto";

export interface SessionData {
  /** The user's canonical actor id (email). */
  actorId: string;
  /** Optional display name from the Google profile. */
  name?: string;
  /** When the session was created (unix ms). */
  createdAt: number;
  /** When the session expires (unix ms). */
  expiresAt: number;
}

export interface SessionStore {
  /** Persist a new session; return the opaque session id. */
  create(data: SessionData): Promise<string>;
  /** Load a session by id; return null if missing or expired. */
  get(sessionId: string): Promise<SessionData | null>;
  /** Destroy a session (logout). Silent on missing. */
  destroy(sessionId: string): Promise<void>;
}

/**
 * Reference in-memory session store. Suitable for single-process
 * deployments and tests. For multi-process / durability, implement a
 * SessionStore against Redis or Postgres.
 */
export class InMemorySessionStore implements SessionStore {
  readonly #sessions = new Map<string, SessionData>();

  async create(data: SessionData): Promise<string> {
    const id = randomBytes(32).toString("base64url");
    this.#sessions.set(id, data);
    return id;
  }

  async get(sessionId: string): Promise<SessionData | null> {
    const data = this.#sessions.get(sessionId);
    if (data === undefined) return null;
    if (data.expiresAt <= Date.now()) {
      this.#sessions.delete(sessionId);
      return null;
    }
    return data;
  }

  async destroy(sessionId: string): Promise<void> {
    this.#sessions.delete(sessionId);
  }

  /** Test helper — count of live sessions. */
  size(): number {
    return this.#sessions.size;
  }
}
