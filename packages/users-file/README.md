# @hlao-adapter/users-file

File-backed HLAO `verifyActor` source. Loads a static JSON list of principals
from disk and exposes them as an allowlist. Intended for small deployments,
CI, local dev, or as a bootstrap before an IdP is wired up.

## What this adapter does

Loads a JSON file into memory once at startup, then returns `true` from
`verifyActor(actorId)` if the id is in the file. Optionally reloads on file
change (opt-in `watch: true`).

The file shape:

```json
{
  "actors": ["alice@example.com", "bob@example.com"]
}
```

Or with metadata:

```json
{
  "actors": [
    { "id": "alice@example.com", "displayName": "Alice", "roles": ["approver"] },
    { "id": "bob@example.com", "displayName": "Bob" }
  ]
}
```

## Usage

```ts
import { createUsersFileVerifier } from "@hlao-adapter/users-file";

const users = await createUsersFileVerifier({
  path: process.env.USERS_FILE_PATH!,
  watch: false,
});

// Runner deps:
const runner = createRunner({ verifyActor: users.verifyActor, ... });

// Optional: enumerate actors elsewhere in your deployment.
users.listActors().forEach((a) => console.log(a.id, a.displayName));
```

## Configuration

| Field   | What it is                                                            |
| ------- | --------------------------------------------------------------------- |
| `path`  | Path to the JSON file. Resolved against `process.cwd()` if relative.  |
| `watch` | Optional; when true, reloads the file on change via `fs.watchFile`.   |

## Dependencies

- `zod` for file-shape validation.
- No external network or auth deps. `node:fs` is used directly.

## Testing

Unit tests write a tempfile, load it, verify actors, then mutate + reload.
Run with `pnpm --filter @hlao-adapter/users-file test`.
