# LMP Message Storage — alpha9

## Current behavior

The node stores an authenticated submission in SQLite before returning a `STORED` acknowledgement. The persistent idempotency key is `(sender Principal ID, message_id)`. Repeating the same ID with the same recipient and body returns the existing record; reusing it with different content returns `MESSAGE_ID_CONFLICT`.

`SQLiteMessageStore.pending_for(recipient)` lists messages still in `STORED` state. `mark_delivered(sender, message_id, recipient)` transitions one stored record to `DELIVERED`. These are storage primitives only: no delivery worker invokes them yet, and `DELIVERED` must not be interpreted as proof that an end-user read a message.

## Persistence and format

- A filesystem path persists rows across process restarts.
- The CLI server defaults to `lmp-messages.sqlite3`; use `--storage PATH` to choose another file.
- The Python `NodeConfig` defaults to `:memory:` to keep test and embedded use isolated. Set `storage_path` explicitly for persistence.
- Filesystem databases use SQLite WAL mode and `synchronous=FULL`.
- Bodies are encoded using a collision-free tagged JSON representation inside the database. Wire payloads remain CBOR.
- The database is **not encrypted at rest** in this alpha. Protect it and backups with operating-system permissions and disk encryption.

## Known limitations

- No automatic retry/backoff worker or recipient online-session registry.
- No per-recipient quota, retention policy, expiry enforcement, or database compaction policy.
- No end-to-end encryption; the node can read stored bodies.
- The store is a local SQLite adapter, not a federation-wide distributed database.
- A successful `STORED` response proves only that this node committed the message locally.
