# Federation Outbox (alpha17)

`FederationOutbox` is a durable storage primitive for messages that must be forwarded between LMP nodes. It is intentionally separate from `SQLiteMessageStore`: the latter stores a decoded message body, while federation forwarding must preserve the original origin-signed envelope bytes.

## Guarantees in this prototype

- `enqueue()` parses and verifies the origin-signed envelope before storing it.
- The original envelope bytes are persisted unchanged; a relay must not reconstruct or re-sign the origin message.
- The relay trace is stored separately and can be updated under a valid worker lease.
- `(origin_principal_id, message_id)` is the idempotency key. Re-enqueueing the same envelope returns the existing item; a conflicting envelope under that key is rejected.
- `claim()` creates time-limited worker leases. `retry()` releases a worker's lease and schedules another attempt. `acknowledge()` marks the row `SENT` only for the worker holding the lease.
- Filesystem databases use SQLite WAL and `synchronous=FULL`; `:memory:` is for tests only.

## Explicit limitations

This component does not choose routes, open network connections, verify the relay trace against a local authorization policy, or guarantee end-to-end delivery. Callers must validate/append relay receipts and perform authenticated network sends. `SENT` means the next hop acknowledged durable acceptance, not that the final recipient received or read the message. Retry may cause at-least-once transmission.

The outbox is not yet integrated with `DeliveryWorker`, `FederationSender`, or the node's `TYPE_SIGNED_ENVELOPE` handler. That integration is the next milestone.
