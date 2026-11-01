# Federation outbox lease fencing (alpha20)

## Why this change exists

A worker ID alone is not sufficient to authorize a queue mutation. If a lease expires and the same worker ID claims the message again, an old asynchronous task may still finish late. Without a per-claim token, that stale task could acknowledge or alter the new claim.

## Behavior

Each successful `FederationOutbox.claim()` creates an unpredictable lease token and returns it in `FederationOutboxItem.lease_token`. Updating a relay trace, acknowledging a successful send, retrying, or marking an item failed now requires both `worker_id` and the exact token. These mutations also require that the lease has not expired according to the operation's clock.

A reclaim replaces the token. The previous token is therefore fenced off even if the same worker ID is reused. Claim selection also returns only rows actually claimed in that transaction, avoiding accidental selection of older rows with the same worker ID and lease timestamp.

## Compatibility

On startup, the outbox checks the SQLite table schema and adds the nullable `lease_token` column when opening databases created by earlier alpha versions. Existing rows are preserved. A row without a token is not considered claimed by an active worker; it becomes eligible once its old lease is absent or expires.

## Tests

Regression tests cover stale tokens, repeated claims from the same worker, simultaneous claims from two SQLite connections, and automatic migration of the previous schema. These tests validate local queue semantics; they do not establish production readiness or guarantee delivery exactly once across a network. Network delivery remains at-least-once and relies on stable message IDs plus receiver-side deduplication.
