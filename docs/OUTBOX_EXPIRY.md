# Federation outbox expiry handling

Alpha22 makes expiry a terminal queue outcome. A queued envelope retains its signed `expires_at` value; the worker checks that timestamp before route lookup or network I/O. If the validity window has closed, the worker attempts a lease-token-fenced transition from `PENDING` to `EXPIRED` and clears lease fields.

Expired records are not retried because retrying cannot make the signed envelope valid again. The receiving node must continue validating expiry independently. The worker accepts an injectable `now` value for deterministic testing; normal operation uses the system clock.

This is not a dead-letter inspection API, nor does it currently delete expired rows automatically. Operators can inspect the `EXPIRED` state and decide on retention policy.
