# LMP Core alpha31 — lost-ACK idempotency validation

## Scenario
The real TLS integration test exercises A -> B -> C. A sends an origin-signed
envelope to B; B durably enqueues it before acknowledging `STORED`. A duplicate
A -> B delivery is then submitted to verify idempotent enqueue/acceptance.

B relays the message to C over TLS 1.3. C accepts and stores it, but the test
wrapper deliberately drops the first `STORED` acknowledgement after the actual
TLS send returns successfully. B retries after its backoff. The test checks the
second delivery returns `STORED` and B marks the outbox item `SENT`.

## Assertions strengthened in alpha31
- Duplicate ingress to B returns `STORED` without changing the signed envelope bytes.
- C has exactly one logical message for the recipient after the ACK-loss retry.
- The origin-signed envelope bytes are identical on both B -> C attempts.
- The relay-trace bytes are identical on both attempts, so retry does not append a duplicate receipt.
- B transitions from `PENDING` after the ambiguous first attempt to `SENT` only after the second matching ACK.

## Limits
This is a local multi-node TLS integration test using real protocol framing and
SQLite stores, not a test across independent hosts or a lossy physical network.
The environment initially lacks the declared `cbor2` dependency, so the integration
test cannot be collected until that dependency is installed. No runtime or wire
protocol changes are made.
