# LMP Core alpha29 — hard process-crash validation

## Scope
alpha29 adds a subprocess regression test for the SQLite federation outbox. A child
OS process claims an item and blocks after the claim transaction commits. The parent
then terminates the child without a graceful shutdown, reopens the same database,
and verifies the lease and exact envelope bytes survived.

## Assertions
- The claimed row and lease token are durable after abrupt child termination.
- A second worker cannot claim before lease expiry.
- The item becomes claimable at lease expiry and receives a different lease token.
- The original signed envelope bytes are unchanged.
- A stale completion from the killed worker cannot mark the row SENT.
- The recovered worker can acknowledge the item.

## Limits
This is a real process-termination test of the outbox claim boundary. It does not
simulate power loss or kernel/storage-controller failure, and it does not kill the
federation worker after relay-receipt persistence or after remote acceptance. Those
remain separate fault-injection scenarios. The test uses deterministic logical time
for lease expiry, not wall-clock waiting.
