# LMP alpha25 — Federation fault-injection results

## Scope

This iteration focuses on durable federation queue recovery and attempt accounting. It does not add routing features.

## Confirmed issue fixed

In alpha24, `FederationOutbox.claim()` incremented `attempts` when leasing an item. The worker compares that counter with `max_attempts` to decide whether to mark an item `FAILED`. Therefore, repeated process crashes after claim but before network I/O could consume the send-attempt budget without any network send occurring.

### Change

- `attempts` now counts network-send attempts initiated by the worker.
- New `claims` counter records lease acquisitions/reclaims separately.
- `record_attempt()` increments `attempts` only under the current live fencing token and is called immediately before network I/O.
- Existing SQLite databases are migrated by adding `claims INTEGER NOT NULL DEFAULT 0`; existing queue rows and attempt counts are retained.

There is necessarily a small ambiguity window between persisting `record_attempt()` and actually entering the network send function: a process crash in that window may consume one attempt. The change removes the much larger window where every claim, even one that never reached network I/O, consumed an attempt.

## Fault scenarios covered

1. **Claim → process close → reopen → lease expires → reclaim.** The envelope bytes remain identical, the claim counter increases, and the send-attempt counter remains unchanged until a send is initiated.
2. **Stale worker completion.** The previous fencing token cannot acknowledge an item after it has been reclaimed by another worker.
3. **SQLite transaction failure during enqueue.** A trigger injects an error while writing route history; the transaction rolls back both the outbox row and route-history row.
4. **Repeated crashes before network send.** Three abandoned claims do not exhaust `max_attempts=1`; the recovered worker can still send and acknowledge the message.
5. **Ambiguous network outcome.** The existing real-TLS three-node integration test simulates destination durable acceptance followed by loss of the ACK, then verifies retry and destination deduplication after relay restart.

## Verification

Run the complete suite with the local temporary CBOR shim available:

```bash
PYTHONPATH=/tmp python -m pytest -q
```

This is useful regression evidence, but it is **not** a substitute for running with the official `cbor2` package. The current environment does not have the official dependency installed and cannot reach the package index. CI is configured to install declared dependencies and run the suite without a shim; that remote workflow has not been executed from this environment.

## Remaining stability gates

- Full test run using official `cbor2` in a clean environment.
- Verify migration against representative alpha17–alpha24 database files, including queued, leased, and terminal rows.
- Stress test two or more independent worker processes against one SQLite database.
- Exercise storage-full / disk-I/O errors and process termination at multiple points around claim, receipt persistence, send, and ACK.
- Keep message delivery semantics explicit: remote `STORED` means durable acceptance by the next hop, not end-to-end delivery to the final recipient.
