# LMP alpha28 — fault-injection validation report

Date: 2026-10-27

## Changes in this iteration

Two regression tests were added to `tests/test_federation_worker.py`:

1. `test_crash_after_receipt_persisted_before_send_reuses_single_receipt`
   - Injects a failure after the relay trace is committed but before a network attempt is recorded.
   - Reopens the SQLite outbox to model process restart.
   - Confirms the worker reuses the same persisted trace, does not append a duplicate receipt, and only marks the item `SENT` after a matching `STORED` response.
   - Limitation: deterministic crash-boundary injection, not an OS-level kill test.

2. `test_remote_store_then_lost_ack_retries_idempotently`
   - Models receiver-side durable deduplication by `(origin_principal_id, message_id)`.
   - The first network attempt stores the envelope remotely but times out before ACK reaches the sender.
   - Confirms the sender retries with the exact same envelope bytes and relay trace, the receiver retains one logical message, and the sender marks `SENT` only after the subsequent matching ACK.
   - Limitation: mock receiver simulation, not a live multi-node network test.

No runtime implementation or wire protocol behavior changed.

## Executed checks

| Check | Result |
|---|---|
| `pytest -q tests/test_federation_worker.py` | 10 passed |
| `pytest -q tests/test_federation_worker.py tests/test_federation_outbox.py` | 22 passed |
| `python -m compileall -q src tests` | Passed |
| `pip wheel --no-deps --no-build-isolation .` | Wheel built successfully |
| Full `pytest -q` | Blocked at collection: `cbor2` is not installed; 3 modules fail import |
| Isolated wheel build with build dependencies downloaded | Not possible in this environment because the package index cannot be resolved |

The Python startup environment emits a spreadsheet-runtime warmup warning unrelated to LMP. It did not prevent the targeted tests, compile check, or non-isolated wheel build from completing.

## Release gate

Do not treat alpha28 as stable. Before using the test results as release evidence, install the declared official `cbor2` dependency in a clean environment and require the complete test suite and CI workflow to pass. The targeted tests above do not validate CBOR interoperability.
