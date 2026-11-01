# LMP alpha28 — crash-window and lost-ACK tests

## Scope

This release adds regression tests around two delivery failure windows. It does not change runtime behavior or the wire format.

## Scenario A: receipt persisted, send not started

The test injects an exception after `update_trace` has persisted the relay receipt and before `record_attempt` can proceed. It closes and reopens the SQLite outbox to model process restart. Acceptance criteria:

- no network send occurs before the injected failure;
- the row remains retryable;
- the persisted trace contains exactly one receipt;
- after restart, the same trace is reused rather than appending a duplicate receipt;
- the message reaches `SENT` only after the mocked remote returns a matching `STORED` ACK.

This is a deterministic crash-boundary simulation, not an operating-system process kill.

## Scenario B: receiver stores message, ACK is lost

The mock receiver stores the signed envelope idempotently by `(origin_principal_id, message_id)` and then raises a timeout on the first call. The second attempt returns `STORED`. Acceptance criteria:

- both attempts carry identical relay traces and original signed envelope bytes;
- remote durable storage contains one logical message;
- the sender remains `PENDING` after the lost ACK and becomes `SENT` after a valid ACK;
- the send-attempt counter reflects both network attempts.

The test models receiver-side idempotence; it is not a real three-node network fault-injection test.

## Verification

Run in a clean environment with official dependencies:

```bash
python -m pip install -e '.[test]'
python -m pip check
python -m pytest -q
```

The current environment lacks `cbor2`; tests that import CBOR-dependent modules cannot all be considered validated until the full suite passes without a shim.
