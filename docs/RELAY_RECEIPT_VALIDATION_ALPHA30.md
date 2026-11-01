# LMP Core alpha30 — validation report

## Scope
A real worker subprocess is hard-terminated immediately after the actual
`FederationOutbox.update_trace` call commits the relay receipt, before the worker
can record a network attempt or send the envelope.

## Results
- `tests/test_federation_worker.py`: **11 passed**.
- `tests/test_federation_worker.py tests/test_federation_outbox.py`: **24 passed**.
- `python -m compileall -q src tests`: **passed**.
- `pip wheel --no-deps --no-build-isolation`: **passed**.

## Crash/recovery guarantee
The child exits with code 86 immediately after the real trace-update method commits.
The reopened database contains one durable relay receipt and zero recorded send
attempts. After lease expiry, the worker reuses the exact saved trace bytes, sends
the original envelope, and marks it `SENT` only after a matching `STORED` ACK.

## Limits
This is deterministic subprocess fault injection, not a power-loss test or a live
multi-host network-partition test. No runtime implementation or wire-protocol
changes were made. The full suite with the official `cbor2` dependency remains
an open validation item.
