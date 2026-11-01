# LMP Core alpha29 — validation report

## Scope
This release adds a subprocess test that abruptly terminates an OS process after
its SQLite outbox lease has committed. Runtime code and wire protocol are unchanged.

## Results
- `tests/test_federation_outbox.py`: **13 passed**.
- `tests/test_federation_worker.py tests/test_federation_outbox.py`: **23 passed**.
- `python -m compileall -q src tests`: **passed**.
- Wheel build with `pip wheel --no-deps --no-build-isolation`: **passed**.
- ZIP integrity check (`ZipFile.testzip()`): **passed**.

## New crash test assertions
- The durable claim, lease token, and exact signed-envelope bytes survive abrupt
  child-process termination.
- A second worker cannot claim the item before lease expiry.
- At lease expiry, the item is recoverable with a new lease token.
- The stale token from the killed worker cannot acknowledge the item.
- The recovered worker can acknowledge the item and transition it to `SENT`.

## Limits and open validation
This test does not simulate power loss or storage-controller failure, and does not
kill the federation worker after relay-receipt persistence or after remote acceptance.
The full test suite still requires the declared `cbor2` dependency in the environment;
alpha29 does not claim full-suite or official CBOR compatibility validation.

## Build artifact
Wheel: `lmp_core-0.1.0a29-py3-none-any.whl` (49,882 bytes).
Wheel SHA-256: `6b99b6f8a97cb53ab8326242d3080fc6995ef2a0d13906c0a65e0a3f0152dae3`.
