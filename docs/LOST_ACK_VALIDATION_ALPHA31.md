# LMP Core alpha31 — validation report (continued)

## Scope
Alpha31 strengthens the existing real TLS A -> B -> C integration test for duplicate ingress and lost-ACK retry idempotency. Runtime code and wire format are unchanged.

## Results verified in this environment
- Targeted worker/outbox suite: **24 passed in 5.24 s** (re-run on 2026-10-29).
- Broader dependency-independent test run: **68 passed in 4.81 s** (re-run on 2026-10-29) using the explicit exclusions listed below.
- Command used for the 68-test run:
  `python -m pytest -q --ignore=tests/test_federation_three_node.py --ignore=tests/test_codec.py --ignore=tests/test_framing.py --ignore=tests/test_federation.py --ignore=tests/test_federation_sender.py --ignore=tests/test_signed_envelope.py --ignore=tests/test_node_security.py`
- The following modules were excluded from that run: `test_federation_three_node.py`, `test_codec.py`, `test_framing.py`, `test_federation.py`, `test_federation_sender.py`, `test_signed_envelope.py`, `test_node_security.py`. This is a partial suite, not the full test suite.
- `python -m compileall -q src tests`: **passed** in the latest run on 2026-10-29.
- Wheel packaging via `python -m pip wheel --no-deps --no-build-isolation`: **passed**.
- Wheel integrity check: **passed** (`zipfile.testzip()` returned `None`).
- Wheel: `lmp_core-0.1.0a31-py3-none-any.whl` (50,013 bytes; 34 entries).
- Wheel SHA-256: `f03cf82e99a562349e15da05da7faf1b260c84c4e3248cc6d72582b6e53a1444`.
- Clean-venv installation smoke test: **passed**. Installed the wheel into a standard Python 3.13 virtual environment with `--no-deps`; outside the source tree, `import lmp_core` succeeded and distribution metadata reported `0.1.0a31`. This checks wheel installation/import metadata only; it does not validate runtime functions requiring dependencies.

## Blocked checks
- A fresh full-suite attempt on 2026-10-29: **blocked during collection** in `tests/test_codec.py`, `tests/test_federation_three_node.py`, and `tests/test_node_security.py` because `cbor2` is absent (`ModuleNotFoundError`).
- Installing declared dependency `cbor2>=5.7.1,<6` was retried; the configured package index returned no available versions. No official `cbor2` wheel/source was found in searched local paths. The dependency has not been substituted with a shim.
- The full test suite and runtime behavior with the declared real CBOR dependency remain unverified here.
- `python -m build --wheel` cannot run because the `build` module is not installed. The alternative setuptools/pip wheel build above succeeded.

## Integration assertions added (not runtime-validated here)
- Duplicate A -> B delivery returns `STORED` and retains the same queued envelope bytes.
- The first B -> C delivery reaches C and stores the message, but its ACK is dropped.
- The retry sends the same origin-signed envelope bytes and byte-identical relay trace.
- The destination contains one logical message, and B marks the outbox row `SENT` after the retry ACK.

## Next gate
Run the existing CI workflow with the declared real `cbor2` dependency on Python 3.12 and 3.13. Require the full suite, compile step, wheel build, and isolated installed-wheel test to pass. Review those results before changing runtime code or advancing the alpha version.
