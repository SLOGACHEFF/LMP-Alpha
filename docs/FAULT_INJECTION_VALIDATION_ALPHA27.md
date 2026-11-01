# LMP alpha27 — Verification report

Date: 2026-10-27

## Changes

- Added a multiprocessing test in which two independent OS processes open separate SQLite connections and contend for one outbox item.
- Added a SQLite trigger fault-injection test for acknowledgement persistence. A failed `SENT` update must leave the item `PENDING` and recoverable.
- No runtime implementation or wire protocol changes in alpha27; version is `0.1.0a27`.

## Results

| Check | Result | Notes |
|---|---|---|
| Full test suite with temporary `/tmp/cbor2.py` shim | PASS — 110 tests | Regression evidence only; not official CBOR compatibility evidence. |
| Full test suite without shim | BLOCKED — collection errors in 3 modules | `ModuleNotFoundError: No module named 'cbor2'`. |
| `compileall -q src tests` | PASS | Syntax compilation. |
| Wheel build with `pip wheel --no-deps --no-build-isolation .` | PASS | Build does not install runtime dependencies. |
| ZIP integrity | PASS | `unzip -t` reported no errors. |
| `pip check` in shared environment | WARNING | Unrelated global conflict: `moviepy 2.2.1` requires `pillow<12`, but `pillow 12.3.0` is installed. This is not an LMP dependency conflict. |

## SHA-256

- Source archive `lmp-core-v0.1-alpha27.zip`: `02b84d436bb9856322420cd72b9d70421f09b5869f83a1c2359d288c2105294c`
- Wheel `lmp_core-0.1.0a27-py3-none-any.whl`: `0c01804719f3d047a7e622fa978f1e9d8a2746e3040482d8db9b26d26778fd6a`

## Interpretation

The new tests verify that concurrent independent processes do not claim the same ready item and that an injected SQLite failure cannot falsely persist the `SENT` state. The tests pass under the existing temporary CBOR shim. The complete suite remains blocked until the declared official `cbor2` dependency can be installed in a clean environment. Do not mark LMP stable based on the shim-based run.

## Next gates

1. Run CI with official `cbor2` installed from the declared package metadata.
2. Exercise representative database migrations from older alpha versions with pending, leased, and terminal rows.
3. Test worker process termination around relay-receipt persistence, network send, and ACK handling.
4. Run storage and multi-worker stress tests in a clean environment.
