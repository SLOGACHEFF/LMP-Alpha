# LMP alpha27 — Federation storage fault injection

## Scope

This iteration extends queue testing only. It does not change runtime behavior or the wire protocol.

## Added scenarios

1. **Independent OS processes claim the same item concurrently.** Two child processes open separate SQLite connections to the same file and attempt to claim the same ready item at the same timestamp. Acceptance criterion: exactly one process claims it; the durable `claims` counter is exactly one.
2. **Storage failure while recording `SENT`.** A SQLite trigger injects an error into the acknowledgement update. Acceptance criterion: the row remains `PENDING`, its current lease token remains intact, and a later acknowledgement succeeds after the injected failure is removed.

## Verification commands

```bash
PYTHONPATH=/tmp python -m pytest -q
python -m compileall -q src tests
python -m build --wheel
unzip -t ../lmp-core-v0.1-alpha27.zip
```

The first command uses a temporary CBOR shim if `/tmp/cbor2.py` exists. It is regression evidence for the exercised tests only, not proof of official CBOR compatibility. A separate clean-environment run with the declared `cbor2` package is still required.

## Release gate

Do not treat alpha27 as stable until the complete test suite passes with official `cbor2` in a clean environment and the configured CI workflow succeeds.
