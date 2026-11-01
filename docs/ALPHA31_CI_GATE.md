# Alpha31 validation gate — do not advance the alpha yet

## Why this gate is open

The alpha31 change is limited to regression assertions for duplicate ingress and
lost-ACK retries. The assertions compile, but the three-node TLS test has not run
in this environment because the declared `cbor2` dependency is unavailable. The
partial local test run is not a substitute for the full suite.

## Required pass criteria

The existing workflow at `.github/workflows/ci.yml` is the authoritative gate.
It runs on pushes, pull requests, and manual dispatch for Python 3.12 and 3.13.
For **both** Python versions, require all of the following to pass:

1. Install the project and declared test dependencies from `pyproject.toml`.
2. Import `cbor2` from installed `site-packages` (no local shim or substitute).
3. Run the complete `python -m pytest -q` suite, including the three-node TLS test.
4. Compile `src` and `tests` with `compileall`.
5. Build a wheel with `python -m build --wheel`.
6. Install that wheel in an isolated virtual environment and run the full test suite
   against the installed package, outside the source tree.

Do not mark this gate passed based on the dependency-independent subset, compile
checks, or wheel packaging alone. Do not bump the alpha version until the full
workflow is green and the three-node lost-ACK assertions have executed.

## How to run the gate

1. Put the contents of this project directory in a GitHub repository. Preserve
   `.github/workflows/ci.yml` and `pyproject.toml` at the repository root.
2. Push the branch. GitHub Actions should start the **LMP Core CI** workflow
   automatically. Alternatively, open **Actions → LMP Core CI → Run workflow**.
3. Wait for both matrix jobs (`Python 3.12 / real dependencies` and
   `Python 3.13 / real dependencies`) to finish successfully.
4. Inspect the logs for the `cbor2` module path and version, the full test count,
   wheel build, and isolated installed-wheel test. Save the run URL and results
   with the release notes.

## Local reproduction

On a machine with access to the configured package index and Python 3.12 or 3.13:

```bash
python -m pip install --upgrade pip
python -m pip install -e '.[test]' build
python - <<'PY'
from pathlib import Path
import cbor2
print('cbor2:', cbor2.__file__)
assert 'site-packages' in str(Path(cbor2.__file__).resolve())
PY
python -m pytest -q
python -m compileall -q src tests
python -m build --wheel
```

The isolated-wheel portion is intentionally left to the workflow so that it is
run from a clean environment. If dependency installation fails, record the exact
package-index error and keep the gate open; do not replace `cbor2` with a shim.

## Current status in this environment

**OPEN / BLOCKED.** Python 3.13.5 is available and `cryptography` imports, but
`cbor2` cannot be imported. A fresh full-suite attempt stops during collection in
`test_codec.py`, `test_federation_three_node.py`, and `test_node_security.py` with
`ModuleNotFoundError: No module named 'cbor2'`. No Git repository remote is
configured in this workspace, so a GitHub Actions run cannot be initiated here.
