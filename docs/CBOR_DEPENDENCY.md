# Official CBOR dependency and validation

LMP declares `cbor2>=5.7.1,<6` as a runtime dependency. The upper bound is intentionally retained until the project explicitly validates cbor2 6.x behavior. Do not copy a `cbor2.py` shim into the repository or use a shim result as release evidence.

## Install and validate locally

Create a clean virtual environment and install the project plus its test dependencies:

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[test]'
python -c "from importlib.metadata import version; import cbor2; print(version('cbor2'), cbor2.__file__)"
python -m pip check
python -m pytest -q
```

On Windows PowerShell, use `py -3.12 -m venv .venv` and `.\.venv\Scripts\Activate.ps1`.

## Offline installation

If the package index is unavailable, download the wheel from the official PyPI project page on a trusted connected machine, verify its SHA-256 against the PyPI release metadata, transfer it into the environment, and install it with `python -m pip install ./cbor2-<version>-py3-none-any.whl`. Install the rest of LMP's dependencies the same way. Never silently substitute a local implementation.

## CI guarantees

`.github/workflows/ci.yml` installs dependencies from package metadata, checks the installed distribution location, runs the complete suite, builds a wheel, installs that wheel into a separate virtual environment, and reruns tests from outside the source tree. The workflow must pass on both configured Python versions before treating this check as release evidence.
