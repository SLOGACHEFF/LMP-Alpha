# CBOR dependency integration — alpha26 validation record

Date: 2026-10-27

## Changes in this iteration

- Runtime dependency is declared as `cbor2>=5.7.1,<6` in `pyproject.toml`.
- Package version is `0.1.0a26` in both project metadata and `lmp_core.__version__`.
- CI checks that `cbor2` resolves from installed `site-packages`, runs the test suite, builds a wheel, installs that wheel in a separate virtual environment, and reruns tests from outside the source tree.
- `tests/conftest.py` now supports `LMP_TEST_INSTALLED_WHEEL=1` so the installed-wheel test does not prepend the source checkout to `sys.path`.
- `docs/CBOR_DEPENDENCY.md` describes normal and offline installation steps.

## Local results

- `python -m compileall -q src tests`: PASS.
- CI workflow YAML parsed by PyYAML: PASS (GitHub Actions execution itself was not available here).
- Source test suite with the existing temporary `/tmp/cbor2.py` shim: 108 passed. This is diagnostic only and is **not** proof of compatibility with the official dependency.
- Source test suite without a shim: BLOCKED during collection; three test modules fail to import because `cbor2` is not installed.
- `python -m pip install 'cbor2>=5.7.1,<6'`: BLOCKED because this environment cannot resolve the package index (DNS/network error).
- Wheel build with `pip wheel --no-deps --no-build-isolation`: PASS. Artifact: `lmp_core-0.1.0a26-py3-none-any.whl`.
- Wheel metadata confirms `Requires-Dist: cbor2<6,>=5.7.1` and `cryptography<47,>=42`.
- Source archive integrity (`unzip -t`): PASS.

## Release gate

Do not treat alpha26 as validated against the official CBOR library until the new CI workflow passes on both Python 3.12 and 3.13. The local environment has no official `cbor2` package and could not reach the package index, so that final proof remains outstanding.
