from pathlib import Path
import os
import sys

# By default, allow running pytest from a source checkout before editable installation.
# CI sets LMP_TEST_INSTALLED_WHEEL=1 to ensure tests import the built wheel instead.
if os.environ.get("LMP_TEST_INSTALLED_WHEEL") != "1":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
