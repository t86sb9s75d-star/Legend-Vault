#!/usr/bin/env sh
set -eu
# python3 for the same reason as the pre-commit hook: this script runs in a
# developer's shell, where `python` may not exist. CI invokes each step directly
# under actions/setup-python, which provides both spellings.
python3 -m pip install -e .
python3 -m compileall -q src tests scripts
python3 scripts/privacy_scan.py
python3 tests/test_privacy_scan.py
python3 tests/test_private_data_boundary.py
python3 tests/test_synthetic_end_to_end.py
