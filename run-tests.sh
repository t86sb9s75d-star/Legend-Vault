#!/usr/bin/env sh
set -eu
python -m pip install -e .
python -m compileall -q src tests scripts
python scripts/privacy_scan.py
python tests/test_privacy_scan.py
python tests/test_private_data_boundary.py
python tests/test_synthetic_end_to_end.py
