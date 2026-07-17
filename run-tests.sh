#!/usr/bin/env sh
set -eu
python -m pip install -e .
python -m compileall -q src tests
python tests/test_synthetic_end_to_end.py
