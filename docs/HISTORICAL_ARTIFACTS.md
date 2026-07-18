# Historical and non-authoritative repository artifacts

This file classifies preserved engineering artifacts without rewriting or
summarizing their original contents.

## `SOURCE_MANIFEST.json`

The manifest describes the initial source-only GitHub baseline package.

It is historical package evidence, not a live manifest of the current
repository. Later commits can legitimately make its file sizes and hashes differ
from the working tree.

## `LegendVault_Stress_Test_Report_v2.md`

A preserved historical engineering report.

It records earlier verifier experiments, measurements, failure analysis, and
design reasoning. It is evidence of development history, not the current runtime
specification.

## `legend_vault_verify (MODEL 2.0).py`

A preserved standalone verifier and fault-injection implementation.

Its root location and filename do not make it the active package verifier. The
installed CLI currently calls `src/legend_vault/core.py`.

## `fixtures/legend_vault_verify_v0_1_1.py`

A historical verifier fixture retained for reproducibility and compatibility
work.

It should not be silently edited to match current runtime behavior. New runtime
behavior belongs in the package source and new regression tests.

## Authority rule

Current runtime behavior is defined by installed package source under
`src/legend_vault/`, exercised by tests under `tests/`, and constrained by the
current record-format documentation.

Historical artifacts remain preserved as evidence and must not be treated as
current merely because they contain working code.
