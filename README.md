# Legend Vault

Legend Vault is a raw-first, local archival tool for importing, canonicalizing,
verifying, inspecting, and comparing conversation records.

## Private-data boundary

> **This public repository contains software only.** Never place real exports,
> vault records, attachments, receipts, logs, indexes, databases, temporary
> extracted files, or private reports inside this Git working tree. Use a
> separate private data directory outside the repository.

- The current supported surface is **local-first and single-owner**.
- **No live model provider is active** — no API key, no external inference.
- **No real export may be sent to any external service** (no model provider, no
  telemetry, no analytics).
- **Synthetic fixtures are the only data permitted inside the repository.**

A fail-closed runtime guard (`legend_vault.privacy`) refuses to read a real
export from, or write records into, a Git working tree. See
[`docs/PRIVATE_DATA_BOUNDARY.md`](docs/PRIVATE_DATA_BOUNDARY.md).

## Current v0.1 scope

```text
Import → Canonicalize → Build record → Verify → Inspect → Diff
```

`raw/events.jsonl` is authoritative. Markdown transcripts are derived views.

## Run locally

Requires Python 3.10 or newer.

```bash
python -m pip install -e .
legend-vault --help
```

Import a supported ZIP. The source and `--output` must be **outside** this
repository (see the private-data boundary above); the importer refuses paths
inside a Git working tree:

```bash
legend-vault import ../Legend-Vault-Data/incoming/SOURCE.zip \
  --output ../Legend-Vault-Data/records
```

Verify a built record:

```bash
legend-vault verify ../Legend-Vault-Data/records/LV-....zip
```

Compare two records (paths outside the repository):

```bash
legend-vault diff RECORD_A.zip RECORD_B.zip
```

## Trust boundary

- The original source ZIP is preserved unchanged in a built record.
- Every record file except `integrity/hashes.json` is covered by the internal
  SHA-256 ledger.
- Internal hashes detect accidental or uncoordinated modification.
- Internal hashes alone do not prove faithful capture at origin.
- A coordinated rewrite with a regenerated ledger remains undetectable without
  an external receipt or source comparison.

## Privacy

Do not commit private exports, raw transcripts, generated records, or personal
artifacts to this repository. The primary control is the fail-closed runtime
guard in `legend_vault.privacy`, which refuses private-data operations inside a
Git working tree; `.gitignore` is defense in depth, not the control. Review
every commit before pushing, and read
[`docs/PRIVATE_DATA_BOUNDARY.md`](docs/PRIVATE_DATA_BOUNDARY.md).

## Status

The Python CLI baseline is runnable, and its synthetic end-to-end and
verifier fault-injection paths are tested.
Compatibility with an official ChatGPT export must be validated against a real
user-provided export without committing that export to GitHub.
