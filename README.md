# Legend Vault

Legend Vault is a raw-first, local archival tool for importing, canonicalizing,
verifying, inspecting, and comparing conversation records.

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

Import a supported ZIP:

```bash
legend-vault import SOURCE.zip --output vault
```

Verify a built record:

```bash
legend-vault verify vault/LV-....zip
```

Compare two records:

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
artifacts to this repository. The `.gitignore` excludes common Legend Vault
runtime paths and archive names, but review every commit before pushing.

## Status

The Python CLI baseline is runnable and its synthetic end-to-end path is tested.
Compatibility with an official ChatGPT export must be validated against a real
user-provided export without committing that export to GitHub.
