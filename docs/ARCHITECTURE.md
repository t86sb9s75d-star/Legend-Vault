# Legend Vault architecture

## Purpose

Legend Vault is a raw-first archival system for importing, preserving, canonicalizing,
verifying, inspecting, and comparing conversation records.

Its current scope is deliberately narrow:

```text
Import → Canonicalize → Build record → Verify → Inspect → Diff
```

Features outside ingestion, verification, and comparison remain deferred until the
capture and integrity model is proven against real exports.

## Authority hierarchy

Legend Vault separates preserved source material from interpretations and views.

1. **Preserved source archive**
   - The original input ZIP is copied unchanged into the record.
   - Its SHA-256 digest is recorded.
   - It remains the highest-fidelity source artifact available to the importer.

2. **Canonical event stream**
   - `raw/events.jsonl` is the authoritative machine-readable interpretation.
   - Each line contains one canonical event.
   - Import, verification, and diff operations use this stream.

3. **Derived views**
   - Markdown transcripts are generated from the canonical event stream.
   - They are readable projections, not independent authorities.
   - A view can be regenerated without changing the preserved source.

4. **Integrity metadata**
   - The manifest declares the record's file inventory.
   - The internal SHA-256 ledger detects uncoordinated file modification.
   - Gap records explicitly declare missing, unavailable, unsupported, or
     reference-only material.

## Runtime components

### `src/legend_vault/cli.py`

The command-line boundary.

It parses these commands:

- `import`
- `verify`
- `diff`
- `open`

The CLI translates command-line arguments into calls to the core module and maps
results onto process exit codes.

### `src/legend_vault/core.py`

The current implementation core.

Its responsibilities include:

- source ZIP detection;
- fixture transcript parsing;
- ChatGPT-style `conversations.json` parsing;
- actor and timestamp normalization;
- deterministic event identifier generation;
- canonical JSONL generation;
- derived transcript rendering;
- artifact preservation;
- gap recording;
- manifest and hash-ledger generation;
- record ZIP verification;
- record comparison.

This file currently contains several logically separate subsystems. Splitting it
should wait until their boundaries and invariants are proven, because premature
separation can hide rather than remove coupling.

### `schemas/event.schema.json`

The declared event schema.

At present it documents the intended event shape, but the runtime verifier does
not yet enforce the complete schema. Schema enforcement is therefore an open
hardening task rather than a proven guarantee.

### `tests/`

The executable evidence layer.

The synthetic end-to-end test proves that a controlled source archive can pass
through import, record construction, verification, and self-comparison.

The fault-injection suite proves selected rejection paths by deliberately
damaging otherwise valid records.

### `.github/workflows/ci.yml`

The continuous-integration boundary.

Every push and pull request is tested across supported Python versions. CI
demonstrates repeatable execution in a clean environment; it does not prove
compatibility with an untested real export.

## Record layout

A built record currently has this logical structure:

```text
LV-.../
├── README.md
├── original/
│   └── <source archive>
├── raw/
│   ├── events.jsonl
│   ├── transcript.md
│   └── artifacts/
├── views/
│   └── transcript.md
└── integrity/
    ├── artifacts.json
    ├── gaps.json
    ├── hashes.json
    ├── manifest.json
    └── source-receipt.json
```

## Core invariants

A record is intended to satisfy all of the following:

- the original source archive is preserved unchanged;
- canonical events have contiguous sequence numbers beginning at one;
- every event content hash matches its content;
- every required record file exists;
- every file is declared by the manifest;
- every file except `integrity/hashes.json` is covered by the ledger;
- no ledger entry silently points to absent material;
- derived views never replace the canonical event stream;
- missing or unsupported information is declared rather than silently discarded;
- unsafe archive paths never escape the record boundary.

Some of these invariants are already enforced. Others remain explicit
pre-export hardening targets.

## Trust model

Internal hashes prove internal consistency only.

They can detect accidental damage or an edit made without regenerating the
ledger. They cannot prove faithful capture at origin, because someone able to
rewrite the record can also regenerate its internal hashes.

Origin and publication claims require evidence outside the record, such as:

- an independently stored source digest;
- an external signed receipt;
- a trusted timestamp;
- comparison against the original platform export.

## Design rule

The original source, canonical interpretation, derived views, and integrity
claims must remain distinguishable.

Legend Vault should never gain convenience by making it impossible to tell
which layer produced a fact.
