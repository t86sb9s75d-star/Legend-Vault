# Pre-export readiness audit

## Objective

Bring every export-independent part of Legend Vault as close as possible to a
defensible baseline before validating the current official ChatGPT export.

This is not a feature roadmap. It is an ingestion, verification, and diff
hardening plan.

## Confirmed baseline

The repository currently contains:

- an installable Python package;
- a command-line interface;
- fixture and ChatGPT-style parser paths;
- canonical JSONL generation;
- source archive preservation;
- artifact extraction;
- explicit gap records;
- manifest and SHA-256 ledger generation;
- record verification;
- exact and normalized content comparison;
- a synthetic end-to-end test;
- CI across Python 3.10 through 3.13.

## Pre-export blockers

### P0 — Source ZIP safety before content reads

The importer and active verifier must inspect ZIP metadata before reading all
entry contents.

Required controls include:

- maximum total uncompressed size;
- maximum individual entry size;
- compression-ratio limits;
- absolute-path rejection;
- traversal-path rejection;
- symlink rejection;
- duplicate path rejection;
- case-folded path collision rejection;
- Unicode-normalization collision rejection;
- encrypted-entry handling.

A limit checked only after decompression is not a protective limit.

### P0 — Multi-conversation identity model

The default importer selects every conversation in the export.

The archive-level record identifier, event-level record identifiers, branch
identifiers, and parent-link maps must follow one explicit model. Current code
can produce different per-conversation event record identifiers inside one
aggregate record and uses a cross-conversation node map.

Before real-export validation, choose and enforce one model:

1. one record per selected conversation; or
2. one collection record containing many conversations with a single
   archive-level record identifier and explicit conversation identifiers.

No parent link may resolve across conversation boundaries.

### P0 — Verifier internal consistency

The verifier should validate more than file presence and ledger hashes.

Required checks include:

- ledger algorithm declaration;
- ledger hash syntax;
- ledger phantom entries;
- manifest entry structure;
- manifest byte counts;
- manifest SHA-256 claims;
- manifest duplicate paths;
- source receipt hash against the preserved original archive;
- record identifier agreement across manifest, receipt, gaps, artifacts, and events;
- event identifier uniqueness;
- parent-event references;
- branch identifiers;
- timestamp status and timestamp syntax;
- actor and event-type constraints.

### P0 — Runtime schema enforcement

`schemas/event.schema.json` currently documents the event contract but is not
fully enforced by the standard-library verifier.

The runtime must either:

- enforce the schema itself; or
- declare the schema documentation-only and implement an equivalent explicit
  validator.

A schema file that is never consulted is not a verification guarantee.

### P0 — Negative regression testing

A verifier must be tested with deliberately damaged records.

The first fault-injection suite covers:

- missing required files;
- file hash mismatch;
- event content-hash mismatch;
- non-contiguous sequence values;
- duplicate ZIP paths;
- unsafe traversal paths;
- invalid integrity JSON;
- unmanifested files.

Every newly discovered failure mode should become a permanent regression test.

## Additional hardening

### P1 — Collision-free artifact storage

Sanitizing source paths can cause two different source names to map to the same
stored path.

Artifact storage must be deterministic, collision-free, and reversible through
the artifact manifest. Silent overwrite is unacceptable.

### P1 — Diff semantics

The current comparator primarily matches content hashes and normalized text.

It should define how actor, event type, conversation, sequence, parentage,
branch, timestamp, metadata, and repeated identical content affect matching.
Ambiguous matches should be reported rather than silently resolved.

### P1 — Historical artifact classification

These root or fixture artifacts are preserved but can be mistaken for active
runtime authorities:

- `SOURCE_MANIFEST.json`;
- `LegendVault_Stress_Test_Report_v2.md`;
- `legend_vault_verify (MODEL 2.0).py`;
- `fixtures/legend_vault_verify_v0_1_1.py`.

They should remain unchanged until classified, then be clearly labeled as
initial-package evidence, historical engineering evidence, experimental work,
or compatibility fixtures.

## Blocked until the official export arrives

Only the real export can establish:

- the current `conversations.json` shape;
- all message content types;
- attachment and asset path behavior;
- image, audio, voice, Canvas, tool, and generated-file representation;
- regenerated-response and branch semantics;
- deleted or hidden node behavior;
- metadata completeness;
- export-level duplicate or disconnected structures;
- practical archive size and performance;
- discrepancies between platform-visible history and exported history.

The private export must stay off GitHub.

## Completion criteria for the pre-export stage

The pre-export stage is complete when:

- all P0 items have code-level enforcement;
- every P0 rule has a positive or negative automated test;
- CI runs the entire test suite;
- active and historical verifier files are unambiguous;
- documentation states what is proven and what is merely intended;
- no claim of official-export compatibility appears before real validation.
