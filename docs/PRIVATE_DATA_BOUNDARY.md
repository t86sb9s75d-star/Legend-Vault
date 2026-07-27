# Private-Data Boundary

Legend Vault processes real, highly personal exports (conversations, account
fields, settings, feedback, attachments, images, audio, and other derived
data). This document defines the hard separation between the **public software
repository** and **private user records**, and the rules that keep the two
apart.

The separation is enforced at runtime by `legend_vault.privacy` (fail-closed)
and backed up — never replaced — by `.gitignore`.

## The rule

**Public code lives in this Git repository. Private data never does.**

- This repository contains only: the engine, schemas, tests, documentation, and
  **synthetic** fixtures.
- Real exports, extracted records, attachments, receipts, discrepancy reports,
  indexes, logs, caches, databases, and temporary extracted files live in a
  separate location **outside** any Git working tree.
- `.gitignore` is defense in depth, not the control. A runtime guard refuses
  private-data operations whose source or destination is inside a Git worktree.

## Data classification

Classification is always **declared explicitly by the caller**. The system never
inspects content to guess a classification.

| Class | Meaning | May live in this repo? |
| --- | --- | --- |
| **public** | Engine, schemas, docs, synthetic fixtures, public-safe reports. | Yes |
| **internal** | Non-secret developer notes not meant for publication. | Only if non-sensitive and reviewed |
| **private** | Real exports and everything derived from them (records, transcripts, attachments, receipts, private reports, indexes, databases, logs). | **Never** |
| **secret** | Credentials, keys, tokens, `.env` values. | **Never** |

The runtime guard recognizes `synthetic`, `private`, and `secret`. `private`
and `secret` are always refused inside a Git worktree. `synthetic` is refused
inside a worktree unless the caller explicitly passes
`allow_synthetic_git_worktree=True`. An unknown or missing classification fails
closed.

## Safe directory layout

Keep private data in a sibling directory that is **not** a Git repository:

```text
parent-directory/
├── Legend-Vault/          # public software repository (this repo)
└── Legend-Vault-Data/     # private local data, outside Git
    ├── incoming/          # newly received export ZIPs (originals, untouched)
    ├── originals/         # preserved original export bytes, unchanged
    ├── working/           # scratch extraction / processing
    ├── records/           # built Legend Vault records
    ├── receipts/          # import + integrity receipts
    ├── reports/
    │   ├── private/       # full reports with exact local evidence
    │   └── public-safe/   # redacted, aggregate-only reports
    ├── indexes/           # search / embedding indexes
    ├── databases/         # local databases
    ├── logs/              # runtime logs
    └── temp/              # temporary files
```

Point the importer's `--output` at a path inside `Legend-Vault-Data/`, never at
a path inside this repository.

## Processing real exports

1. Place the export ZIP under `Legend-Vault-Data/incoming/` — **never** copy it
   into this repository, even temporarily. Local Git tooling, editors, indexing
   services, backup systems, and hooks may observe a file before it is deleted,
   so "delete it before commit" is not an acceptable workflow.
2. Preserve the original export bytes unchanged in private storage.
3. Run ingestion with the destination outside the repository. Real ingestion is
   classified `private` by default; the runtime guard refuses it if the source
   or destination is inside a Git worktree.
4. Never pass real export content to a public test, fixture, snapshot, log, or
   assertion message.

## Temporary files, caches, logs, databases, indexes, receipts, reports, archives

Every **derived destination** carries the same classification as its source.
When a real export is processed, all of the following are `private` and must be
written outside the repository: temporary/extracted files, caches, logs,
receipts, discrepancy reports, search/embedding indexes, local databases, and
final archives. The guard protects the destination root, so everything nested
under it is covered.

## Public-safe reports

Discrepancy and verification tooling must distinguish two report kinds:

- **Private full report** — exact local evidence. Contains message text,
  titles, account data, attachment names, local private paths, asset-map
  values, or unique user identifiers. Always `private`; never committed.
- **Public-safe report** — safe to share. Contains **only**: aggregate counts,
  schema names, error codes, synthetic examples, redacted placeholders, and
  hashes *only* where publishing them cannot reveal or enable correlation of
  private data.

Neither report is committed automatically. A public-safe report requires manual
review before publication.

## Integrity ledger vs. external trust anchor

- The **internal integrity ledger** (`integrity/hashes.json` inside a record)
  detects accidental or uncoordinated modification of a record's files. It does
  **not** prove faithful capture at origin: a coordinated rewrite with a
  regenerated ledger is undetectable from the ledger alone.
- An **external trust anchor** (an independent receipt, a comparison against the
  original source, or a signature held outside the record) is required to prove
  a record is unchanged since publication. The internal ledger and the external
  anchor are different guarantees; do not present one as the other.

## No external transmission this phase

During this phase Legend Vault is **local-first and single-owner**. No external
model provider, inference service, telemetry, analytics, or crash-reporting
system may receive real export content, and there is no live model provider, API
key, or network data transfer. Real export content stays on the local machine.

## Raw exports and remote storage

A private GitHub repository is **not** the preferred primary location for raw
exports. Even a private remote copies data off the local machine and into
systems (hosting, backups, integrations) outside the owner's direct control.
Keep raw exports in local private storage (`Legend-Vault-Data/`) and treat any
remote as a deliberate, separately-authorized decision.

## Incident response: private data in Git history

If real export content is committed (or reaches a remote):

1. **Stop.** Do not push further; if already pushed, treat the data as exposed.
2. Rotate any exposed secret immediately (keys, tokens) — removal from history
   does not undo exposure.
3. Remove the data from history (e.g. `git filter-repo`) on a coordinated basis;
   a plain revert leaves the content in history.
4. Force-update the affected refs only with explicit human authorization, and
   notify anyone who may have cloned or fetched.
5. Record the incident (what, when, scope) in a private note — not in this repo.
6. Add or tighten a guard/ignore so the same class of data cannot re-enter.

## Redaction vs. history

Editing or removing a value in the current working tree does **not** erase it
from the repository's history. Earlier commits still contain the old content,
and on a public repository that content has already been exposed and may be
cloned, forked, cached, or mirrored.

- **Current-tree redaction** (what a normal remediation PR does) stops the value
  from appearing in the *latest* tree and prevents accidental re-use going
  forward.
- **History cleanup** (removing the value from *all* prior commits, e.g. with
  `git filter-repo`) is a **separate, destructive, coordinated** operation. It
  rewrites commit hashes, requires an authorized force-update, and must be
  coordinated with everyone who has cloned or forked. It is decided and executed
  on its own, after the redaction PR is merged — never bundled into it.

## Correlatable identifiers

A hash is not automatically safe to publish. The **SHA-256 of a real private
export** is a stable fingerprint: anyone who holds the same export can confirm
it matches this repository. Treat digests, receipts, and derived measurements of
private source material as **correlatable identifiers**, not as anonymous
metadata. Hashes of *public* source files (e.g. a source-code manifest) are fine
because the files themselves are already public.

## Synthetic fixtures

Synthetic fixtures must be **invented**, never copied from a real export. Do not
paste real filenames, digests, dates, counts, titles, or content into fixtures,
tests, snapshots, or reports. If a report needs example numbers, label them
clearly as synthetic; if it documents real-export measurements, state that they
were removed and kept only in private audit records outside the repository.

## Preventive scanning

`scripts/privacy_scan.py` is a deterministic, offline, fail-closed scanner over
**tracked files** (and text members of tracked ZIPs, inspected in memory). It
runs in CI and as a local pre-commit hook, reports only `path:line: RULE-ID`
(never the matched value), and exits non-zero on any finding. Rules:

- `LV-PRIV-001` private-export-identifier (real-export archive names)
- `LV-PRIV-002` private-export-digest (a full SHA-256 labeled as export/private)
- `LV-PRIV-003` secret-pattern (private-key blocks, API-key/token shapes)
- `LV-PRIV-004` personal-identifier (emails, account/user IDs with real values)
- `LV-PRIV-005` local-private-path (local user home paths)
- `LV-PRIV-006` raw-export-payload (known raw-export payload filenames)

The scanner keeps a **narrow, documented allowlist** — only its own rule
definitions (`scripts/privacy_scan.py`), its synthetic test fixtures
(`tests/test_privacy_scan.py`), and `.gitignore` (which lists the very payload
patterns being scanned for). The allowlist is intentionally small; widening it
requires a clear, written justification.
