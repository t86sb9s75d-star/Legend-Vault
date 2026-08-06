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
**tracked files** (`git ls-files`, so the index — including staged additions —
is what gets scanned). It runs in CI and as a local pre-commit hook, reports
only `path:line: RULE-ID` (never the matched value), and exits non-zero on any
finding. Rules:

- `LV-PRIV-001` private-export-identifier (real-export archive names)
- `LV-PRIV-002` private-export-digest (a full SHA-256 near a source/export
  digest label)
- `LV-PRIV-003` secret-pattern (private-key blocks, API-key/token shapes)
- `LV-PRIV-004` personal-identifier (emails, account/user IDs with real values)
- `LV-PRIV-005` local-private-path (local user home paths)
- `LV-PRIV-006` raw-export-payload (known raw-export payload filenames)
- `LV-PRIV-007` unscannable-content (unreadable, undecodable, malformed,
  encrypted, unsupported-format, oversized, or too deeply nested content)

### What "fail closed" means here

The scanner never silently skips content. Anything it cannot read, decode,
parse, or bound becomes an explicit `LV-PRIV-007` finding — an unscannable file
fails the scan rather than passing by omission. If git itself cannot be queried,
the scan exits non-zero instead of reporting success.

### Encoding and binary handling

Encoding is not trusted. Every byte stream is scanned through several text
views — UTF-8 (lossy) and Latin-1 always, UTF-16 LE/BE when a NUL byte is
present, and UTF-32 LE/BE when a NUL-run or BOM indicates it — so UTF-16/UTF-32
text, Latin-1 text, and ASCII embedded inside otherwise-binary content are all
covered. There is no "looks binary, skip it" path. The supported set is exactly
those encodings; other multibyte encodings are not decoded, though their ASCII
substrings remain visible through the Latin-1 view.

### Archive handling

A recognised archive is always either inspected or rejected — never passed
through as ordinary bytes:

| Format | Behaviour |
|---|---|
| ZIP | inspected in memory, recursively |
| TAR (plain, `.gz`, `.bz2`, `.xz`) | inspected in memory, recursively |
| GZIP / BZIP2 / XZ single streams | decompressed under the byte budget, then inspected |
| 7z, RAR | **not parsed** — reported `LV-PRIV-007` (fail closed) rather than treated as scanned |
| malformed / encrypted / oversized | reported `LV-PRIV-007` |

Detection is by **signature first, extension second**, so an archive renamed to
`.md` is still treated as an archive, and a prose file merely *named* like an
archive is not. Members are read **in memory and never extracted** to disk or
into the repository. Nested archives are followed to a bounded depth.

The extension half of that rule covers **every** recognised compression
extension — `.gz`, `.bz2`, `.xz`, `.lzma` — not just the common one. A damaged
or truncated stream loses its magic bytes, and a format missing from the
fallback would then be treated as ordinary bytes and read as "no findings",
because the payload is still compressed and therefore invisible to every text
view. That is a silent miss rather than a harmless mislabel, so the fallback
fails closed to `LV-PRIV-007` instead.

#### Resource accounting is debit-on-consumption

The byte budget measures **expanded bytes inspected** — decompressed or
extracted output the scanner actually reads. Every read goes through one helper
that charges the shared budget **at the moment bytes are consumed**, before any
validation decision. Bytes read from content that is then rejected as oversized,
malformed, unreadable, or otherwise `LV-PRIV-007` are charged exactly the same,
so a crafted archive cannot obtain free reads by failing repeatedly. A read that
raises mid-way is charged its full allowance, so an exception cannot restore
capacity. A declared member size is treated only as a preflight signal; actual
consumption is authoritative. When the shared budget is exhausted the containing
archive scan stops and is reported `LV-PRIV-007` rather than partially trusted.

**Exact guarantee:** total consumption across a scan is at most
`_MAX_TOTAL_BYTES + 1`. The single extra byte is the sentinel that distinguishes
"exactly at the limit" from "over the limit" on the final read; it is charged
like any other byte, so the overshoot is a constant, not per member — verified
against archives holding 1 to 200 malicious members. Compressed input bytes are
not charged separately; each expansion level is charged once as it expands, so
a nested member is charged at each level it is expanded through. The tracked
file's own bytes are read from disk under the per-file size cap and are not part
of this budget.

### Names, symlinks, and safe output

A name is itself text that can leak, so path and archive-member names are
scanned with the same canonical rules used for content, including the contextual
digest rule. Name rules run even when content cannot be read — which is the only
thing that can be inspected for a directory entry, since it has no content at
all. Symlinks are never followed; the link's **target string** is scanned, which
is what git stores, and the same applies to a link target recorded inside a tar
header.

The local-path rule is the one rule that depends on *who is asking*, because
only some names can be absolute:

| name comes from | guarantee | `LV-PRIV-005` |
|---|---|---|
| `git ls-files` (tracked path) | always repository-relative | not applied — a directory legitimately called `docs/home/<user>/` is not a home directory |
| archive member name | none; chosen by whoever built the archive | applied, **anchored** — `/home/<user>/x` is flagged, relative `home/<user>/x` is not |

Callers state which case they are in explicitly, because guessing wrong is a
detection gap in one direction and a false positive in the other.

Because a name can *be* the prohibited value, scanner output never prints a
location verbatim. Each path component is checked, and an unsafe component is
replaced by a stable one-way marker:

```text
docs/<redacted-name:9f2c1a7b40de>/notes.md:0: LV-PRIV-004
bundle.zip!/home/<redacted-name:2bd806c97f0e>/vault/secret.txt:0: LV-PRIV-005
```

Two rules mean something only across a *sequence* of components rather than
within one, and both are evaluated at that scope: a digest label may sit in one
component with the digest in another, and `alice` is identifying only because
`home` precedes it. Safe components are preserved so the entry stays
identifiable for remediation, the marker is deterministic for a given name, and
the prohibited substring never reaches stdout, stderr, or CI logs. Error paths
follow the same rule: the fail-closed `ScanError` message names no path at all.

**Rendered output is checked against the rules that produced it.** Every leak
found in review so far had one shape — a value correctly detected, then
reproduced by the code reporting it. So rather than testing instances,
`test_rendered_output_never_trips_a_content_rule` renders a cross-product of
location shapes and asserts each rendered chunk is itself judged clean under the
strictest reading of the name rules. `LV-PRIV-006` is the single documented
exception: it names a payload *category* (`conversations.json` is identical in
every export and carries nothing user-specific), kept legible for remediation.

### Exemption philosophy

**No file is exempt from every rule.** There is no whole-file allowlist, and no
inline "suppress this" comment anyone can add. An exemption is a single entry
keyed by *(path, rule, SHA-256 of the exact stripped line)*, which makes it:

- **narrow** — one rule, on one line, in one file;
- **alteration-sensitive** — edit that line and the exemption stops applying, so
  neighbouring text can never inherit trust;
- **documented** — every entry carries a written reason;
- **deterministic** — no environment input, no heuristics.

Today the repository has exactly three exemptions, all on `.gitignore`, all for
`LV-PRIV-001`: those lines must literally name the export archives they exclude.
`scripts/privacy_scan.py` and `tests/test_privacy_scan.py` contain rule-shaped
text yet hold **no exemptions at all** — their prohibited shapes are assembled
at runtime from fragments, so a real secret pasted into either file is still
detected. Tests assert all of this, including that `LV-PRIV-007` can never be
exempted.

### Known limits (do not overstate the guarantee)

- Detection is **pattern- and context-based**. It cannot recognise an arbitrary
  private value that carries no recognisable shape or nearby label.
- `LV-PRIV-002` binds a digest to a label within a small line window. A digest
  deliberately separated from any label by more than that window, or carrying no
  label at all, is indistinguishable from a public hash and is not flagged.
- Obfuscated forms (e.g. an address written as `name [at] example.com`) are not
  matched; the false-positive cost of matching them is too high.
- `LV-PRIV-005` on a *name* is **anchored**: an archive member called
  `/home/<user>/x` is flagged, but a relative one called `home/<user>/x` is not.
  A relative tree containing `home/` is ordinary inside an archive, and treating
  it as a local path would false-positive on any tracked directory named `home`.
- The scanner sees the **current tree only**. It cannot detect or remove values
  that already exist in git history — see "Redaction vs. history" above.
