# Legend Vault Stress Test — Reproducible Revision 2

> **This public report uses synthetic or redacted evidence.** Real-export
> identifiers, fingerprints, and measurements are retained only in private audit
> records outside the repository.

- **Source archive:** `<private export archive — redacted>`
- **Source SHA-256:** `<redacted>`
- **Verifier at the time of the run:** `legend_vault_verify.py` v0.1.0
- **Verifier SHA-256:** `<redacted>`
- **Verifier in this tree today:** `legend_vault_verify (MODEL 2.0).py` v0.1.1.
  The file was renamed and revised after this run, so the command below names
  the file that exists now. The measurements above are from v0.1.0 and are **not**
  re-attributed to v0.1.1; re-running today may legitimately differ.
- **Standard-library only:** Yes

## Corrections to Revision 1

### 1. The earlier harness was not executable

Claude's criticism is correct. The first stress-test package contained a 218-byte placeholder called a reusable harness, but it held comments rather than the executed validation code. That violated the report's own build-provenance requirement.

Revision 2 includes:

- The complete executable verifier
- All eleven fault-injection generators
- The exact command
- Python and platform metadata
- Source and verifier hashes
- Machine-readable reproduced results
- Captured stdout and stderr

### 2. The internal-heading count was wrong

The earlier report used an internal-heading count that silently excluded some
heading levels: it counted only non-event `##` headings and omitted `#`, `###`,
and deeper headings. That measurement is withdrawn. The corrected, reproducible
formula is:

```text
all Markdown headings
− archive title heading
− event headings
= internal message headings
```

The specific counts were derived from the private export and have been removed
from this public report. They are retained only in private audit records
outside the repository.

### 3. The scoreboard wording overstated the archive's defenses

Test Fixture 001 ships no verifier and automatically detects **0 of 11** mutations.

The external v0.1.0 verifier:

- Rejected **8 of 11** mutated archives
- Accepted **3 of 11**
- Matched all **11 of 11** declared test expectations

The three accepted mutations are demonstrations of current design weaknesses:

1. README alteration
2. Gap-ledger alteration
3. Transcript rewrite with coordinated internal hash updates

Therefore, the accurate statement is:

> An external verifier can reject eight defined corrupt or hostile mutations. The archive itself provides no active detection, and three integrity attacks remain indistinguishable without an external trust anchor.

## Independently reproduced measurements

The independently reproduced measurements — archive size, entry count, parsed
event count, actor breakdown, timestamp availability, and code-fence and heading
counts — were derived from the private export. They have been removed from this
public report and are retained only in private audit records outside the
repository.

The methodology remains reproducible: measurements are produced by running the
standard-library verifier over the source archive and parsing its canonical
event stream. Anyone holding the private export can reproduce them locally.

## Reproducible command

```bash
python3 "legend_vault_verify (MODEL 2.0).py" "<private export archive — redacted>" \
  --fault-test \
  --json-out reproduced-results.json
```

## Triage under the anti-expansion rule

### Already part of the v0.1 critical path

These do not create new systems:

- Official-export comparison and completeness testing
- Nullable timestamp handling
- Canonical JSONL event output
- Stable event, parent, branch, and source IDs
- Artifact ingestion from the official export
- Explicit unavailable-artifact records

### Fold into v0.1 now

These are small enough and directly fix observed failures:

- Hash every payload and metadata file
- Give every manifest entry size, media type, and hash
- Put all ZIP entries under one record-ID root directory
- Add per-event provenance and fidelity labels
- Enforce path, duplicate-name, expansion-ratio, and total-size limits
- Preserve these eleven fault cases as regression tests
- Add a secret/PII scan report before any shareable export
- Include executable build provenance, not a placeholder

### Use a cheap external anchor first

A Git commit can provide a practical first external receipt for the canonical manifest hash, provided the commit is pushed to a remote repository whose history is protected or independently mirrored.

A local Git commit alone is not an append-only guarantee because local history can be rewritten.

For v0.1:

```text
canonical manifest root
→ committed to protected remote Git history
→ commit ID stored in the vault record
```

### Defer until the share boundary justifies it

- Digital signatures
- User-managed signing keys
- Merkle trees
- Transparency logs
- Hardware-backed keys

These remain valid later designs, but they are not required to build and test the official-export parser.

## Revised verdict

```text
Fixture structure:          ACCEPTED
Transcript byte transfer:   VERIFIED
External verifier:          NOW REPRODUCIBLE
Archive self-verification:  NOT IMPLEMENTED
Metadata integrity:         FAILED
Authenticity:               FAILED
Platform completeness:      UNPROVEN
Production acceptance:      REJECTED
```

## Immediate build order

1. Parse one official ChatGPT export.
2. Emit canonical JSONL with stable IDs and provenance.
3. Bundle every accessible artifact; create typed gaps for the rest.
4. Generate a complete manifest and all-file hashes.
5. Run the executable verifier and eleven regression cases.
6. Run secret/PII scanning before sharing.
7. Commit the manifest root to protected remote Git history.
8. Diff the official-export result against Test Fixture 001.
9. Stop testing the fixture and proceed based on that discrepancy report.

This revision is itself reproducible from the included executable harness and preserved result files.
