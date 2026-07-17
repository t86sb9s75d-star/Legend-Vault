# Legend Vault Stress Test — Reproducible Revision 2

**Source archive:** `LegendVault RawRecord 2026-07-16.zip`  
**Source SHA-256:** `8c65f0fbf5987bb434a223c9926dc5b92403a9f7d0d08b03353dfde5e6387f40`  
**Verifier:** `legend_vault_verify.py` v0.1.0  
**Verifier SHA-256:** `0229acfa06f34911f83e58d465066bfd9f52b164a66aab5b2b0652098796b07d`  
**Standard-library only:** Yes

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

The earlier report stated **150 internal headings**. The reproducible formula is:

```text
all Markdown headings
− archive title heading
− event headings
= internal message headings

425 − 1 − 124 = 300
```

Correct result: **300 internal message headings**.

The prior value of 150 counted only non-event `##` headings and silently excluded `#`, `###`, and deeper headings. That measurement is withdrawn.

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

| Measurement | Result |
|---|---:|
| Compressed source ZIP bytes | 66,626 |
| ZIP entries | 5 |
| Parsed events | 124 |
| User / Assistant / Tool | 61 / 60 / 3 |
| Valid ISO timestamps | 61 |
| Unavailable timestamps | 63 |
| Code-fence lines | 218 |
| All Markdown headings | 425 |
| Archive-title headings | 1 |
| Event headings | 124 |
| Internal message headings | 300 |

## Reproducible command

```bash
python legend_vault_verify.py "LegendVault RawRecord 2026-07-16.zip" \
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
