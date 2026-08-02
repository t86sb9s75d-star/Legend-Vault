#!/usr/bin/env python3
"""Deterministic, offline privacy scanner for tracked files.

Purpose
-------
Fail-closed check that prohibited private / correlatable content cannot be
committed to this public repository. It complements the runtime
``legend_vault.privacy`` guard: the guard keeps private *data* out of the
working tree at ingestion time; this scanner keeps private *values* out of
tracked *text*.

Design guarantees
-----------------
- Operates on **tracked files only** (``git ls-files``).
- Reads locally; never uploads content and never calls a network service.
- **Never silently skips content.** Anything that cannot be decoded, parsed, or
  read becomes an explicit ``LV-PRIV-007`` finding rather than a gap. Encoding
  is not trusted: every byte stream is scanned through several text views
  (UTF-8, Latin-1, and UTF-16 when NUL bytes are present), so UTF-16 text,
  Latin-1 text, and ASCII embedded inside binary blobs are all covered.
- **Recurses into nested archives** up to ``_MAX_ARCHIVE_DEPTH``; deeper nesting
  is reported as unscannable instead of ignored.
- Reports only ``path:line: RULE-ID`` — never the matched value.
- Exits non-zero (fail closed) if any finding is present.
- Deterministic: fixed rule order, sorted output, no environment input.

Deliberate limits (documented, not hidden)
------------------------------------------
- Detection is pattern-based. It cannot recognise an arbitrary private value
  that carries no recognisable shape or label.
- Very large members are bounded by ``_MAX_MEMBER_BYTES`` /
  ``_MAX_TOTAL_BYTES``; exceeding a bound yields ``LV-PRIV-007`` (fail closed),
  not a silent skip.
- Symlinks are never followed. A tracked symlink's *target string* is scanned
  (that is what git stores), so a link pointing at a private location is caught.
- The scanner sees the **current tree only**. It cannot remove values that
  already exist in git history; see docs/PRIVATE_DATA_BOUNDARY.md.

Rules
-----
- ``LV-PRIV-001`` private-export-identifier — a real-export archive name.
- ``LV-PRIV-002`` private-export-digest — a full SHA-256 near an export /
  source-archive digest label (public source-manifest hashes are unlabeled and
  are not matched).
- ``LV-PRIV-003`` secret-pattern — private-key blocks and API-key/token shapes.
- ``LV-PRIV-004`` personal-identifier — emails and account/user IDs bound to a
  realistic value.
- ``LV-PRIV-005`` local-private-path — local user home paths.
- ``LV-PRIV-006`` raw-export-payload — known raw-export payload filenames.
- ``LV-PRIV-007`` unscannable-content — content that could not be fully
  inspected (unreadable, undecodable, malformed/encrypted archive, too large,
  or nested too deeply). Fail-closed: unscannable is treated as a finding.
"""

from __future__ import annotations

import io
import re
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path

ALL_RULES: frozenset[str] = frozenset(
    {
        "LV-PRIV-001",
        "LV-PRIV-002",
        "LV-PRIV-003",
        "LV-PRIV-004",
        "LV-PRIV-005",
        "LV-PRIV-006",
        "LV-PRIV-007",
    }
)

# --- Allowlist (narrow, rule-scoped, documented) ------------------------------
# Exemptions are per rule, never whole-file blanket trust:
#   * scripts/privacy_scan.py     — defines every rule pattern, so it necessarily
#                                   contains rule-shaped text.
#   * tests/test_privacy_scan.py  — exercises every rule with synthetic values.
#   * .gitignore                  — lists the raw-export payload/archive names it
#                                   protects against; exempt ONLY from those two
#                                   name rules, still scanned for secrets,
#                                   personal identifiers, and local paths.
ALLOWLIST: dict[str, frozenset[str]] = {
    "scripts/privacy_scan.py": ALL_RULES,
    "tests/test_privacy_scan.py": ALL_RULES,
    ".gitignore": frozenset({"LV-PRIV-001", "LV-PRIV-006"}),
}

# --- Bounds -------------------------------------------------------------------
_MAX_ARCHIVE_DEPTH = 3
_MAX_MEMBER_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_BYTES = 256 * 1024 * 1024

# --- Rule patterns ------------------------------------------------------------

# A real-export archive name family (not a format reference). Separator-tolerant
# so "Raw  Record", "raw_record", and "RawRecords" are all covered.
_EXPORT_ARCHIVE = re.compile(
    r"(?:raw[\s_-]*record\w*|chatgpt[\s_-]*export\w*)[^\n]*"
    r"\.(?:zip|tar|tar\.gz|tgz|gz|7z|rar)\b",
    re.IGNORECASE,
)

# 64-hex digest, reported only when a digest-context label appears within
# _DIGEST_WINDOW lines. A bare `"sha256": "..."` entry (public source manifest)
# carries no source/archive qualifier and is intentionally not matched.
_HEX64 = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")
# Lines of context searched on each side of a digest. Wide enough that a label
# separated from its value by blank lines or markdown still binds; narrow enough
# that a structured manifest of public source hashes stays clean (regression-
# tested against SOURCE_MANIFEST.json).
_DIGEST_WINDOW = 4
_DIGEST_QUALIFIER = r"(?:source|archive|record|vault|export|import(?:ed)?|transcript|original)"
_DIGEST_WORD = r"(?:sha-?\s?256|sha|digest|fingerprint|checksum|hash)"
_DIGEST_CONTEXT = re.compile(
    r"(?:export|raw[\s_-]*record|source archive|private[\s_-](?:export|archive|source))"
    rf"|{_DIGEST_QUALIFIER}.{{0,40}}{_DIGEST_WORD}"
    rf"|{_DIGEST_WORD}.{{0,40}}{_DIGEST_QUALIFIER}",
    re.IGNORECASE,
)

# Secrets: private-key blocks and common token shapes.
_SECRET = re.compile(
    # Key blocks, incl. "PRIVATE KEY BLOCK" (PGP) and typed keys (RSA/OPENSSH).
    r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY(?:[ A-Z]+)?-----"
    # Provider tokens. The body charset allows '-' and '_' so segmented keys
    # (sk-ant-…, sk-proj-…) are covered, not just single alphanumeric runs.
    r"|\bsk-[A-Za-z0-9_-]{20,}"
    r"|\bgh[pousr]_[A-Za-z0-9]{30,}"
    r"|\bgithub_pat_[A-Za-z0-9_]{20,}"
    r"|\bxox[baprs]-[A-Za-z0-9-]{10,}"
    r"|\bAKIA[0-9A-Z]{16}\b"
    r"|\bAIza[A-Za-z0-9_-]{30,}"
    r"|authorization:\s*bearer\s+[A-Za-z0-9._-]{20,}",
    re.IGNORECASE,
)

# Emails, or account/user IDs bound to a realistic value (short synthetic IDs
# like "conv-1" / "synthetic-user" are intentionally not matched).
_PERSONAL = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    r"|\b(?:account|user)[ _-]?id\b\s*[:=]\s*[\"']?"
    r"(?:[0-9a-fA-F]{8}-[0-9a-fA-F-]{8,}|[A-Za-z0-9]{16,})",
    re.IGNORECASE,
)

# Local user home paths. POSIX form stays case-sensitive so "/users/" inside an
# ordinary URL is not flagged; the Windows form is case-insensitive because a
# drive-letter user path has no such collision.
_LOCAL_PATH_POSIX = re.compile(r"(?:/home/|/Users/)[A-Za-z0-9._-]+/")
_LOCAL_PATH_WIN = re.compile(r"[A-Za-z]:\\Users\\", re.IGNORECASE)

# Known raw-export payload filenames (matched against a basename).
_PAYLOAD_NAME = re.compile(
    r"^(?:conversations(?:-[^/]*)?\.json"
    r"|user\.json|user_settings\.json|message_feedback\.json"
    r"|library_files\.json|conversation_asset_file_names\.json"
    r"|ads\.json|export_manifest\.json|chat\.html|.+\.dat)$",
    re.IGNORECASE,
)

_CONTENT_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("LV-PRIV-001", _EXPORT_ARCHIVE),
    ("LV-PRIV-003", _SECRET),
    ("LV-PRIV-004", _PERSONAL),
    ("LV-PRIV-005", _LOCAL_PATH_POSIX),
    ("LV-PRIV-005", _LOCAL_PATH_WIN),
)


@dataclass(frozen=True)
class Finding:
    path: str
    rule_id: str
    line: int

    def __str__(self) -> str:
        # Only location + rule; never the matched value.
        return f"{self.path}:{self.line}: {self.rule_id}"


def rules_for_line(line: str) -> list[str]:
    """Single-line rules. LV-PRIV-002 needs surrounding context; see scan_text."""
    hits = []
    for rid, rx in _CONTENT_RULES:
        if rid not in hits and rx.search(line):
            hits.append(rid)
    return hits


def rules_for_name(name: str) -> list[str]:
    """Rules evaluated against a path/member name.

    A name is itself text that can leak (an export archive name, an email, a
    payload filename), so the content rules are applied to it too — except
    LV-PRIV-005, because a tracked path is always repository-relative and can
    never be a local absolute path (a directory literally called ``home/x/``
    would otherwise false-positive).
    """
    normalized = name.replace("\\", "/")
    base = normalized.rsplit("/", 1)[-1]
    hits: list[str] = []
    if _PAYLOAD_NAME.match(base):
        hits.append("LV-PRIV-006")
    for rid in rules_for_line(normalized):
        if rid != "LV-PRIV-005" and rid not in hits:
            hits.append(rid)
    return hits


def scan_text(display_path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        for rid in rules_for_line(line):
            findings.append(Finding(display_path, rid, i))
        # LV-PRIV-002: a digest plus a digest-context label within a small
        # window, so a label on its own line still binds to the hash below it.
        if _HEX64.search(line):
            lo = max(0, i - 1 - _DIGEST_WINDOW)
            hi = min(len(lines), i + _DIGEST_WINDOW)
            if any(_DIGEST_CONTEXT.search(ctx) for ctx in lines[lo:hi]):
                findings.append(Finding(display_path, "LV-PRIV-002", i))
    return findings


def text_views(data: bytes) -> list[str]:
    """Return every plausible text interpretation of ``data``.

    Encoding is never trusted. UTF-8 (lossy) plus Latin-1 covers ASCII embedded
    in otherwise-binary content and Latin-1 text; UTF-16 views are added when NUL
    bytes are present. Views are de-duplicated so pure-ASCII files scan once.
    """
    views: list[str] = []

    def add(view: str) -> None:
        if view and view not in views:
            views.append(view)

    add(data.decode("utf-8", errors="replace"))
    add(data.decode("latin-1", errors="replace"))
    if b"\x00" in data:
        for codec in ("utf-16-le", "utf-16-be"):
            add(data.decode(codec, errors="replace"))
    return views


def scan_bytes(display_path: str, data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    for view in text_views(data):
        findings.extend(scan_text(display_path, view))
    return findings


def scan_archive(
    display_path: str,
    data: bytes,
    *,
    depth: int = 1,
    budget: list[int] | None = None,
) -> list[Finding]:
    """Scan a ZIP archive's members from memory. Recurses into nested archives.

    Never extracts to disk. Any member that cannot be read, or that exceeds a
    bound, becomes an LV-PRIV-007 finding rather than a silent gap.
    """
    if budget is None:
        budget = [_MAX_TOTAL_BYTES]
    findings: list[Finding] = []

    if depth > _MAX_ARCHIVE_DEPTH:
        return [Finding(display_path, "LV-PRIV-007", 0)]

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        # Malformed / unsupported archive: unscannable, not ignorable.
        return [Finding(display_path, "LV-PRIV-007", 0)]

    with zf:
        for info in zf.infolist():
            member_display = f"{display_path}!{info.filename}"
            if info.is_dir():
                continue
            for rid in rules_for_name(info.filename):
                findings.append(Finding(member_display, rid, 0))
            if info.file_size > _MAX_MEMBER_BYTES or budget[0] <= 0:
                findings.append(Finding(member_display, "LV-PRIV-007", 0))
                continue
            try:
                member = zf.read(info)
            except Exception:
                # Encrypted, corrupt, or otherwise unreadable member.
                findings.append(Finding(member_display, "LV-PRIV-007", 0))
                continue
            budget[0] -= len(member)
            if _looks_like_zip(member):
                findings.extend(
                    scan_archive(member_display, member, depth=depth + 1, budget=budget)
                )
                continue
            findings.extend(scan_bytes(member_display, member))
    return findings


def _looks_like_zip(data: bytes) -> bool:
    return data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


def scan_tracked_entry(rel_path: str, abs_path: Path) -> list[Finding]:
    """Scan one tracked path. Name rules always run, even if content cannot be
    read, so a prohibited *name* is caught regardless of the entry's state."""
    findings: list[Finding] = [Finding(rel_path, rid, 0) for rid in rules_for_name(rel_path)]

    if abs_path.is_symlink():
        # Never follow the link. Git stores the target string as the content, so
        # scanning that string catches a link pointing at a private location.
        try:
            target = abs_path.readlink()
        except OSError:
            return findings + [Finding(rel_path, "LV-PRIV-007", 0)]
        findings.extend(scan_text(rel_path, str(target)))
        findings.extend(Finding(rel_path, rid, 0) for rid in rules_for_name(str(target)))
        return findings

    if abs_path.is_dir():
        # Submodule / gitlink: its contents are not part of this repository.
        return findings

    try:
        data = abs_path.read_bytes()
    except OSError:
        return findings + [Finding(rel_path, "LV-PRIV-007", 0)]

    if len(data) > _MAX_MEMBER_BYTES:
        return findings + [Finding(rel_path, "LV-PRIV-007", 0)]

    if abs_path.suffix.lower() == ".zip" or _looks_like_zip(data):
        findings.extend(scan_archive(rel_path, data))
        return findings

    findings.extend(scan_bytes(rel_path, data))
    return findings


class ScanError(RuntimeError):
    """The scan could not be performed at all (fail closed)."""


def _repo_root() -> Path:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ScanError("cannot determine repository root (git unavailable)") from exc
    return Path(out.stdout.strip())


def _tracked_files(root: Path) -> list[str]:
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z"], cwd=root, capture_output=True, check=True
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ScanError("cannot enumerate tracked files (git ls-files failed)") from exc
    return [p for p in out.stdout.decode("utf-8", errors="replace").split("\0") if p]


def scan_repository() -> list[Finding]:
    root = _repo_root()
    findings: list[Finding] = []
    for rel in _tracked_files(root):
        exempt = ALLOWLIST.get(rel, frozenset())
        for finding in scan_tracked_entry(rel, root / rel):
            if finding.rule_id not in exempt:
                findings.append(finding)
    return findings


def main() -> int:
    try:
        findings = scan_repository()
    except ScanError as exc:
        # Fail closed: an unperformable scan is never a pass.
        print(f"PRIVACY SCAN FAILED: {exc}", file=sys.stderr)
        return 2
    unique = sorted(set(findings), key=lambda x: (x.path, x.line, x.rule_id))
    for f in unique:
        print(str(f))
    if unique:
        print(
            f"\nPRIVACY SCAN FAILED: {len(unique)} finding(s). "
            f"See rule IDs above; sensitive values are intentionally not printed.",
            file=sys.stderr,
        )
        return 1
    print("privacy scan: no findings in tracked files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
