#!/usr/bin/env python3
"""Deterministic, offline privacy scanner for tracked files.

Purpose
-------
Fail-closed check that prohibited private / correlatable content cannot be
committed to this public repository. It complements the runtime
``legend_vault.privacy`` guard: the guard keeps private *data* out of the
working tree at ingestion time; this scanner keeps private *values* out of
tracked *text*.

Guarantees
----------
- Operates on **tracked files only** (``git ls-files``).
- Reads locally; never uploads content and never calls a network service.
- Inspects text files, Markdown, and patches; inspects text members of tracked
  ZIP archives **in memory** (no extraction into the repository).
- Reports only ``path:line: RULE-ID`` — never the matched sensitive value.
- Exits non-zero (fail closed) if any finding is present.
- Supports a narrow, documented allowlist for files that legitimately contain
  rule-like patterns (this scanner's own rules, its synthetic test fixtures, and
  the protective ``.gitignore`` patterns).

Rules
-----
- ``LV-PRIV-001`` private-export-identifier — a real-export archive name
  (RawRecord / chatgpt-export ... .zip), by filename or in text.
- ``LV-PRIV-002`` private-export-digest — a full SHA-256 on a line labeled as an
  export / private source (public source-manifest hashes are not labeled and are
  not matched).
- ``LV-PRIV-003`` secret-pattern — private-key blocks and common API-key/token
  shapes.
- ``LV-PRIV-004`` personal-identifier — email addresses and account/user IDs
  bound to a realistic (UUID / long-token) value.
- ``LV-PRIV-005`` local-private-path — local user home paths.
- ``LV-PRIV-006`` raw-export-payload — known raw-export payload filenames, by
  tracked path or ZIP member name.
"""

from __future__ import annotations

import re
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path

# --- Allowlist (narrow, documented) -------------------------------------------
# These files legitimately contain rule-like patterns and must not self-trip.
ALLOWLIST: frozenset[str] = frozenset(
    {
        "scripts/privacy_scan.py",  # this scanner's own rule definitions
        "tests/test_privacy_scan.py",  # synthetic fixtures exercising the rules
        ".gitignore",  # protective ignore patterns for the payloads we scan for
    }
)

# --- Rule patterns ------------------------------------------------------------

# A real-export archive name family (not a format reference).
_EXPORT_ARCHIVE = re.compile(
    r"\b(?:raw[ _-]?record|chatgpt[ _-]?export)\b[^\n]*\.zip", re.IGNORECASE
)

# 64-hex digest, only reported when the same line is labeled export/private.
_HEX64 = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")
_EXPORT_LABEL = re.compile(
    r"(export|raw[ _-]?record|source archive|private[ _-](?:export|archive|source))",
    re.IGNORECASE,
)

# Secrets: private-key blocks and common token shapes.
_SECRET = re.compile(
    r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"
    r"|\bsk-[A-Za-z0-9]{20,}\b"
    r"|\bgh[pousr]_[A-Za-z0-9]{30,}\b"
    r"|\bxox[baprs]-[A-Za-z0-9-]{10,}\b"
    r"|\bAKIA[0-9A-Z]{16}\b"
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

# Local user home paths (case-sensitive so "/Users/" does not match "/users/"
# inside ordinary URLs).
_LOCAL_PATH = re.compile(r"(?:/home/|/Users/)[A-Za-z0-9._-]+/|[A-Za-z]:\\Users\\")

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
    ("LV-PRIV-005", _LOCAL_PATH),
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
    hits = [rid for rid, rx in _CONTENT_RULES if rx.search(line)]
    if _HEX64.search(line) and _EXPORT_LABEL.search(line):
        hits.append("LV-PRIV-002")
    return hits


def rules_for_name(name: str) -> list[str]:
    base = name.rsplit("/", 1)[-1]
    hits: list[str] = []
    if _PAYLOAD_NAME.match(base):
        hits.append("LV-PRIV-006")
    if _EXPORT_ARCHIVE.search(base):
        hits.append("LV-PRIV-001")
    return hits


def scan_text(display_path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for i, line in enumerate(text.splitlines(), 1):
        for rid in rules_for_line(line):
            findings.append(Finding(display_path, rid, i))
    return findings


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data[:4096]


def scan_zip(display_path: str, zip_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            member_display = f"{display_path}!{info.filename}"
            for rid in rules_for_name(info.filename):
                findings.append(Finding(member_display, rid, 0))
            data = zf.read(info)
            if _is_binary(data):
                continue
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                continue
            findings.extend(scan_text(member_display, text))
    return findings


def scan_tracked_file(rel_path: str, abs_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    for rid in rules_for_name(rel_path):
        findings.append(Finding(rel_path, rid, 0))
    if abs_path.suffix.lower() == ".zip" or zipfile.is_zipfile(abs_path):
        findings.extend(scan_zip(rel_path, abs_path))
        return findings
    data = abs_path.read_bytes()
    if _is_binary(data):
        return findings
    findings.extend(scan_text(rel_path, data.decode("utf-8", errors="replace")))
    return findings


def _repo_root() -> Path:
    out = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=True,
    )
    return Path(out.stdout.strip())


def _tracked_files(root: Path) -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        capture_output=True,
        check=True,
    )
    return [p for p in out.stdout.decode("utf-8").split("\0") if p]


def scan_repository() -> list[Finding]:
    root = _repo_root()
    findings: list[Finding] = []
    for rel in _tracked_files(root):
        if rel in ALLOWLIST:
            continue
        abs_path = root / rel
        if not abs_path.is_file():
            continue
        findings.extend(scan_tracked_file(rel, abs_path))
    return findings


def main() -> int:
    findings = scan_repository()
    for f in sorted(set(findings), key=lambda x: (x.path, x.line, x.rule_id)):
        print(str(f))
    if findings:
        print(
            f"\nPRIVACY SCAN FAILED: {len(set(findings))} finding(s). "
            f"See rule IDs above; sensitive values are intentionally not printed.",
            file=sys.stderr,
        )
        return 1
    print("privacy scan: no findings in tracked files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
