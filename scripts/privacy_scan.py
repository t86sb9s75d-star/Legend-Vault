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
- Operates on **tracked content only**, from an explicitly named source: the
  working tree (default) or the **staged index** (``--staged``, used by the
  pre-commit hook, which reads staged blobs from git rather than from disk).
- Reads locally; never uploads content and never calls a network service.
- **Never silently skips content.** Anything that cannot be decoded, parsed,
  read, or bounded becomes an explicit ``LV-PRIV-007`` finding rather than a
  gap. Encoding is not trusted: byte streams are scanned through several text
  views (UTF-8, Latin-1, and UTF-16/UTF-32 when NUL patterns indicate them).
- **Recognised archive formats are inspected or rejected, never treated as
  ordinary bytes.** ZIP/TAR/GZIP/BZIP2/XZ are inspected in memory; formats that
  cannot be inspected without new dependencies (7z, RAR) yield ``LV-PRIV-007``.
- **Output never reproduces a prohibited value, nor anything derived from it.**
  Unsafe components are replaced with a ``<redacted-name:N>`` marker numbered by
  position, so remediation is still possible while nothing published can be
  recomputed from a guess at the secret.
- **No file is exempt from every rule.** Exemptions are line-scoped and
  alteration-sensitive (see ``_LINE_EXEMPTIONS``).
- Deterministic: fixed rule order, sorted output, no environment input.

Deliberate limits (documented, not hidden)
------------------------------------------
- Detection is pattern- and context-based. It cannot recognise an arbitrary
  private value that carries no recognisable shape or nearby label.
- ``LV-PRIV-002`` binds a digest to a label within ``_DIGEST_WINDOW`` lines. A
  digest deliberately separated further, or carrying no label at all, is
  indistinguishable from a public hash and is not flagged.
- Obfuscated forms (e.g. an address written as ``name [at] example.com``) are
  not matched; the false-positive cost is too high.
- ``LV-PRIV-005`` on a *name* is anchored: an archive member called
  ``/home/<user>/x`` is flagged, a relative one called ``home/<user>/x`` is not.
  A relative tree containing ``home/`` is ordinary inside an archive, and a
  tracked path is repository-relative by construction.
- Supported text encodings are exactly: UTF-8, Latin-1, UTF-16 LE/BE, UTF-32
  LE/BE. Other multibyte encodings are not decoded (their ASCII substrings are
  still visible through the Latin-1 view).
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
  inspected (unreadable, undecodable, malformed/encrypted/unsupported archive,
  too large, or nested too deeply). Fail-closed: unscannable is a finding.
"""

from __future__ import annotations

import bz2
import gzip
import hashlib
import io
import lzma
import re
import subprocess
import sys
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

ALL_RULES: tuple[str, ...] = (
    "LV-PRIV-001",
    "LV-PRIV-002",
    "LV-PRIV-003",
    "LV-PRIV-004",
    "LV-PRIV-005",
    "LV-PRIV-006",
    "LV-PRIV-007",
)

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
    r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY(?:[ A-Z]+)?-----"
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

# The same rule anchored to the start of a *name*. A tracked path is always
# repository-relative, but an archive member name is unconstrained text that may
# be absolute. Anchoring is what makes the rule safe to apply there: it fires on
# `/home/<user>/vault/x` while leaving an ordinary relative member such as
# `home/<user>/x` or `docs/home/<user>/notes.md` alone, since a directory tree
# containing `home/` is unremarkable inside an archive.
_SLASH_RUN = re.compile(r"/{2,}")
_WIN_DRIVE = re.compile(r"^[A-Za-z]:$")
_LOCAL_USER = re.compile(r"^[A-Za-z0-9._-]+$")  # same charset as _LOCAL_PATH_POSIX
_LOCAL_USER_INDEX = 2  # ["", "home", "<user>", …] and ["C:", "Users", "<user>", …]


def _path_components(name: str) -> list[str]:
    """The one canonical component list for a `/`-normalized name.

    Runs of slashes collapse, so a single path has a single representation.
    Everything downstream — the absoluteness decision, the identity index, and
    the rendered output — is derived from this one list.
    """
    return _SLASH_RUN.sub("/", name).split("/")


def _identity_component_index(components: list[str]) -> int | None:
    """Index of the user-identifying component, or None if not a local home path.

    This is the single source of truth for both questions — *is* this an
    absolute local path, and *which* component names the user. Deciding those
    from two separate representations is precisely what allowed `//home/<user>/y` to
    be judged absolute from a collapsed string while the renderer split the
    uncollapsed one, redacting `home` and printing the username: the rule went
    quiet because its trigger was destroyed, and the secret survived.
    """
    if len(components) <= _LOCAL_USER_INDEX + 1:
        # A trailing component is required, matching the content rule's trailing
        # `/`: `/home/<user>` alone is not treated as a home path.
        return None
    root, second = components[0], components[1]
    if not _LOCAL_USER.match(components[_LOCAL_USER_INDEX]):
        return None
    if root == "" and second in ("home", "Users"):
        return _LOCAL_USER_INDEX
    if _WIN_DRIVE.match(root) and second.lower() == "users":
        return _LOCAL_USER_INDEX
    return None


def _is_absolute_local_path(normalized: str) -> bool:
    """True when a `/`-normalized name denotes an absolute local home path."""
    return _identity_component_index(_path_components(normalized)) is not None

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

# --- Exemptions ---------------------------------------------------------------
# No file is exempt from every rule. An exemption is keyed by
# (tracked path, rule id, sha256 of the stripped source line) and therefore:
#   * covers one rule on one exact line, not a file;
#   * is alteration-sensitive — edit the line and the exemption stops applying,
#     so neighbouring text can never inherit trust;
#   * carries an explicit written reason.
# Name-derived findings (line 0) can never be exempted.
_LINE_EXEMPTIONS: dict[tuple[str, str, str], str] = {}


def _encode_total(text: str) -> bytes:
    """Encode to bytes without ever raising.

    Names taken from archive headers or the filesystem can carry lone surrogates
    (``os.fsdecode`` / tar header decoding use ``surrogateescape``). Strict UTF-8
    encoding raises on those, which would crash output rendering — the one place
    that must never fail, since a crash could print an unsafe traceback.
    """
    try:
        return text.encode("utf-8", errors="surrogatepass")
    except UnicodeEncodeError:  # pragma: no cover - belt and braces
        return text.encode("utf-8", errors="backslashreplace")


# C0 controls, DEL, and C1 controls. C1 can appear via the Latin-1 text view.
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _printable(text: str) -> str:
    """A form of ``text`` that is safe to write to stdout/stderr.

    Encodable is not the same as printable. Findings are emitted one per line,
    so a name carrying a newline splits one finding across two lines — and the
    second line is attacker-chosen text that reads exactly like a finding. A
    carriage return can overwrite a real finding in a terminal, and an ANSI
    escape can colour it into invisibility. Control characters are therefore
    escaped, not merely encoded.

    Verified before the fix: a ZIP member name containing a newline made the CLI
    print two finding lines from one finding, the second a fabricated rule id.
    """
    decoded = _encode_total(text).decode("utf-8", errors="replace")
    return _CONTROL_CHARS.sub(lambda m: f"\\x{ord(m.group()):02x}", decoded)


def _line_digest(line: str) -> str:
    return hashlib.sha256(_encode_total(line.strip())).hexdigest()


def _register_exemption(path: str, rule_id: str, line: str, reason: str) -> None:
    _LINE_EXEMPTIONS[(path, rule_id, _line_digest(line))] = reason


# `.gitignore` must literally name the export archives it excludes, so those
# exact lines cannot avoid LV-PRIV-001. They are the only exemptions in the
# repository: three individual lines, one rule, each alteration-sensitive.
#
# The fragments below are joined at runtime so this source file does not itself
# contain a contiguous export-archive name — the scanner therefore needs no
# exemption for its own rule definitions.
for _head, _tail in (
    ("*.chatgpt-ex", "port.zip"),
    ("chatgpt-ex", "port*.zip"),
    ("LegendVault_RawRec", "ord*.zip"),
):
    _register_exemption(
        ".gitignore",
        "LV-PRIV-001",
        _head + _tail,
        "protective ignore pattern that must name the export archive it excludes",
    )


def _is_exempt(path: str, rule_id: str, line_text: str) -> bool:
    return (path, rule_id, _line_digest(line_text)) in _LINE_EXEMPTIONS


def exemptions() -> dict[str, set[str]]:
    """Public view of what is exempt, for inspection and tests: path -> rules.

    Every entry is line-scoped; this collapses them to the rules touched so a
    test can assert that no path is exempt from every rule.
    """
    summary: dict[str, set[str]] = {}
    for path, rule_id, _digest in _LINE_EXEMPTIONS:
        summary.setdefault(path, set()).add(rule_id)
    return summary


def exemption_reasons() -> dict[tuple[str, str, str], str]:
    """Every exemption with its written reason (documented narrowness)."""
    return dict(_LINE_EXEMPTIONS)


# --- Safe output rendering ----------------------------------------------------


def _component_is_unsafe(component: str) -> bool:
    if not component:
        return False
    if _PAYLOAD_NAME.match(component):
        # A payload filename is a category, not a private value; keep it legible.
        return False
    return bool(rules_for_line(component)) or bool(
        _HEX64.search(component) and _DIGEST_CONTEXT.search(component)
    )


def safe_location(location: str) -> str:
    """Render a path / archive-member location without reproducing a prohibited
    value. Safe components are preserved; an unsafe component is replaced by a
    positional marker so the entry remains identifiable for remediation.

    The marker is **not** derived from the value it hides. Nothing published
    here may be recomputable from a guess at the secret, which rules out any
    unkeyed digest of the component — swapping SHA-256 for another hash would
    preserve the defect, not fix it.

    Context is evaluated across the **whole location**, not per component. The
    digest rule is contextual, so a label can sit in one component while the
    digest sits in another (``Source SHA-256/<hex>.txt``, or a label on an outer
    archive with the digest on an inner member). Judging components in isolation
    would detect that finding and then print the digest verbatim, so any
    component carrying a digest is redacted whenever the location as a whole
    supplies digest context. A bare hash with no such context anywhere stays
    readable.

    An absolute local home path is the other shape whose meaning lives in the
    component *sequence* rather than in any one component: the username is only
    identifying because ``home`` precedes it. ``_identity_component_index``
    supplies that position, reading the same canonical component list that is
    rendered here — runs of slashes are collapsed, so ``//home/<user>/y`` and
    ``/home/<user>/y`` cannot disagree about which component holds the username.
    Collapsing is mildly lossy for display and deliberately so: an output that
    is already non-verbatim by design gains nothing from preserving a slash run,
    and one representation is worth more than an exact one.
    """
    location_has_digest_context = bool(_DIGEST_CONTEXT.search(location))
    rendered: list[str] = []
    redacted_count = 0
    for chunk in location.split("!"):
        # Both the decision and the rendering read this one component list, so a
        # repeated slash cannot shift the index out from under the redaction.
        components = _path_components(chunk)
        identity = _identity_component_index(components)
        parts = []
        for index, component in enumerate(components):
            if (
                index == identity
                or _component_is_unsafe(component)
                or (location_has_digest_context and _HEX64.search(component))
            ):
                # The ordinal is derived from POSITION, never from the component.
                # This previously published sha256(component)[:12], which is a
                # 48-bit fingerprint *of the private value*: anyone holding a
                # candidate could hash it and confirm the match, and the same
                # value produced the same marker everywhere, linking occurrences
                # across the whole report. That is precisely the correlatable
                # identifier this repository's own policy prohibits (see
                # "Correlatable identifiers" in docs/PRIVATE_DATA_BOUNDARY.md,
                # and rule LV-PRIV-002, which exists to flag exactly this shape).
                # A positional ordinal cannot be recomputed from a guess.
                redacted_count += 1
                parts.append(f"<redacted-name:{redacted_count}>")
            else:
                # Safe components are preserved, but still normalised so an
                # undecodable byte cannot crash the caller that prints them.
                parts.append(_printable(component))
        rendered.append("/".join(parts))
    return "!".join(rendered)


@dataclass(frozen=True)
class Finding:
    path: str
    rule_id: str
    line: int
    # Excluded from equality so identical findings still de-duplicate.
    note: str = field(default="", compare=False)

    @property
    def safe_path(self) -> str:
        return safe_location(self.path)

    def __str__(self) -> str:
        # Location + rule only, with unsafe name components redacted.
        return f"{self.safe_path}:{self.line}: {self.rule_id}"


def rules_for_line(line: str) -> list[str]:
    """Single-line content rules. LV-PRIV-002 needs surrounding context and is
    applied by scan_text (and, for names, via the single-line degenerate case)."""
    hits: list[str] = []
    for rid, rx in _CONTENT_RULES:
        if rid not in hits and rx.search(line):
            hits.append(rid)
    return hits


def rules_for_name(name: str, *, repo_relative: bool = True) -> list[str]:
    """Rules evaluated against a path / archive-member name.

    A name is itself text that can leak, so the same canonical detection used
    for content is applied to it — including the contextual digest rule, which
    degenerates to same-line context for a single-line name.

    ``repo_relative`` states whether the caller can *guarantee* the name is
    relative to the repository root, which only ``git ls-files`` output can. For
    such a path LV-PRIV-005 is meaningless — it can never be a local absolute
    path — while the unanchored rule would false-positive on a directory
    legitimately called ``docs/home/<user>/``. An archive member name carries no
    such guarantee: it is text chosen by whoever built the archive and may be
    absolute, so the anchored ``_is_absolute_local_path`` check applies instead.
    Passing the wrong value is a detection gap in one direction and a false
    positive in the other, so callers state it explicitly.
    """
    normalized = name.replace("\\", "/")
    base = normalized.rsplit("/", 1)[-1]
    hits: list[str] = []
    if _PAYLOAD_NAME.match(base):
        hits.append("LV-PRIV-006")
    if not repo_relative and _is_absolute_local_path(normalized):
        hits.append("LV-PRIV-005")
    for finding in scan_text("", normalized):
        if finding.rule_id != "LV-PRIV-005" and finding.rule_id not in hits:
            hits.append(finding.rule_id)
    return hits


def scan_text(display_path: str, text: str, *, exempt_path: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        rule_ids = list(rules_for_line(line))
        # LV-PRIV-002: a digest plus a digest-context label within a small
        # window, so a label on its own line still binds to the hash below it.
        if _HEX64.search(line):
            lo = max(0, i - 1 - _DIGEST_WINDOW)
            hi = min(len(lines), i + _DIGEST_WINDOW)
            if any(_DIGEST_CONTEXT.search(ctx) for ctx in lines[lo:hi]):
                rule_ids.append("LV-PRIV-002")
        for rid in rule_ids:
            if exempt_path is not None and _is_exempt(exempt_path, rid, line):
                continue
            findings.append(Finding(display_path, rid, i))
    return findings


def text_views(data: bytes) -> list[str]:
    """Every plausible text interpretation of ``data``.

    Encoding is never trusted. UTF-8 (lossy) plus Latin-1 covers ASCII embedded
    in otherwise-binary content and Latin-1 text. UTF-16 views are added when a
    NUL byte is present; UTF-32 views when the NUL run pattern or a BOM
    indicates it. Views are de-duplicated so pure-ASCII files scan once.
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
    # UTF-32 puts three NULs between ASCII characters; a BOM is also decisive.
    if b"\x00\x00\x00" in data or data[:4] in (b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff"):
        for codec in ("utf-32-le", "utf-32-be"):
            try:
                add(data.decode(codec, errors="replace"))
            except (UnicodeDecodeError, LookupError):
                continue
    return views


def scan_bytes(display_path: str, data: bytes, *, exempt_path: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for view in text_views(data):
        findings.extend(scan_text(display_path, view, exempt_path=exempt_path))
    return findings


# --- Archive handling ---------------------------------------------------------

_SIG_ZIP = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_SIG_GZIP = b"\x1f\x8b"
_SIG_BZIP2 = b"BZh"
_SIG_XZ = b"\xfd7zXZ\x00"
_SIG_7Z = b"7z\xbc\xaf\x27\x1c"
_SIG_RAR = (b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")  # RAR4, RAR5


def detect_archive(data: bytes, name: str = "") -> str | None:
    """Return an archive kind for ``data`` (signature first, then extension).

    Kinds: ``zip``, ``tar``, ``gzip``, ``bzip2``, ``xz``, or ``unsupported``
    (a recognised format this scanner will not parse). ``None`` means "not an
    archive", which is the only case that may be treated as ordinary bytes.

    Every magic-byte test uses ``startswith``, never a fixed-width slice
    compared against a constant. A slice states the signature's length in a
    second place, and the two drifted: ``_SIG_RAR`` held 7-byte constants while
    the comparison sliced 8 bytes, so both were unreachable and a RAR without a
    ``.rar`` name was read as ordinary bytes — a silent miss, since its payload
    stays compressed. ``startswith`` takes the length from the constant itself,
    so signatures of any length can be added without a second edit.
    """
    if data.startswith(_SIG_ZIP):
        return "zip"
    if data.startswith(_SIG_GZIP):
        return "gzip"
    if data.startswith(_SIG_BZIP2):
        return "bzip2"
    if data.startswith(_SIG_XZ):
        return "xz"
    if data.startswith(_SIG_7Z):
        return "unsupported"
    if data.startswith(_SIG_RAR):
        return "unsupported"
    if len(data) >= 262 and data[257:262] == b"ustar":
        return "tar"
    lowered = name.lower()
    if lowered.endswith((".7z", ".rar")):
        return "unsupported"
    if lowered.endswith(".zip"):
        return "zip"
    if lowered.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")):
        return "tar"
    # Single-stream compression. Every recognised extension needs a fallback,
    # not just .gz: a damaged or truncated stream loses its magic bytes, and
    # without the fallback it would be treated as ordinary bytes — which reads
    # as "no findings", because the payload is still compressed and therefore
    # invisible to every text view. Fail closed instead.
    if lowered.endswith(".gz"):
        return "gzip"
    if lowered.endswith(".bz2"):
        return "bzip2"
    if lowered.endswith((".xz", ".lzma")):
        return "xz"
    return None


class Budget:
    """Debit-on-consumption accounting for **expanded bytes inspected**.

    The metric is decompressed/extracted output that the scanner reads, charged
    at the moment it is consumed — never after a validation succeeds. Bytes read
    from content that is subsequently rejected, oversized, malformed, or
    unreadable are charged all the same, so a crafted archive cannot obtain free
    reads by repeatedly failing. One instance is shared through every nested
    container. Compressed input bytes are not charged separately; each expansion
    level is charged once, as it is expanded.

    **Exact guarantee.** Total consumption across a whole scan is at most
    ``_MAX_TOTAL_BYTES + 1``. The single extra byte is the sentinel that
    distinguishes "exactly at the limit" from "over the limit" on the final
    read; because it is charged like any other byte, the budget then reads as
    exhausted and every later member gets a zero allowance and is never read.
    The overshoot is therefore constant, not per member — verified against
    archives with 1 to 200 malicious members.
    """

    __slots__ = ("remaining", "consumed")

    def __init__(self, total: int) -> None:
        self.remaining = max(0, total)
        self.consumed = 0

    def charge(self, count: int) -> None:
        count = max(0, count)
        self.consumed += count
        self.remaining = max(0, self.remaining - count)  # never negative

    @property
    def exhausted(self) -> bool:
        return self.remaining <= 0

    def allowance(self, per_member_limit: int) -> int:
        """Bytes this member may consume: the smaller of the per-member limit
        and what is left of the shared total."""
        return max(0, min(per_member_limit, self.remaining))


def _read_charged(stream, budget: Budget, per_member_limit: int) -> tuple[bytes, bool]:
    """The single bounded-read helper every archive path must use.

    Reads at most ``allowance + 1`` bytes (the extra byte detects overflow) and
    charges **everything actually read** to ``budget`` before any decision is
    taken. Returns ``(data, overflowed)``; on overflow the data is discarded but
    the consumption still stands. A failure mid-read charges the full allowance
    pessimistically, so an exception can never restore capacity.
    """
    allowance = budget.allowance(per_member_limit)
    if allowance <= 0:
        return b"", True
    try:
        chunk = stream.read(allowance + 1)
    except Exception:
        budget.charge(allowance)
        return b"", True
    budget.charge(len(chunk))  # charged before the overflow branch
    if len(chunk) > allowance:
        return b"", True
    return chunk, False


def _decompress_charged(raw: bytes, kind: str, budget: Budget) -> bytes | None:
    """Decompress a single-stream container through the charged reader.

    ``None`` signals unscannable. Decompressors carry no declared size, so this
    is the path where an unbounded expansion would otherwise occur; every byte
    produced is charged, including on the overflow path.
    """
    stream = io.BytesIO(raw)
    try:
        # Each stdlib wrapper takes its source differently; only gzip uses
        # `fileobj`.
        if kind == "gzip":
            handle = gzip.GzipFile(fileobj=stream)
        elif kind == "bzip2":
            handle = bz2.BZ2File(stream)
        else:
            handle = lzma.LZMAFile(stream)
    except Exception:
        return None
    try:
        with handle:
            data, overflowed = _read_charged(handle, budget, _MAX_MEMBER_BYTES)
    except Exception:
        return None
    return None if overflowed else data


def scan_archive(
    display_path: str,
    data: bytes,
    *,
    depth: int = 1,
    budget: Budget | None = None,
    kind: str | None = None,
) -> list[Finding]:
    """Scan an archive's contents from memory. Recurses into nested archives.

    Never extracts to disk. Any member that cannot be read, or that would exceed
    a bound, becomes an LV-PRIV-007 finding rather than a silent gap. All nested
    containers share one :class:`Budget`, charged as bytes are consumed.
    """
    if budget is None:
        budget = Budget(_MAX_TOTAL_BYTES)
    if depth > _MAX_ARCHIVE_DEPTH:
        return [Finding(display_path, "LV-PRIV-007", 0, note="max archive depth")]

    kind = kind or detect_archive(data, display_path)
    if kind == "unsupported":
        return [Finding(display_path, "LV-PRIV-007", 0, note="unsupported archive")]
    if kind is None:
        # detect_archive() defines None as "not an archive" — the one case that
        # may be treated as ordinary bytes. Reporting it unscannable would be
        # false: the bytes are readable and scanning them yields strictly more
        # than a finding that says nothing could be inspected. This matches what
        # scan_tracked_entry() already does with unrecognised data.
        return scan_bytes(display_path, data)
    if kind == "zip":
        return _scan_zip(display_path, data, depth, budget)
    if kind == "tar":
        return _scan_tar(display_path, data, depth, budget)
    return _scan_single_stream(display_path, data, kind, depth, budget)


def _scan_member(
    member_display: str, data: bytes, depth: int, budget: Budget
) -> list[Finding]:
    """Scan one extracted member: recurse if it is itself an archive."""
    kind = detect_archive(data, member_display)
    if kind is not None:
        return scan_archive(
            member_display, data, depth=depth + 1, budget=budget, kind=kind
        )
    return scan_bytes(member_display, data)


def _scan_zip(display_path: str, data: bytes, depth: int, budget: Budget) -> list[Finding]:
    findings: list[Finding] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        return [Finding(display_path, "LV-PRIV-007", 0, note="malformed zip")]
    with zf:
        for info in zf.infolist():
            member_display = f"{display_path}!{info.filename}"
            # Name rules run before the directory check: a directory entry has no
            # content to fall back on, so its name is the only thing that can be
            # inspected, and skipping it would make the name a blind spot.
            findings.extend(
                Finding(member_display, rid, 0)
                for rid in rules_for_name(info.filename, repo_relative=False)
            )
            if info.is_dir():
                continue
            if budget.exhausted:
                # Stop expanding once the shared total is spent; the archive is
                # reported unscannable rather than partially trusted.
                findings.append(Finding(display_path, "LV-PRIV-007", 0, note="budget exhausted"))
                break
            # The declared size is only a preflight signal; actual consumption
            # is authoritative and is charged by _read_charged.
            if info.file_size > _MAX_MEMBER_BYTES:
                findings.append(Finding(member_display, "LV-PRIV-007", 0, note="declared oversize"))
                continue
            try:
                handle = zf.open(info)
            except Exception:
                findings.append(Finding(member_display, "LV-PRIV-007", 0, note="unreadable"))
                continue
            with handle:
                member, overflowed = _read_charged(handle, budget, _MAX_MEMBER_BYTES)
            if overflowed:
                findings.append(Finding(member_display, "LV-PRIV-007", 0, note="over budget"))
                continue
            findings.extend(_scan_member(member_display, member, depth, budget))
    return findings


def _scan_tar(display_path: str, data: bytes, depth: int, budget: Budget) -> list[Finding]:
    findings: list[Finding] = []
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:")
    except Exception:
        return [Finding(display_path, "LV-PRIV-007", 0, note="malformed tar")]
    with tf:
        try:
            members = tf.getmembers()
        except Exception:
            return [Finding(display_path, "LV-PRIV-007", 0, note="malformed tar")]
        for info in members:
            member_display = f"{display_path}!{info.name}"
            findings.extend(
                Finding(member_display, rid, 0)
                for rid in rules_for_name(info.name, repo_relative=False)
            )
            # A symlink/hardlink carries its target as header text. That target is
            # data the archive ships, so it is scanned exactly like a filesystem
            # symlink's target (see scan_tracked_entry). Findings are attached to
            # the member's location, never to the target, so rendering cannot
            # print the target itself.
            link_target = getattr(info, "linkname", "") or ""
            if link_target:
                findings.extend(scan_text(member_display, link_target))
                findings.extend(
                    Finding(member_display, rid, 0)
                    for rid in rules_for_name(link_target, repo_relative=False)
                )
            if not info.isfile():
                # Directories and links carry no readable member content.
                continue
            if budget.exhausted:
                findings.append(Finding(display_path, "LV-PRIV-007", 0, note="budget exhausted"))
                break
            if info.size > _MAX_MEMBER_BYTES:
                findings.append(Finding(member_display, "LV-PRIV-007", 0, note="declared oversize"))
                continue
            try:
                fh = tf.extractfile(info)
            except Exception:
                findings.append(Finding(member_display, "LV-PRIV-007", 0, note="unreadable"))
                continue
            if fh is None:
                continue
            with fh:
                member, overflowed = _read_charged(fh, budget, _MAX_MEMBER_BYTES)
            if overflowed:
                findings.append(Finding(member_display, "LV-PRIV-007", 0, note="over budget"))
                continue
            findings.extend(_scan_member(member_display, member, depth, budget))
    return findings


def _scan_single_stream(
    display_path: str, data: bytes, kind: str, depth: int, budget: Budget
) -> list[Finding]:
    inner = _decompress_charged(data, kind, budget)
    if inner is None:
        return [Finding(display_path, "LV-PRIV-007", 0, note=f"undecompressible {kind}")]
    member_display = f"{display_path}!<{kind}-stream>"
    return _scan_member(member_display, inner, depth, budget)


# --- Tracked-entry scanning ---------------------------------------------------


def _read_file_bounded(abs_path: Path, limit: int) -> tuple[bytes, bool | None]:
    """Read at most ``limit + 1`` bytes from a file.

    Returns ``(data, oversized)``. ``oversized is None`` means the file could not
    be read at all. The single extra byte distinguishes "exactly at the limit"
    from "over it" without consuming the remainder — the same sentinel discipline
    ``_read_charged`` uses inside archives.
    """
    try:
        with abs_path.open("rb") as handle:
            data = handle.read(limit + 1)
    except OSError:
        return b"", None
    if len(data) > limit:
        return b"", True
    return data, False


def scan_tracked_entry(rel_path: str, abs_path: Path) -> list[Finding]:
    """Scan one tracked path. Name rules always run, even if content cannot be
    read, so a prohibited *name* is caught regardless of the entry's state."""
    findings: list[Finding] = [Finding(rel_path, rid, 0) for rid in rules_for_name(rel_path)]

    if abs_path.is_symlink():
        # Never follow the link. Git stores the target string as the content, so
        # scanning that string catches a link pointing at a private location.
        try:
            target = str(abs_path.readlink())
        except OSError:
            return findings + [Finding(rel_path, "LV-PRIV-007", 0, note="unreadable link")]
        findings.extend(scan_text(rel_path, target))
        # repo_relative=False: a link target is not a repository path. It is an
        # arbitrary string that may name an absolute location, exactly like a
        # tar linkname. Leaving it True disabled the anchored check, and the
        # content rules alone do not cover every spelling — `c:/users/<user>/x`
        # matched neither the case-sensitive POSIX pattern nor the
        # backslash-only Windows one, and went undetected end to end.
        findings.extend(
            Finding(rel_path, rid, 0)
            for rid in rules_for_name(target, repo_relative=False)
        )
        return findings

    if abs_path.is_dir():
        # Submodule / gitlink: its contents are not part of this repository.
        return findings

    # Bounded read, never read_bytes(). The size limit used to be checked after
    # the whole file was already in memory, so a large tracked file was fully
    # consumed before being called oversized — measured at 40x a shrunken bound.
    # That is the same "validate after consumption" class the archive budget was
    # rebuilt around, surviving at the top level. A stat() first would still
    # race, so the read itself is what must be bounded: at most
    # _MAX_MEMBER_BYTES + 1 bytes, the extra byte only to tell "at the limit"
    # from "over" it.
    data, oversized = _read_file_bounded(abs_path, _MAX_MEMBER_BYTES)
    if oversized is None:
        return findings + [Finding(rel_path, "LV-PRIV-007", 0, note="unreadable")]
    if oversized:
        return findings + [Finding(rel_path, "LV-PRIV-007", 0, note="oversized")]

    kind = detect_archive(data, rel_path)
    if kind is not None:
        findings.extend(scan_archive(rel_path, data, kind=kind))
        return findings

    findings.extend(scan_bytes(rel_path, data, exempt_path=rel_path))
    return findings


class ScanError(RuntimeError):
    """The scan could not be performed at all (fail closed).

    **Its message is printed verbatim to stderr by main(), so it must never be
    built from a caller-supplied value.** Every message here is a fixed string
    naming no path, no argument and no content. This is enforced structurally by
    ``test_scan_error_messages_never_interpolate_a_value``, which parses this
    module and rejects any ``ScanError`` constructed from an f-string.
    """


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
    # surrogateescape, never replace: a filename is bytes on POSIX and need not
    # be valid UTF-8. `replace` substitutes U+FFFD, so the name no longer names
    # the file — `root / rel` misses, and the entry is reported LV-PRIV-007
    # "unreadable" while its CONTENT is never scanned and the stated reason is
    # wrong. surrogateescape round-trips exactly, so the file is opened and
    # scanned; output stays safe because safe_location()/_printable() already
    # encode surrogates via _encode_total().
    decoded = out.stdout.decode("utf-8", errors="surrogateescape")
    return [p for p in decoded.split("\0") if p]


# --- Index (staged) scanning --------------------------------------------------
# Two different states exist and they are not interchangeable:
#
#   INDEX         what git will actually commit
#   WORKING TREE  what happens to be on disk right now
#
# Enumerating one and reading the other is not a guarantee about either. It let a
# file be staged with a prohibited value while the worktree copy was replaced
# with safe text: the scan passed and the commit would have carried the value.
# Each mode now names its own source of truth.

_GITLINK_MODE = "160000"
_SYMLINK_MODE = "120000"


def _index_entries(root: Path) -> list[tuple[str, str, str]]:
    """(mode, blob sha, path) for every entry in the index, from git itself."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "-s", "-z"], cwd=root, capture_output=True, check=True
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ScanError("cannot enumerate the index (git ls-files -s failed)") from exc
    entries: list[tuple[str, str, str]] = []
    for record in out.stdout.decode("utf-8", errors="surrogateescape").split("\0"):
        if not record:
            continue
        # "<mode> <sha> <stage>\t<path>"
        meta, _, path = record.partition("\t")
        fields = meta.split()
        if len(fields) < 3 or not path:
            raise ScanError("cannot parse the index (unexpected git ls-files -s output)")
        entries.append((fields[0], fields[1], path))
    return entries


def _read_blob_bounded(root: Path, sha: str, limit: int) -> tuple[bytes, bool | None]:
    """Read at most ``limit + 1`` bytes of a git blob, bounded like a file read."""
    try:
        proc = subprocess.Popen(
            ["git", "cat-file", "blob", sha],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return b"", None

    failed_read = False
    try:
        with proc.stdout as stream:
            data = stream.read(limit + 1)
    except OSError:
        data, failed_read = b"", True

    oversized = len(data) > limit
    # Signal only a process whose output is being abandoned; a fully drained
    # stream leaves nothing to kill, and git has already exited on its own.
    if oversized or failed_read:
        proc.kill()
    status = proc.wait()

    if failed_read:
        return b"", None
    if oversized:
        # A definite classification: the blob exceeded the bound. git's exit
        # status is not consulted because the pipe was deliberately abandoned.
        return b"", True
    if status != 0:
        # git could not produce the blob — a missing or corrupt object. The
        # earlier version ignored the exit status, so this returned empty
        # content that then scanned as *clean*: an unreadable object silently
        # became a passing entry, inverting the scanner's central invariant
        # that unscannable is a finding.
        return b"", None
    return data, False


def scan_index_entry(rel_path: str, mode: str, sha: str, root: Path) -> list[Finding]:
    """Scan one *staged* entry, taking both identity and content from git.

    Nothing here touches the working tree, so a divergent on-disk copy cannot
    make a staged value invisible.
    """
    findings: list[Finding] = [Finding(rel_path, rid, 0) for rid in rules_for_name(rel_path)]

    if mode == _GITLINK_MODE:
        # A submodule commit pointer; its contents are not part of this
        # repository, exactly as in worktree mode.
        return findings

    data, oversized = _read_blob_bounded(root, sha, _MAX_MEMBER_BYTES)
    if oversized is None:
        return findings + [Finding(rel_path, "LV-PRIV-007", 0, note="unreadable blob")]
    if oversized:
        return findings + [Finding(rel_path, "LV-PRIV-007", 0, note="oversized")]

    if mode == _SYMLINK_MODE:
        # For a symlink git stores the target string as the blob content, so the
        # staged target is scanned with the same rules the worktree path uses.
        target = data.decode("utf-8", errors="surrogateescape")
        findings.extend(scan_text(rel_path, target))
        findings.extend(
            Finding(rel_path, rid, 0)
            for rid in rules_for_name(target, repo_relative=False)
        )
        return findings

    kind = detect_archive(data, rel_path)
    if kind is not None:
        findings.extend(scan_archive(rel_path, data, kind=kind))
        return findings

    findings.extend(scan_bytes(rel_path, data, exempt_path=rel_path))
    return findings


def scan_repository(*, source: str = "worktree") -> list[Finding]:
    """Scan the repository from an explicitly named source of truth.

    ``source="worktree"`` enumerates tracked paths and reads them from disk.
    ``source="index"`` reads staged identity *and* staged content from git, so
    it judges what a commit would actually contain.
    """
    root = _repo_root()
    findings: list[Finding] = []
    if source == "index":
        for mode, sha, rel in _index_entries(root):
            findings.extend(scan_index_entry(rel, mode, sha, root))
        return findings
    if source != "worktree":
        # Same rule as the CLI branch: main() prints ScanError text verbatim to
        # stderr, so no ScanError may be built from a caller-supplied value.
        raise ScanError("unknown scan source (expected 'worktree' or 'index')")
    for rel in _tracked_files(root):
        findings.extend(scan_tracked_entry(rel, root / rel))
    return findings


def _emit(line: str, *, stream=None) -> None:
    """Write a finding line, degrading gracefully if the stream's encoding
    cannot represent a character. Reporting must never raise."""
    target = stream or sys.stdout
    try:
        print(line, file=target)
    except UnicodeEncodeError:  # pragma: no cover - locale-dependent
        encoding = getattr(target, "encoding", None) or "ascii"
        print(line.encode(encoding, errors="backslashreplace").decode(encoding), file=target)


def main(argv: list[str] | None = None) -> int:
    # Arguments are parsed explicitly and an unknown one fails closed. Before
    # this, argv was ignored entirely, so `--staged` silently ran an ordinary
    # worktree scan and exited 0 — a flag that looks honoured while doing
    # something else is worse than no flag.
    args = list(sys.argv[1:] if argv is None else argv)
    source = "worktree"
    for arg in args:
        if arg == "--staged":
            source = "index"
        elif arg == "--worktree":
            source = "worktree"
        else:
            # The argument is NOT echoed. Everything this program writes is
            # subject to the same rule, and an argument is caller-supplied text
            # that may itself be a prohibited value — someone passing a private
            # path by mistake must not have it reproduced in a terminal or CI
            # log by the very tool that exists to prevent that.
            print(
                "PRIVACY SCAN FAILED: unrecognised argument "
                "(expected --staged or --worktree)",
                file=sys.stderr,
            )
            return 2
    try:
        findings = scan_repository(source=source)
    except ScanError as exc:
        # Fail closed: an unperformable scan is never a pass. The message names
        # no path, so it cannot leak an unsafe name.
        print(f"PRIVACY SCAN FAILED: {exc}", file=sys.stderr)
        return 2
    unique = sorted(set(findings), key=lambda x: (x.path, x.line, x.rule_id))
    for f in unique:
        _emit(str(f))
    if unique:
        print(
            f"\nPRIVACY SCAN FAILED: {len(unique)} finding(s). "
            f"See rule IDs above; sensitive values are intentionally not printed.",
            file=sys.stderr,
        )
        return 1
    scanned = "staged index" if source == "index" else "tracked files"
    print(f"privacy scan: no findings in {scanned}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
