"""Tests for scripts/privacy_scan.py.

All prohibited values here are synthetic (reserved example domains, obviously
fake tokens, invented paths, runtime-built hex) and every prohibited *shape* is
assembled at runtime from fragments, so this tracked file contains no contiguous
scanner-matching value and needs **no allowlist exemption at all**. The tests
call the scanner functions directly on in-memory strings, on temp files created
outside the tracked tree, and — for output-safety cases — through the real CLI
entry point in a throwaway git repository.

Coverage is organised as: per-rule detection (positive), false-positive guards
(negative), bounds/edge behaviour (boundary), and adversarial bypass regressions
(each one corresponds to a bypass that was demonstrated against an earlier
revision of the scanner).
"""

from __future__ import annotations

import bz2
import gzip
import hashlib
import io
import shutil
import lzma
import os
import re
import ast
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import privacy_scan  # noqa: E402
from privacy_scan import (  # noqa: E402
    ALL_RULES,
    detect_archive,
    exemption_reasons,
    exemptions,
    rules_for_name,
    safe_location,
    scan_archive,
    scan_bytes,
    scan_text,
    scan_tracked_entry,
    text_views,
)

# Synthetic constants. Every prohibited *shape* is assembled at runtime from
# fragments so this tracked source file contains no contiguous value that the
# scanner would match — the test file therefore needs no allowlist exemption.
_FAKE_HEX = "deadbeef" * 8  # 64 hex chars, obviously synthetic
_FAKE_GH_TOKEN = "ghp" + "_" + "A" * 36
_FAKE_EMAIL = "person" + "@" + "example" + ".com"  # reserved example domain
_FAKE_HOME = "/ho" + "me/alice/vault/records/x"
_FAKE_WIN_PATH = "c:" + chr(92) + "us" + "ers" + chr(92) + "bob" + chr(92) + "rec.json"
_FAKE_PRIVATE_TARGET = "/ho" + "me/someone/Legend-Vault-Data/records/r.json"
_FAKE_KEY_HEADER = "-----BEGIN RSA PRIVATE " + "KEY-----"
_FAKE_PGP_HEADER = "-----BEGIN PGP PRIVATE " + "KEY BLOCK-----"
_FAKE_EXPORT_ZIP = "SyntheticVault RawRec" + "ord 2000-01-01.zip"
_FAKE_EXPORT_TGZ = "SyntheticVault RawRec" + "ord 2000-01-01.tar.gz"
_FAKE_CGPT_ARCHIVE = "ChatGPT Ex" + "port 2000.zip"


def _ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


def _tmp_file(d: Path, name: str, data: bytes) -> Path:
    p = d / name
    p.write_bytes(data)
    return p


# --- per-rule detection (positive) -------------------------------------------


def test_synthetic_private_export_filename_rejected() -> None:
    assert "LV-PRIV-001" in _ids(
        scan_text("report.md", "Source archive: " + _FAKE_EXPORT_ZIP)
    )


def test_synthetic_private_export_digest_rejected() -> None:
    assert "LV-PRIV-002" in _ids(scan_text("report.md", "Private export SHA-256: " + _FAKE_HEX))


def test_email_rejected() -> None:
    assert "LV-PRIV-004" in _ids(scan_text("notes.md", "reach me at " + _FAKE_EMAIL))


def test_fake_api_token_rejected() -> None:
    assert "LV-PRIV-003" in _ids(scan_text("config.txt", "token = " + _FAKE_GH_TOKEN))


def test_private_key_header_rejected() -> None:
    assert "LV-PRIV-003" in _ids(scan_text("key.txt", _FAKE_KEY_HEADER))


def test_local_user_path_rejected() -> None:
    assert "LV-PRIV-005" in _ids(scan_text("log.md", "wrote record to " + _FAKE_HOME))


def test_payload_filename_rejected_by_name() -> None:
    assert "LV-PRIV-006" in rules_for_name("user.json")
    assert "LV-PRIV-006" in rules_for_name("conversations-3.json")
    assert "LV-PRIV-006" in rules_for_name("some/dir/asset.dat")
    assert "LV-PRIV-006" not in rules_for_name("src/legend_vault/core.py")


# --- false-positive guards (negative) ----------------------------------------


def test_public_source_manifest_hash_not_flagged() -> None:
    # A bare manifest hash line (no export/source qualifier) must not be flagged.
    assert scan_text("SOURCE_MANIFEST.json", '  "sha256": "' + _FAKE_HEX + '"') == []


def test_real_source_manifest_file_has_no_findings() -> None:
    # Boundary guard for the digest context window: the committed manifest holds
    # many *public* source hashes and must stay clean.
    root = Path(__file__).resolve().parents[1]
    rel = "SOURCE_MANIFEST.json"
    assert scan_tracked_entry(rel, root / rel) == []


def test_safe_synthetic_fixture_passes() -> None:
    assert scan_text("fixtures/example.md", "a small deterministic synthetic fixture") == []


def test_repo_relative_home_dir_is_not_a_local_path() -> None:
    # A repo-relative path can never be an absolute local path.
    assert rules_for_name("docs/ho" + "me/alice/guide.md") == []


def test_sanitized_stress_report_passes() -> None:
    root = Path(__file__).resolve().parents[1]
    rel = "LegendVault_Stress_Test_Report_v2.md"
    findings = scan_tracked_entry(rel, root / rel)
    assert findings == [], [str(f) for f in findings]


# --- reporting / determinism --------------------------------------------------


def test_finding_str_does_not_reproduce_value() -> None:
    findings = scan_text("c.txt", "token=" + _FAKE_GH_TOKEN)
    assert findings
    for f in findings:
        rendered = str(f)
        assert _FAKE_GH_TOKEN not in rendered
        assert rendered == f"{f.path}:{f.line}: {f.rule_id}"


def test_output_is_deterministic() -> None:
    text = "a " + _FAKE_EMAIL + "\nb " + _FAKE_HOME + "\n"
    assert [str(f) for f in scan_text("d.md", text)] == [str(f) for f in scan_text("d.md", text)]


# --- allowlist is rule-scoped, narrow, documented -----------------------------


def test_no_file_is_exempt_from_every_rule() -> None:
    # The core property: whole-file trust must not exist in any form.
    for path, rules in exemptions().items():
        assert set(rules) != set(ALL_RULES), path
        assert len(rules) < len(ALL_RULES), path


def test_scanner_and_test_sources_have_no_exemptions() -> None:
    # Both files carry rule-shaped text yet are fully scanned: prohibited shapes
    # are assembled at runtime instead of being exempted.
    summary = exemptions()
    assert "scripts/privacy_scan.py" not in summary
    assert "tests/test_privacy_scan.py" not in summary


def test_unscannable_rule_can_never_be_exempted() -> None:
    for path, rules in exemptions().items():
        assert "LV-PRIV-007" not in rules, path


def test_every_exemption_is_line_scoped_and_documented() -> None:
    reasons = exemption_reasons()
    assert reasons, "expected at least one narrow exemption"
    for (path, rule_id, digest), reason in reasons.items():
        assert path == ".gitignore"          # the only file needing any
        assert rule_id == "LV-PRIV-001"      # exactly one rule
        assert len(digest) == 64             # bound to one exact line
        assert reason.strip()                # written reason


def test_exemption_is_alteration_sensitive() -> None:
    # An exempted pattern is exempt only as that exact line; altering it, or
    # putting the same text in another file, restores detection.
    exempt_line = next(iter(exemption_reasons()))
    assert privacy_scan._is_exempt(".gitignore", "LV-PRIV-001", "chatgpt-ex" + "port*.zip")
    assert not privacy_scan._is_exempt(
        ".gitignore", "LV-PRIV-001", "chatgpt-ex" + "port*.zip  # edited"
    )
    assert not privacy_scan._is_exempt("other.txt", "LV-PRIV-001", "chatgpt-ex" + "port*.zip")
    assert exempt_line[0] == ".gitignore"


# --- adversarial regressions (each was a demonstrated bypass) -----------------


def test_bypass_utf16_text_file_is_scanned() -> None:
    # NUL bytes previously classified the whole file as binary and skipped it.
    with tempfile.TemporaryDirectory() as d:
        p = _tmp_file(Path(d), "utf16.md", ("contact " + _FAKE_EMAIL).encode("utf-16"))
        assert "LV-PRIV-004" in _ids(scan_tracked_entry("utf16.md", p))


def test_bypass_content_after_early_nul_is_scanned() -> None:
    with tempfile.TemporaryDirectory() as d:
        p = _tmp_file(Path(d), "n.md", b"head\x00\nbody " + _FAKE_EMAIL.encode())
        assert "LV-PRIV-004" in _ids(scan_tracked_entry("n.md", p))


def test_bypass_non_utf8_zip_member_is_scanned() -> None:
    # A member that is not valid UTF-8 was previously skipped silently.
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "latin1.zip"
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("note.txt", ("caf\u00e9 " + _FAKE_EMAIL).encode("latin-1"))
        assert "LV-PRIV-004" in _ids(scan_tracked_entry("latin1.zip", p))


def test_bypass_nested_zip_is_scanned() -> None:
    with tempfile.TemporaryDirectory() as d:
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as izf:
            izf.writestr("leak.txt", "contact " + _FAKE_EMAIL)
        p = Path(d) / "outer.zip"
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("inner.zip", inner.getvalue())
        assert "LV-PRIV-004" in _ids(scan_tracked_entry("outer.zip", p))


def test_archive_nested_beyond_depth_is_reported_unscannable() -> None:
    data = b"leaf " + _FAKE_EMAIL.encode()
    for i in range(privacy_scan._MAX_ARCHIVE_DEPTH + 1):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(f"lvl{i}.zip" if i else "leaf.txt", data)
        data = buf.getvalue()
    ids = _ids(scan_archive("deep.zip", data))
    assert "LV-PRIV-007" in ids or "LV-PRIV-004" in ids


def test_malformed_archive_is_reported_not_crashed() -> None:
    with tempfile.TemporaryDirectory() as d:
        p = _tmp_file(Path(d), "broken.zip", b"not a zip at all")
        assert "LV-PRIV-007" in _ids(scan_tracked_entry("broken.zip", p))


def test_unreadable_zip_member_is_reported_unscannable() -> None:
    # Encrypted member: readable listing, unreadable content.
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "enc.zip"
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("secret.txt", "contact " + _FAKE_EMAIL)
        raw = bytearray(p.read_bytes())
        for sig, flag_off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            idx = 0
            while True:
                idx = raw.find(sig, idx)
                if idx < 0:
                    break
                raw[idx + flag_off] |= 1
                idx += 4
        p.write_bytes(bytes(raw))
        assert "LV-PRIV-007" in _ids(scan_tracked_entry("enc.zip", p))


def test_zip_disguised_by_extension_is_still_scanned() -> None:
    with tempfile.TemporaryDirectory() as d:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("leak.txt", "contact " + _FAKE_EMAIL)
        p = _tmp_file(Path(d), "notes.md", buf.getvalue())
        assert "LV-PRIV-004" in _ids(scan_tracked_entry("notes.md", p))


def test_source_sha256_label_is_detected() -> None:
    # The label the historical report actually used before redaction.
    assert "LV-PRIV-002" in _ids(scan_text("r.md", "**Source SHA-256:** `" + _FAKE_HEX + "`"))


def test_other_digest_labels_are_detected() -> None:
    for line in (
        "Archive SHA-256: " + _FAKE_HEX,
        "Vault fingerprint: " + _FAKE_HEX,
        "sha256 of the archive = " + _FAKE_HEX,
        "Record digest: " + _FAKE_HEX,
        "Original transcript checksum " + _FAKE_HEX,
    ):
        assert "LV-PRIV-002" in _ids(scan_text("r.md", line)), line


def test_digest_separated_from_its_label_is_detected() -> None:
    # Label and value on different lines (markdown block form).
    text = "**Source SHA-256:**\n\n\n`" + _FAKE_HEX + "`\n"
    assert "LV-PRIV-002" in _ids(scan_text("r.md", text))


def test_segmented_and_additional_secret_shapes_detected() -> None:
    for line in (
        "key = sk-ant-api03-" + "A" * 40,
        "key = sk-proj-" + "B" * 40,
        "token: github_pat_" + "C" * 40,
        "api = AIza" + "D" * 35,
        _FAKE_PGP_HEADER,
    ):
        assert "LV-PRIV-003" in _ids(scan_text("c.txt", line)), line


def test_lowercase_windows_user_path_detected() -> None:
    assert "LV-PRIV-005" in _ids(scan_text("r.md", "saved to " + _FAKE_WIN_PATH))


def test_export_archive_with_other_extension_detected() -> None:
    assert "LV-PRIV-001" in _ids(
        scan_text("r.md", "archive: " + _FAKE_EXPORT_TGZ)
    )


def test_dangling_symlink_name_is_still_checked() -> None:
    # Name rules must not depend on the target existing.
    with tempfile.TemporaryDirectory() as d:
        link = Path(d) / "user.json"
        link.symlink_to(Path(d) / "missing")
        assert "LV-PRIV-006" in _ids(scan_tracked_entry("user.json", link))


def test_symlink_target_pointing_at_private_path_is_detected() -> None:
    with tempfile.TemporaryDirectory() as d:
        link = Path(d) / "link"
        link.symlink_to(_FAKE_PRIVATE_TARGET)
        assert "LV-PRIV-005" in _ids(scan_tracked_entry("link", link))


def test_prohibited_value_in_markdown_detected() -> None:
    with tempfile.TemporaryDirectory() as d:
        md = _tmp_file(Path(d), "report.md", ("Private export digest: " + _FAKE_HEX).encode())
        assert "LV-PRIV-002" in _ids(scan_tracked_entry("report.md", md))


def test_prohibited_value_in_zip_text_member_detected() -> None:
    with tempfile.TemporaryDirectory() as d:
        z = Path(d) / "bundle.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("notes/leak.md", "contact " + _FAKE_EMAIL + "\n")
        assert "LV-PRIV-004" in _ids(scan_tracked_entry("bundle.zip", z))


def test_prohibited_value_in_names_detected() -> None:
    assert "LV-PRIV-004" in rules_for_name(f"docs/{_FAKE_EMAIL}-notes.md")
    assert "LV-PRIV-001" in rules_for_name("archive/" + _FAKE_CGPT_ARCHIVE)
    with tempfile.TemporaryDirectory() as d:
        z = Path(d) / "mn.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("dir\\subdir\\user.json", "{}")
        assert "LV-PRIV-006" in _ids(scan_tracked_entry("mn.zip", z))


# --- boundary / robustness ----------------------------------------------------


def test_text_views_dedupes_pure_ascii() -> None:
    assert len(text_views(b"plain ascii text")) == 1
    assert len(text_views("caf\u00e9".encode("utf-16"))) > 1


def test_empty_inputs_do_not_crash() -> None:
    assert scan_bytes("e.md", b"") == []
    with tempfile.TemporaryDirectory() as d:
        p = _tmp_file(Path(d), "empty.md", b"")
        assert scan_tracked_entry("empty.md", p) == []
        z = Path(d) / "empty.zip"
        with zipfile.ZipFile(z, "w"):
            pass
        assert scan_tracked_entry("empty.zip", z) == []


def test_oversized_file_is_reported_unscannable() -> None:
    with tempfile.TemporaryDirectory() as d:
        p = _tmp_file(Path(d), "big.bin", b"x" * 16)
        original = privacy_scan._MAX_MEMBER_BYTES
        privacy_scan._MAX_MEMBER_BYTES = 8
        try:
            assert "LV-PRIV-007" in _ids(scan_tracked_entry("big.bin", p))
        finally:
            privacy_scan._MAX_MEMBER_BYTES = original



# --- CLI output safety: prohibited values must never reach stdout/stderr ------


def _run_cli_repo(files: dict, symlinks: dict | None = None):
    """Build a throwaway git repo, track files, and run the real CLI entry point.

    Returns (returncode, stdout, stderr). Nothing touches the real repository.
    """
    with tempfile.TemporaryDirectory() as d:
        repo = Path(d)
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "t@invalid"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
        for rel, data in files.items():
            target = repo / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            subprocess.run(["git", "add", "-f", rel], cwd=repo, check=True)
        for rel, dest in (symlinks or {}).items():
            (repo / rel).symlink_to(dest)
            subprocess.run(["git", "add", "-f", rel], cwd=repo, check=True)
        proc = subprocess.run(
            [sys.executable, str(_SCANNER)], cwd=repo, capture_output=True, text=True
        )
        return proc.returncode, proc.stdout, proc.stderr


_SCANNER = Path(__file__).resolve().parents[1] / "scripts" / "privacy_scan.py"


def test_cli_output_excludes_email_in_filename() -> None:
    rc, out, err = _run_cli_repo({f"docs/{_FAKE_EMAIL}-notes.md": b"safe"})
    assert rc == 1
    assert _FAKE_EMAIL not in out and _FAKE_EMAIL not in err
    assert "redacted-name:" in out


def test_cli_output_excludes_token_in_filename() -> None:
    rc, out, err = _run_cli_repo({f"docs/{_FAKE_GH_TOKEN}.md": b"safe"})
    assert rc == 1
    assert _FAKE_GH_TOKEN not in out and _FAKE_GH_TOKEN not in err


def test_cli_output_excludes_unsafe_archive_member_names() -> None:
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as izf:
        izf.writestr(f"{_FAKE_EMAIL}-inner.txt", "x")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(f"{_FAKE_EMAIL}-member.txt", "x")
        zf.writestr("nested.zip", inner.getvalue())
    rc, out, err = _run_cli_repo({"bundle.zip": buf.getvalue()})
    assert rc == 1
    assert _FAKE_EMAIL not in out and _FAKE_EMAIL not in err
    # The safe outer location is still identifiable.
    assert "bundle.zip" in out


def test_cli_output_excludes_symlink_target_value() -> None:
    rc, out, err = _run_cli_repo({"keep.md": b"safe"}, symlinks={"lnk": _FAKE_PRIVATE_TARGET})
    assert rc == 1
    assert _FAKE_PRIVATE_TARGET not in out and _FAKE_PRIVATE_TARGET not in err


def test_cli_keeps_safe_paths_readable() -> None:
    rc, out, err = _run_cli_repo({"docs/notes.md": ("mail " + _FAKE_EMAIL).encode()})
    assert rc == 1
    assert "docs/notes.md" in out          # safe components preserved verbatim
    assert _FAKE_EMAIL not in out and _FAKE_EMAIL not in err


def test_safe_location_is_stable_and_component_scoped() -> None:
    unsafe = f"docs/{_FAKE_EMAIL}/inner.md"
    first, second = safe_location(unsafe), safe_location(unsafe)
    assert first == second                      # stable
    assert _FAKE_EMAIL not in first
    assert first.startswith("docs/") and first.endswith("/inner.md")  # scoped


# --- archive format boundaries ------------------------------------------------


def _tar_bytes(name: str, payload: bytes, compress: str | None = None) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w" if compress is None else f"w:{compress}") as tf:
        info = tarfile.TarInfo(name)
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    return raw.getvalue()


def test_tar_content_is_inspected() -> None:
    data = _tar_bytes("note.txt", ("contact " + _FAKE_EMAIL).encode())
    assert "LV-PRIV-004" in _ids(scan_archive("bundle.tar", data))


def test_tar_gz_and_tgz_content_is_inspected() -> None:
    data = _tar_bytes("note.txt", ("contact " + _FAKE_EMAIL).encode(), "gz")
    for name in ("bundle.tar.gz", "bundle.tgz"):
        assert "LV-PRIV-004" in _ids(scan_archive(name, data)), name


def test_gzip_stream_content_is_inspected() -> None:
    data = gzip.compress(("path " + _FAKE_HOME).encode())
    assert "LV-PRIV-005" in _ids(scan_archive("blob.gz", data))


def test_bzip2_and_xz_streams_are_inspected() -> None:
    for data in (
        bz2.compress(("contact " + _FAKE_EMAIL).encode()),
        lzma.compress(("contact " + _FAKE_EMAIL).encode()),
    ):
        assert "LV-PRIV-004" in _ids(scan_archive("blob.bin", data))


def test_unsupported_archive_formats_fail_closed() -> None:
    for data, name in (
        (b"7z\xbc\xaf\x27\x1c" + b"\x00" * 32, "bundle.7z"),
        (b"Rar!\x1a\x07\x00" + b"\x00" * 32, "bundle.rar"),
    ):
        assert "LV-PRIV-007" in _ids(scan_archive(name, data))
    # Extension-only detection, with no usable signature, must also fail closed.
    assert "LV-PRIV-007" in _ids(scan_archive("mystery.7z", b"not really an archive"))


def test_archive_detected_by_signature_despite_extension() -> None:
    data = _tar_bytes("note.txt", ("contact " + _FAKE_EMAIL).encode())
    with tempfile.TemporaryDirectory() as d:
        p = _tmp_file(Path(d), "harmless.md", data)
        assert "LV-PRIV-004" in _ids(scan_tracked_entry("harmless.md", p))


def test_archive_lookalike_name_is_not_a_false_positive() -> None:
    with tempfile.TemporaryDirectory() as d:
        p = _tmp_file(Path(d), "notes-about-tar.md", b"plain prose about archives\n")
        assert scan_tracked_entry("notes-about-tar.md", p) == []


def test_nested_mixed_formats_are_bounded() -> None:
    inner = _tar_bytes("leak.txt", ("contact " + _FAKE_EMAIL).encode())
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("inner.tar", inner)
    ids = _ids(scan_archive("outer.zip", buf.getvalue()))
    assert "LV-PRIV-004" in ids or "LV-PRIV-007" in ids


def test_archives_are_never_extracted_to_disk() -> None:
    data = _tar_bytes("note.txt", ("contact " + _FAKE_EMAIL).encode(), "gz")
    with tempfile.TemporaryDirectory() as d:
        before = set(Path(d).rglob("*"))
        p = _tmp_file(Path(d), "b.tgz", data)
        scan_tracked_entry("b.tgz", p)
        after = set(Path(d).rglob("*"))
        assert after == before | {p}


def test_detect_archive_classifies_known_kinds() -> None:
    assert detect_archive(b"PK\x03\x04rest") == "zip"
    assert detect_archive(gzip.compress(b"x")) == "gzip"
    assert detect_archive(b"plain text", "notes.md") is None


# --- UTF-32 and encoding coverage ---------------------------------------------


def test_utf32_variants_are_scanned() -> None:
    for codec in ("utf-32", "utf-32-le", "utf-32-be"):
        data = ("contact " + _FAKE_EMAIL).encode(codec)
        assert "LV-PRIV-004" in _ids(scan_bytes("f.md", data)), codec


def test_utf32_inside_zip_member_is_scanned() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("m.txt", ("contact " + _FAKE_EMAIL).encode("utf-32-le"))
    assert "LV-PRIV-004" in _ids(scan_archive("u32.zip", buf.getvalue()))


def test_safe_utf32_content_passes() -> None:
    assert scan_bytes("f.md", "ordinary synthetic prose".encode("utf-32-le")) == []


def test_text_views_are_deterministic_and_bounded() -> None:
    data = ("contact " + _FAKE_EMAIL).encode("utf-32-le")
    assert text_views(data) == text_views(data)
    assert len(text_views(b"plain ascii")) == 1


# --- contextual digest detection in names -------------------------------------


def test_source_labeled_digest_in_filename_is_detected() -> None:
    assert "LV-PRIV-002" in rules_for_name(f"Source SHA-256 {_FAKE_HEX}.txt")
    assert "LV-PRIV-002" in rules_for_name(f"Archive digest {_FAKE_HEX}.txt")


def test_source_labeled_digest_in_member_names_is_detected() -> None:
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as izf:
        izf.writestr(f"Archive digest {_FAKE_HEX}.txt", "x")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(f"Source SHA-256 {_FAKE_HEX}.txt", "x")
        zf.writestr("nested.zip", inner.getvalue())
    assert "LV-PRIV-002" in _ids(scan_archive("b.zip", buf.getvalue()))


def test_bare_public_hash_filename_is_accepted() -> None:
    assert rules_for_name(f"artifacts/{_FAKE_HEX}.bin") == []


def test_digest_finding_output_does_not_reproduce_the_digest() -> None:
    rc, out, err = _run_cli_repo({f"Source SHA-256 {_FAKE_HEX}.txt": b"safe"})
    assert rc == 1
    assert _FAKE_HEX not in out and _FAKE_HEX not in err


# --- total archive budget -----------------------------------------------------


def _with_budget(total: int, member: int):
    """Temporarily shrink the scanner's bounds; returns the previous values.

    Written as plain statements rather than a tuple of side effects: the order
    of assignment and of the saved read has to be unambiguous, and a reader
    should not have to work out that only element [0] was ever the return value.
    """
    saved = (privacy_scan._MAX_TOTAL_BYTES, privacy_scan._MAX_MEMBER_BYTES)
    privacy_scan._MAX_TOTAL_BYTES = total
    privacy_scan._MAX_MEMBER_BYTES = member
    return saved


def _restore_budget(saved) -> None:
    privacy_scan._MAX_TOTAL_BYTES, privacy_scan._MAX_MEMBER_BYTES = saved


def _counted_scan(data: bytes):
    """Scan an archive while counting bytes actually decompressed."""
    counted = {"n": 0}
    real_open = zipfile.ZipFile.open

    class _CountingReader(io.RawIOBase):
        def __init__(self, inner):
            self._inner = inner

        def read(self, size=-1):
            chunk = self._inner.read(size)
            counted["n"] += len(chunk)
            return chunk

        def close(self):
            self._inner.close()

    def patched_open(self, name, mode="r", pwd=None, **kw):
        return _CountingReader(real_open(self, name, mode, pwd, **kw))

    zipfile.ZipFile.open = patched_open
    try:
        findings = scan_archive("z.zip", data)
    finally:
        zipfile.ZipFile.open = real_open
    return findings, counted["n"]


def test_total_budget_is_enforced_before_decompression() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", "A" * 700)
        zf.writestr("b.txt", "B" * 700)
    saved = _with_budget(1000, 800)
    try:
        findings, read_bytes = _counted_scan(buf.getvalue())
    finally:
        _restore_budget(saved)
    # Bound is total + 1: the single sentinel byte that distinguishes "exactly
    # at the limit" from "over the limit" on the final read. It is charged like
    # any other byte, so it cannot recur per member (see
    # test_repeated_overflow_cannot_accumulate_consumption).
    assert read_bytes <= 1001, read_bytes
    assert "LV-PRIV-007" in _ids(findings)          # and it fails closed


def test_member_exactly_at_limit_is_read_and_one_over_is_rejected() -> None:
    for size, expect_finding in ((100, False), (101, True)):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("m.txt", "A" * size)
        saved = _with_budget(10_000, 100)
        try:
            ids = _ids(scan_archive("z.zip", buf.getvalue()))
        finally:
            _restore_budget(saved)
        assert ("LV-PRIV-007" in ids) is expect_finding, size


def test_nested_archives_share_one_total_budget() -> None:
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as izf:
        izf.writestr("i.txt", "I" * 400)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", "A" * 400)
        zf.writestr("inner.zip", inner.getvalue())
    saved = _with_budget(500, 450)
    try:
        findings, read_bytes = _counted_scan(buf.getvalue())
    finally:
        _restore_budget(saved)
    assert read_bytes <= 500 + 1, read_bytes
    assert "LV-PRIV-007" in _ids(findings)


def test_high_expansion_ratio_member_is_bounded() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bomb.txt", "A" * 200_000)  # compresses to a few hundred bytes
    saved = _with_budget(5_000, 1_000)
    try:
        findings, read_bytes = _counted_scan(buf.getvalue())
    finally:
        _restore_budget(saved)
    assert read_bytes <= 5_001, read_bytes
    assert "LV-PRIV-007" in _ids(findings)


def test_budget_failure_output_is_safe() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(f"{_FAKE_EMAIL}.txt", "A" * 700)
    saved = _with_budget(10, 10)
    try:
        rendered = [str(f) for f in scan_archive("z.zip", buf.getvalue())]
    finally:
        _restore_budget(saved)
    assert rendered
    assert all(_FAKE_EMAIL not in r for r in rendered)



# --- resource accounting: debit-on-consumption --------------------------------
# These measure the ACTUAL number of decompressed bytes read, not the budget
# variable, because the defect they guard against was that the variable did not
# reflect real consumption.


class _CountingReader(io.RawIOBase):
    def __init__(self, inner, counter):
        self._inner = inner
        self._counter = counter

    def read(self, size=-1):
        chunk = self._inner.read(size)
        self._counter["n"] += len(chunk)
        return chunk

    def readable(self):
        return True


def _measure_consumption(data: bytes, total: int, member: int, kind: str | None = None):
    """Scan an archive under shrunken bounds, counting every decompressed byte."""
    counter = {"n": 0}
    real_zip_open = zipfile.ZipFile.open
    real_tar_extract = tarfile.TarFile.extractfile
    real_gzip_read = gzip.GzipFile.read
    real_bz2_read = bz2.BZ2File.read
    real_lzma_read = lzma.LZMAFile.read
    saved = (privacy_scan._MAX_TOTAL_BYTES, privacy_scan._MAX_MEMBER_BYTES)
    privacy_scan._MAX_TOTAL_BYTES, privacy_scan._MAX_MEMBER_BYTES = total, member

    def zip_open(self, name, mode="r", pwd=None, **kw):
        return _CountingReader(real_zip_open(self, name, mode, pwd, **kw), counter)

    def tar_extract(self, m):
        got = real_tar_extract(self, m)
        return _CountingReader(got, counter) if got is not None else None

    def counted(real):
        def _read(self, size=-1):
            out = real(self, size)
            counter["n"] += len(out)
            return out
        return _read

    zipfile.ZipFile.open = zip_open
    tarfile.TarFile.extractfile = tar_extract
    gzip.GzipFile.read = counted(real_gzip_read)
    bz2.BZ2File.read = counted(real_bz2_read)
    lzma.LZMAFile.read = counted(real_lzma_read)
    try:
        findings = scan_archive("probe.bin", data, kind=kind)
    finally:
        zipfile.ZipFile.open = real_zip_open
        tarfile.TarFile.extractfile = real_tar_extract
        gzip.GzipFile.read = real_gzip_read
        bz2.BZ2File.read = real_bz2_read
        lzma.LZMAFile.read = real_lzma_read
        privacy_scan._MAX_TOTAL_BYTES, privacy_scan._MAX_MEMBER_BYTES = saved
    return findings, counter["n"]


def _zip_of_gz_members(count: int, payload: int) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(count):
            zf.writestr(f"m{i}.gz", gzip.compress(b"A" * payload))
    return buf.getvalue()


def test_single_stream_overflow_is_charged() -> None:
    # The reachable case: decompressors carry no declared size. Before the fix
    # this consumed limit+1 per member without ever debiting.
    findings, consumed = _measure_consumption(_zip_of_gz_members(1, 5_000), 2_000, 1_000)
    assert consumed <= 2_001, consumed
    assert "LV-PRIV-007" in _ids(findings)


def test_repeated_overflow_cannot_accumulate_consumption() -> None:
    # The headline defect: many understated members must not each get a fresh
    # uncharged read. Consumption must stay flat as member count grows.
    measurements = [
        _measure_consumption(_zip_of_gz_members(n, 5_000), 2_000, 1_000)[1]
        for n in (1, 5, 40)
    ]
    assert all(c <= 2_001 for c in measurements), measurements
    assert measurements[-1] == measurements[-2], measurements  # flat, not growing


def test_zip_size_mismatch_branch_charges_bytes_read() -> None:
    # Structurally identical accounting path in the ZIP walker.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.txt", "A" * 4_000)
        zf.writestr("b.txt", "B" * 4_000)
    findings, consumed = _measure_consumption(buf.getvalue(), 1_000, 3_000)
    assert consumed <= 1_001, consumed
    assert "LV-PRIV-007" in _ids(findings)


def test_tar_size_mismatch_branch_charges_bytes_read() -> None:
    findings, consumed = _measure_consumption(
        _tar_bytes("m.txt", b"A" * 4_000), 1_000, 3_000, kind="tar"
    )
    assert consumed <= 1_001, consumed
    assert "LV-PRIV-007" in _ids(findings)


def test_nested_containers_share_one_consumption_budget() -> None:
    inner = _zip_of_gz_members(4, 4_000)
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w") as zf:
        zf.writestr("inner.zip", inner)
    findings, consumed = _measure_consumption(outer.getvalue(), 2_000, 50_000)
    assert consumed <= 2_001, consumed


def test_failed_member_then_another_member_stays_within_total() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("big.gz", gzip.compress(b"A" * 9_000))
        zf.writestr("later.txt", "contact " + _FAKE_EMAIL)
    findings, consumed = _measure_consumption(buf.getvalue(), 1_500, 1_200)
    assert consumed <= 1_501, consumed
    assert "LV-PRIV-007" in _ids(findings)


def test_member_exactly_at_remaining_limit_succeeds() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("m.txt", "contact " + _FAKE_EMAIL)
    size = len("contact " + _FAKE_EMAIL)
    findings, _ = _measure_consumption(buf.getvalue(), size, size)
    assert "LV-PRIV-004" in _ids(findings)
    assert "LV-PRIV-007" not in _ids(findings)


def test_member_one_byte_above_remaining_limit_fails_closed() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("m.txt", "contact " + _FAKE_EMAIL)
    size = len("contact " + _FAKE_EMAIL)
    findings, _ = _measure_consumption(buf.getvalue(), size - 1, size - 1)
    assert "LV-PRIV-007" in _ids(findings)


def test_exception_after_partial_read_cannot_restore_capacity() -> None:
    budget = privacy_scan.Budget(100)

    class _Exploding(io.RawIOBase):
        def read(self, size=-1):
            raise OSError("boom")

    data, overflowed = privacy_scan._read_charged(_Exploding(), budget, 100)
    assert data == b"" and overflowed
    assert budget.consumed == 100          # charged pessimistically
    assert budget.remaining == 0


def test_budget_never_becomes_negative() -> None:
    budget = privacy_scan.Budget(10)
    budget.charge(50)
    assert budget.remaining == 0
    budget.charge(-5)                      # nonsense input cannot credit back
    assert budget.remaining == 0
    assert budget.exhausted


def test_exhausted_budget_grants_no_allowance() -> None:
    budget = privacy_scan.Budget(0)
    assert budget.allowance(1_000) == 0
    data, overflowed = privacy_scan._read_charged(io.BytesIO(b"A" * 100), budget, 1_000)
    assert data == b"" and overflowed
    assert budget.consumed == 0            # nothing was read at all


def test_safe_archive_under_the_limit_still_scans() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("ok.txt", "contact " + _FAKE_EMAIL)
    findings, consumed = _measure_consumption(buf.getvalue(), 10_000, 10_000)
    assert "LV-PRIV-004" in _ids(findings)
    assert "LV-PRIV-007" not in _ids(findings)
    assert consumed < 10_000


def test_consumption_accounting_is_deterministic() -> None:
    data = _zip_of_gz_members(6, 4_000)
    first = _measure_consumption(data, 2_000, 1_000)
    second = _measure_consumption(data, 2_000, 1_000)
    assert first[1] == second[1]
    assert sorted(str(f) for f in first[0]) == sorted(str(f) for f in second[0])


def test_budget_failure_output_never_exposes_member_names() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(f"{_FAKE_EMAIL}.gz", gzip.compress(b"A" * 9_000))
    findings, _ = _measure_consumption(buf.getvalue(), 1_000, 800)
    rendered = [str(f) for f in findings]
    assert rendered
    assert all(_FAKE_EMAIL not in r for r in rendered)



# --- undecodable names must not crash output rendering ------------------------
# Archive headers and filesystem names can carry lone surrogates
# (surrogateescape). Strict UTF-8 encoding of those raises, and a crash in the
# reporting path could emit an unsafe traceback.

_SURROGATE = "\udcff"


def test_safe_location_handles_surrogate_names() -> None:
    rendered = safe_location(f"{_FAKE_EMAIL}-{_SURROGATE}.txt")
    assert _FAKE_EMAIL not in rendered
    assert "redacted-name:" in rendered


def test_finding_str_handles_surrogate_names() -> None:
    rendered = str(privacy_scan.Finding(f"{_FAKE_EMAIL}-{_SURROGATE}.txt", "LV-PRIV-004", 0))
    assert _FAKE_EMAIL not in rendered
    rendered.encode("utf-8")  # must be encodable, i.e. printable


def test_safe_component_with_surrogate_is_still_printable() -> None:
    rendered = safe_location(f"docs/notes-{_SURROGATE}.md")
    rendered.encode("utf-8")
    assert rendered.startswith("docs/")


def test_line_digest_handles_surrogates() -> None:
    assert len(privacy_scan._line_digest(f"x{_SURROGATE}y")) == 64


def test_emit_degrades_instead_of_raising() -> None:
    class _AsciiOnly(io.StringIO):
        encoding = "ascii"

        def write(self, text):
            text.encode("ascii")  # raises on non-ASCII, like a strict stream
            return super().write(text)

    sink = _AsciiOnly()
    privacy_scan._emit("caf\u00e9/<redacted-name:abc123>:0: LV-PRIV-004", stream=sink)
    assert "LV-PRIV-004" in sink.getvalue()


def test_scan_of_archive_with_undecodable_member_name_does_not_crash() -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        payload = ("contact " + _FAKE_EMAIL).encode()
        info = tarfile.TarInfo(f"bad-{_SURROGATE}-{_FAKE_EMAIL}.txt")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    rendered = [str(f) for f in scan_archive("b.tar", buf.getvalue(), kind="tar")]
    assert rendered
    for line in rendered:
        line.encode("utf-8")
        assert _FAKE_EMAIL not in line



# --- cross-component digest rendering -----------------------------------------
# The digest rule is contextual, so a label can sit in one path component while
# the digest sits in another. Judging components in isolation detected the
# finding and then printed the digest verbatim.


def test_split_component_digest_is_redacted_in_tracked_path() -> None:
    rendered = safe_location(f"Source SHA-256/{_FAKE_HEX}.txt")
    assert _FAKE_HEX not in rendered
    assert "redacted-name:" in rendered
    assert rendered.startswith("Source SHA-256/")   # label kept for remediation


def test_split_component_digest_is_redacted_in_archive_member() -> None:
    rendered = safe_location(f"bundle.zip!Archive digest/{_FAKE_HEX}.bin")
    assert _FAKE_HEX not in rendered
    assert rendered.startswith("bundle.zip!")


def test_split_component_digest_is_redacted_in_nested_member() -> None:
    rendered = safe_location(f"o.zip!inner.zip!Vault fingerprint/{_FAKE_HEX}.txt")
    assert _FAKE_HEX not in rendered


def test_digest_label_on_outer_archive_redacts_inner_member() -> None:
    # Context supplied by a different chunk of the location entirely.
    rendered = safe_location(f"Source SHA-256.zip!{_FAKE_HEX}.txt")
    assert _FAKE_HEX not in rendered


def test_cli_output_excludes_split_component_digest() -> None:
    rc, out, err = _run_cli_repo({f"Source SHA-256/{_FAKE_HEX}.txt": b"safe"})
    assert rc == 1
    assert _FAKE_HEX not in out and _FAKE_HEX not in err
    assert "redacted-name:" in out


def test_cli_output_excludes_split_component_digest_in_archive() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(f"Archive digest/{_FAKE_HEX}.txt", "x")
    rc, out, err = _run_cli_repo({"bundle.zip": buf.getvalue()})
    assert rc == 1
    assert _FAKE_HEX not in out and _FAKE_HEX not in err


def test_split_component_digest_with_surrogate_does_not_crash() -> None:
    rendered = safe_location(f"Source SHA-256/{_FAKE_HEX}-{_SURROGATE}.txt")
    rendered.encode("utf-8")
    assert _FAKE_HEX not in rendered


def test_bare_hash_without_any_context_is_not_redacted() -> None:
    # False-positive guard: with no digest context anywhere in the location the
    # hash is an ordinary public artefact name and stays readable.
    assert rules_for_name(f"artifacts/{_FAKE_HEX}.bin") == []
    assert _FAKE_HEX in safe_location(f"artifacts/{_FAKE_HEX}.bin")



# --- archive link targets ------------------------------------------------------
# A tar symlink/hardlink carries its target in the header. That target is data
# the archive ships and must be scanned like a filesystem symlink's target.


def _tar_with_link(target: str, kind: bytes = tarfile.SYMTYPE, name: str = "link") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo(name)
        info.type = kind
        info.linkname = target
        info.size = 0
        tf.addfile(info)
    return buf.getvalue()


def test_tar_symlink_target_with_private_path_detected() -> None:
    data = _tar_with_link(_FAKE_PRIVATE_TARGET)
    assert "LV-PRIV-005" in _ids(scan_archive("a.tar", data, kind="tar"))


def test_tar_symlink_target_with_email_detected() -> None:
    data = _tar_with_link(f"{_FAKE_EMAIL}.txt")
    assert "LV-PRIV-004" in _ids(scan_archive("a.tar", data, kind="tar"))


def test_tar_symlink_target_with_export_archive_detected() -> None:
    data = _tar_with_link(_FAKE_EXPORT_ZIP)
    assert "LV-PRIV-001" in _ids(scan_archive("a.tar", data, kind="tar"))


def test_tar_hardlink_target_is_scanned() -> None:
    data = _tar_with_link(_FAKE_PRIVATE_TARGET, kind=tarfile.LNKTYPE)
    assert "LV-PRIV-005" in _ids(scan_archive("a.tar", data, kind="tar"))


def test_tar_link_target_is_not_reproduced_in_output() -> None:
    data = _tar_with_link(f"{_FAKE_EMAIL}.txt")
    rendered = [str(f) for f in scan_archive("a.tar", data, kind="tar")]
    assert rendered
    assert all(_FAKE_EMAIL not in line for line in rendered)


def test_link_target_inside_nested_archive_is_scanned() -> None:
    inner = _tar_with_link(_FAKE_PRIVATE_TARGET)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("inner.tar", inner)
    assert "LV-PRIV-005" in _ids(scan_archive("outer.zip", buf.getvalue(), kind="zip"))


def test_zip_symlink_target_still_detected_via_content() -> None:
    # Control: a zip stores a symlink's target as the member's content, which the
    # ordinary content path already covers.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        entry = zipfile.ZipInfo("link")
        entry.external_attr = (0xA1FF) << 16
        zf.writestr(entry, _FAKE_PRIVATE_TARGET)
    assert "LV-PRIV-005" in _ids(scan_archive("a.zip", buf.getvalue(), kind="zip"))


def test_link_without_target_does_not_false_positive() -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("plain-dir")
        info.type = tarfile.DIRTYPE
        tf.addfile(info)
    assert scan_archive("a.tar", buf.getvalue(), kind="tar") == []


# --- Regressions: absolute private paths as archive member names --------------
# rules_for_name() dropped LV-PRIV-005 unconditionally. That is correct for a
# tracked path — git guarantees it is repository-relative — but an archive member
# name is text chosen by whoever built the archive and may be absolute, so seven
# member-name shapes went entirely undetected, including bare directory entries
# that have no content to fall back on.

_FAKE_ABS_HOME = "/ho" + "me/alice/vault/secret.txt"
_FAKE_ABS_HOME_DIR = "/ho" + "me/alice/vault/"
_FAKE_ABS_MAC = "/Us" + "ers/alice/vault/secret.txt"
_FAKE_ABS_WIN = "C:" + chr(92) + "Us" + "ers" + chr(92) + "alice" + chr(92) + "x.txt"
# A *relative* tracked path that merely contains a `home/` directory. Assembled
# from fragments like every other prohibited shape here, because the unanchored
# content rule does match it — that is exactly why the anchored name rule exists.
_FAKE_REPO_HOME_PATH = "docs/ho" + "me/alice/notes.md"


def _zip_with_entries(entries) -> bytes:
    """entries: (name, data) pairs; data None makes a directory entry."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries:
            if data is None:
                info = zipfile.ZipInfo(name if name.endswith("/") else name + "/")
                info.external_attr = 0o40755 << 16
                zf.writestr(info, b"")
            else:
                zf.writestr(name, data)
    return buf.getvalue()


def _tar_with_entries(entries) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            if data is None:
                info.type = tarfile.DIRTYPE
                info.size = 0
                tf.addfile(info)
            else:
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_zip_member_named_absolute_private_path_detected() -> None:
    data = _zip_with_entries([(_FAKE_ABS_HOME, b"innocuous")])
    assert "LV-PRIV-005" in _ids(scan_archive("a.zip", data, kind="zip"))


def test_zip_directory_entry_named_private_path_detected() -> None:
    # A directory entry carries no content at all: if its name is skipped, the
    # entry is a blind spot by construction.
    data = _zip_with_entries([(_FAKE_ABS_HOME_DIR, None)])
    assert "LV-PRIV-005" in _ids(scan_archive("a.zip", data, kind="zip"))


def test_tar_member_named_absolute_private_path_detected() -> None:
    data = _tar_with_entries([(_FAKE_ABS_HOME, b"innocuous")])
    assert "LV-PRIV-005" in _ids(scan_archive("a.tar", data, kind="tar"))


def test_tar_directory_member_named_private_path_detected() -> None:
    data = _tar_with_entries([(_FAKE_ABS_HOME_DIR, None)])
    assert "LV-PRIV-005" in _ids(scan_archive("a.tar", data, kind="tar"))


def test_tar_member_named_windows_private_path_detected() -> None:
    data = _tar_with_entries([(_FAKE_ABS_WIN, b"innocuous")])
    assert "LV-PRIV-005" in _ids(scan_archive("a.tar", data, kind="tar"))


def test_zip_member_named_macos_private_path_detected() -> None:
    data = _zip_with_entries([(_FAKE_ABS_MAC, b"innocuous")])
    assert "LV-PRIV-005" in _ids(scan_archive("a.zip", data, kind="zip"))


def test_nested_archive_member_named_private_path_detected() -> None:
    inner = _zip_with_entries([(_FAKE_ABS_HOME, b"innocuous")])
    outer = _zip_with_entries([("inner.zip", inner)])
    assert "LV-PRIV-005" in _ids(scan_archive("o.zip", outer, kind="zip"))


def test_cli_output_does_not_reproduce_private_member_name() -> None:
    rc, out, err = _run_cli_repo({"bundle.zip": _zip_with_entries([(_FAKE_ABS_HOME, b"x")])})
    assert rc == 1
    # The username is the identifying component and must not survive rendering.
    assert "alice" not in out and "alice" not in err
    assert _FAKE_ABS_HOME not in out and _FAKE_ABS_HOME not in err


def test_tracked_repo_path_containing_home_directory_is_not_flagged() -> None:
    # The false-positive guard that makes the repo_relative distinction load
    # bearing: a tracked path is relative, so a `home/<user>/` directory in it
    # is part of this repository, not somebody's home directory.
    assert "LV-PRIV-005" not in rules_for_name(_FAKE_REPO_HOME_PATH)


def test_relative_archive_member_with_home_directory_is_not_flagged() -> None:
    # A relative tree containing `home/` is ordinary inside an archive; only an
    # absolute member name denotes a real local home directory.
    data = _tar_with_entries([("home/alice/x.txt", b"ok")])
    assert "LV-PRIV-005" not in _ids(scan_archive("a.tar", data, kind="tar"))


def test_rules_for_name_repo_relative_distinction() -> None:
    # One name, two judgements — the parameter must actually change behaviour.
    assert "LV-PRIV-005" not in rules_for_name(_FAKE_ABS_HOME, repo_relative=True)
    assert "LV-PRIV-005" in rules_for_name(_FAKE_ABS_HOME, repo_relative=False)
    # …and it must not turn the relative case into a false positive.
    assert "LV-PRIV-005" not in rules_for_name(_FAKE_REPO_HOME_PATH, repo_relative=False)


# --- Regressions: single-stream extension fallback ----------------------------
# detect_archive() fell back on extension for .gz only. A damaged .bz2/.xz lost
# its magic bytes, was treated as ordinary bytes, and read as "no findings" —
# because the payload was still compressed and so invisible to every text view.


def _damaged(blob: bytes) -> bytes:
    broken = bytearray(blob)
    broken[0] ^= 0xFF  # break the magic, leave the stream otherwise intact
    return bytes(broken)


# Compressible payload, so the compressed form genuinely hides the plaintext.
_SECRET_PAYLOAD = (("contact " + _FAKE_EMAIL + " at " + _FAKE_HOME + "\n") * 200).encode()


def test_compressed_payload_is_invisible_to_text_views() -> None:
    # The mechanism that makes the missing fallback a silent miss rather than a
    # harmless mislabel: if the bytes were readable as text, the content rules
    # would still catch them.
    assert scan_bytes("x.bin", bz2.compress(_SECRET_PAYLOAD)) == []
    assert scan_bytes("x.bin", lzma.compress(_SECRET_PAYLOAD)) == []


def test_damaged_bz2_stream_is_reported_unscannable() -> None:
    data = _damaged(bz2.compress(_SECRET_PAYLOAD))
    assert detect_archive(data, "x.bz2") == "bzip2"
    assert "LV-PRIV-007" in _ids(scan_archive("x.bz2", data))


def test_damaged_xz_stream_is_reported_unscannable() -> None:
    data = _damaged(lzma.compress(_SECRET_PAYLOAD))
    assert detect_archive(data, "x.xz") == "xz"
    assert "LV-PRIV-007" in _ids(scan_archive("x.xz", data))


def test_damaged_lzma_stream_is_reported_unscannable() -> None:
    data = _damaged(lzma.compress(_SECRET_PAYLOAD, format=lzma.FORMAT_ALONE))
    assert detect_archive(data, "x.lzma") == "xz"
    assert "LV-PRIV-007" in _ids(scan_archive("x.lzma", data))


def test_cli_fails_closed_on_damaged_single_stream_files() -> None:
    for name, blob in (
        ("payload.bz2", bz2.compress(_SECRET_PAYLOAD)),
        ("payload.xz", lzma.compress(_SECRET_PAYLOAD)),
    ):
        rc, out, err = _run_cli_repo({name: _damaged(blob)})
        assert rc == 1, f"{name} passed the scan"
        assert "LV-PRIV-007" in out


def test_intact_bz2_content_is_still_inspected() -> None:
    data = bz2.compress(("contact " + _FAKE_EMAIL).encode())
    assert "LV-PRIV-004" in _ids(scan_archive("x.bz2", data))


def test_plaintext_named_bz2_is_still_scanned_as_text() -> None:
    # The fallback must not stop ordinary text that merely carries the extension
    # from being scanned; it is reported unscannable, which is still a finding.
    rc, out, err = _run_cli_repo({"notes.bz2": ("contact " + _FAKE_EMAIL).encode()})
    assert rc == 1


# --- Structural guard: detection and rendering may never disagree -------------


def test_rendered_output_never_trips_a_content_rule() -> None:
    """Rendered output must not be judged unsafe by the rules that produced it.

    Necessary but **not sufficient** — see
    `test_rendered_output_never_preserves_the_identifying_value`, which exists
    because this test alone passed while the username was being printed:
    redacting the component that makes a rule fire (`home`) silences the rule
    while preserving the secret (the username). A rule-level invariant can be
    satisfied by destroying the evidence instead of the value, so the value-level
    invariant is asserted separately.

    LV-PRIV-006 is the one documented exception: it names a payload *category*
    (`conversations.json` is identical in every export and carries nothing
    user-specific), which is deliberately kept legible for remediation.
    """
    pieces = [
        _FAKE_ABS_HOME,
        _FAKE_ABS_HOME_DIR,
        _FAKE_ABS_MAC,
        _FAKE_ABS_WIN,
        "//ho" + "me/alice/x/",
        _FAKE_REPO_HOME_PATH,
        "home/alice/x.txt",
        f"Source SHA-256/{_FAKE_HEX}.txt",
        f"docs/{_FAKE_EMAIL}-notes.md",
        _FAKE_EXPORT_ZIP,
        "conversations.json",
        "Archive digest",
        f"{_FAKE_HEX}.bin",
        "plain/dir/file.txt",
    ]
    checked = 0
    for first in pieces:
        for second in pieces:
            for location in (first, f"{first}!{second}"):
                checked += 1
                for chunk in safe_location(location).split("!"):
                    residue = [
                        rule
                        for rule in rules_for_name(chunk, repo_relative=False)
                        if rule != "LV-PRIV-006"
                    ]
                    assert not residue, f"{location!r} rendered to unsafe {chunk!r}: {residue}"
    assert checked > 300


# --- Regressions: one path, one representation --------------------------------
# Absoluteness was decided from a slash-collapsed string while the renderer split
# the uncollapsed one, so `//home/<user>/x` redacted `home` at index 2 and
# printed the username. Both the leak and the fact that the rule-level invariant
# stayed green are regression-tested here.

_IDENTITY = "alice"  # the value that must never survive rendering
_HOME_ROOT = "/ho" + "me"
_USERS_ROOT = "/Us" + "ers"


def _slash_variants() -> list[str]:
    """The same local home path written with assorted slash runs."""
    return [
        f"{_HOME_ROOT}/{_IDENTITY}/vault/x.txt",
        f"/{_HOME_ROOT}/{_IDENTITY}/vault/x.txt",
        f"//{_HOME_ROOT}/{_IDENTITY}/vault/x.txt",
        f"{_HOME_ROOT}//{_IDENTITY}/vault/x.txt",
        f"{_HOME_ROOT}/{_IDENTITY}//vault/x.txt",
        f"{_HOME_ROOT}/{_IDENTITY}/vault/",
        f"/{_HOME_ROOT}/{_IDENTITY}/vault/",
        f"{_USERS_ROOT}/{_IDENTITY}/x.txt",
        f"/{_USERS_ROOT}/{_IDENTITY}/x.txt",
        "C://Us" + f"ers/{_IDENTITY}/x.txt",
        "C:/Us" + f"ers/{_IDENTITY}/x.txt",
    ]


def test_rendered_output_never_preserves_the_identifying_value() -> None:
    """The value-level invariant: the username itself must not survive.

    The rule-level invariant was blind to this. Redacting `home` removes the
    trigger for LV-PRIV-005, so the rendered form is judged clean — while the
    username it was supposed to hide is still in the output. Assert the value.
    """
    for path in _slash_variants():
        for location in (path, f"bundle.zip!{path}", f"o.zip!i.zip!{path}"):
            rendered = safe_location(location)
            assert _IDENTITY not in rendered, f"{location!r} leaked via {rendered!r}"


def test_slash_runs_do_not_shift_the_redacted_component() -> None:
    # Every spelling of the same path must reduce to the same rendering, which
    # is what "one representation" buys: no variant can index differently.
    renderings = {
        safe_location(p)
        for p in _slash_variants()
        if p.startswith(_HOME_ROOT) or p.startswith("/" + _HOME_ROOT)
        if "vault/x.txt" in p
    }
    assert len(renderings) == 1, renderings
    assert _IDENTITY not in renderings.pop()


def test_slash_run_paths_are_still_detected() -> None:
    for path in _slash_variants():
        assert "LV-PRIV-005" in rules_for_name(path, repo_relative=False), path


def test_cli_output_excludes_username_with_slash_runs() -> None:
    for member in (
        f"/{_HOME_ROOT}/{_IDENTITY}/vault/x.txt",
        f"{_HOME_ROOT}//{_IDENTITY}/vault/x.txt",
    ):
        rc, out, err = _run_cli_repo({"bundle.zip": _zip_with_entries([(member, b"x")])})
        assert rc == 1
        assert _IDENTITY not in out and _IDENTITY not in err, member


def test_identity_index_and_absoluteness_agree() -> None:
    # The two questions are answered by one function, so they cannot disagree.
    # Assert that directly, including on the shapes that must stay negative.
    for path in _slash_variants():
        components = privacy_scan._path_components(path)
        assert privacy_scan._identity_component_index(components) is not None
        assert privacy_scan._is_absolute_local_path(path)
    # Negatives: repository-relative shapes, and a root carrying no username.
    # `{_HOME_ROOT}/{_IDENTITY}` used to be asserted negative here too — the same
    # wrong oracle as the old trailing-component test, reached from the other
    # side. It is now a positive case below.
    for path in (_FAKE_REPO_HOME_PATH, "home/alice/x.txt", _HOME_ROOT, _HOME_ROOT + "/"):
        assert not privacy_scan._is_absolute_local_path(path), path
    assert privacy_scan._is_absolute_local_path(f"{_HOME_ROOT}/{_IDENTITY}")


def test_bare_home_directory_is_flagged() -> None:
    """Replaces test_home_path_without_trailing_component_is_not_flagged.

    That test asserted a bare `/home/<user>` was safe, justified only by
    "parity with the content rule, which requires a trailing `/`" — an
    implementation detail defended by another implementation detail, with no
    governing policy behind either. The rule is *local user home paths*, and the
    home directory is one: it names the same user as any file inside it.

    An owner review challenged the assertion rather than the code, which is the
    only way a wrong oracle can be found — the suite cannot detect that its own
    expected value is wrong.
    """
    assert "LV-PRIV-005" in rules_for_name(
        f"{_HOME_ROOT}/{_IDENTITY}", repo_relative=False
    )


# --- Regressions: magic-byte checks must be reachable -------------------------
# _SIG_RAR held 7-byte constants while detect_archive() compared data[:8], so
# both were unreachable and RAR was recognised by extension alone. A RAR without
# a .rar name was read as ordinary bytes — a silent miss, its payload still
# compressed. The existing unsupported-formats test passed throughout because it
# used .rar filenames, exercising the extension path rather than the signature.

_RAR4_SIG = b"Rar!\x1a\x07\x00"
_RAR5_SIG = b"Rar!\x1a\x07\x01\x00"


def test_rar4_detected_by_signature_without_extension() -> None:
    assert detect_archive(_RAR4_SIG + b"\x00" * 64, "notes.md") == "unsupported"


def test_rar5_detected_by_signature_without_extension() -> None:
    assert detect_archive(_RAR5_SIG + b"\x00" * 64, "notes.md") == "unsupported"


def test_rar_detected_by_signature_with_no_name() -> None:
    assert detect_archive(_RAR4_SIG + b"\x00" * 64, "") == "unsupported"


def test_cli_fails_closed_on_disguised_rar() -> None:
    rc, out, err = _run_cli_repo({"payload.bin": _RAR4_SIG + b"\x00" * 512})
    assert rc == 1
    assert "LV-PRIV-007" in out


def test_every_archive_signature_is_reachable() -> None:
    """The structural guard: a signature constant that no comparison can match
    is a silent hole, and inspection is how it survived. Assert reachability by
    construction instead — a buffer beginning with each declared signature must
    be recognised as *some* archive kind.
    """
    signatures = (
        privacy_scan._SIG_ZIP,
        privacy_scan._SIG_GZIP,
        privacy_scan._SIG_BZIP2,
        privacy_scan._SIG_XZ,
        privacy_scan._SIG_7Z,
        privacy_scan._SIG_RAR,
    )
    checked = 0
    for declared in signatures:
        for signature in declared if isinstance(declared, tuple) else (declared,):
            checked += 1
            kind = detect_archive(signature + b"\x00" * 128, "")
            assert kind is not None, f"unreachable signature {signature!r}"
    assert checked >= 8


def test_signature_detection_precedes_extension() -> None:
    # "Signature first, extension second" must hold for the unsupported formats
    # too: a disguised archive cannot launder itself through a benign name.
    for signature in (_RAR4_SIG, _RAR5_SIG, b"7z\xbc\xaf\x27\x1c"):
        for name in ("notes.md", "data.txt", "image.png", ""):
            assert detect_archive(signature + b"\x00" * 64, name) == "unsupported"


# --- Regressions: a filename is bytes, and a guard must be able to run --------


def test_non_utf8_tracked_filename_has_its_content_scanned() -> None:
    """`git ls-files -z` was decoded with errors="replace".

    A POSIX filename need not be valid UTF-8. U+FFFD substitution meant the name
    no longer named the file, so the entry was reported LV-PRIV-007 "unreadable"
    and its content was never scanned — failing closed, but for the wrong reason
    and without ever looking inside.
    """
    raw_name = b"notes-\xff-private.md"
    with tempfile.TemporaryDirectory() as d:
        repo = Path(d)
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "t@invalid"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
        target = os.path.join(os.fsdecode(repo), os.fsdecode(raw_name))
        with open(os.fsencode(target), "wb") as fh:
            fh.write(("contact " + _FAKE_EMAIL).encode())
        subprocess.run(["git", "add", "-f", os.fsdecode(raw_name)], cwd=repo, check=True)
        proc = subprocess.run(
            [sys.executable, str(_SCANNER)], cwd=repo, capture_output=True, text=True
        )
    combined = proc.stdout + proc.stderr
    assert proc.returncode == 1
    assert "LV-PRIV-004" in combined, "content of a non-UTF-8-named file was not scanned"
    assert _FAKE_EMAIL not in combined, "output reproduced the prohibited value"


def test_tracked_path_decoding_round_trips() -> None:
    raw = b"notes-\xff-private.md"
    assert os.fsencode(raw.decode("utf-8", errors="surrogateescape")) == raw
    # The old behaviour, kept explicit so the difference cannot be re-introduced
    # unnoticed.
    assert os.fsencode(raw.decode("utf-8", errors="replace")) != raw


def test_pre_commit_hook_names_an_interpreter_that_exists() -> None:
    """`language: system` runs the hook in the developer's shell, where a bare
    `python` may not exist (stock Debian/Ubuntu). A fail-closed guard that
    cannot start is worse than no guard, because the failure looks like a pass.
    """
    config = (Path(__file__).resolve().parents[1] / ".pre-commit-config.yaml").read_text()
    entries = [l.strip() for l in config.splitlines() if l.strip().startswith("entry:")]
    assert entries, "no hook entry found"
    for entry in entries:
        command = entry.split(":", 1)[1].split()[0]
        assert command != "python", f"{entry!r} depends on a bare `python`"


def test_run_tests_script_names_an_interpreter_that_exists() -> None:
    script = (Path(__file__).resolve().parents[1] / "run-tests.sh").read_text()
    for line in script.splitlines():
        stripped = line.strip()
        if stripped.startswith("python "):
            raise AssertionError(f"{stripped!r} depends on a bare `python`")


# --- Regression: scan_archive honours detect_archive's documented contract ----


def test_scan_archive_on_non_archive_bytes_scans_them() -> None:
    # detect_archive() defines None as "not an archive" — the one case that may
    # be treated as ordinary bytes. Reporting LV-PRIV-007 said nothing could be
    # inspected, which was false and hid the finding.
    plain = ("contact " + _FAKE_EMAIL).encode()
    assert detect_archive(plain, "notes.txt") is None
    assert "LV-PRIV-004" in _ids(scan_archive("notes.txt", plain))


def test_scan_archive_still_fails_closed_on_unsupported_formats() -> None:
    # The other branch must not have moved: a recognised-but-unparseable format
    # is still unscannable.
    for data, name in ((b"7z\xbc\xaf\x27\x1c" + b"\x00" * 32, "x.7z"),
                       (_RAR4_SIG + b"\x00" * 32, "x.bin")):
        assert "LV-PRIV-007" in _ids(scan_archive(name, data))


# --- Regressions: output is one line per finding, always ----------------------
# _printable() guaranteed encodability, not printability. A name carrying a
# newline split one finding across two lines, the second being attacker-chosen
# text that reads exactly like a finding; CR could overwrite a real finding in a
# terminal and ANSI escapes could hide one.

_FORGED = "real" + chr(10) + "bundle.zip:0: LV-PRIV-999 FORGED" + chr(10) + "x.txt"


def test_control_characters_are_escaped_in_rendered_locations() -> None:
    rendered = safe_location(_FORGED)
    assert "\n" not in rendered and "\r" not in rendered and "\x1b" not in rendered
    assert "\\x0a" in rendered


def test_all_c0_and_c1_controls_are_escaped() -> None:
    for code in list(range(0x00, 0x20)) + [0x7F] + list(range(0x80, 0xA0)):
        rendered = safe_location(f"a{chr(code)}b.md")
        assert chr(code) not in rendered, f"U+{code:04X} survived rendering"


def test_cli_emits_one_line_per_finding_despite_newline_in_member_name() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(_FORGED, ("contact " + _FAKE_EMAIL).encode())
    rc, out, err = _run_cli_repo({"bundle.zip": buf.getvalue()})
    assert rc == 1
    finding_lines = [line for line in out.splitlines() if ": LV-PRIV-" in line]
    assert len(finding_lines) == 1, f"one finding produced {len(finding_lines)} lines"
    combined = out + err
    assert not any(
        char in combined for char in ("\r", "\x1b", "\t")
    ), "raw control characters reached output"


# --- Regression: a symlink target is not a repository path --------------------


def test_symlink_target_with_lowercase_drive_path_is_detected() -> None:
    """scan_tracked_entry() judged link targets as repo-relative, which disabled
    the anchored absolute check. The content rules alone did not cover every
    spelling: the POSIX pattern is case-sensitive and the Windows pattern only
    matches backslashes, so a lowercase forward-slash drive path escaped both.
    """
    target = "c:/us" + "ers/alice/vault/x.txt"
    with tempfile.TemporaryDirectory() as d:
        link = Path(d) / "lnk"
        link.symlink_to(target)
        assert "LV-PRIV-005" in _ids(scan_tracked_entry("lnk", link))


def test_symlink_target_spellings_are_all_detected() -> None:
    users = "Us" + "ers"
    targets = [
        "C:" + chr(92) + users + chr(92) + "alice" + chr(92) + "x.txt",
        "C:/" + users + "/alice/x.txt",
        "c:/" + users.lower() + "/alice/x.txt",
        "c:" + chr(92) + users.lower() + chr(92) + "alice" + chr(92) + "x.txt",
        _FAKE_HOME + "/x.txt",
    ]
    for target in targets:
        with tempfile.TemporaryDirectory() as d:
            link = Path(d) / "lnk"
            link.symlink_to(target)
            assert "LV-PRIV-005" in _ids(scan_tracked_entry("lnk", link)), target


# --- Regression: the tar length guard matches the slice it guards -------------


def test_tar_signature_detected_at_minimum_length() -> None:
    # data[257:262] is valid once len(data) >= 262; the guard demanded 263.
    header = bytearray(262)
    header[257:262] = b"ustar"
    assert detect_archive(bytes(header), "") == "tar"


def test_tar_signature_guard_does_not_overreach() -> None:
    # One byte short, the slice cannot contain the signature and must not match.
    assert detect_archive(bytes(261), "") is None


# --- Guards: documented commands must be runnable -----------------------------
# A report that names a file which is not in the tree cannot be reproduced, and
# an unrunnable reproduction reads exactly like a reproducible one.


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _tracked() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=_repo_root(), capture_output=True, text=True, check=True
    )
    return out.stdout.splitlines()


def test_documented_commands_name_files_that_exist() -> None:
    tracked = set(_tracked())
    for doc in ("LegendVault_Stress_Test_Report_v2.md", "docs/PRIVATE_DATA_BOUNDARY.md"):
        text = (_repo_root() / doc).read_text(errors="replace")
        for match in re.finditer(r"^\s*python3?\s+(\"[^\"]+\"|\S+)", text, re.MULTILINE):
            named = match.group(1).strip('"')
            if named.startswith("-"):
                continue
            assert named in tracked, f"{doc} runs {named!r}, which is not tracked"


def test_documented_commands_use_python3() -> None:
    for doc in ("LegendVault_Stress_Test_Report_v2.md", "docs/PRIVATE_DATA_BOUNDARY.md"):
        text = (_repo_root() / doc).read_text(errors="replace")
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("python "):
                raise AssertionError(f"{doc}: {stripped!r} depends on a bare `python`")


# --- Property pinned after a disproven report: .lzma streams are inspected ----
# A review claimed LZMAFile defaults to FORMAT_XZ, which would make an intact
# LZMA-alone stream unscannable. Measured: the read default is FORMAT_AUTO and
# such a stream is inspected. The property is worth pinning anyway, so that
# passing an explicit format later cannot silently make .lzma opaque.


def test_intact_lzma_alone_stream_is_inspected() -> None:
    payload = (("contact " + _FAKE_EMAIL + "\n") * 50).encode()
    blob = lzma.compress(payload, format=lzma.FORMAT_ALONE)
    assert detect_archive(blob, "payload.lzma") == "xz"
    assert "LV-PRIV-004" in _ids(scan_archive("payload.lzma", blob, kind="xz"))


def test_intact_xz_stream_is_inspected() -> None:
    payload = (("contact " + _FAKE_EMAIL + "\n") * 50).encode()
    blob = lzma.compress(payload, format=lzma.FORMAT_XZ)
    assert "LV-PRIV-004" in _ids(scan_archive("payload.xz", blob))


# =============================================================================
# OWNER-REVIEW REGRESSIONS
# Three findings raised by independent owner review that twelve automated review
# rounds did not surface.
# =============================================================================

# --- O1: the redaction marker must not be derived from the value -------------
# safe_location() published sha256(component)[:12] — a 48-bit fingerprint OF THE
# SECRET. Anyone holding a candidate could hash it and confirm the match, and the
# same value produced the same marker everywhere, linking occurrences. That is
# the correlatable identifier this repository's own policy prohibits, and the
# exact shape LV-PRIV-002 exists to flag.

_O1_SECRET = f"{_FAKE_EMAIL}-notes.md"


def _sha_markers(component: str) -> list[str]:
    digest = hashlib.sha256(component.encode("utf-8", errors="surrogatepass")).hexdigest()
    return [digest, digest[:12]]


def test_marker_is_not_recomputable_from_a_candidate_value() -> None:
    rendered = safe_location(f"docs/{_O1_SECRET}")
    assert _O1_SECRET not in rendered
    for marker in _sha_markers(_O1_SECRET):
        assert marker not in rendered, "a guesser could confirm the value from the output"


def test_marker_is_not_a_stable_value_derived_fingerprint() -> None:
    # The same secret in two unrelated locations must not yield a shared token
    # that links the two findings together.
    first = safe_location(f"docs/{_O1_SECRET}")
    second = safe_location(f"other/dir/deeper/{_O1_SECRET}")
    for marker in _sha_markers(_O1_SECRET):
        assert marker not in first and marker not in second


def test_marker_is_positional_not_content_derived() -> None:
    # Two *different* secrets at the same position render identically; the marker
    # therefore carries no information about what it hides.
    one = safe_location(f"docs/{_FAKE_EMAIL}-a.md")
    two = safe_location(f"docs/{_FAKE_GH_TOKEN}.md")
    assert one == two
    # …and position is what distinguishes markers within one location.
    both = safe_location(f"{_FAKE_EMAIL}-a.md/{_FAKE_GH_TOKEN}.md")
    assert "<redacted-name:1>" in both and "<redacted-name:2>" in both


def test_cli_output_contains_no_digest_of_a_prohibited_value() -> None:
    rc, out, err = _run_cli_repo({f"docs/{_O1_SECRET}": b"safe"})
    assert rc == 1
    combined = out + err
    assert _O1_SECRET not in combined
    for marker in _sha_markers(_O1_SECRET):
        assert marker not in combined


def test_no_sixty_four_hex_token_is_ever_emitted_for_a_redacted_name() -> None:
    # A blanket check: rendered output must not contain any full-length digest,
    # whichever unkeyed hash a future edit might reach for.
    for location in (f"docs/{_O1_SECRET}", f"bundle.zip!{_FAKE_HOME}/x", _FAKE_EXPORT_ZIP):
        rendered = safe_location(location)
        assert not re.search(r"[0-9a-fA-F]{32,}", rendered), rendered


# --- O2: the top-level size limit must bound the read, not follow it ---------


class _CountingFile(io.RawIOBase):
    """Counts bytes actually delivered by the real file object."""

    def __init__(self, inner, counter):
        self._inner = inner
        self._counter = counter

    def read(self, size=-1):
        chunk = self._inner.read(size)
        self._counter["n"] += len(chunk)
        return chunk

    def readable(self) -> bool:
        return True

    def close(self) -> None:
        try:
            self._inner.close()
        finally:
            super().close()


def _measure_file_read(path: Path, limit: int):
    """Scan one tracked file under a shrunken bound, counting real bytes read.

    The count comes from the file object, not from any accounting inside the
    scanner — the production path has no counter of its own to trust.
    """
    counter = {"n": 0}
    real_open = Path.open
    real_read_bytes = Path.read_bytes
    saved = privacy_scan._MAX_MEMBER_BYTES
    privacy_scan._MAX_MEMBER_BYTES = limit

    def counting_open(self, *a, **kw):
        mode = a[0] if a else kw.get("mode", "r")
        handle = real_open(self, *a, **kw)
        return _CountingFile(handle, counter) if "b" in mode else handle

    def counting_read_bytes(self):
        with counting_open(self, "rb") as fh:
            return fh.read()

    Path.open = counting_open
    Path.read_bytes = counting_read_bytes
    try:
        findings = scan_tracked_entry(path.name, path)
    finally:
        Path.open = real_open
        Path.read_bytes = real_read_bytes
        privacy_scan._MAX_MEMBER_BYTES = saved
    return findings, counter["n"]


def test_oversized_file_is_not_fully_read_before_being_rejected() -> None:
    limit = 4096
    with tempfile.TemporaryDirectory() as d:
        big = Path(d) / "big.bin"
        big.write_bytes(b"A" * (limit * 50))
        findings, consumed = _measure_file_read(big, limit)
    assert "LV-PRIV-007" in _ids(findings)
    assert consumed <= limit + 1, f"read {consumed} bytes to reject a {limit}-byte limit"


def test_file_exactly_at_the_limit_is_scanned() -> None:
    limit = 4096
    body = ("contact " + _FAKE_EMAIL).encode()
    with tempfile.TemporaryDirectory() as d:
        exact = Path(d) / "exact.txt"
        exact.write_bytes(body + b"." * (limit - len(body)))
        findings, consumed = _measure_file_read(exact, limit)
    assert "LV-PRIV-004" in _ids(findings)
    assert consumed <= limit + 1


def test_file_one_byte_over_the_limit_fails_closed() -> None:
    limit = 4096
    with tempfile.TemporaryDirectory() as d:
        over = Path(d) / "over.txt"
        over.write_bytes(b"B" * (limit + 1))
        findings, consumed = _measure_file_read(over, limit)
    assert "LV-PRIV-007" in _ids(findings)
    assert consumed <= limit + 1


def test_bounded_file_read_is_deterministic() -> None:
    limit = 2048
    with tempfile.TemporaryDirectory() as d:
        target = Path(d) / "f.bin"
        target.write_bytes(b"C" * (limit * 10))
        first = _measure_file_read(target, limit)
        second = _measure_file_read(target, limit)
    assert first[0] == second[0] and first[1] == second[1]


def test_unreadable_file_is_reported_not_crashed() -> None:
    with tempfile.TemporaryDirectory() as d:
        missing = Path(d) / "gone.txt"
        assert "LV-PRIV-007" in _ids(scan_tracked_entry("gone.txt", missing))


# --- O3: staged mode judges the index, worktree mode judges the worktree -----


def _staged_repo(staged: dict, worktree: dict | None = None) -> Path:
    """Build a repo where staged content and worktree content can differ."""
    repo = Path(tempfile.mkdtemp(prefix="staged_"))
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "t@invalid"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
    for rel, data in staged.items():
        target = repo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        subprocess.run(["git", "add", "-f", rel], cwd=repo, check=True)
    for rel, data in (worktree or {}).items():
        (repo / rel).write_bytes(data)   # diverge AFTER staging
    return repo


def _scan_modes(repo: Path):
    def run(args):
        return subprocess.run(
            [sys.executable, str(_SCANNER), *args], cwd=repo, capture_output=True, text=True
        )
    return run([]), run(["--staged"])


def test_staged_prohibited_value_is_detected_even_when_worktree_is_safe() -> None:
    """CASE A — the commit would carry the value; the worktree hides it."""
    repo = _staged_repo(
        staged={"notes.md": ("contact " + _FAKE_EMAIL).encode()},
        worktree={"notes.md": b"nothing to see here\n"},
    )
    try:
        worktree_run, staged_run = _scan_modes(repo)
        assert staged_run.returncode == 1, "staged mode missed a staged prohibited value"
        assert "LV-PRIV-004" in staged_run.stdout
        assert _FAKE_EMAIL not in staged_run.stdout + staged_run.stderr
        # Worktree mode answers about the worktree, which is genuinely clean.
        assert worktree_run.returncode == 0
    finally:
        shutil.rmtree(repo, ignore_errors=True)


def test_staged_mode_ignores_unstaged_worktree_content() -> None:
    """CASE B — the value exists only on disk and is not part of the commit."""
    repo = _staged_repo(
        staged={"notes.md": b"nothing to see here\n"},
        worktree={"notes.md": ("contact " + _FAKE_EMAIL).encode()},
    )
    try:
        worktree_run, staged_run = _scan_modes(repo)
        assert staged_run.returncode == 0, "staged mode judged unstaged content"
        assert worktree_run.returncode == 1
    finally:
        shutil.rmtree(repo, ignore_errors=True)


def test_staged_symlink_target_is_scanned_from_the_index() -> None:
    repo = Path(tempfile.mkdtemp(prefix="staged_link_"))
    try:
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "t@invalid"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
        (repo / "lnk").symlink_to(_FAKE_PRIVATE_TARGET)
        subprocess.run(["git", "add", "-f", "lnk"], cwd=repo, check=True)
        # Diverge the worktree AFTER staging, so a worktree scan would see only
        # the harmless target. Without this the test passes even when --staged
        # is ignored, proving nothing about where the content came from.
        (repo / "lnk").unlink()
        (repo / "lnk").symlink_to("docs/harmless.md")
        proc = subprocess.run(
            [sys.executable, str(_SCANNER), "--staged"], cwd=repo,
            capture_output=True, text=True,
        )
        assert proc.returncode == 1
        assert "LV-PRIV-005" in proc.stdout
        assert _FAKE_PRIVATE_TARGET not in proc.stdout + proc.stderr
    finally:
        shutil.rmtree(repo, ignore_errors=True)


def test_staged_mode_handles_non_utf8_paths() -> None:
    repo = Path(tempfile.mkdtemp(prefix="staged_raw_"))
    try:
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "t@invalid"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
        raw = b"staged-\xff-notes.md"
        target = os.path.join(os.fsdecode(repo), os.fsdecode(raw))
        with open(os.fsencode(target), "wb") as fh:
            fh.write(("contact " + _FAKE_EMAIL).encode())
        subprocess.run(["git", "add", "-f", os.fsdecode(raw)], cwd=repo, check=True)
        # Diverge the worktree so only the staged blob carries the value.
        with open(os.fsencode(target), "wb") as fh:
            fh.write(b"nothing to see here\n")
        proc = subprocess.run(
            [sys.executable, str(_SCANNER), "--staged"], cwd=repo,
            capture_output=True, text=True,
        )
        assert proc.returncode == 1
        assert "LV-PRIV-004" in proc.stdout
    finally:
        shutil.rmtree(repo, ignore_errors=True)


def test_unknown_cli_argument_fails_closed() -> None:
    # argv was previously ignored entirely, so `--staged` ran a worktree scan and
    # exited 0 — the flag looked honoured while doing something else.
    proc = subprocess.run(
        [sys.executable, str(_SCANNER), "--nonsense"],
        cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True,
    )
    assert proc.returncode == 2
    # Assert the property (rejected, and the caller's text is not echoed) rather
    # than the exact prose, which changed once the message stopped quoting argv.
    assert "PRIVACY SCAN FAILED" in proc.stderr
    assert "--nonsense" not in proc.stdout + proc.stderr


def test_pre_commit_hook_uses_staged_mode() -> None:
    config = (Path(__file__).resolve().parents[1] / ".pre-commit-config.yaml").read_text()
    entry = next(l for l in config.splitlines() if l.strip().startswith("entry:"))
    assert "--staged" in entry, "the hook must judge the index, not the worktree"


def test_scan_repository_rejects_an_unknown_source() -> None:
    try:
        privacy_scan.scan_repository(source="whatever")
    except privacy_scan.ScanError:
        return
    raise AssertionError("an unknown scan source must fail closed")


# --- Regression: an unreadable git object must be a finding, not a pass ------
# _read_blob_bounded() ignored `git cat-file`'s exit status, so a missing or
# corrupt object returned empty content that then scanned CLEAN — the scanner's
# central invariant ("unscannable is a finding") inverted in the newest path.

_ABSENT_SHA = "0" * 40  # well-formed, not in any object store


def _index_repo_with_blob(content: bytes = b"hello\n") -> Path:
    repo = Path(tempfile.mkdtemp(prefix="blob_"))
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "t@invalid"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
    (repo / "a.txt").write_bytes(content)
    subprocess.run(["git", "add", "-f", "a.txt"], cwd=repo, check=True)
    return repo


def test_missing_blob_is_reported_unreadable_not_empty() -> None:
    repo = _index_repo_with_blob()
    try:
        data, oversized = privacy_scan._read_blob_bounded(repo, _ABSENT_SHA, 1024)
        assert oversized is None, "a missing object must be unreadable, not empty"
        assert data == b""
    finally:
        shutil.rmtree(repo, ignore_errors=True)


def test_entry_with_missing_blob_fails_closed() -> None:
    repo = _index_repo_with_blob()
    try:
        findings = privacy_scan.scan_index_entry("a.txt", "100644", _ABSENT_SHA, repo)
        assert "LV-PRIV-007" in _ids(findings), "an unreadable object scanned clean"
    finally:
        shutil.rmtree(repo, ignore_errors=True)


def test_malformed_blob_sha_fails_closed() -> None:
    repo = _index_repo_with_blob()
    try:
        _, oversized = privacy_scan._read_blob_bounded(repo, "not-a-sha", 1024)
        assert oversized is None
    finally:
        shutil.rmtree(repo, ignore_errors=True)


def test_legitimately_empty_blob_is_clean_not_unreadable() -> None:
    # The control that keeps the fix honest: empty content is a successful read
    # and must stay distinguishable from a failed one.
    repo = _index_repo_with_blob(b"")
    try:
        sha = subprocess.run(
            ["git", "rev-parse", ":a.txt"], cwd=repo, capture_output=True, text=True
        ).stdout.strip()
        data, oversized = privacy_scan._read_blob_bounded(repo, sha, 1024)
        assert oversized is False and data == b""
        assert privacy_scan.scan_index_entry("a.txt", "100644", sha, repo) == []
    finally:
        shutil.rmtree(repo, ignore_errors=True)


def test_oversized_blob_is_bounded_and_reported() -> None:
    limit = 512
    repo = _index_repo_with_blob(b"A" * (limit * 20))
    try:
        sha = subprocess.run(
            ["git", "rev-parse", ":a.txt"], cwd=repo, capture_output=True, text=True
        ).stdout.strip()
        data, oversized = privacy_scan._read_blob_bounded(repo, sha, limit)
        assert oversized is True and data == b""
    finally:
        shutil.rmtree(repo, ignore_errors=True)


def test_repeated_blob_reads_do_not_raise() -> None:
    # The reviewer also suspected proc.kill() could raise on an already-exited
    # process. Measured across 50 trials of each ordering and 200 helper calls:
    # it does not — CPython's send_signal() polls first and skips a reaped
    # process. Kept as a guard rather than a fix, since no defect was found.
    repo = _index_repo_with_blob()
    try:
        sha = subprocess.run(
            ["git", "rev-parse", ":a.txt"], cwd=repo, capture_output=True, text=True
        ).stdout.strip()
        for _ in range(25):
            assert privacy_scan._read_blob_bounded(repo, sha, 1024) == (b"hello\n", False)
    finally:
        shutil.rmtree(repo, ignore_errors=True)


# --- Regression: no error message echoes a caller-supplied value -------------
# The CLI's unknown-argument branch printed {arg!r}, reproducing whatever was
# passed. An argument is caller-supplied text that may itself be a prohibited
# value, and the output-safety guarantee is unconditional — it does not stop at
# the findings list. The same class existed in scan_repository()'s ScanError.


def _cli(args):
    return subprocess.run(
        [sys.executable, str(_SCANNER), *args],
        cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True,
    )


def test_unknown_argument_is_not_echoed() -> None:
    for value in (_FAKE_EMAIL, _FAKE_HOME, _FAKE_GH_TOKEN, _FAKE_EXPORT_ZIP):
        proc = _cli([value])
        assert proc.returncode == 2
        assert value not in proc.stdout + proc.stderr, f"{value!r} was echoed"


def test_unknown_argument_still_fails_closed() -> None:
    # The fix must not turn a rejection into an acceptance.
    proc = _cli(["--nonsense"])
    assert proc.returncode == 2
    assert "unrecognised argument" in proc.stderr


def test_valid_modes_still_run() -> None:
    for mode in ("--staged", "--worktree"):
        assert _cli([mode]).returncode == 0


def test_scan_repository_error_does_not_echo_its_argument() -> None:
    try:
        privacy_scan.scan_repository(source=_FAKE_HOME)
    except privacy_scan.ScanError as exc:
        assert _FAKE_HOME not in str(exc)
        return
    raise AssertionError("an unknown scan source must fail closed")


def test_scan_error_messages_are_string_literals() -> None:
    """The structural guard, stated as the property rather than one syntax.

    main() prints ScanError text verbatim to stderr, so safety must hold at every
    construction site. The first version of this guard rejected only f-strings,
    which is one *way* of interpolating rather than the property itself —
    `"x " + value`, `"x {}".format(value)` and `"x %s" % value` all bypassed it.

    The invariant is: **a ScanError message is a fixed string literal**, so no
    caller-controlled value can reach stderr through it.

    FORWARD GUARD, not a fix. All five current sites already comply; no unsafe
    behaviour was reproduced. This closes the remaining ways to violate the rule
    in future, and is not counted as a defect fixed.
    """
    source = (Path(__file__).resolve().parents[1] / "scripts" / "privacy_scan.py").read_text()
    offenders = []
    for node in ast.walk(ast.parse(source)):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "ScanError"
            and node.args
        ):
            arg = node.args[0]
            if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
                offenders.append((node.lineno, type(arg).__name__))
    assert not offenders, f"ScanError message is not a string literal at {offenders}"


def test_scan_error_guard_rejects_every_interpolation_form() -> None:
    """Prove the guard can go red — for each bypass the old version allowed."""

    def offends(expr: str) -> bool:
        node = ast.parse(expr).body[0].value
        arg = node.args[0]
        return not (isinstance(arg, ast.Constant) and isinstance(arg.value, str))

    for expr in (
        'ScanError(f"bad {source!r}")',
        'ScanError("bad " + source)',
        'ScanError("bad {}".format(source))',
        'ScanError("bad %s" % source)',
        "ScanError(message)",
    ):
        assert offends(expr), f"guard would accept {expr}"
    # …and still accepts a plain literal, including implicit concatenation.
    assert not offends('ScanError("a fixed message")')
    assert not offends('ScanError("a fixed " "message")')


# --- New-Code Invariant Gate: the missing three-state witness ----------------
# Rule B requires every I/O boundary to distinguish success, LEGITIMATE EMPTY,
# and failure. The worktree read path (_read_file_bounded, added with the
# bounded-read fix) had witnesses for success, failure and boundary but none for
# legitimate empty. Behaviour was already correct; the proof was absent.
#
# Classification: PROPERTY PIN, not a regression. It passes against the earlier
# head too, because the defect was in the witness set rather than the code.


def test_scan_of_empty_file_is_clean() -> None:
    with tempfile.TemporaryDirectory() as d:
        empty = Path(d) / "empty.txt"
        empty.write_bytes(b"")
        data, oversized = privacy_scan._read_file_bounded(empty, 1024)
        assert (data, oversized) == (b"", False), "empty must read as success"
        assert scan_tracked_entry("empty.txt", empty) == []


def test_empty_file_is_distinguishable_from_an_unreadable_one() -> None:
    # The distinction Rule B exists to protect: a fail-closed system must never
    # collapse "could not read" into "read nothing".
    with tempfile.TemporaryDirectory() as d:
        empty = Path(d) / "empty.txt"
        empty.write_bytes(b"")
        missing = Path(d) / "gone.txt"
        assert privacy_scan._read_file_bounded(empty, 1024)[1] is False
        assert privacy_scan._read_file_bounded(missing, 1024)[1] is None
        assert scan_tracked_entry("empty.txt", empty) == []
        assert "LV-PRIV-007" in _ids(scan_tracked_entry("gone.txt", missing))


def test_empty_file_with_archive_extension_fails_closed() -> None:
    # Empty content that claims to be an archive is unscannable, not clean.
    with tempfile.TemporaryDirectory() as d:
        target = Path(d) / "empty.zip"
        target.write_bytes(b"")
        assert "LV-PRIV-007" in _ids(scan_tracked_entry("empty.zip", target))


# =============================================================================
# OWNER FINDING O4 — a bare home directory is a local private path
# The identifying username is revealed by `/home/<user>` exactly as by
# `/home/<user>/file.txt`. A descendant component does not make the user more
# private, and `_LOCAL_PATH_WIN` had always flagged the bare Windows root, so
# the three other spellings were also internally inconsistent.
# Witnesses cover each production family that handles these differently.
# =============================================================================

_O4_USER = "alice"
_O4_BARE = {
    "posix": "/ho" + "me/" + _O4_USER,
    "macos": "/Us" + "ers/" + _O4_USER,
    "win_fwd": "C:/Us" + "ers/" + _O4_USER,
    "win_native": "C:" + chr(92) + "Us" + "ers" + chr(92) + _O4_USER,
}


def test_o4_bare_home_detected_in_content() -> None:
    for label, bare in _O4_BARE.items():
        assert "LV-PRIV-005" in _ids(scan_text("f.md", bare)), label


def test_o4_bare_home_detected_in_archive_member_name() -> None:
    for label, bare in _O4_BARE.items():
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(bare, b"innocuous")
        assert "LV-PRIV-005" in _ids(scan_archive("a.zip", buf.getvalue(), kind="zip")), label


def test_o4_bare_home_detected_in_tar_link_target() -> None:
    for label, bare in _O4_BARE.items():
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            info = tarfile.TarInfo("link")
            info.type = tarfile.SYMTYPE
            info.linkname = bare
            tf.addfile(info)
        assert "LV-PRIV-005" in _ids(scan_archive("a.tar", buf.getvalue(), kind="tar")), label


def test_o4_bare_home_detected_in_filesystem_symlink_target() -> None:
    for label, bare in _O4_BARE.items():
        if chr(92) in bare:
            continue  # a native Windows path is not a valid POSIX link target here
        with tempfile.TemporaryDirectory() as d:
            link = Path(d) / "lnk"
            link.symlink_to(bare)
            assert "LV-PRIV-005" in _ids(scan_tracked_entry("lnk", link)), label


def test_o4_bare_home_identity_is_redacted_in_output() -> None:
    for label, bare in _O4_BARE.items():
        rendered = safe_location(bare)
        assert _O4_USER not in rendered, f"{label}: identity survived as {rendered!r}"


def test_o4_cli_detects_bare_home_without_exposing_it() -> None:
    # The real production entry point, for both a link target and a member name.
    with tempfile.TemporaryDirectory() as d:
        repo = Path(d)
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "t@invalid"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
        (repo / "lnk").symlink_to(_O4_BARE["posix"])
        subprocess.run(["git", "add", "-f", "lnk"], cwd=repo, check=True)
        proc = subprocess.run(
            [sys.executable, str(_SCANNER)], cwd=repo, capture_output=True, text=True
        )
    assert proc.returncode == 1
    assert "LV-PRIV-005" in proc.stdout
    assert _O4_USER not in proc.stdout + proc.stderr


# --- O4 negative controls: widening must not create false positives ----------


def test_o4_url_path_segments_are_not_flagged() -> None:
    # The new branch is deliberately narrower than the existing one: a URL's
    # host supplies an alphanumeric immediately before the path, which excludes
    # it. Without this the widening would flag ordinary documentation links.
    for text in (
        "https://example.com/home/index",
        "http://host.example/home/dashboard",
        "https://example.com/Users/profile",
        "see https://x.example/home/about for docs",
    ):
        assert "LV-PRIV-005" not in _ids(scan_text("f.md", text)), text


def test_o4_repository_relative_equivalents_stay_clean() -> None:
    for text in (f"docs/home/{_O4_USER}", f"home/{_O4_USER}", f"Users/{_O4_USER}"):
        assert "LV-PRIV-005" not in _ids(scan_text("f.md", text)), text
        assert "LV-PRIV-005" not in rules_for_name(text, repo_relative=False), text


def test_o4_home_root_without_a_username_is_not_flagged() -> None:
    # No identifying component is present, so there is nothing to protect.
    for text in ("/home/", "/home", "/Users/", "/Users"):
        assert "LV-PRIV-005" not in _ids(scan_text("f.md", text)), text


def test_o4_word_beginning_with_home_is_not_flagged() -> None:
    assert "LV-PRIV-005" not in _ids(scan_text("f.md", "/homeless-shelter/notes"))


def test_o4_descendant_paths_still_detected() -> None:
    # The pre-existing branch must be untouched by the addition.
    for bare in _O4_BARE.values():
        sep = chr(92) if chr(92) in bare else "/"
        assert "LV-PRIV-005" in _ids(scan_text("f.md", bare + sep + "file.txt"))


# --- Contract-accuracy guards -------------------------------------------------
# A docstring that DEFINES a security invariant is part of the contract. When the
# guard was strengthened from "no f-string" to "must be a literal" and renamed,
# the docstring kept pointing at the old name and the old, weaker scope — so the
# text at the definition site understated what is enforced and named a test that
# no longer existed. A future editor reading it would believe `"x " + value` was
# permitted. The fix is to correct the prose, never to weaken the guard to match.


def test_scan_error_docstring_names_an_existing_test() -> None:
    doc = privacy_scan.ScanError.__doc__ or ""
    referenced = set(re.findall(r"test_[a-z0-9_]+", doc))
    assert referenced, "the contract must name the test that enforces it"
    defined = {
        node.name
        for node in ast.walk(ast.parse(Path(__file__).read_text()))
        if isinstance(node, ast.FunctionDef)
    }
    missing = sorted(name for name in referenced if name not in defined)
    assert not missing, f"ScanError docstring names non-existent test(s): {missing}"


def test_scan_error_docstring_does_not_understate_the_guard() -> None:
    # The enforced property is "string literal". Prose implying only f-strings
    # are rejected is weaker than reality and misleads future edits.
    doc = privacy_scan.ScanError.__doc__ or ""
    assert "literal" in doc, "the contract must state the literal-only rule"
    assert ".format(" in doc or "concatenat" in doc.lower(), (
        "the contract must make clear that non-f-string interpolation is also rejected"
    )


def test_repo_root_failure_message_covers_both_causes() -> None:
    """`_repo_root()` catches OSError *and* CalledProcessError.

    Reproduces both classes through a subprocess and requires one accurate fixed
    literal. Diagnostic correctness, not a privacy bypass — but the message is
    still output, so it must name no path.
    """
    code = (
        "import sys; sys.path.insert(0, %r); import privacy_scan as ps\n"
        "try:\n"
        "    ps._repo_root()\n"
        "except ps.ScanError as e:\n"
        "    print('SCANERROR:' + str(e))\n"
        "else:\n"
        "    print('NOERROR')\n"
        % str(Path(__file__).resolve().parents[1] / "scripts")
    )
    messages = {}
    # A: git cannot be executed at all.
    with tempfile.TemporaryDirectory() as shim:
        for tool in ("sh", "bash"):
            found = shutil.which(tool)
            if found:
                os.symlink(found, os.path.join(shim, tool))
        proc = subprocess.run(
            [sys.executable, "-c", code],
            cwd=str(Path(__file__).resolve().parents[1]),
            env={**os.environ, "PATH": shim}, capture_output=True, text=True,
        )
        messages["git-unavailable"] = proc.stdout.strip()
    # B: git works, but the working directory is not a repository.
    with tempfile.TemporaryDirectory() as outside:
        proc = subprocess.run(
            [sys.executable, "-c", code], cwd=outside, capture_output=True, text=True
        )
        messages["not-a-repository"] = proc.stdout.strip()

    expected = (
        "cannot determine repository root "
        "(git unavailable, or not inside a git repository)"
    )
    for label, out in messages.items():
        assert out.startswith("SCANERROR:"), f"{label}: {out}"
        text = out[len("SCANERROR:"):]
        # Exact match, so the assertion cannot be satisfied vacuously: it pins
        # both that the message names both causes and that it carries no path,
        # for each cause independently.
        assert text == expected, f"{label}: {text!r}"


_TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]


if __name__ == "__main__":
    for test in _TESTS:
        test()
    print(f"Privacy scan tests passed ({len(_TESTS)} cases).")
