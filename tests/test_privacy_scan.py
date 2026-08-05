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
import io
import lzma
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
    """Temporarily shrink the scanner's bounds."""
    return (
        (privacy_scan._MAX_TOTAL_BYTES, privacy_scan._MAX_MEMBER_BYTES),
        setattr(privacy_scan, "_MAX_TOTAL_BYTES", total),
        setattr(privacy_scan, "_MAX_MEMBER_BYTES", member),
    )[0]


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


_TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]


if __name__ == "__main__":
    for test in _TESTS:
        test()
    print(f"Privacy scan tests passed ({len(_TESTS)} cases).")
