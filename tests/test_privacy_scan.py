"""Tests for scripts/privacy_scan.py.

All prohibited values here are synthetic (reserved example domains, obviously
fake tokens, invented paths, runtime-built hex). This file is on the scanner's
allowlist, so its synthetic literals do not trip the repository scan; the tests
call the scanner functions directly on in-memory strings and temp files created
outside the tracked tree.

Coverage is organised as: per-rule detection (positive), false-positive guards
(negative), bounds/edge behaviour (boundary), and adversarial bypass regressions
(each one corresponds to a bypass that was demonstrated against an earlier
revision of the scanner).
"""

from __future__ import annotations

import io
import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import privacy_scan  # noqa: E402
from privacy_scan import (  # noqa: E402
    ALL_RULES,
    ALLOWLIST,
    rules_for_name,
    scan_archive,
    scan_bytes,
    scan_text,
    scan_tracked_entry,
    text_views,
)

# Synthetic constants (never copied from any real export).
_FAKE_HEX = "deadbeef" * 8  # 64 hex chars, obviously synthetic
_FAKE_GH_TOKEN = "ghp_" + "A" * 36
_FAKE_EMAIL = "person@example.com"  # reserved example domain
_FAKE_HOME = "/home/alice/vault/records/x"


def _ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


def _tmp_file(d: Path, name: str, data: bytes) -> Path:
    p = d / name
    p.write_bytes(data)
    return p


# --- per-rule detection (positive) -------------------------------------------


def test_synthetic_private_export_filename_rejected() -> None:
    assert "LV-PRIV-001" in _ids(
        scan_text("report.md", "Source archive: SyntheticVault RawRecord 2000-01-01.zip")
    )


def test_synthetic_private_export_digest_rejected() -> None:
    assert "LV-PRIV-002" in _ids(scan_text("report.md", "Private export SHA-256: " + _FAKE_HEX))


def test_email_rejected() -> None:
    assert "LV-PRIV-004" in _ids(scan_text("notes.md", "reach me at " + _FAKE_EMAIL))


def test_fake_api_token_rejected() -> None:
    assert "LV-PRIV-003" in _ids(scan_text("config.txt", "token = " + _FAKE_GH_TOKEN))


def test_private_key_header_rejected() -> None:
    assert "LV-PRIV-003" in _ids(scan_text("key.txt", "-----BEGIN RSA PRIVATE KEY-----"))


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
    assert rules_for_name("docs/home/alice/guide.md") == []


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


def test_allowlist_is_rule_scoped_and_narrow() -> None:
    assert set(ALLOWLIST) == {
        "scripts/privacy_scan.py",
        "tests/test_privacy_scan.py",
        ".gitignore",
    }
    # .gitignore may name export payloads/archives, but is NOT trusted for
    # secrets, personal identifiers, or local paths.
    gitignore_exempt = ALLOWLIST[".gitignore"]
    assert gitignore_exempt == {"LV-PRIV-001", "LV-PRIV-006"}
    for rule in ("LV-PRIV-002", "LV-PRIV-003", "LV-PRIV-004", "LV-PRIV-005", "LV-PRIV-007"):
        assert rule not in gitignore_exempt
    assert ALLOWLIST["scripts/privacy_scan.py"] == ALL_RULES


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
        "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    ):
        assert "LV-PRIV-003" in _ids(scan_text("c.txt", line)), line


def test_lowercase_windows_user_path_detected() -> None:
    assert "LV-PRIV-005" in _ids(scan_text("r.md", r"saved to c:\users\bob\vault\rec.json"))


def test_export_archive_with_other_extension_detected() -> None:
    assert "LV-PRIV-001" in _ids(
        scan_text("r.md", "archive: SyntheticVault RawRecord 2000-01-01.tar.gz")
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
        link.symlink_to("/home/someone/Legend-Vault-Data/records/r.json")
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
    assert "LV-PRIV-001" in rules_for_name("archive/ChatGPT Export 2000.zip")
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


_TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]


if __name__ == "__main__":
    for test in _TESTS:
        test()
    print(f"Privacy scan tests passed ({len(_TESTS)} cases).")
