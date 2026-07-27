"""Tests for scripts/privacy_scan.py.

All prohibited values here are synthetic (reserved example domains, obviously
fake tokens, invented paths, runtime-built hex). This file is on the scanner's
allowlist, so its synthetic literals do not trip the repository scan; the tests
call the scanner functions directly on in-memory strings and temp files created
outside the tracked tree.
"""

from __future__ import annotations

import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import privacy_scan  # noqa: E402
from privacy_scan import (  # noqa: E402
    rules_for_name,
    scan_text,
    scan_tracked_file,
    scan_zip,
)

# Synthetic constants (never copied from any real export).
_FAKE_HEX = "deadbeef" * 8  # 64 hex chars, obviously synthetic
_FAKE_GH_TOKEN = "ghp_" + "A" * 36
_FAKE_EMAIL = "person@example.com"  # reserved example domain
_FAKE_HOME = "/home/alice/vault/records/x"


def _rule_ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


def test_synthetic_private_export_filename_rejected() -> None:
    findings = scan_text("report.md", "Source archive: SyntheticVault RawRecord 2000-01-01.zip")
    assert "LV-PRIV-001" in _rule_ids(findings)


def test_synthetic_private_export_digest_rejected() -> None:
    findings = scan_text("report.md", "Private export SHA-256: " + _FAKE_HEX)
    assert "LV-PRIV-002" in _rule_ids(findings)


def test_public_source_manifest_hash_not_flagged() -> None:
    # A bare manifest hash line (no export/private label) must not be flagged.
    findings = scan_text("SOURCE_MANIFEST.json", '  "sha256": "' + _FAKE_HEX + '"')
    assert findings == []


def test_email_rejected() -> None:
    findings = scan_text("notes.md", "reach me at " + _FAKE_EMAIL)
    assert "LV-PRIV-004" in _rule_ids(findings)


def test_fake_api_token_rejected() -> None:
    findings = scan_text("config.txt", "token = " + _FAKE_GH_TOKEN)
    assert "LV-PRIV-003" in _rule_ids(findings)


def test_private_key_header_rejected() -> None:
    findings = scan_text("key.txt", "-----BEGIN RSA PRIVATE KEY-----")
    assert "LV-PRIV-003" in _rule_ids(findings)


def test_local_user_path_rejected() -> None:
    findings = scan_text("log.md", "wrote record to " + _FAKE_HOME)
    assert "LV-PRIV-005" in _rule_ids(findings)


def test_payload_filename_rejected_by_name() -> None:
    assert "LV-PRIV-006" in rules_for_name("user.json")
    assert "LV-PRIV-006" in rules_for_name("conversations-3.json")
    assert "LV-PRIV-006" in rules_for_name("some/dir/asset.dat")
    assert "LV-PRIV-006" not in rules_for_name("src/legend_vault/core.py")


def test_safe_synthetic_fixture_passes() -> None:
    findings = scan_text("fixtures/example.md", "a small deterministic synthetic fixture")
    assert findings == []


def test_prohibited_value_in_markdown_detected() -> None:
    with tempfile.TemporaryDirectory() as d:
        md = Path(d) / "report.md"
        md.write_text("Private export digest: " + _FAKE_HEX + "\n", encoding="utf-8")
        findings = scan_tracked_file("report.md", md)
    assert "LV-PRIV-002" in _rule_ids(findings)


def test_prohibited_value_in_zip_text_member_detected() -> None:
    with tempfile.TemporaryDirectory() as d:
        z = Path(d) / "bundle.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("notes/leak.md", "contact " + _FAKE_EMAIL + "\n")
        findings = scan_zip("bundle.zip", z)
    assert "LV-PRIV-004" in _rule_ids(findings)


def test_finding_str_does_not_reproduce_value() -> None:
    findings = scan_text("c.txt", "token=" + _FAKE_GH_TOKEN)
    assert findings
    for f in findings:
        rendered = str(f)
        assert _FAKE_GH_TOKEN not in rendered
        assert _FAKE_GH_TOKEN not in f.path
        assert rendered == f"{f.path}:{f.line}: {f.rule_id}"


def test_sanitized_stress_report_passes() -> None:
    root = Path(__file__).resolve().parents[1]
    rel = "LegendVault_Stress_Test_Report_v2.md"
    findings = scan_tracked_file(rel, root / rel)
    assert findings == [], [str(f) for f in findings]


_TESTS = [
    test_synthetic_private_export_filename_rejected,
    test_synthetic_private_export_digest_rejected,
    test_public_source_manifest_hash_not_flagged,
    test_email_rejected,
    test_fake_api_token_rejected,
    test_private_key_header_rejected,
    test_local_user_path_rejected,
    test_payload_filename_rejected_by_name,
    test_safe_synthetic_fixture_passes,
    test_prohibited_value_in_markdown_detected,
    test_prohibited_value_in_zip_text_member_detected,
    test_finding_str_does_not_reproduce_value,
    test_sanitized_stress_report_passes,
]


if __name__ == "__main__":
    for test in _TESTS:
        test()
    print(f"Privacy scan tests passed ({len(_TESTS)} cases).")
