#!/usr/bin/env python3
"""
Legend Vault verifier and fault-injection harness.

Standard-library only.

Usage:
    python legend_vault_verify.py ARCHIVE.zip
    python legend_vault_verify.py ARCHIVE.zip --fault-test
    python legend_vault_verify.py ARCHIVE.zip --fault-test --json-out results.json

Exit codes:
    0: accepted by the verifier (warnings may exist)
    1: rejected because one or more validation errors were found
    2: invocation or runtime failure
"""
from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import sys
import unicodedata
import zipfile
from typing import Any

VERSION = "0.1.1"

REQUIRED_FILES = {
    "README.md",
    "integrity/hashes.json",
    "integrity/gaps.json",
    "integrity/manifest.json",
    "raw/transcript.md",
}

EVENT_RE = re.compile(
    r"^## (?P<seq>\d+)\. (?P<role>[A-Z]+)\n"
    r"\*\*Timestamp:\*\* (?P<timestamp>.+?)\n\n",
    re.MULTILINE,
)

HEADING_RE = re.compile(r"^#{1,6}\s", re.MULTILINE)

VALID_ROLES = {"USER", "ASSISTANT", "TOOL", "SYSTEM"}
HASH_LEDGER_EXEMPT = {"integrity/hashes.json"}  # self-reference is impossible


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_zip(blob: bytes) -> tuple[list[zipfile.ZipInfo], dict[str, bytes], str | None]:
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        infos = zf.infolist()
        files: dict[str, bytes] = {}
        for info in infos:
            # Keep the last copy in files, while duplicate-name checks use infos.
            files[info.filename] = zf.read(info)
        bad_crc = zf.testzip()
    return infos, files, bad_crc


def add_error(result: dict[str, Any], code: str, detail: str) -> None:
    result["errors"].append({"code": code, "detail": detail})


def add_warning(result: dict[str, Any], code: str, detail: str) -> None:
    result["warnings"].append({"code": code, "detail": detail})


def add_pass(result: dict[str, Any], code: str, detail: str) -> None:
    result["passes"].append({"code": code, "detail": detail})


def validate_archive(
    blob: bytes,
    *,
    max_total_uncompressed: int = 500 * 1024 * 1024,
    max_entry_uncompressed: int = 200 * 1024 * 1024,
    max_compression_ratio: float = 100.0,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "verifier_version": VERSION,
        "archive_sha256": sha256_bytes(blob),
        "errors": [],
        "warnings": [],
        "passes": [],
        "metrics": {},
        "accepted": False,
    }

    try:
        infos, files, bad_crc = load_zip(blob)
    except Exception as exc:
        add_error(result, "ZIP_OPEN_FAILED", f"{type(exc).__name__}: {exc}")
        return result

    names = [info.filename for info in infos]
    result["metrics"]["zip_entry_count"] = len(names)
    result["metrics"]["zip_total_compressed_bytes"] = sum(info.compress_size for info in infos)
    result["metrics"]["zip_total_uncompressed_bytes"] = sum(info.file_size for info in infos)

    if bad_crc:
        add_error(result, "ZIP_CRC_FAILURE", bad_crc)
    else:
        add_pass(result, "ZIP_CRC_OK", "All entry CRC checks passed.")

    if result["metrics"]["zip_total_uncompressed_bytes"] > max_total_uncompressed:
        add_error(
            result,
            "ZIP_TOTAL_LIMIT",
            f"Uncompressed total exceeds {max_total_uncompressed} bytes.",
        )

    for info in infos:
        name = info.filename
        normalized = os.path.normpath(name)
        if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
            add_error(result, "ABSOLUTE_PATH", name)
        if normalized.startswith("..") or "/../" in f"/{name}/":
            add_error(result, "PATH_TRAVERSAL", name)
        if "\\" in name:
            add_warning(result, "BACKSLASH_PATH", name)

        mode = (info.external_attr >> 16) & 0xFFFF
        if (mode & 0o170000) == 0o120000:
            add_error(result, "SYMLINK_ENTRY", name)

        if info.flag_bits & 0x1:
            add_warning(result, "ENCRYPTED_ENTRY", name)

        if info.file_size > max_entry_uncompressed:
            add_error(
                result,
                "ZIP_ENTRY_LIMIT",
                f"{name}: {info.file_size} bytes exceeds {max_entry_uncompressed}.",
            )

        ratio = (
            info.file_size / info.compress_size
            if info.compress_size
            else (math.inf if info.file_size else 1.0)
        )
        if ratio > max_compression_ratio:
            add_error(
                result,
                "ZIP_COMPRESSION_RATIO",
                f"{name}: ratio={ratio:.2f}, limit={max_compression_ratio:.2f}",
            )

    counts = collections.Counter(names)
    for name, count in counts.items():
        if count > 1:
            add_error(result, "DUPLICATE_PATH", f"{name} appears {count} times.")

    case_map: dict[str, list[str]] = collections.defaultdict(list)
    nfc_map: dict[str, list[str]] = collections.defaultdict(list)
    for name in names:
        case_map[name.casefold()].append(name)
        nfc_map[unicodedata.normalize("NFC", name)].append(name)

    for values in case_map.values():
        if len(values) > 1 and len(set(values)) > 1:
            add_error(result, "CASE_COLLISION", repr(values))
    for values in nfc_map.values():
        if len(values) > 1 and len(set(values)) > 1:
            add_error(result, "UNICODE_COLLISION", repr(values))

    for required in sorted(REQUIRED_FILES - set(names)):
        add_error(result, "MISSING_REQUIRED_FILE", required)

    parsed_json: dict[str, Any] = {}
    for name in (
        "integrity/hashes.json",
        "integrity/gaps.json",
        "integrity/manifest.json",
    ):
        if name not in files:
            continue
        try:
            parsed_json[name] = json.loads(files[name])
            add_pass(result, "JSON_VALID", name)
        except Exception as exc:
            add_error(result, "INVALID_JSON", f"{name}: {exc}")

    manifest = parsed_json.get("integrity/manifest.json", {})
    manifest_entries = manifest.get("files", []) if isinstance(manifest, dict) else []
    manifest_paths = [
        entry.get("path")
        for entry in manifest_entries
        if isinstance(entry, dict) and isinstance(entry.get("path"), str)
    ]

    for name in sorted(set(names) - set(manifest_paths)):
        add_error(result, "UNMANIFESTED_FILE", name)
    for name in sorted(set(manifest_paths) - set(names)):
        add_error(result, "MANIFEST_PHANTOM_FILE", name)

    for entry in manifest_entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            add_error(result, "MALFORMED_MANIFEST_ENTRY", repr(entry))
            continue
        path = entry["path"]
        if path not in files:
            continue

        if "bytes" not in entry:
            add_warning(result, "MANIFEST_SIZE_MISSING", path)
        elif entry["bytes"] != len(files[path]):
            add_error(
                result,
                "MANIFEST_SIZE_MISMATCH",
                f"{path}: expected={entry['bytes']}, actual={len(files[path])}",
            )

        if "sha256" not in entry:
            add_warning(result, "MANIFEST_HASH_MISSING", path)
        else:
            actual = sha256_bytes(files[path])
            if entry["sha256"] != actual:
                add_error(
                    result,
                    "MANIFEST_HASH_MISMATCH",
                    f"{path}: expected={entry['sha256']}, actual={actual}",
                )

    hash_obj = parsed_json.get("integrity/hashes.json", {})
    ledger = hash_obj.get("entries", {}) if isinstance(hash_obj, dict) else {}
    if not isinstance(ledger, dict):
        add_error(result, "MALFORMED_HASH_LEDGER", "entries must be an object")
        ledger = {}

    for name in names:
        if name in HASH_LEDGER_EXEMPT:
            continue
        if name not in ledger:
            add_error(
                result,
                "HASH_LEDGER_MISSING",
                f"{name}: every archive file except integrity/hashes.json must be hashed.",
            )
    for name, expected in ledger.items():
        if name not in files:
            add_error(result, "HASH_LEDGER_PHANTOM", name)
            continue
        actual = sha256_bytes(files[name])
        if expected != actual:
            add_error(
                result,
                "HASH_LEDGER_MISMATCH",
                f"{name}: expected={expected}, actual={actual}",
            )

    if "raw/transcript.md" in files:
        try:
            transcript = files["raw/transcript.md"].decode("utf-8")
            add_pass(result, "TRANSCRIPT_UTF8", "raw/transcript.md decodes as UTF-8.")
        except UnicodeDecodeError as exc:
            add_error(result, "TRANSCRIPT_ENCODING", str(exc))
            transcript = ""

        if transcript:
            event_matches = list(EVENT_RE.finditer(transcript))
            result["metrics"]["event_count"] = len(event_matches)
            roles = [match.group("role") for match in event_matches]
            result["metrics"]["role_counts"] = dict(collections.Counter(roles))

            if not event_matches:
                add_error(result, "NO_EVENTS_PARSED", "No event headings matched.")
            else:
                seqs = [int(match.group("seq")) for match in event_matches]
                contiguous = seqs == list(range(1, max(seqs) + 1))
                if contiguous:
                    add_pass(
                        result,
                        "EVENT_SEQUENCE_CONTIGUOUS",
                        f"Events are contiguous from 1 through {max(seqs)}.",
                    )
                else:
                    add_error(
                        result,
                        "EVENT_SEQUENCE_FAILURE",
                        f"Parsed sequence begins {seqs[:5]} and ends {seqs[-5:]}.",
                    )

                manifest_count = manifest.get("record_count") if isinstance(manifest, dict) else None
                if manifest_count is not None and manifest_count != len(event_matches):
                    add_error(
                        result,
                        "RECORD_COUNT_MISMATCH",
                        f"manifest={manifest_count}, parsed={len(event_matches)}",
                    )

                unknown_roles = sorted(set(roles) - VALID_ROLES)
                for role in unknown_roles:
                    add_warning(result, "UNKNOWN_ROLE", role)

                valid_timestamp_count = 0
                unavailable_timestamp_count = 0
                invalid_timestamp_count = 0
                prior_known: tuple[int, dt.datetime] | None = None
                for match in event_matches:
                    seq = int(match.group("seq"))
                    raw_timestamp = match.group("timestamp").strip()
                    if raw_timestamp == "timestamp unavailable":
                        unavailable_timestamp_count += 1
                        continue
                    try:
                        parsed = dt.datetime.fromisoformat(
                            raw_timestamp.replace("Z", "+00:00")
                        )
                        valid_timestamp_count += 1
                    except ValueError:
                        invalid_timestamp_count += 1
                        add_error(
                            result,
                            "INVALID_TIMESTAMP",
                            f"event={seq}: {raw_timestamp}",
                        )
                        continue

                    if prior_known and parsed < prior_known[1]:
                        add_error(
                            result,
                            "TIMESTAMP_NONMONOTONIC",
                            (
                                f"event {seq} ({parsed.isoformat()}) precedes "
                                f"event {prior_known[0]} ({prior_known[1].isoformat()})"
                            ),
                        )
                    prior_known = (seq, parsed)

                result["metrics"]["valid_timestamp_count"] = valid_timestamp_count
                result["metrics"]["unavailable_timestamp_count"] = unavailable_timestamp_count
                result["metrics"]["invalid_timestamp_count"] = invalid_timestamp_count

            fence_line_count = sum(
                1 for line in transcript.splitlines() if line.startswith("```")
            )
            result["metrics"]["code_fence_line_count"] = fence_line_count
            if fence_line_count % 2:
                add_error(
                    result,
                    "UNBALANCED_CODE_FENCES",
                    f"{fence_line_count} fence lines is odd.",
                )
            else:
                add_pass(
                    result,
                    "CODE_FENCES_BALANCED",
                    f"{fence_line_count} fence lines.",
                )

            # Heading formula:
            # all Markdown headings minus the archive title minus all event headings.
            all_heading_count = len(HEADING_RE.findall(transcript))
            archive_title_count = 1 if transcript.startswith("# Legend Vault Raw Conversation Record") else 0
            event_heading_count = len(event_matches)
            internal_heading_count = (
                all_heading_count - archive_title_count - event_heading_count
            )
            result["metrics"]["all_markdown_heading_count"] = all_heading_count
            result["metrics"]["archive_title_heading_count"] = archive_title_count
            result["metrics"]["event_heading_count"] = event_heading_count
            result["metrics"]["internal_message_heading_count"] = internal_heading_count

    result["accepted"] = len(result["errors"]) == 0
    return result


def rebuild_zip(files: dict[str, bytes], duplicate: tuple[str, bytes] | None = None) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name in sorted(files):
            zf.writestr(name, files[name])
        if duplicate is not None:
            zf.writestr(duplicate[0], duplicate[1])
    return output.getvalue()


def set_transcript_hashes(files: dict[str, bytes]) -> None:
    digest = sha256_bytes(files["raw/transcript.md"])

    hash_obj = json.loads(files["integrity/hashes.json"])
    hash_obj.setdefault("entries", {})["raw/transcript.md"] = digest
    files["integrity/hashes.json"] = json.dumps(
        hash_obj, ensure_ascii=False, indent=2
    ).encode("utf-8")

    manifest = json.loads(files["integrity/manifest.json"])
    for entry in manifest.get("files", []):
        if entry.get("path") == "raw/transcript.md":
            entry["sha256"] = digest
            entry["bytes"] = len(files["raw/transcript.md"])
    files["integrity/manifest.json"] = json.dumps(
        manifest, ensure_ascii=False, indent=2
    ).encode("utf-8")

    # A coordinated editor can regenerate the complete internal ledger.
    # This remains indistinguishable without an external trust anchor.
    strict = build_strict_internal_ledger(files)
    files.clear()
    files.update(strict)



def build_strict_internal_ledger(files: dict[str, bytes]) -> dict[str, bytes]:
    """
    Return a copy whose internal ledger hashes every archive file except
    integrity/hashes.json. The ledger cannot hash itself without recursion.
    An external archive/root receipt is still required for authenticity.
    """
    repaired = dict(files)
    hash_obj = json.loads(repaired["integrity/hashes.json"])
    hash_obj["algorithm"] = "SHA-256"
    hash_obj["coverage"] = (
        "Every archive file except integrity/hashes.json; "
        "the ledger itself requires an external trust anchor."
    )
    hash_obj["entries"] = {
        name: sha256_bytes(data)
        for name, data in sorted(repaired.items())
        if name not in HASH_LEDGER_EXEMPT
    }
    repaired["integrity/hashes.json"] = json.dumps(
        hash_obj, ensure_ascii=False, indent=2
    ).encode("utf-8")
    return repaired


def run_fault_tests(original_blob: bytes) -> dict[str, Any]:
    _, original_files, _ = load_zip(original_blob)
    original_files = build_strict_internal_ledger(original_files)
    scenarios: list[dict[str, Any]] = []

    def execute(
        name: str,
        mutated_blob: bytes,
        *,
        should_reject: bool,
        purpose: str,
    ) -> None:
        validation = validate_archive(mutated_blob)
        rejected = not validation["accepted"]
        scenarios.append(
            {
                "name": name,
                "purpose": purpose,
                "should_reject": should_reject,
                "rejected": rejected,
                "expectation_met": rejected == should_reject,
                "errors": validation["errors"],
                "warnings": validation["warnings"],
            }
        )

    files = dict(original_files)
    changed = bytearray(files["raw/transcript.md"])
    changed[min(500, len(changed) - 1)] ^= 1
    files["raw/transcript.md"] = bytes(changed)
    execute(
        "Transcript bit flip; hashes unchanged",
        rebuild_zip(files),
        should_reject=True,
        purpose="Detect ordinary transcript corruption or tampering.",
    )

    files = dict(original_files)
    files["README.md"] += b"\nTAMPERED\n"
    execute(
        "README tamper",
        rebuild_zip(files),
        should_reject=True,
        purpose="Verify that README tampering is rejected by full internal-ledger coverage.",
    )

    files = dict(original_files)
    gap_obj = json.loads(files["integrity/gaps.json"])
    gap_obj["unavailable_not_included"] = []
    files["integrity/gaps.json"] = json.dumps(
        gap_obj, ensure_ascii=False, indent=2
    ).encode("utf-8")
    execute(
        "Gap ledger altered to hide missing material",
        rebuild_zip(files),
        should_reject=True,
        purpose="Verify that gap-ledger tampering is rejected by full internal-ledger coverage.",
    )

    files = dict(original_files)
    files["raw/transcript.md"] = files["raw/transcript.md"].replace(
        b"I want to create", b"I chose to create", 1
    )
    set_transcript_hashes(files)
    execute(
        "Transcript rewritten and internal hashes recomputed",
        rebuild_zip(files),
        should_reject=False,
        purpose=(
            "Demonstrate that internal checksums alone cannot establish "
            "authenticity against a coordinated editor."
        ),
    )

    files = dict(original_files)
    del files["raw/transcript.md"]
    execute(
        "Required transcript removed",
        rebuild_zip(files),
        should_reject=True,
        purpose="Reject a missing required payload.",
    )

    files = dict(original_files)
    files["extra.txt"] = b"unexpected"
    execute(
        "Unexpected file added",
        rebuild_zip(files),
        should_reject=True,
        purpose="Reject an unmanifested payload.",
    )

    files = dict(original_files)
    text = files["raw/transcript.md"].decode("utf-8")
    text = text.replace("## 50. USER", "## 500. USER", 1)
    files["raw/transcript.md"] = text.encode("utf-8")
    set_transcript_hashes(files)
    execute(
        "Event sequence corrupted with hashes updated",
        rebuild_zip(files),
        should_reject=True,
        purpose="Use semantic checks beyond cryptographic hashes.",
    )

    files = dict(original_files)
    files["../escape.txt"] = b"x"
    execute(
        "ZIP path traversal entry",
        rebuild_zip(files),
        should_reject=True,
        purpose="Reject extraction outside the target directory.",
    )

    execute(
        "Duplicate raw/transcript.md entry",
        rebuild_zip(
            dict(original_files),
            duplicate=("raw/transcript.md", b"malicious duplicate"),
        ),
        should_reject=True,
        purpose="Reject ambiguous duplicate ZIP paths.",
    )

    files = dict(original_files)
    files["integrity/manifest.json"] = b"{not json"
    execute(
        "Malformed manifest JSON",
        rebuild_zip(files),
        should_reject=True,
        purpose="Fail closed on invalid integrity metadata.",
    )

    files = dict(original_files)
    files["bomb.txt"] = b"A" * (2 * 1024 * 1024)
    execute(
        "Highly compressible expansion payload",
        rebuild_zip(files),
        should_reject=True,
        purpose="Reject suspicious expansion ratios.",
    )

    return {
        "scenario_count": len(scenarios),
        "expectations_met": sum(1 for item in scenarios if item["expectation_met"]),
        "scenarios": scenarios,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--fault-test", action="store_true")
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()

    try:
        blob = args.archive.read_bytes()
    except Exception as exc:
        print(f"Could not read archive: {exc}", file=sys.stderr)
        return 2

    output: dict[str, Any] = {
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "archive": str(args.archive),
        "validation": validate_archive(blob),
    }

    if args.fault_test:
        output["fault_tests"] = run_fault_tests(blob)

    rendered = json.dumps(output, ensure_ascii=False, indent=2)
    if args.json_out:
        args.json_out.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)

    return 0 if output["validation"]["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
