from __future__ import annotations

import json
from pathlib import Path
import tempfile
import zipfile

import legend_vault.core as core
from legend_vault.core import build_record, sha256_bytes, verify_record_zip


def build_synthetic_export(path: Path) -> None:
    conversations = [{
        "id": "conv-fault-test",
        "title": "Verifier fault injection",
        "mapping": {
            "root": {
                "id": "root",
                "parent": None,
                "children": ["m1"],
                "message": None,
            },
            "m1": {
                "id": "m1",
                "parent": "root",
                "children": ["m2"],
                "message": {
                    "id": "msg-1",
                    "author": {"role": "user"},
                    "create_time": 1760000000,
                    "content": {
                        "content_type": "text",
                        "parts": ["Preserve this exactly."],
                    },
                    "status": "finished_successfully",
                    "end_turn": True,
                },
            },
            "m2": {
                "id": "m2",
                "parent": "m1",
                "children": [],
                "message": {
                    "id": "msg-2",
                    "author": {"role": "assistant"},
                    "create_time": 1760000001,
                    "content": {
                        "content_type": "text",
                        "parts": ["Recorded."],
                    },
                    "status": "finished_successfully",
                    "end_turn": True,
                },
            },
        },
        "current_node": "m2",
    }]
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("conversations.json", json.dumps(conversations))
        archive.writestr("user.json", json.dumps({"id": "synthetic-user"}))


def read_entries(path: Path) -> list[tuple[str, bytes]]:
    with zipfile.ZipFile(path) as archive:
        return [(info.filename, archive.read(info)) for info in archive.infolist()]


def write_entries(path: Path, entries: list[tuple[str, bytes]]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries:
            archive.writestr(name, data)


def replace_entry(
    entries: list[tuple[str, bytes]],
    suffix: str,
    replacement: bytes,
) -> list[tuple[str, bytes]]:
    replaced = False
    output: list[tuple[str, bytes]] = []
    for name, data in entries:
        if name.endswith(suffix):
            output.append((name, replacement))
            replaced = True
        else:
            output.append((name, data))
    assert replaced, suffix
    return output


def get_entry(entries: list[tuple[str, bytes]], suffix: str) -> tuple[str, bytes]:
    matches = [(name, data) for name, data in entries if name.endswith(suffix)]
    assert len(matches) == 1, (suffix, [name for name, _ in matches])
    return matches[0]


def update_event_stream_integrity(
    entries: list[tuple[str, bytes]],
    event_stream: bytes,
) -> list[tuple[str, bytes]]:
    _, manifest_data = get_entry(entries, "/integrity/manifest.json")
    manifest = json.loads(manifest_data)
    event_digest = sha256_bytes(event_stream)

    for entry in manifest["files"]:
        if entry.get("path") == "raw/events.jsonl":
            entry["bytes"] = len(event_stream)
            entry["sha256"] = event_digest
            break
    else:
        raise AssertionError("raw/events.jsonl missing from manifest")

    manifest_rendered = (
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")
    entries = replace_entry(
        entries,
        "/integrity/manifest.json",
        manifest_rendered,
    )

    _, ledger_data = get_entry(entries, "/integrity/hashes.json")
    ledger = json.loads(ledger_data)
    ledger["entries"]["raw/events.jsonl"] = event_digest
    ledger["entries"]["integrity/manifest.json"] = sha256_bytes(
        manifest_rendered
    )
    ledger_rendered = (
        json.dumps(ledger, ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")
    return replace_entry(
        entries,
        "/integrity/hashes.json",
        ledger_rendered,
    )


def error_codes(result: dict[str, object]) -> set[str]:
    errors = result.get("errors", [])
    return {
        str(error.get("code"))
        for error in errors
        if isinstance(error, dict)
    }


def assert_rejected_with(path: Path, expected_code: str) -> None:
    result = verify_record_zip(path)
    assert not result["accepted"], result
    assert expected_code in error_codes(result), result


def build_valid_record(root: Path) -> Path:
    source = root / "synthetic-export.zip"
    output = root / "vault"
    build_synthetic_export(source)
    _, archive_path, _ = build_record(source, output)
    verification = verify_record_zip(archive_path)
    assert verification["accepted"], verification
    return archive_path


def test_missing_required_file(valid: Path, root: Path) -> None:
    entries = [
        (name, data)
        for name, data in read_entries(valid)
        if not name.endswith("/integrity/gaps.json")
    ]
    damaged = root / "missing-required.zip"
    write_entries(damaged, entries)
    assert_rejected_with(damaged, "MISSING_REQUIRED_FILE")


def test_hash_mismatch(valid: Path, root: Path) -> None:
    entries = read_entries(valid)
    _, transcript = get_entry(entries, "/views/transcript.md")
    entries = replace_entry(
        entries,
        "/views/transcript.md",
        transcript + b"tampered\n",
    )
    damaged = root / "hash-mismatch.zip"
    write_entries(damaged, entries)
    assert_rejected_with(damaged, "HASH_MISMATCH")


def test_event_content_hash(valid: Path, root: Path) -> None:
    entries = read_entries(valid)
    _, stream_data = get_entry(entries, "/raw/events.jsonl")
    events = [
        json.loads(line)
        for line in stream_data.decode("utf-8").splitlines()
    ]
    events[0]["content"] = (
        "Changed while retaining the old event content hash."
    )
    stream = (
        "\n".join(
            json.dumps(
                event,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            for event in events
        )
        + "\n"
    ).encode("utf-8")
    entries = replace_entry(entries, "/raw/events.jsonl", stream)
    entries = update_event_stream_integrity(entries, stream)
    damaged = root / "event-content-hash.zip"
    write_entries(damaged, entries)
    assert_rejected_with(damaged, "EVENT_CONTENT_HASH")


def test_event_sequence(valid: Path, root: Path) -> None:
    entries = read_entries(valid)
    _, stream_data = get_entry(entries, "/raw/events.jsonl")
    events = [
        json.loads(line)
        for line in stream_data.decode("utf-8").splitlines()
    ]
    events[0]["sequence"] = 2
    stream = (
        "\n".join(
            json.dumps(
                event,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            for event in events
        )
        + "\n"
    ).encode("utf-8")
    entries = replace_entry(entries, "/raw/events.jsonl", stream)
    entries = update_event_stream_integrity(entries, stream)
    damaged = root / "event-sequence.zip"
    write_entries(damaged, entries)
    assert_rejected_with(damaged, "EVENT_SEQUENCE")


def test_duplicate_path(valid: Path, root: Path) -> None:
    entries = read_entries(valid)
    readme_name, readme_data = get_entry(entries, "/README.md")
    entries.append((readme_name, readme_data))
    damaged = root / "duplicate-path.zip"
    write_entries(damaged, entries)
    assert_rejected_with(damaged, "DUPLICATE_PATH")


def test_unsafe_path(valid: Path, root: Path) -> None:
    entries = read_entries(valid)
    entries.append(("../escape.txt", b"must never be extracted"))
    damaged = root / "unsafe-path.zip"
    write_entries(damaged, entries)
    assert_rejected_with(damaged, "UNSAFE_PATH")


def test_invalid_integrity_json(valid: Path, root: Path) -> None:
    entries = replace_entry(
        read_entries(valid),
        "/integrity/manifest.json",
        b"{not valid json\n",
    )
    damaged = root / "invalid-integrity-json.zip"
    write_entries(damaged, entries)
    assert_rejected_with(damaged, "INVALID_INTEGRITY_JSON")


def test_unmanifested_file(valid: Path, root: Path) -> None:
    entries = read_entries(valid)
    event_name, _ = get_entry(entries, "/raw/events.jsonl")
    root_prefix = event_name[: -len("raw/events.jsonl")]
    entries.append((root_prefix + "unexpected.txt", b"not declared"))
    damaged = root / "unmanifested-file.zip"
    write_entries(damaged, entries)
    assert_rejected_with(damaged, "UNMANIFESTED_FILE")


def test_member_too_large(valid: Path, root: Path) -> None:
    entries = read_entries(valid)
    event_name, _ = get_entry(entries, "/raw/events.jsonl")
    root_prefix = event_name[: -len("raw/events.jsonl")]
    old_limit = core.MAX_ZIP_MEMBER_BYTES
    core.MAX_ZIP_MEMBER_BYTES = 1024
    try:
        entries.append((root_prefix + "oversized.bin", b"x" * 2048))
        damaged = root / "member-too-large.zip"
        write_entries(damaged, entries)
        assert_rejected_with(damaged, "MEMBER_TOO_LARGE")
    finally:
        core.MAX_ZIP_MEMBER_BYTES = old_limit


def test_total_uncompressed_limit(valid: Path, root: Path) -> None:
    entries = read_entries(valid)
    event_name, _ = get_entry(entries, "/raw/events.jsonl")
    root_prefix = event_name[: -len("raw/events.jsonl")]
    old_limit = core.MAX_ZIP_TOTAL_BYTES
    core.MAX_ZIP_TOTAL_BYTES = 4096
    try:
        entries.append((root_prefix + "near-limit-a.bin", b"a" * 2500))
        entries.append((root_prefix + "near-limit-b.bin", b"b" * 2500))
        damaged = root / "total-uncompressed-limit.zip"
        write_entries(damaged, entries)
        assert_rejected_with(damaged, "ZIP_TOTAL_UNCOMPRESSED_LIMIT")
    finally:
        core.MAX_ZIP_TOTAL_BYTES = old_limit


def test_fault_injection_suite() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        valid = build_valid_record(root)
        cases = [
            test_missing_required_file,
            test_hash_mismatch,
            test_event_content_hash,
            test_event_sequence,
            test_duplicate_path,
            test_unsafe_path,
            test_invalid_integrity_json,
            test_unmanifested_file,
            test_member_too_large,
            test_total_uncompressed_limit,
        ]
        for case in cases:
            case(valid, root)


if __name__ == "__main__":
    test_fault_injection_suite()
    print("Verifier fault-injection tests passed.")
