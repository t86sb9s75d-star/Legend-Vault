from __future__ import annotations

import json
from pathlib import Path
import tempfile
import zipfile

from legend_vault.core import (
    LegendVaultError,
    build_record,
    diff_records,
    parse_chatgpt_export,
    verify_record_zip,
)


def build_synthetic_export(path: Path) -> None:
    conversations = [{
        "id": "conv-1",
        "title": "Synthetic Legend Vault Test",
        "mapping": {
            "root": {"id": "root", "parent": None, "children": ["m1"], "message": None},
            "m1": {
                "id": "m1", "parent": "root", "children": ["m2"],
                "message": {
                    "id": "msg-1", "author": {"role": "user"},
                    "create_time": 1760000000,
                    "content": {"content_type": "text", "parts": ["Hello vault"]},
                    "status": "finished_successfully", "end_turn": True,
                },
            },
            "m2": {
                "id": "m2", "parent": "m1", "children": [],
                "message": {
                    "id": "msg-2", "author": {"role": "assistant"},
                    "create_time": 1760000001,
                    "content": {"content_type": "text", "parts": ["Recorded."]},
                    "status": "finished_successfully", "end_turn": True,
                },
            },
        },
        "current_node": "m2",
    }]
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("conversations.json", json.dumps(conversations))
        archive.writestr("user.json", json.dumps({"id": "synthetic-user"}))


def synthetic_conversation(conversation_id: str) -> dict[str, object]:
    return {
        "id": conversation_id,
        "title": conversation_id,
        "mapping": {
            "root": {"id": "root", "parent": None, "children": ["message"], "message": None},
            "message": {
                "id": "message",
                "parent": "root",
                "children": [],
                "message": {
                    "id": f"{conversation_id}-message",
                    "author": {"role": "user"},
                    "create_time": 1760000000,
                    "content": {
                        "content_type": "text",
                        "parts": [conversation_id],
                    },
                },
            },
        },
        "current_node": "message",
    }


def build_sharded_synthetic_export(path: Path) -> None:
    shards = {
        "conversations-zeta.json": "zeta",
        "conversations-alpha.json": "alpha",
        "conversations-10.json": "ten",
        "conversations-02.json": "two",
        "nested/conversations-beta.json": "beta",
    }
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, conversation_id in shards.items():
            archive.writestr(name, json.dumps([synthetic_conversation(conversation_id)]))


def test_synthetic_import_verify_and_diff() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        source = root / "synthetic-export.zip"
        output = root / "vault"
        build_synthetic_export(source)

        record_dir, archive_path, summary = build_record(source, output)
        assert record_dir.exists()
        assert archive_path.exists()
        assert summary["source_format"] == "chatgpt_export"
        assert summary["event_count"] == 2

        verification = verify_record_zip(archive_path)
        assert verification["accepted"], verification
        assert verification["metrics"]["event_count"] == 2

        comparison = diff_records(archive_path, archive_path)
        assert comparison["exact_match_count"] == 2
        assert comparison["normalized_match_count"] == 0
        assert comparison["left_only_count"] == 0
        assert comparison["right_only_count"] == 0


def test_sharded_export_is_sorted_and_combined() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        source = Path(temp_dir) / "sharded-export.zip"
        build_sharded_synthetic_export(source)

        events, _, _, metadata = parse_chatgpt_export(source)

        assert metadata["conversation_count_in_export"] == 5
        assert [event["source_conversation_id"] for event in events] == [
            "two",
            "ten",
            "alpha",
            "zeta",
            "beta",
        ]


def test_malformed_shard_is_rejected() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        source = Path(temp_dir) / "malformed-shard-export.zip"
        with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("conversations-good.json", "[]")
            archive.writestr("conversations-bad.json", "{not json")

        try:
            parse_chatgpt_export(source)
        except LegendVaultError as exc:
            assert "Could not parse conversation shard conversations-bad.json" in str(exc)
        else:
            raise AssertionError("Expected malformed shard to be rejected")


def test_legacy_conversations_file_remains_supported() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        source = Path(temp_dir) / "legacy-export.zip"
        build_synthetic_export(source)

        events, _, _, metadata = parse_chatgpt_export(source)

        assert metadata["conversations_path"] == "conversations.json"
        assert metadata["conversation_count_in_export"] == 1
        assert len(events) == 2


if __name__ == "__main__":
    test_synthetic_import_verify_and_diff()
    test_sharded_export_is_sorted_and_combined()
    test_malformed_shard_is_rejected()
    test_legacy_conversations_file_remains_supported()

    from test_verifier_fault_injection import test_fault_injection_suite

    test_fault_injection_suite()
    print("Synthetic end-to-end and verifier fault-injection tests passed.")
