from __future__ import annotations

import json
from pathlib import Path
import tempfile
import zipfile

from legend_vault.core import build_record, diff_records, verify_record_zip


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


if __name__ == "__main__":
    test_synthetic_import_verify_and_diff()
    print("Synthetic end-to-end test passed.")
