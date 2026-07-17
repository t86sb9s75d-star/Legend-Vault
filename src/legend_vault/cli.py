
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .core import LegendVaultError, build_record, diff_records, verify_record_zip


def main() -> int:
    parser = argparse.ArgumentParser(prog="legend-vault")
    sub = parser.add_subparsers(dest="command", required=True)

    import_parser = sub.add_parser("import", help="Import a ChatGPT export or Legend Vault fixture.")
    import_parser.add_argument("source", type=Path)
    import_parser.add_argument("--output", type=Path, default=Path("vault"))
    import_parser.add_argument("--conversation", help="Conversation ID or title substring.")

    verify_parser = sub.add_parser("verify", help="Verify a built Legend Vault record ZIP.")
    verify_parser.add_argument("record", type=Path)

    diff_parser = sub.add_parser("diff", help="Compare two canonical Legend Vault records.")
    diff_parser.add_argument("left", type=Path)
    diff_parser.add_argument("right", type=Path)
    diff_parser.add_argument("--json-out", type=Path)

    open_parser = sub.add_parser("open", help="Print the local path of a record directory.")
    open_parser.add_argument("record", type=Path)

    args = parser.parse_args()

    try:
        if args.command == "import":
            args.output.mkdir(parents=True, exist_ok=True)
            record_dir, archive_path, summary = build_record(
                args.source, args.output, conversation_selector=args.conversation
            )
            print(json.dumps({
                "status": "imported",
                "record_dir": str(record_dir),
                "archive": str(archive_path),
                **summary
            }, indent=2))
            return 0

        if args.command == "verify":
            result = verify_record_zip(args.record)
            print(json.dumps(result, indent=2))
            return 0 if result["accepted"] else 1

        if args.command == "diff":
            result = diff_records(args.left, args.right)
            rendered = json.dumps(result, indent=2)
            if args.json_out:
                args.json_out.write_text(rendered + "\n", encoding="utf-8")
            print(rendered)
            return 0

        if args.command == "open":
            print(args.record.resolve())
            return 0

    except (LegendVaultError, OSError, ValueError, KeyError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, indent=2), file=sys.stderr)
        return 2

    return 2
