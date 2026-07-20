
from __future__ import annotations

import collections
import datetime as dt
import hashlib
import io
import json
import mimetypes
import os
from pathlib import Path
import re
import shutil
import unicodedata
import uuid
import zipfile
from typing import Any, Iterable

SCHEMA_VERSION = "0.1.0"
NAMESPACE = uuid.UUID("f4e91854-9063-4f42-b3c6-1d55b6042c47")
EVENT_RE = re.compile(
    r"^## (?P<seq>\d+)\. (?P<role>[A-Z]+)\n"
    r"\*\*Timestamp:\*\* (?P<timestamp>.+?)\n\n",
    re.MULTILINE,
)
ATTACHMENT_RE = re.compile(r"^- `([^`]+)`", re.MULTILINE)


class LegendVaultError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_event_id(record_id: str, source_message_id: str | None, sequence: int, content_hash: str) -> str:
    basis = f"{record_id}|{source_message_id or ''}|{sequence}|{content_hash}"
    return "evt_" + uuid.uuid5(NAMESPACE, basis).hex


def iso_from_unix(value: Any) -> tuple[str | None, str]:
    if value in (None, "", 0):
        return None, "unavailable"
    try:
        numeric = float(value)
        return dt.datetime.fromtimestamp(numeric, tz=dt.timezone.utc).isoformat().replace("+00:00", "Z"), "source_provided"
    except Exception:
        return None, "invalid_source_timestamp"


def normalize_actor(role: str | None) -> str:
    role = (role or "").lower()
    if role in {"user", "assistant", "tool", "system"}:
        return role
    return "unknown"


def flatten_content(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            else:
                parts.append(json.dumps(item, ensure_ascii=False, sort_keys=True))
        return "\n".join(parts)
    if isinstance(content, dict):
        parts = content.get("parts")
        if isinstance(parts, list):
            return flatten_content(parts)
        text = content.get("text")
        if isinstance(text, str):
            return text
        return json.dumps(content, ensure_ascii=False, sort_keys=True)
    return str(content)


def parse_fixture_transcript(text: str, source_archive_hash: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    matches = list(EVENT_RE.finditer(text))
    if not matches:
        raise LegendVaultError("No Legend Vault transcript events were found.")

    record_id = "LV-" + source_archive_hash[:16]
    events: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []

    for index, match in enumerate(matches):
        body_start = match.end()
        body_end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        body = text[body_start:body_end].rstrip()

        attachments: list[str] = []
        record_note = None
        content = body
        if "\n**Attachments:**" in content:
            content, attachment_section = content.split("\n**Attachments:**", 1)
            if "\n**Record note:**" in attachment_section:
                attachment_section, record_note = attachment_section.split("\n**Record note:**", 1)
                record_note = record_note.strip()
            attachments = ATTACHMENT_RE.findall(attachment_section)
        elif "\n**Record note:**" in content:
            content, record_note = content.split("\n**Record note:**", 1)
            record_note = record_note.strip()

        seq = int(match.group("seq"))
        raw_role = match.group("role")
        raw_timestamp = match.group("timestamp").strip()
        created_at = None if raw_timestamp == "timestamp unavailable" else raw_timestamp
        timestamp_status = "unavailable" if created_at is None else "source_provided"
        content = content.rstrip()
        content_hash = sha256_bytes(content.encode("utf-8"))
        source_message_id = f"fixture-{seq}"

        events.append({
            "schema_version": SCHEMA_VERSION,
            "event_id": stable_event_id(record_id, source_message_id, seq, content_hash),
            "record_id": record_id,
            "source_platform": "legend_vault_fixture",
            "source_conversation_id": None,
            "source_message_id": source_message_id,
            "parent_event_id": None,
            "branch_id": "fixture-main",
            "sequence": seq,
            "actor": normalize_actor(raw_role),
            "event_type": "message" if raw_role != "TOOL" else "tool_event",
            "created_at": created_at,
            "timestamp_status": timestamp_status,
            "content": content,
            "content_format": "markdown",
            "capture_method": "fixture_transcript",
            "fidelity": "normalized",
            "artifact_ids": [],
            "content_sha256": content_hash,
            "source_metadata": {
                "raw_role": raw_role,
                "attachment_references": attachments,
                "record_note": record_note
            }
        })

        for attachment in attachments:
            gaps.append({
                "gap_id": "gap_" + uuid.uuid5(NAMESPACE, f"{record_id}|{seq}|{attachment}").hex,
                "record_id": record_id,
                "event_sequence": seq,
                "category": "referenced_artifact",
                "reference": attachment,
                "status": "reference_only",
                "detail": "Referenced by the fixture transcript; binary availability depends on the source archive."
            })

    return events, gaps


def conversation_nodes_in_order(conversation: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    mapping = conversation.get("mapping") or {}
    if not isinstance(mapping, dict):
        return []

    roots = [
        node_id for node_id, node in mapping.items()
        if isinstance(node, dict) and not node.get("parent")
    ]

    ordered: list[tuple[str, dict[str, Any]]] = []
    visited: set[str] = set()

    def visit(node_id: str) -> None:
        if node_id in visited or node_id not in mapping:
            return
        visited.add(node_id)
        node = mapping[node_id]
        ordered.append((node_id, node))
        children = node.get("children") or []
        for child in children:
            if isinstance(child, str):
                visit(child)

    for root in roots:
        visit(root)

    # Preserve any disconnected nodes rather than silently dropping them.
    for node_id in mapping:
        visit(node_id)

    return ordered


def branch_id_for_node(node_id: str, mapping: dict[str, Any]) -> str:
    cursor = node_id
    lineage: list[str] = []
    seen: set[str] = set()
    while cursor and cursor not in seen and cursor in mapping:
        seen.add(cursor)
        lineage.append(cursor)
        parent = mapping[cursor].get("parent")
        cursor = parent if isinstance(parent, str) else ""
    rootward = list(reversed(lineage))
    anchor = rootward[1] if len(rootward) > 1 else rootward[0]
    return "branch_" + uuid.uuid5(NAMESPACE, anchor).hex[:16]


def parse_chatgpt_export(zip_path: Path, conversation_selector: str | None = None) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    source_hash = sha256_file(zip_path)
    with zipfile.ZipFile(zip_path) as zf:
        names = zf.namelist()
        conversation_shards = sorted(
            name
            for name in names
            if (
                name.rsplit("/", 1)[-1].startswith("conversations-")
                and name.rsplit("/", 1)[-1].endswith(".json")
            )
        )
        if conversation_shards:
            conversations_name = conversation_shards[0]
            conversations = []
            for shard_name in conversation_shards:
                try:
                    shard = json.loads(zf.read(shard_name))
                except Exception as exc:
                    raise LegendVaultError(
                        f"Could not parse conversation shard {shard_name}: {exc}"
                    ) from exc
                if not isinstance(shard, list):
                    raise LegendVaultError(
                        f"Conversation shard {shard_name} is not a list."
                    )
                conversations.extend(shard)
        else:
            conversations_name = next(
                (name for name in names if name.rstrip("/") == "conversations.json"),
                None,
            )
            if conversations_name is None:
                conversations_name = next(
                    (name for name in names if name.endswith("/conversations.json")),
                    None,
                )
            if conversations_name is None:
                raise LegendVaultError(
                    "No conversations.json or conversations-*.json shard was found in the ZIP."
                )

            try:
                conversations = json.loads(zf.read(conversations_name))
            except Exception as exc:
                raise LegendVaultError(f"Could not parse {conversations_name}: {exc}") from exc

            if not isinstance(conversations, list):
                raise LegendVaultError("conversations.json is not a list.")

        chosen: list[dict[str, Any]]
        if conversation_selector:
            lowered = conversation_selector.casefold()
            chosen = [
                conv for conv in conversations
                if str(conv.get("id", "")).casefold() == lowered
                or lowered in str(conv.get("title", "")).casefold()
            ]
            if not chosen:
                raise LegendVaultError(f"No conversation matched: {conversation_selector}")
        else:
            chosen = conversations

        events: list[dict[str, Any]] = []
        gaps: list[dict[str, Any]] = []
        sequence = 0
        message_to_event: dict[str, str] = {}
        pending_parent_links: list[tuple[dict[str, Any], str | None]] = []

        for conv in chosen:
            conv_id = str(conv.get("id") or conv.get("conversation_id") or uuid.uuid4())
            record_id = "LV-" + uuid.uuid5(NAMESPACE, f"{source_hash}|{conv_id}").hex[:16]
            mapping = conv.get("mapping") if isinstance(conv.get("mapping"), dict) else {}

            for node_id, node in conversation_nodes_in_order(conv):
                message = node.get("message")
                if not isinstance(message, dict):
                    continue
                sequence += 1
                message_id = str(message.get("id") or node_id)
                author = message.get("author") if isinstance(message.get("author"), dict) else {}
                role = normalize_actor(author.get("role"))
                content = flatten_content(message.get("content"))
                created_at, timestamp_status = iso_from_unix(message.get("create_time"))
                content_hash = sha256_bytes(content.encode("utf-8"))
                event_id = stable_event_id(record_id, message_id, sequence, content_hash)

                event = {
                    "schema_version": SCHEMA_VERSION,
                    "event_id": event_id,
                    "record_id": record_id,
                    "source_platform": "chatgpt",
                    "source_conversation_id": conv_id,
                    "source_message_id": message_id,
                    "parent_event_id": None,
                    "branch_id": branch_id_for_node(node_id, mapping),
                    "sequence": sequence,
                    "actor": role,
                    "event_type": "message",
                    "created_at": created_at,
                    "timestamp_status": timestamp_status,
                    "content": content,
                    "content_format": "markdown",
                    "capture_method": "official_export",
                    "fidelity": "source_original",
                    "artifact_ids": [],
                    "content_sha256": content_hash,
                    "source_metadata": {
                        "conversation_title": conv.get("title"),
                        "node_id": node_id,
                        "recipient": message.get("recipient"),
                        "status": message.get("status"),
                        "end_turn": message.get("end_turn"),
                        "weight": message.get("weight"),
                        "metadata": message.get("metadata") if isinstance(message.get("metadata"), dict) else {}
                    }
                }
                events.append(event)
                message_to_event[node_id] = event_id
                pending_parent_links.append((event, node.get("parent")))

            if not mapping:
                gaps.append({
                    "gap_id": "gap_" + uuid.uuid5(NAMESPACE, f"{record_id}|mapping").hex,
                    "record_id": record_id,
                    "category": "conversation_structure",
                    "status": "missing",
                    "detail": "Conversation mapping was unavailable or malformed."
                })

        for event, parent_node_id in pending_parent_links:
            if isinstance(parent_node_id, str):
                event["parent_event_id"] = message_to_event.get(parent_node_id)

        # Preserve every other file in the export as an artifact.
        artifact_entries: list[dict[str, Any]] = []
        for name in names:
            if name.endswith("/") or name == conversations_name:
                continue
            data = zf.read(name)
            artifact_id = "art_" + uuid.uuid5(NAMESPACE, f"{source_hash}|{name}|{sha256_bytes(data)}").hex
            artifact_entries.append({
                "artifact_id": artifact_id,
                "source_path": name,
                "bytes": len(data),
                "sha256": sha256_bytes(data),
                "media_type": mimetypes.guess_type(name)[0] or "application/octet-stream",
                "data": data
            })

        metadata = {
            "source_archive_sha256": source_hash,
            "source_format": "chatgpt_export",
            "conversation_count_in_export": len(conversations),
            "conversation_count_selected": len(chosen),
            "conversations_path": conversations_name
        }
        return events, gaps, artifact_entries, metadata


def detect_and_parse(source_zip: Path, conversation_selector: str | None = None):
    source_hash = sha256_file(source_zip)
    with zipfile.ZipFile(source_zip) as zf:
        names = set(zf.namelist())
        transcript_name = next((n for n in names if n.rstrip("/") == "raw/transcript.md"), None)
        if transcript_name:
            text = zf.read(transcript_name).decode("utf-8")
            events, gaps = parse_fixture_transcript(text, source_hash)
            artifacts = []
            for name in sorted(names):
                if name.endswith("/") or name == transcript_name:
                    continue
                data = zf.read(name)
                artifacts.append({
                    "artifact_id": "art_" + uuid.uuid5(NAMESPACE, f"{source_hash}|{name}|{sha256_bytes(data)}").hex,
                    "source_path": name,
                    "bytes": len(data),
                    "sha256": sha256_bytes(data),
                    "media_type": mimetypes.guess_type(name)[0] or "application/octet-stream",
                    "data": data
                })
            return events, gaps, artifacts, {
                "source_archive_sha256": source_hash,
                "source_format": "legend_vault_fixture",
                "transcript_path": transcript_name
            }

    return parse_chatgpt_export(source_zip, conversation_selector)


def render_transcript(events: list[dict[str, Any]]) -> str:
    lines = [
        "# Legend Vault Transcript View",
        "",
        "Generated from canonical `raw/events.jsonl`. This Markdown file is a derived view.",
        ""
    ]
    for event in events:
        lines.extend([
            f"## {event['sequence']}. {event['actor'].upper()}",
            f"**Timestamp:** {event.get('created_at') or 'timestamp unavailable'}",
            f"**Event ID:** `{event['event_id']}`",
            f"**Fidelity:** `{event['fidelity']}`",
            "",
            event["content"],
            ""
        ])
    return "\n".join(lines)


def safe_artifact_path(name: str) -> Path:
    candidate = Path(name)
    safe_parts = []
    for part in candidate.parts:
        if part in {"", ".", ".."}:
            continue
        safe_parts.append(part.replace("\\", "_"))
    return Path(*safe_parts) if safe_parts else Path("unnamed-artifact")


def build_record(
    source_zip: Path,
    output_root: Path,
    *,
    conversation_selector: str | None = None,
) -> tuple[Path, Path, dict[str, Any]]:
    events, gaps, artifacts, source_metadata = detect_and_parse(source_zip, conversation_selector)
    if not events:
        raise LegendVaultError("The importer produced zero events.")

    record_id = events[0]["record_id"] if len({event["record_id"] for event in events}) == 1 else (
        "LV-" + source_metadata["source_archive_sha256"][:16]
    )
    record_dir = output_root / record_id
    if record_dir.exists():
        shutil.rmtree(record_dir)

    (record_dir / "original").mkdir(parents=True)
    (record_dir / "raw" / "artifacts").mkdir(parents=True)
    (record_dir / "views").mkdir(parents=True)
    (record_dir / "integrity").mkdir(parents=True)

    shutil.copyfile(source_zip, record_dir / "original" / source_zip.name)

    events_path = record_dir / "raw" / "events.jsonl"
    with events_path.open("w", encoding="utf-8", newline="\n") as handle:
        for event in events:
            handle.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")

    transcript = render_transcript(events)
    (record_dir / "raw" / "transcript.md").write_text(transcript, encoding="utf-8", newline="\n")
    (record_dir / "views" / "transcript.md").write_text(transcript, encoding="utf-8", newline="\n")

    artifact_manifest = []
    for artifact in artifacts:
        target = record_dir / "raw" / "artifacts" / safe_artifact_path(artifact["source_path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(artifact["data"])
        artifact_manifest.append({
            key: value for key, value in artifact.items() if key != "data"
        } | {"stored_path": target.relative_to(record_dir).as_posix()})

    source_receipt = {
        "record_id": record_id,
        "source_archive": source_zip.name,
        "source_archive_sha256": source_metadata["source_archive_sha256"],
        "source_format": source_metadata["source_format"],
        "imported_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "importer_version": SCHEMA_VERSION,
        "conversation_selector": conversation_selector,
        "source_metadata": source_metadata
    }
    (record_dir / "integrity" / "source-receipt.json").write_text(
        json.dumps(source_receipt, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8"
    )

    gaps_payload = {
        "record_id": record_id,
        "gap_count": len(gaps),
        "gaps": gaps
    }
    (record_dir / "integrity" / "gaps.json").write_text(
        json.dumps(gaps_payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8"
    )

    (record_dir / "integrity" / "artifacts.json").write_text(
        json.dumps({"record_id": record_id, "artifacts": artifact_manifest}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8"
    )

    readme = f"""# Legend Vault Record {record_id}

- Source format: `{source_metadata['source_format']}`
- Canonical events: `raw/events.jsonl`
- Derived transcript: `views/transcript.md`
- Source archive preserved unchanged: `original/{source_zip.name}`
- Events: {len(events)}
- Gaps: {len(gaps)}

This record uses a strict internal ledger: every file except
`integrity/hashes.json` is hashed. The ledger itself requires an external
receipt to prove unchanged-since-publish.
"""
    (record_dir / "README.md").write_text(readme, encoding="utf-8", newline="\n")

    # Create placeholders so both integrity files are included by path.
    hashes_path = record_dir / "integrity" / "hashes.json"
    manifest_path = record_dir / "integrity" / "manifest.json"
    hashes_path.write_text("{}\n", encoding="utf-8")
    manifest_path.write_text("{}\n", encoding="utf-8")

    # Build a single manifest. Self-referential files are listed without
    # self-size/self-hash claims; hashes.json covers manifest.json externally
    # within the record, while hashes.json itself needs an external receipt.
    manifest_entries = []
    for path in sorted(record_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(record_dir).as_posix()
        entry = {
            "path": rel,
            "media_type": mimetypes.guess_type(path.name)[0] or "application/octet-stream",
            "role": (
                "canonical_event_stream" if rel == "raw/events.jsonl"
                else "derived_transcript" if rel.startswith("views/")
                else "raw_transcript_view" if rel == "raw/transcript.md"
                else "source_archive" if rel.startswith("original/")
                else "integrity_metadata" if rel.startswith("integrity/")
                else "documentation"
            )
        }
        if rel not in {"integrity/manifest.json", "integrity/hashes.json"}:
            entry["bytes"] = path.stat().st_size
            entry["sha256"] = sha256_file(path)
        manifest_entries.append(entry)

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "record_id": record_id,
        "record_count": len(events),
        "source_format": source_metadata["source_format"],
        "files": manifest_entries
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8"
    )

    # Strict hash ledger: all files except itself.
    entries = {}
    for path in sorted(record_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(record_dir).as_posix()
        if rel == "integrity/hashes.json":
            continue
        entries[rel] = sha256_file(path)
    hashes = {
        "algorithm": "SHA-256",
        "coverage": "Every record file except integrity/hashes.json.",
        "entries": entries
    }
    hashes_path.write_text(
        json.dumps(hashes, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8"
    )

    # ZIP under a single root directory.
    archive_path = output_root / f"{record_id}.zip"
    if archive_path.exists():
        archive_path.unlink()
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(record_dir.rglob("*")):
            if path.is_file():
                zf.write(path, arcname=f"{record_id}/{path.relative_to(record_dir).as_posix()}")

    return record_dir, archive_path, {
        "record_id": record_id,
        "event_count": len(events),
        "gap_count": len(gaps),
        "artifact_count": len(artifacts),
        "archive_sha256": sha256_file(archive_path),
        "source_format": source_metadata["source_format"]
    }


def locate_record_root(names: list[str]) -> str:
    roots = {name.split("/", 1)[0] for name in names if "/" in name}
    if len(roots) == 1 and all(name.startswith(next(iter(roots)) + "/") for name in names):
        return next(iter(roots)) + "/"
    return ""


def verify_record_zip(path: Path) -> dict[str, Any]:
    result = {
        "archive": str(path),
        "archive_sha256": sha256_file(path),
        "errors": [],
        "warnings": [],
        "metrics": {},
        "accepted": False
    }

    try:
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            names = [info.filename for info in infos]
            bad = zf.testzip()
            files = {info.filename: zf.read(info) for info in infos}
    except Exception as exc:
        result["errors"].append({"code": "ZIP_OPEN_FAILED", "detail": str(exc)})
        return result

    if bad:
        result["errors"].append({"code": "ZIP_CRC_FAILURE", "detail": bad})

    # Security checks
    for info in infos:
        name = info.filename
        normalized = os.path.normpath(name)
        if name.startswith("/") or normalized.startswith("..") or "/../" in f"/{name}/":
            result["errors"].append({"code": "UNSAFE_PATH", "detail": name})
        ratio = info.file_size / info.compress_size if info.compress_size else (999999 if info.file_size else 1)
        if ratio > 100:
            result["errors"].append({"code": "COMPRESSION_RATIO", "detail": f"{name}: {ratio:.2f}"})

    counts = collections.Counter(names)
    for name, count in counts.items():
        if count > 1:
            result["errors"].append({"code": "DUPLICATE_PATH", "detail": f"{name}: {count}"})

    root = locate_record_root(names)
    logical_files = {name[len(root):]: data for name, data in files.items() if not name.endswith("/")}
    required = {
        "README.md", "raw/events.jsonl", "raw/transcript.md",
        "integrity/manifest.json", "integrity/hashes.json",
        "integrity/gaps.json", "integrity/source-receipt.json"
    }
    for missing in sorted(required - set(logical_files)):
        result["errors"].append({"code": "MISSING_REQUIRED_FILE", "detail": missing})

    try:
        manifest = json.loads(logical_files["integrity/manifest.json"])
        hashes = json.loads(logical_files["integrity/hashes.json"])
    except Exception as exc:
        result["errors"].append({"code": "INVALID_INTEGRITY_JSON", "detail": str(exc)})
        return result

    manifest_paths = {entry.get("path") for entry in manifest.get("files", []) if isinstance(entry, dict)}
    for name in sorted(set(logical_files) - manifest_paths):
        result["errors"].append({"code": "UNMANIFESTED_FILE", "detail": name})
    for name in sorted(manifest_paths - set(logical_files)):
        result["errors"].append({"code": "MANIFEST_PHANTOM", "detail": name})

    ledger = hashes.get("entries", {})
    for name, data in logical_files.items():
        if name == "integrity/hashes.json":
            continue
        expected = ledger.get(name)
        if expected is None:
            result["errors"].append({"code": "HASH_LEDGER_MISSING", "detail": name})
        elif expected != sha256_bytes(data):
            result["errors"].append({"code": "HASH_MISMATCH", "detail": name})

    # Parse canonical events and validate.
    events = []
    try:
        for line_number, line in enumerate(logical_files["raw/events.jsonl"].decode("utf-8").splitlines(), 1):
            event = json.loads(line)
            events.append(event)
            expected_hash = sha256_bytes(event.get("content", "").encode("utf-8"))
            if event.get("content_sha256") != expected_hash:
                result["errors"].append({"code": "EVENT_CONTENT_HASH", "detail": f"line {line_number}"})
    except Exception as exc:
        result["errors"].append({"code": "EVENT_STREAM_INVALID", "detail": str(exc)})
        return result

    seqs = [event.get("sequence") for event in events]
    if seqs != list(range(1, len(events) + 1)):
        result["errors"].append({"code": "EVENT_SEQUENCE", "detail": repr(seqs[:10])})

    if manifest.get("record_count") != len(events):
        result["errors"].append({
            "code": "RECORD_COUNT",
            "detail": f"manifest={manifest.get('record_count')} actual={len(events)}"
        })

    result["metrics"] = {
        "root_prefix": root,
        "file_count": len(logical_files),
        "event_count": len(events),
        "role_counts": dict(collections.Counter(event.get("actor") for event in events)),
        "ledger_entry_count": len(ledger)
    }
    result["accepted"] = not result["errors"]
    return result


def load_events_from_record(path: Path) -> list[dict[str, Any]]:
    if path.is_dir():
        events_path = path / "raw" / "events.jsonl"
        return [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        root = locate_record_root(names)
        name = root + "raw/events.jsonl"
        return [json.loads(line) for line in zf.read(name).decode("utf-8").splitlines() if line.strip()]


def normalized_text(value: str) -> str:
    return " ".join(value.split()).casefold()


def diff_records(left: Path, right: Path) -> dict[str, Any]:
    left_events = load_events_from_record(left)
    right_events = load_events_from_record(right)

    right_by_hash: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    right_by_normalized: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for event in right_events:
        right_by_hash[event["content_sha256"]].append(event)
        right_by_normalized[normalized_text(event["content"])].append(event)

    exact = []
    normalized = []
    left_only = []
    consumed_right: set[str] = set()

    for event in left_events:
        match = next(
            (candidate for candidate in right_by_hash[event["content_sha256"]]
             if candidate["event_id"] not in consumed_right),
            None
        )
        if match:
            consumed_right.add(match["event_id"])
            exact.append({"left": event["event_id"], "right": match["event_id"]})
            continue

        match = next(
            (candidate for candidate in right_by_normalized[normalized_text(event["content"])]
             if candidate["event_id"] not in consumed_right),
            None
        )
        if match:
            consumed_right.add(match["event_id"])
            normalized.append({"left": event["event_id"], "right": match["event_id"]})
        else:
            left_only.append(event["event_id"])

    right_only = [
        event["event_id"] for event in right_events if event["event_id"] not in consumed_right
    ]
    return {
        "left_event_count": len(left_events),
        "right_event_count": len(right_events),
        "exact_match_count": len(exact),
        "normalized_match_count": len(normalized),
        "left_only_count": len(left_only),
        "right_only_count": len(right_only),
        "exact_matches": exact,
        "normalized_matches": normalized,
        "left_only": left_only,
        "right_only": right_only
    }
