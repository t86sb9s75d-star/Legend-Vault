"""Tests for the fail-closed private-data boundary.

Every path here is synthetic and lives under a throwaway temp directory. Fake
Git worktrees are created with a ``.git`` directory (normal clone) or a ``.git``
file (linked worktree) so the tests never depend on — or write into — the real
repository. No real export values appear anywhere in this file.
"""

from __future__ import annotations

import json
import os
import tempfile
import zipfile
from pathlib import Path

from legend_vault.core import build_record
from legend_vault.privacy import (
    PrivateDataBoundaryError,
    assert_private_data_path,
    find_git_worktree,
)


# --- helpers ------------------------------------------------------------------


def _make_worktree(root: Path, *, linked: bool = False) -> Path:
    """Create a fake Git worktree root. ``linked`` uses a .git *file*."""
    repo = root / "repo"
    repo.mkdir(parents=True, exist_ok=True)
    if linked:
        (repo / ".git").write_text("gitdir: /elsewhere/.git/worktrees/repo\n", encoding="utf-8")
    else:
        (repo / ".git").mkdir()
    return repo


def _write_synthetic_export(path: Path) -> None:
    conversations = [{
        "id": "conv-synthetic",
        "title": "Synthetic Boundary Fixture",
        "mapping": {
            "root": {"id": "root", "parent": None, "children": ["m1"], "message": None},
            "m1": {
                "id": "m1", "parent": "root", "children": [],
                "message": {
                    "id": "msg-1", "author": {"role": "user"},
                    "create_time": 1760000000,
                    "content": {"content_type": "text", "parts": ["synthetic hello"]},
                    "status": "finished_successfully", "end_turn": True,
                },
            },
        },
        "current_node": "m1",
    }]
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("conversations.json", json.dumps(conversations))
        archive.writestr("user.json", json.dumps({"id": "synthetic-user"}))


def _expect_boundary_error(func) -> PrivateDataBoundaryError:
    try:
        func()
    except PrivateDataBoundaryError as exc:
        return exc
    raise AssertionError("expected PrivateDataBoundaryError, but none was raised")


# --- cases --------------------------------------------------------------------


def test_reject_existing_private_file_in_worktree() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        repo = _make_worktree(Path(tmp))
        target = repo / "records" / "data.json"
        target.parent.mkdir(parents=True)
        target.write_text("placeholder", encoding="utf-8")
        _expect_boundary_error(lambda: assert_private_data_path(
            target, purpose="record", classification="private"))


def test_reject_not_yet_created_private_output_in_worktree() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        repo = _make_worktree(Path(tmp))
        target = repo / "vault" / "LV-abcdef" / "raw"  # does not exist
        _expect_boundary_error(lambda: assert_private_data_path(
            target, purpose="Legend Vault output", classification="private"))
        assert not target.exists()  # guard created nothing


def test_reject_private_in_linked_worktree_dot_git_file() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        repo = _make_worktree(Path(tmp), linked=True)
        assert (repo / ".git").is_file()
        target = repo / "sub" / "record.dat"
        _expect_boundary_error(lambda: assert_private_data_path(
            target, purpose="record", classification="private"))


def test_accept_private_path_outside_worktree() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        outside = Path(tmp) / "outside" / "records" / "data.json"
        assert find_git_worktree(outside) is None
        # Must not raise.
        assert_private_data_path(outside, purpose="record", classification="private")


def test_accept_synthetic_in_worktree_only_with_override() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        repo = _make_worktree(Path(tmp))
        fixture = repo / "fixtures" / "synthetic.zip"
        # Must not raise when the synthetic override is explicit.
        assert_private_data_path(
            fixture,
            purpose="synthetic test fixture",
            classification="synthetic",
            allow_synthetic_git_worktree=True,
        )


def test_reject_synthetic_in_worktree_without_override() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        repo = _make_worktree(Path(tmp))
        fixture = repo / "fixtures" / "synthetic.zip"
        _expect_boundary_error(lambda: assert_private_data_path(
            fixture, purpose="synthetic test fixture", classification="synthetic"))


def test_rejection_before_output_creation() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        repo = _make_worktree(root)
        source = root / "outside" / "synthetic-export.zip"  # outside worktree
        source.parent.mkdir(parents=True)
        _write_synthetic_export(source)
        output = repo / "vault"  # inside worktree -> must be refused
        _expect_boundary_error(lambda: build_record(source, output))
        assert not output.exists()  # nothing was created


def test_rejection_before_invalid_zip_is_opened() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        repo = _make_worktree(root)
        source = repo / "not-really.zip"  # inside worktree, and not a valid zip
        source.write_text("this is not a zip", encoding="utf-8")
        output = root / "outside-out"  # outside worktree
        # The source guard must fire before any attempt to open the bad zip,
        # so we get a boundary error rather than a zip parse error.
        _expect_boundary_error(lambda: build_record(source, output))


def test_synthetic_build_in_worktree_requires_explicit_override() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        repo = _make_worktree(Path(tmp))
        source = repo / "fixtures" / "synthetic-export.zip"
        source.parent.mkdir(parents=True)
        _write_synthetic_export(source)

        # Default (private) ingestion into the repo is refused.
        _expect_boundary_error(lambda: build_record(source, repo / "vault-default"))

        # Explicit synthetic + override succeeds and actually builds a record.
        record_dir, archive_path, summary = build_record(
            source,
            repo / "vault-synthetic",
            classification="synthetic",
            allow_synthetic_git_worktree=True,
        )
        assert record_dir.exists()
        assert archive_path.exists()
        assert summary["event_count"] == 1


def test_error_message_excludes_file_contents() -> None:
    secret = "SUPER_SECRET_CONVERSATION_BODY_9f8e7d"
    with tempfile.TemporaryDirectory() as tmp:
        repo = _make_worktree(Path(tmp))
        target = repo / "records" / "conversation.json"
        target.parent.mkdir(parents=True)
        target.write_text(secret, encoding="utf-8")
        exc = _expect_boundary_error(lambda: assert_private_data_path(
            target, purpose="record", classification="private"))
        assert secret not in str(exc)


def test_override_cannot_permit_private() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        repo = _make_worktree(Path(tmp))
        target = repo / "records" / "x.json"
        _expect_boundary_error(lambda: assert_private_data_path(
            target,
            purpose="record",
            classification="private",
            allow_synthetic_git_worktree=True,
        ))


def test_override_cannot_permit_secret() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        repo = _make_worktree(Path(tmp))
        target = repo / "secrets" / "key.pem"
        _expect_boundary_error(lambda: assert_private_data_path(
            target,
            purpose="secret material",
            classification="secret",
            allow_synthetic_git_worktree=True,
        ))


def test_unknown_classification_fails_closed() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        # Even outside a worktree, an unrecognized classification is refused.
        outside = Path(tmp) / "outside" / "x"
        _expect_boundary_error(lambda: assert_private_data_path(
            outside, purpose="record", classification="public"))  # type: ignore[arg-type]


def test_missing_classification_rejected_by_signature() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "x"
        try:
            assert_private_data_path(target, purpose="record")  # type: ignore[call-arg]
        except TypeError:
            return
        raise AssertionError("missing classification should raise TypeError")


def test_nested_private_destinations_in_worktree_rejected() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        repo = _make_worktree(Path(tmp))
        nested = [
            "temp/extract/x",
            "cache/y",
            "caches/z",
            "logs/run.log",
            "receipts/receipt.json",
            "reports/private/report.json",
            "indexes/index.bin",
            "databases/vault.sqlite",
            "archives/LV-1.zip",
        ]
        for rel in nested:
            target = repo / rel
            _expect_boundary_error(lambda t=target: assert_private_data_path(
                t, purpose="derived output", classification="private"))


def test_environment_variables_cannot_enable_override() -> None:
    saved = {k: os.environ.get(k) for k in ("CI", "LEGEND_VAULT_ALLOW_GIT_WORKTREE")}
    os.environ["CI"] = "true"
    os.environ["LEGEND_VAULT_ALLOW_GIT_WORKTREE"] = "1"
    try:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _make_worktree(Path(tmp))
            target = repo / "records" / "x.json"
            # Private is still refused despite the env vars...
            _expect_boundary_error(lambda: assert_private_data_path(
                target, purpose="record", classification="private"))
            # ...and synthetic without an explicit override is still refused.
            _expect_boundary_error(lambda: assert_private_data_path(
                target, purpose="fixture", classification="synthetic"))
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


_TESTS = [
    test_reject_existing_private_file_in_worktree,
    test_reject_not_yet_created_private_output_in_worktree,
    test_reject_private_in_linked_worktree_dot_git_file,
    test_accept_private_path_outside_worktree,
    test_accept_synthetic_in_worktree_only_with_override,
    test_reject_synthetic_in_worktree_without_override,
    test_rejection_before_output_creation,
    test_rejection_before_invalid_zip_is_opened,
    test_synthetic_build_in_worktree_requires_explicit_override,
    test_error_message_excludes_file_contents,
    test_override_cannot_permit_private,
    test_override_cannot_permit_secret,
    test_unknown_classification_fails_closed,
    test_missing_classification_rejected_by_signature,
    test_nested_private_destinations_in_worktree_rejected,
    test_environment_variables_cannot_enable_override,
]


if __name__ == "__main__":
    for test in _TESTS:
        test()
    print(f"Private-data boundary tests passed ({len(_TESTS)} cases).")
