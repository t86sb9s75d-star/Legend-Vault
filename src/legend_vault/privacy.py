"""Fail-closed private-data boundary.

This module enforces a hard separation between the public software repository and
private user records (real ChatGPT exports and everything derived from them).
Private and secret data must never live inside a Git working tree; only
explicitly-declared synthetic data may, and only when the caller opts in.

Design rules (deliberate):
- Classification is supplied *explicitly* by the caller. This module never
  inspects file contents, and never guesses whether data is synthetic, private,
  or secret.
- It never reads environment variables and never shells out to Git; the check is
  a deterministic filesystem walk.
- It never creates directories, and works on paths that do not yet exist.
- Unknown or missing classifications fail closed (refuse).
- Errors identify only the operation and the rejected destination — never file
  contents, account identifiers, titles, excerpts, or export metadata.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

DataClassification = Literal["synthetic", "private", "secret"]

_VALID_CLASSIFICATIONS: frozenset[str] = frozenset({"synthetic", "private", "secret"})


class PrivateDataBoundaryError(RuntimeError):
    """Raised when an operation would place private data inside a Git worktree,
    or when a classification is unknown/missing (fail-closed)."""


def find_git_worktree(path: Path) -> Path | None:
    """Return the Git working-tree root at or above ``path``, else ``None``.

    Resolves ``path`` (without requiring it to exist) and walks upward. A
    directory is a working-tree root if it contains a ``.git`` **directory**
    (normal clone) or a ``.git`` **file** (linked worktree, holding
    ``gitdir: ...``). The root and every descendant are considered inside.
    """
    resolved = path.resolve()
    for candidate in (resolved, *resolved.parents):
        marker = candidate / ".git"
        if marker.is_dir() or marker.is_file():
            return candidate
    return None


def assert_private_data_path(
    path: Path,
    *,
    purpose: str,
    classification: DataClassification,
    allow_synthetic_git_worktree: bool = False,
) -> None:
    """Refuse to place ``classification`` data at ``path`` inside a Git worktree.

    - ``private`` / ``secret`` are always rejected inside a worktree, regardless
      of ``allow_synthetic_git_worktree``.
    - ``synthetic`` is rejected inside a worktree unless
      ``allow_synthetic_git_worktree=True`` is passed explicitly.
    - Anything outside every Git worktree is allowed.
    - An unknown or missing classification fails closed.

    Raises ``PrivateDataBoundaryError`` on refusal. Performs no filesystem
    mutation and reads no file contents.
    """
    if classification not in _VALID_CLASSIFICATIONS:
        # Fail closed: never allow an operation we cannot classify.
        raise PrivateDataBoundaryError(
            f"Refusing private-data operation: {purpose} has an unrecognized data "
            f"classification; refusing by default."
        )

    worktree = find_git_worktree(path)
    if worktree is None:
        return

    resolved = path.resolve()

    if classification in ("private", "secret"):
        raise PrivateDataBoundaryError(
            f"Refusing private-data operation: {purpose} destination is inside a "
            f"Git working tree ({resolved}). Choose a private data directory "
            f"outside the repository."
        )

    # classification == "synthetic"
    if not allow_synthetic_git_worktree:
        raise PrivateDataBoundaryError(
            f"Refusing private-data operation: {purpose} is synthetic but the "
            f"in-repository synthetic override (allow_synthetic_git_worktree=True) "
            f"was not declared. Destination: {resolved}."
        )
