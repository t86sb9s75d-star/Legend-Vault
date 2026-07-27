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
- A path counts as inside a worktree if **either** its lexical (as-named,
  symlinks not followed) absolute form **or** its symlink-resolved form is inside
  one. This closes symlink bypasses in both directions: a path lexically inside
  the repo that symlinks outward is still refused, and a path outside that
  symlinks into the repo is refused too.
- Unrecognized classifications fail closed (refuse); a *missing* classification
  argument raises ``TypeError`` from the function signature.
- Errors identify only the operation and the rejected destination (the lexical
  path the caller provided) — never file contents, account identifiers, titles,
  excerpts, or export metadata.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

DataClassification = Literal["synthetic", "private", "secret"]

_VALID_CLASSIFICATIONS: frozenset[str] = frozenset({"synthetic", "private", "secret"})


class PrivateDataBoundaryError(RuntimeError):
    """Raised when an operation would place private data inside a Git worktree,
    or when the caller passes an *unrecognized* classification value (fail-closed).

    A *missing* classification argument does not raise this: it raises
    ``TypeError`` from the function signature before this exception could be
    constructed. Catch that separately if you may omit the keyword.
    """


def _lexical_abspath(path: Path) -> Path:
    """Absolute path with ``..`` normalized lexically and **no symlink
    resolution** — the location the caller named. Uses no env vars; reads
    nothing from disk."""
    return Path(os.path.abspath(path))


def _resolved_abspath(path: Path) -> Path:
    """Fully resolved absolute path (symlinks followed), tolerant of a
    not-yet-existing tail. Falls back to the lexical form if resolution fails
    (e.g. a symlink loop) so the check still runs."""
    try:
        return path.resolve()
    except (OSError, RuntimeError):
        return _lexical_abspath(path)


def _worktree_root_of(abs_path: Path) -> Path | None:
    """Walk ``abs_path`` and its parents; return the first directory holding a
    ``.git`` directory (normal clone) or ``.git`` file (linked worktree)."""
    for candidate in (abs_path, *abs_path.parents):
        marker = candidate / ".git"
        if marker.is_dir() or marker.is_file():
            return candidate
    return None


def find_git_worktree(path: Path) -> Path | None:
    """Return a Git working-tree root at or above ``path``, else ``None``.

    Checks **both** interpretations of ``path`` and returns a worktree root if
    either is inside one:

    - the *lexical* absolute path (``..`` normalized, symlinks **not** followed)
      — the location the caller named; and
    - the *resolved* absolute path (symlinks followed), tolerant of a
      not-yet-existing tail.

    A ``.git`` directory (normal clone) or ``.git`` file (linked worktree) marks
    a root; the root and every descendant are inside. Works on paths that do not
    yet exist and performs no filesystem mutation.
    """
    for abs_path in (_lexical_abspath(path), _resolved_abspath(path)):
        root = _worktree_root_of(abs_path)
        if root is not None:
            return root
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
    - An unrecognized classification fails closed; a missing one raises
      ``TypeError`` from this signature.

    Raises ``PrivateDataBoundaryError`` on refusal. Performs no filesystem
    mutation and reads no file contents. Error messages report the lexical
    destination the caller provided, never the symlink-resolved target.
    """
    # The destination shown in errors is the path as the caller named it — never
    # the symlink-resolved target (no symlink confusion, no content).
    destination = _lexical_abspath(path)

    if classification not in _VALID_CLASSIFICATIONS:
        # Fail closed: never allow an operation we cannot classify.
        raise PrivateDataBoundaryError(
            f"Refusing private-data operation: {purpose} destination ({destination}) "
            f"has an unrecognized data classification; refusing by default."
        )

    if find_git_worktree(path) is None:
        return

    if classification in ("private", "secret"):
        raise PrivateDataBoundaryError(
            f"Refusing private-data operation: {purpose} destination is inside a "
            f"Git working tree ({destination}). Choose a private data directory "
            f"outside the repository."
        )

    # classification == "synthetic"
    if not allow_synthetic_git_worktree:
        raise PrivateDataBoundaryError(
            f"Refusing private-data operation: {purpose} is synthetic but the "
            f"in-repository synthetic override (allow_synthetic_git_worktree=True) "
            f"was not declared. Destination: {destination}."
        )
