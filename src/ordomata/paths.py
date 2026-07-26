"""Canonical and legacy local-state path resolution.

The rename to Ordomata changes the default state directory to ``.ordomata``.
Existing ``.agentops`` directories contain append-only audit records whose
stored paths must not be rewritten merely for branding.  A legacy-only state
root therefore remains readable and writable in place.  Seeing both roots is
ambiguous and fails closed instead of creating split histories.
"""

from __future__ import annotations

from pathlib import Path

from .errors import ConfigurationError


STATE_DIRECTORY_NAME = ".ordomata"
LEGACY_STATE_DIRECTORY_NAME = ".agentops"


def _directory_entry_exists(path: Path) -> bool:
    """Return whether an entry exists, including a broken symlink."""

    return path.exists() or path.is_symlink()


def resolve_state_directory_name(project_root: str | Path) -> str:
    """Select the one unambiguous state-directory name without mutating it."""

    root = Path(project_root)
    canonical = root / STATE_DIRECTORY_NAME
    legacy = root / LEGACY_STATE_DIRECTORY_NAME
    canonical_exists = _directory_entry_exists(canonical)
    legacy_exists = _directory_entry_exists(legacy)
    if canonical_exists and legacy_exists:
        raise ConfigurationError(
            "both .ordomata and legacy .agentops state directories exist; "
            "refusing to split or merge append-only history"
        )
    selected = legacy if legacy_exists else canonical
    if selected.is_symlink():
        raise ConfigurationError("state directory must not be a symlink")
    if selected.exists() and not selected.is_dir():
        raise ConfigurationError("state directory must be a directory")
    return selected.name


def resolve_state_root(project_root: str | Path) -> Path:
    """Return the canonical root or the sole legacy compatibility root."""

    root = Path(project_root)
    return root / resolve_state_directory_name(root)


__all__ = [
    "LEGACY_STATE_DIRECTORY_NAME",
    "STATE_DIRECTORY_NAME",
    "resolve_state_directory_name",
    "resolve_state_root",
]
