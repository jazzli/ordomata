"""Digest-only contract for a future controller-owned no-Git job tree.

This v1 module deliberately performs no filesystem, process, network, Git,
database, or worker action.  It validates a bounded controller-owned source
bundle against the exact path-policy and resource-limit snapshots bound into
v4 repository-registration evidence.  Its result is only a future
materialization target: it cannot create a job tree, copy source bytes,
reconcile a patch, or enable worker execution or dispatch.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
import unicodedata
from typing import Any

from .authorization import canonical_digest
from .errors import ValidationError
from .worker_cell_containment import (
    RepositoryWorkerCellContainmentContract,
    derive_repository_worker_cell_containment_contract,
)


REPOSITORY_WORKER_JOB_TREE_SCHEMA_VERSION = 1
REPOSITORY_WORKER_JOB_TREE_CONTRACT_KIND = (
    "repository_worker_no_git_job_tree_contract"
)

_INVALID_CONTRACT_MESSAGE = "repository worker job tree contract is invalid"
_INVALID_SOURCE_BUNDLE_MESSAGE = (
    "repository worker job tree source bundle is invalid"
)
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_WINDOWS_ABSOLUTE_PATH_PATTERN = re.compile(r"[A-Za-z]:[\\/]")
_MAX_PATH_CHARACTERS = 500
_MAX_PATH_BYTES = 4 * 1024
_MAX_SOURCE_FILES = 4_096
_MAX_SOURCE_BYTES = 64 * 1024 * 1024
_MAX_SOURCE_FILE_BYTES = 16 * 1024 * 1024
_MANDATORY_PROTECTED_PATHS = frozenset({".agentops", ".git", ".ordomata"})
_PROHIBITED_PATH_COMPONENTS = frozenset(
    {
        ".agentops",
        ".aws",
        ".claude",
        ".codex",
        ".docker",
        ".env",
        ".gnupg",
        ".kube",
        ".netrc",
        ".npmrc",
        ".ordomata",
        ".pypirc",
        ".ssh",
        ".git",
    }
)
_PATH_POLICY_KEYS = frozenset(
    {"allowed_paths", "protected_paths", "generated_paths", "vendor_paths"}
)
_RESOURCE_LIMIT_BOUNDS: dict[str, tuple[int, int]] = {
    "cpu_count": (1, 64),
    "cpu_seconds": (1, 86_400),
    "memory_bytes": (64 * 1024 * 1024, 64 * 1024 * 1024 * 1024),
    "process_count": (1, 1_024),
    "workspace_bytes": (1024 * 1024, 1024 * 1024 * 1024 * 1024),
    "output_bytes": (1024, 1024 * 1024 * 1024),
    "artifact_count": (1, 1_024),
    "artifact_bytes": (1024, 1024 * 1024 * 1024),
    "wall_seconds": (1, 86_400),
    "idle_seconds": (1, 3_600),
}

# Capture the immutable proof boundary during import.  A later public-module
# monkeypatch must not replace validation of detached registration evidence.
_BUILTIN_DERIVE_CONTAINMENT_CONTRACT = (
    derive_repository_worker_cell_containment_contract
)
_BUILTIN_CANONICAL_DIGEST = canonical_digest


class _InvalidJobTree(ValueError):
    """Private sentinel used to keep validation failures value-free."""


def _is_digest(value: Any) -> bool:
    return type(value) is str and _DIGEST_PATTERN.fullmatch(value) is not None


def _is_canonical_relative_path(value: Any) -> bool:
    if (
        type(value) is not str
        or not value
        or len(value) > _MAX_PATH_CHARACTERS
        or "\\" in value
        or _WINDOWS_ABSOLUTE_PATH_PATTERN.match(value) is not None
        or value.startswith("/")
        or value.endswith("/")
        or "//" in value
        or unicodedata.normalize("NFC", value) != value
    ):
        return False
    try:
        if len(value.encode("utf-8")) > _MAX_PATH_BYTES:
            return False
    except UnicodeError:
        return False
    parts = value.split("/")
    if any(
        not part
        or part in {".", ".."}
        or any(ord(character) < 32 or ord(character) == 127 for character in part)
        for part in parts
    ):
        return False
    return True


def _is_at_or_below(path: str, root: str) -> bool:
    return path == root or path.startswith(f"{root}/")


def _is_at_or_below_casefold(path: str, root: str) -> bool:
    return _is_at_or_below(path.casefold(), root.casefold())


def _validate_path_sequence(
    value: Any,
    *,
    minimum: int,
    maximum: int,
) -> tuple[str, ...]:
    if type(value) is not list or not minimum <= len(value) <= maximum:
        raise _InvalidJobTree
    if any(not _is_canonical_relative_path(item) for item in value):
        raise _InvalidJobTree
    paths = tuple(value)
    if paths != tuple(sorted(paths)) or len(paths) != len(set(paths)):
        raise _InvalidJobTree
    for index, path in enumerate(paths):
        for other in paths[index + 1 :]:
            if _is_at_or_below_casefold(path, other) or _is_at_or_below_casefold(
                other, path
            ):
                raise _InvalidJobTree
    return paths


def _path_policy_snapshot(value: Any) -> dict[str, list[str]]:
    if type(value) is not dict or frozenset(value) != _PATH_POLICY_KEYS:
        raise _InvalidJobTree
    allowed = _validate_path_sequence(value["allowed_paths"], minimum=1, maximum=128)
    protected = _validate_path_sequence(
        value["protected_paths"], minimum=1, maximum=128
    )
    generated = _validate_path_sequence(value["generated_paths"], minimum=0, maximum=64)
    vendor = _validate_path_sequence(value["vendor_paths"], minimum=0, maximum=64)
    if not _MANDATORY_PROTECTED_PATHS.issubset(protected):
        raise _InvalidJobTree
    for allowed_path in allowed:
        for protected_path in protected:
            casefold_related = _is_at_or_below_casefold(
                allowed_path, protected_path
            ) or _is_at_or_below_casefold(protected_path, allowed_path)
            exactly_related = _is_at_or_below(
                allowed_path, protected_path
            ) or _is_at_or_below(protected_path, allowed_path)
            if casefold_related and not exactly_related:
                raise _InvalidJobTree
    if any(
        _is_at_or_below_casefold(allowed_path, protected_path)
        for allowed_path in allowed
        for protected_path in _MANDATORY_PROTECTED_PATHS
    ):
        raise _InvalidJobTree
    exclusions = generated + vendor
    if len(exclusions) != len(set(exclusions)):
        raise _InvalidJobTree
    for excluded_path in exclusions:
        if any(
            _is_at_or_below_casefold(excluded_path, protected_path)
            or _is_at_or_below_casefold(protected_path, excluded_path)
            for protected_path in protected
        ):
            raise _InvalidJobTree
    return {
        "allowed_paths": list(allowed),
        "generated_paths": list(generated),
        "protected_paths": list(protected),
        "vendor_paths": list(vendor),
    }


def _resource_limits_snapshot(value: Any) -> dict[str, int]:
    if type(value) is not dict or frozenset(value) != frozenset(
        _RESOURCE_LIMIT_BOUNDS
    ):
        raise _InvalidJobTree
    checked: dict[str, int] = {}
    for name, (minimum, maximum) in _RESOURCE_LIMIT_BOUNDS.items():
        item = value[name]
        if type(item) is not int or not minimum <= item <= maximum:
            raise _InvalidJobTree
        checked[name] = item
    if (
        checked["idle_seconds"] > checked["wall_seconds"]
        or checked["cpu_seconds"]
        > checked["cpu_count"] * checked["wall_seconds"]
        or checked["output_bytes"] > checked["workspace_bytes"]
        or checked["artifact_bytes"] > checked["workspace_bytes"]
    ):
        raise _InvalidJobTree
    return checked


def _prohibited_component(path: str) -> bool:
    for component in path.split("/"):
        folded = component.casefold()
        if (
            folded in _PROHIBITED_PATH_COMPONENTS
            or folded.startswith(".env.")
            or folded.startswith(".envrc.")
        ):
            return True
    return False


@dataclass(frozen=True, slots=True)
class RepositoryWorkerJobTreeSourceFile:
    """One controller-owned regular file for a future no-Git job tree."""

    relative_path: str = field(repr=False)
    content: bytes = field(repr=False)
    executable: bool = False

    def __post_init__(self) -> None:
        if (
            not _is_canonical_relative_path(self.relative_path)
            or type(self.content) is not bytes
            or len(self.content) > _MAX_SOURCE_FILE_BYTES
            or type(self.executable) is not bool
        ):
            raise ValidationError(_INVALID_SOURCE_BUNDLE_MESSAGE)

    @property
    def content_digest(self) -> str:
        self.__post_init__()
        return f"sha256:{hashlib.sha256(self.content).hexdigest()}"


@dataclass(frozen=True, slots=True)
class RepositoryWorkerJobTreeSourceBundle:
    """Bounded in-memory controller input; it is not a filesystem snapshot."""

    files: tuple[RepositoryWorkerJobTreeSourceFile, ...] = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.files) is not tuple
            or not 1 <= len(self.files) <= _MAX_SOURCE_FILES
        ):
            raise ValidationError(_INVALID_SOURCE_BUNDLE_MESSAGE)
        if any(
            type(item) is not RepositoryWorkerJobTreeSourceFile
            for item in self.files
        ):
            raise ValidationError(_INVALID_SOURCE_BUNDLE_MESSAGE)
        try:
            paths = tuple(item.relative_path for item in self.files)
            sizes = tuple(len(item.content) for item in self.files)
        except (AttributeError, TypeError):
            raise ValidationError(_INVALID_SOURCE_BUNDLE_MESSAGE) from None
        if (
            any(not _is_canonical_relative_path(path) for path in paths)
            or paths != tuple(sorted(paths))
            or len(paths) != len(set(paths))
            or sum(sizes) > _MAX_SOURCE_BYTES
        ):
            raise ValidationError(_INVALID_SOURCE_BUNDLE_MESSAGE)
        for index, path in enumerate(paths):
            if _prohibited_component(path):
                raise ValidationError(_INVALID_SOURCE_BUNDLE_MESSAGE)
            for other in paths[index + 1 :]:
                if (
                    _is_at_or_below_casefold(path, other)
                    or _is_at_or_below_casefold(other, path)
                ):
                    raise ValidationError(_INVALID_SOURCE_BUNDLE_MESSAGE)

    @property
    def source_file_count(self) -> int:
        self.__post_init__()
        return len(self.files)

    @property
    def source_total_bytes(self) -> int:
        self.__post_init__()
        return sum(len(item.content) for item in self.files)

    @property
    def source_bundle_digest(self) -> str:
        self.__post_init__()
        return _BUILTIN_CANONICAL_DIGEST(
            {
                "files": [
                    {
                        "content_bytes": len(item.content),
                        "content_digest": item.content_digest,
                        "executable": item.executable,
                        "relative_path": item.relative_path,
                    }
                    for item in self.files
                ],
                "kind": "repository_worker_job_tree_source_bundle",
                "schema_version": REPOSITORY_WORKER_JOB_TREE_SCHEMA_VERSION,
            }
        )


@dataclass(frozen=True, slots=True)
class RepositoryWorkerJobTreeContract:
    """Digest-only target for a future controller materializer and reconciler."""

    containment_contract_digest: str
    registration_ref: str
    repository_ref: str
    registration_digest: str
    registration_evidence_digest: str
    filesystem_identity_ref: str
    path_policy_digest: str
    resource_limits_digest: str
    source_bundle_digest: str
    source_file_count: int
    source_total_bytes: int

    def __post_init__(self) -> None:
        if (
            any(
                not _is_digest(getattr(self, name))
                for name in (
                    "containment_contract_digest",
                    "registration_ref",
                    "repository_ref",
                    "registration_digest",
                    "registration_evidence_digest",
                    "filesystem_identity_ref",
                    "path_policy_digest",
                    "resource_limits_digest",
                    "source_bundle_digest",
                )
            )
            or type(self.source_file_count) is not int
            or not 1 <= self.source_file_count <= _MAX_SOURCE_FILES
            or type(self.source_total_bytes) is not int
            or not 0 <= self.source_total_bytes <= _MAX_SOURCE_BYTES
        ):
            raise ValidationError(_INVALID_CONTRACT_MESSAGE)

    @property
    def contract_digest(self) -> str:
        return _BUILTIN_CANONICAL_DIGEST(self.to_contract_mapping())

    def to_contract_mapping(self) -> dict[str, Any]:
        self.__post_init__()
        return {
            "containment_contract_digest": self.containment_contract_digest,
            "filesystem_identity_ref": self.filesystem_identity_ref,
            "git_metadata_prohibited": True,
            "kind": REPOSITORY_WORKER_JOB_TREE_CONTRACT_KIND,
            "path_policy_digest": self.path_policy_digest,
            "registration_digest": self.registration_digest,
            "registration_evidence_digest": self.registration_evidence_digest,
            "registration_ref": self.registration_ref,
            "repository_ref": self.repository_ref,
            "required_job_tree_mode": "controller_owned_no_git",
            "required_patch_reconciliation": "controller_owned",
            "resource_limits_digest": self.resource_limits_digest,
            "schema_version": REPOSITORY_WORKER_JOB_TREE_SCHEMA_VERSION,
            "source_bundle_digest": self.source_bundle_digest,
            "source_file_count": self.source_file_count,
            "source_total_bytes": self.source_total_bytes,
        }

    def to_mapping(self) -> dict[str, Any]:
        mapping = self.to_contract_mapping()
        mapping.update(
            {
                "authority_granted": False,
                "contract_digest": self.contract_digest,
                "dispatch_enabled": False,
                "materialization_implemented": False,
                "materialization_permitted": False,
                "path_policy_bound": True,
                "reconciliation_implemented": False,
                "registration_evidence_revalidated": False,
                "source_snapshot_verified": False,
                "worker_execution_permitted": False,
            }
        )
        return mapping


def _validate_source_bundle_policy(
    source_bundle: RepositoryWorkerJobTreeSourceBundle,
    *,
    path_policy: dict[str, list[str]],
    resource_limits: dict[str, int],
) -> None:
    source_bundle.__post_init__()
    if source_bundle.source_total_bytes > resource_limits["workspace_bytes"]:
        raise _InvalidJobTree
    for file in source_bundle.files:
        path = file.relative_path
        if (
            not any(
                _is_at_or_below(path, allowed_path)
                for allowed_path in path_policy["allowed_paths"]
            )
            or any(
                _is_at_or_below(path, protected_path)
                for protected_path in path_policy["protected_paths"]
            )
            or any(
                _is_at_or_below(path, excluded_path)
                for excluded_path in (
                    path_policy["generated_paths"] + path_policy["vendor_paths"]
                )
            )
        ):
            raise _InvalidJobTree


def derive_repository_worker_job_tree_contract(
    registration_evidence: dict[str, Any],
    *,
    path_policy: dict[str, Any],
    resource_limits: dict[str, Any],
    source_bundle: RepositoryWorkerJobTreeSourceBundle,
) -> RepositoryWorkerJobTreeContract:
    """Bind one source bundle to v4 registration evidence without I/O.

    The caller must still obtain a fresh controller-owned source snapshot,
    materialize it, reconcile any candidate, and revalidate all facts at the
    authoritative dispatch PEP.  This function only makes that future input
    exact and reviewable.
    """

    try:
        containment_contract = _BUILTIN_DERIVE_CONTAINMENT_CONTRACT(
            registration_evidence
        )
        if type(containment_contract) is not RepositoryWorkerCellContainmentContract:
            raise _InvalidJobTree
        checked_policy = _path_policy_snapshot(path_policy)
        checked_limits = _resource_limits_snapshot(resource_limits)
        if (
            _BUILTIN_CANONICAL_DIGEST(checked_policy)
            != containment_contract.path_policy_digest
            or _BUILTIN_CANONICAL_DIGEST(checked_limits)
            != containment_contract.resource_limits_digest
            or type(source_bundle) is not RepositoryWorkerJobTreeSourceBundle
        ):
            raise _InvalidJobTree
        _validate_source_bundle_policy(
            source_bundle,
            path_policy=checked_policy,
            resource_limits=checked_limits,
        )
        return RepositoryWorkerJobTreeContract(
            containment_contract_digest=containment_contract.contract_digest,
            registration_ref=containment_contract.registration_ref,
            repository_ref=containment_contract.repository_ref,
            registration_digest=containment_contract.registration_digest,
            registration_evidence_digest=(
                containment_contract.registration_evidence_digest
            ),
            filesystem_identity_ref=containment_contract.filesystem_identity_ref,
            path_policy_digest=containment_contract.path_policy_digest,
            resource_limits_digest=containment_contract.resource_limits_digest,
            source_bundle_digest=source_bundle.source_bundle_digest,
            source_file_count=source_bundle.source_file_count,
            source_total_bytes=source_bundle.source_total_bytes,
        )
    except (
        AttributeError,
        KeyError,
        TypeError,
        UnicodeError,
        ValidationError,
        ValueError,
    ):
        raise ValidationError(_INVALID_CONTRACT_MESSAGE) from None


__all__ = [
    "REPOSITORY_WORKER_JOB_TREE_CONTRACT_KIND",
    "REPOSITORY_WORKER_JOB_TREE_SCHEMA_VERSION",
    "RepositoryWorkerJobTreeContract",
    "RepositoryWorkerJobTreeSourceBundle",
    "RepositoryWorkerJobTreeSourceFile",
    "derive_repository_worker_job_tree_contract",
]
