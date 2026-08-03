"""Descriptor-safe capture of a detached no-Git job-tree candidate.

This controller-only library primitive reads an active, materialized job tree
through the materializer's held descriptor and returns bounded private bytes
plus digest-only evidence.  It does not launch or contain a worker, prove that
the candidate came from one, apply a patch, use Git, persist state, or grant
authority.  A later lifecycle and containment boundary must establish those
separate properties before any worker dispatch can exist.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Any
import unicodedata

from .authorization import canonical_digest
from .errors import ValidationError
from .repository_worker_job_tree import (
    REPOSITORY_WORKER_JOB_TREE_SCHEMA_VERSION,
    RepositoryWorkerJobTreeContract,
    RepositoryWorkerJobTreeSourceBundle,
    RepositoryWorkerJobTreeSourceFile,
    _MAX_SOURCE_BYTES,
    _MAX_SOURCE_FILE_BYTES,
    _MAX_SOURCE_FILES,
    _is_at_or_below,
    _is_canonical_relative_path,
    _path_policy_snapshot,
    _prohibited_component,
    _resource_limits_snapshot,
)
from .repository_worker_job_tree_materialization import (
    MATERIALIZATION_SCOPE,
    REPOSITORY_WORKER_JOB_TREE_MATERIALIZATION_KIND,
    REPOSITORY_WORKER_JOB_TREE_MATERIALIZATION_SCHEMA_VERSION,
    RepositoryWorkerJobTreeMaterializationLease,
    RepositoryWorkerJobTreeMaterializationReceipt,
    _validated_inputs,
)
from .repository_worker_job_tree_reconciliation import (
    REPOSITORY_WORKER_JOB_TREE_CANDIDATE_BUNDLE_KIND,
    REPOSITORY_WORKER_JOB_TREE_RECONCILIATION_SCHEMA_VERSION,
    RepositoryWorkerJobTreeCandidateBundle,
)
from .repository_worker_job_tree_snapshot import (
    RepositoryWorkerJobTreeSourceSnapshot,
)


REPOSITORY_WORKER_JOB_TREE_CANDIDATE_SNAPSHOT_SCHEMA_VERSION = 1
REPOSITORY_WORKER_JOB_TREE_CANDIDATE_SNAPSHOT_KIND = (
    "repository_worker_no_git_job_tree_candidate_snapshot"
)
CANDIDATE_SNAPSHOT_SCOPE = "posix_descriptor_no_git_candidate_snapshot_v1"

_INVALID_MESSAGE = "repository worker job tree candidate snapshot is invalid"
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CONCRETE_PATH_TYPE = type(Path())
_DIRECTORY_MODE = 0o700
_REGULAR_FILE_MODE = 0o600
_EXECUTABLE_FILE_MODE = 0o700
_READ_CHUNK_BYTES = 64 * 1024
_MAX_SOURCE_NODES = _MAX_SOURCE_FILES * 8
_REQUIRED_DESCRIPTOR_FLAGS = (
    "O_CLOEXEC",
    "O_DIRECTORY",
    "O_NOFOLLOW",
    "O_NONBLOCK",
)

# Freeze the imported proof boundary at import.  The publicly named helpers
# below remain useful for unit-level inspection, but they cannot relax the
# validation path used by a later capture or evidence rendering operation.
_BUILTIN_CANONICAL_DIGEST = canonical_digest
_BUILTIN_VALIDATED_INPUTS = _validated_inputs
_BUILTIN_PATH_POLICY_SNAPSHOT = _path_policy_snapshot
_BUILTIN_RESOURCE_LIMITS_SNAPSHOT = _resource_limits_snapshot
_BUILTIN_IS_AT_OR_BELOW = _is_at_or_below
_BUILTIN_IS_CANONICAL_RELATIVE_PATH = _is_canonical_relative_path
_BUILTIN_PROHIBITED_COMPONENT = _prohibited_component
_SOURCE_SNAPSHOT_TYPE = RepositoryWorkerJobTreeSourceSnapshot
_CONTRACT_TYPE = RepositoryWorkerJobTreeContract
_SOURCE_BUNDLE_TYPE = RepositoryWorkerJobTreeSourceBundle
_SOURCE_FILE_TYPE = RepositoryWorkerJobTreeSourceFile
_MATERIALIZATION_LEASE_TYPE = RepositoryWorkerJobTreeMaterializationLease
_MATERIALIZATION_RECEIPT_TYPE = RepositoryWorkerJobTreeMaterializationReceipt
_CANDIDATE_BUNDLE_TYPE = RepositoryWorkerJobTreeCandidateBundle
_BUILTIN_SOURCE_BUNDLE_POST_INIT = (
    RepositoryWorkerJobTreeSourceBundle.__post_init__
)
_BUILTIN_CANDIDATE_BUNDLE_POST_INIT = (
    RepositoryWorkerJobTreeCandidateBundle.__post_init__
)
_BUILTIN_MATERIALIZATION_RECEIPT_POST_INIT = (
    RepositoryWorkerJobTreeMaterializationReceipt.__post_init__
)


class _InvalidCandidateSnapshot(ValueError):
    """Private sentinel that keeps public failures fixed and value-free."""


def _is_digest(value: Any) -> bool:
    return type(value) is str and _DIGEST_PATTERN.fullmatch(value) is not None


_BUILTIN_IS_DIGEST = _is_digest


def _content_digest(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


_BUILTIN_CONTENT_DIGEST = _content_digest


def _source_bundle_digest(bundle: RepositoryWorkerJobTreeSourceBundle) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "files": [
                {
                    "content_bytes": len(item.content),
                    "content_digest": _BUILTIN_CONTENT_DIGEST(item.content),
                    "executable": item.executable,
                    "relative_path": item.relative_path,
                }
                for item in bundle.files
            ],
            "kind": "repository_worker_job_tree_source_bundle",
            "schema_version": REPOSITORY_WORKER_JOB_TREE_SCHEMA_VERSION,
        }
    )


_BUILTIN_SOURCE_BUNDLE_DIGEST = _source_bundle_digest


def _candidate_bundle_digest(
    bundle: RepositoryWorkerJobTreeCandidateBundle,
) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "files": [
                {
                    "content_bytes": len(item.content),
                    "content_digest": _BUILTIN_CONTENT_DIGEST(item.content),
                    "executable": item.executable,
                    "relative_path": item.relative_path,
                }
                for item in bundle.files
            ],
            "kind": REPOSITORY_WORKER_JOB_TREE_CANDIDATE_BUNDLE_KIND,
            "schema_version": REPOSITORY_WORKER_JOB_TREE_RECONCILIATION_SCHEMA_VERSION,
        }
    )


_BUILTIN_CANDIDATE_BUNDLE_DIGEST = _candidate_bundle_digest


def _path_ref(relative_path: str) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "kind": REPOSITORY_WORKER_JOB_TREE_CANDIDATE_SNAPSHOT_KIND,
            "relative_path": relative_path,
            "schema_version": (
                REPOSITORY_WORKER_JOB_TREE_CANDIDATE_SNAPSHOT_SCHEMA_VERSION
            ),
        }
    )


_BUILTIN_PATH_REF = _path_ref


def _directory_paths_for_files(
    files: tuple[RepositoryWorkerJobTreeSourceFile, ...],
) -> tuple[str, ...]:
    directories: set[str] = set()
    for file in files:
        parts = file.relative_path.split("/")[:-1]
        for index in range(1, len(parts) + 1):
            directories.add("/".join(parts[:index]))
    return tuple(sorted(directories))


_BUILTIN_DIRECTORY_PATHS_FOR_FILES = _directory_paths_for_files


def _validate_candidate_relative_path(
    relative_path: str,
    *,
    path_policy: dict[str, list[str]],
) -> None:
    if (
        not _BUILTIN_IS_CANONICAL_RELATIVE_PATH(relative_path)
        or _BUILTIN_PROHIBITED_COMPONENT(relative_path)
        or not any(
            _BUILTIN_IS_AT_OR_BELOW(relative_path, allowed_path)
            for allowed_path in path_policy["allowed_paths"]
        )
        or any(
            _BUILTIN_IS_AT_OR_BELOW(relative_path, protected_path)
            for protected_path in path_policy["protected_paths"]
        )
        or any(
            _BUILTIN_IS_AT_OR_BELOW(relative_path, excluded_path)
            for excluded_path in (
                path_policy["generated_paths"] + path_policy["vendor_paths"]
            )
        )
    ):
        raise _InvalidCandidateSnapshot


_BUILTIN_VALIDATE_CANDIDATE_RELATIVE_PATH = _validate_candidate_relative_path


def _validate_candidate_bundle_policy(
    bundle: RepositoryWorkerJobTreeCandidateBundle,
    *,
    path_policy: dict[str, list[str]],
    resource_limits: dict[str, int],
) -> None:
    if type(bundle) is not _CANDIDATE_BUNDLE_TYPE:
        raise _InvalidCandidateSnapshot
    _BUILTIN_CANDIDATE_BUNDLE_POST_INIT(bundle)
    if sum(len(item.content) for item in bundle.files) > resource_limits[
        "workspace_bytes"
    ]:
        raise _InvalidCandidateSnapshot
    for file in bundle.files:
        _BUILTIN_VALIDATE_CANDIDATE_RELATIVE_PATH(
            file.relative_path,
            path_policy=path_policy,
        )


_BUILTIN_VALIDATE_CANDIDATE_BUNDLE_POLICY = _validate_candidate_bundle_policy


def _validate_source_bundle_policy(
    bundle: RepositoryWorkerJobTreeSourceBundle,
    *,
    path_policy: dict[str, list[str]],
    resource_limits: dict[str, int],
) -> None:
    if type(bundle) is not _SOURCE_BUNDLE_TYPE:
        raise _InvalidCandidateSnapshot
    _BUILTIN_SOURCE_BUNDLE_POST_INIT(bundle)
    candidate_view = _CANDIDATE_BUNDLE_TYPE(files=bundle.files)
    _BUILTIN_VALIDATE_CANDIDATE_BUNDLE_POLICY(
        candidate_view,
        path_policy=path_policy,
        resource_limits=resource_limits,
    )


_BUILTIN_VALIDATE_SOURCE_BUNDLE_POLICY = _validate_source_bundle_policy


def _validate_directory_paths(
    directory_paths: tuple[str, ...],
    *,
    source_bundle: RepositoryWorkerJobTreeSourceBundle,
    candidate_bundle: RepositoryWorkerJobTreeCandidateBundle,
    path_policy: dict[str, list[str]],
) -> None:
    if type(directory_paths) is not tuple:
        raise _InvalidCandidateSnapshot
    if directory_paths != tuple(sorted(directory_paths)) or len(
        directory_paths
    ) != len(set(directory_paths)):
        raise _InvalidCandidateSnapshot
    directory_set = set(directory_paths)
    for relative_path in directory_paths:
        _BUILTIN_VALIDATE_CANDIDATE_RELATIVE_PATH(
            relative_path,
            path_policy=path_policy,
        )
        parent_parts = relative_path.split("/")[:-1]
        if parent_parts and "/".join(parent_parts) not in directory_set:
            raise _InvalidCandidateSnapshot
    for file in candidate_bundle.files:
        parent_parts = file.relative_path.split("/")[:-1]
        if parent_parts and "/".join(parent_parts) not in directory_set:
            raise _InvalidCandidateSnapshot
    baseline_directories = set(
        _BUILTIN_DIRECTORY_PATHS_FOR_FILES(source_bundle.files)
    )
    candidate_directories = set(
        _BUILTIN_DIRECTORY_PATHS_FOR_FILES(candidate_bundle.files)
    )
    if not directory_set.issubset(baseline_directories | candidate_directories):
        raise _InvalidCandidateSnapshot


_BUILTIN_VALIDATE_DIRECTORY_PATHS = _validate_directory_paths


def _candidate_tree_digest(
    *,
    candidate_bundle: RepositoryWorkerJobTreeCandidateBundle,
    directory_paths: tuple[str, ...],
) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "directories": [
                {"path_ref": _BUILTIN_PATH_REF(relative_path)}
                for relative_path in directory_paths
            ],
            "files": [
                {
                    "content_bytes": len(item.content),
                    "content_digest": _BUILTIN_CONTENT_DIGEST(item.content),
                    "executable": item.executable,
                    "path_ref": _BUILTIN_PATH_REF(item.relative_path),
                }
                for item in candidate_bundle.files
            ],
            "kind": REPOSITORY_WORKER_JOB_TREE_CANDIDATE_SNAPSHOT_KIND,
            "schema_version": (
                REPOSITORY_WORKER_JOB_TREE_CANDIDATE_SNAPSHOT_SCHEMA_VERSION
            ),
        }
    )


_BUILTIN_CANDIDATE_TREE_DIGEST = _candidate_tree_digest


def _materialization_receipt_projection(
    receipt: RepositoryWorkerJobTreeMaterializationReceipt,
) -> dict[str, Any]:
    if type(receipt) is not _MATERIALIZATION_RECEIPT_TYPE:
        raise _InvalidCandidateSnapshot
    try:
        _BUILTIN_MATERIALIZATION_RECEIPT_POST_INIT(receipt)
        projection = {
            "executable_file_count": receipt.executable_file_count,
            "job_tree_contract_digest": receipt.job_tree_contract_digest,
            "kind": receipt.kind,
            "materialization_scope": receipt.materialization_scope,
            "materialized_file_count": receipt.materialized_file_count,
            "materialized_total_bytes": receipt.materialized_total_bytes,
            "regular_file_count": receipt.regular_file_count,
            "schema_version": receipt.schema_version,
            "source_bundle_digest": receipt.source_bundle_digest,
            "source_file_count": receipt.source_file_count,
            "source_snapshot_digest": receipt.source_snapshot_digest,
            "source_total_bytes": receipt.source_total_bytes,
        }
        if (
            type(projection["kind"]) is not str
            or projection["kind"]
            != REPOSITORY_WORKER_JOB_TREE_MATERIALIZATION_KIND
            or type(projection["schema_version"]) is not int
            or projection["schema_version"]
            != REPOSITORY_WORKER_JOB_TREE_MATERIALIZATION_SCHEMA_VERSION
            or type(projection["materialization_scope"]) is not str
            or projection["materialization_scope"] != MATERIALIZATION_SCOPE
        ):
            raise _InvalidCandidateSnapshot
        return projection
    except (AttributeError, TypeError, ValidationError, ValueError):
        raise _InvalidCandidateSnapshot from None


_BUILTIN_MATERIALIZATION_RECEIPT_PROJECTION = (
    _materialization_receipt_projection
)


@dataclass(frozen=True, slots=True)
class RepositoryWorkerJobTreeCandidateSnapshot:
    """Private candidate bytes plus digest-only descriptor-capture evidence."""

    kind: str
    schema_version: int
    candidate_snapshot_scope: str
    source_snapshot_digest: str = field(repr=False)
    job_tree_contract_digest: str = field(repr=False)
    materialization_receipt_digest: str = field(repr=False)
    source_bundle_digest: str = field(repr=False)
    candidate_bundle_digest: str = field(repr=False)
    candidate_tree_digest: str = field(repr=False)
    path_policy_digest: str = field(repr=False)
    resource_limits_digest: str = field(repr=False)
    source_bundle: RepositoryWorkerJobTreeSourceBundle = field(repr=False)
    candidate_bundle: RepositoryWorkerJobTreeCandidateBundle = field(repr=False)
    materialization_receipt: RepositoryWorkerJobTreeMaterializationReceipt = (
        field(repr=False)
    )
    path_policy: dict[str, list[str]] = field(repr=False)
    resource_limits: dict[str, int] = field(repr=False)
    directory_paths: tuple[str, ...] = field(repr=False)
    source_file_count: int
    source_total_bytes: int
    candidate_file_count: int
    candidate_directory_count: int
    candidate_total_bytes: int

    def __post_init__(self) -> None:
        try:
            if (
                type(self.kind) is not str
                or self.kind != REPOSITORY_WORKER_JOB_TREE_CANDIDATE_SNAPSHOT_KIND
                or type(self.schema_version) is not int
                or self.schema_version
                != REPOSITORY_WORKER_JOB_TREE_CANDIDATE_SNAPSHOT_SCHEMA_VERSION
                or type(self.candidate_snapshot_scope) is not str
                or self.candidate_snapshot_scope != CANDIDATE_SNAPSHOT_SCOPE
                or not all(
                    _BUILTIN_IS_DIGEST(getattr(self, name))
                    for name in (
                        "source_snapshot_digest",
                        "job_tree_contract_digest",
                        "materialization_receipt_digest",
                        "source_bundle_digest",
                        "candidate_bundle_digest",
                        "candidate_tree_digest",
                        "path_policy_digest",
                        "resource_limits_digest",
                    )
                )
                or type(self.source_bundle) is not _SOURCE_BUNDLE_TYPE
                or type(self.candidate_bundle) is not _CANDIDATE_BUNDLE_TYPE
                or type(self.materialization_receipt)
                is not _MATERIALIZATION_RECEIPT_TYPE
            ):
                raise _InvalidCandidateSnapshot
            checked_policy = _BUILTIN_PATH_POLICY_SNAPSHOT(self.path_policy)
            checked_limits = _BUILTIN_RESOURCE_LIMITS_SNAPSHOT(
                self.resource_limits
            )
            _BUILTIN_VALIDATE_SOURCE_BUNDLE_POLICY(
                self.source_bundle,
                path_policy=checked_policy,
                resource_limits=checked_limits,
            )
            _BUILTIN_VALIDATE_CANDIDATE_BUNDLE_POLICY(
                self.candidate_bundle,
                path_policy=checked_policy,
                resource_limits=checked_limits,
            )
            _BUILTIN_VALIDATE_DIRECTORY_PATHS(
                self.directory_paths,
                source_bundle=self.source_bundle,
                candidate_bundle=self.candidate_bundle,
                path_policy=checked_policy,
            )
            receipt_projection = _BUILTIN_MATERIALIZATION_RECEIPT_PROJECTION(
                self.materialization_receipt
            )
            if (
                self.source_bundle_digest
                != _BUILTIN_SOURCE_BUNDLE_DIGEST(self.source_bundle)
                or self.candidate_bundle_digest
                != _BUILTIN_CANDIDATE_BUNDLE_DIGEST(self.candidate_bundle)
                or self.candidate_tree_digest
                != _BUILTIN_CANDIDATE_TREE_DIGEST(
                    candidate_bundle=self.candidate_bundle,
                    directory_paths=self.directory_paths,
                )
                or self.materialization_receipt_digest
                != _BUILTIN_CANONICAL_DIGEST(receipt_projection)
                or self.path_policy_digest
                != _BUILTIN_CANONICAL_DIGEST(checked_policy)
                or self.resource_limits_digest
                != _BUILTIN_CANONICAL_DIGEST(checked_limits)
                or receipt_projection["source_snapshot_digest"]
                != self.source_snapshot_digest
                or receipt_projection["job_tree_contract_digest"]
                != self.job_tree_contract_digest
                or receipt_projection["source_bundle_digest"]
                != self.source_bundle_digest
                or receipt_projection["source_file_count"]
                != len(self.source_bundle.files)
                or receipt_projection["source_total_bytes"]
                != sum(len(item.content) for item in self.source_bundle.files)
                or type(self.source_file_count) is not int
                or self.source_file_count != len(self.source_bundle.files)
                or type(self.source_total_bytes) is not int
                or self.source_total_bytes
                != sum(len(item.content) for item in self.source_bundle.files)
                or type(self.candidate_file_count) is not int
                or self.candidate_file_count != len(self.candidate_bundle.files)
                or type(self.candidate_directory_count) is not int
                or self.candidate_directory_count != len(self.directory_paths)
                or type(self.candidate_total_bytes) is not int
                or self.candidate_total_bytes
                != sum(len(item.content) for item in self.candidate_bundle.files)
            ):
                raise _InvalidCandidateSnapshot
        except (
            AttributeError,
            TypeError,
            UnicodeError,
            ValidationError,
            ValueError,
        ):
            raise ValidationError(_INVALID_MESSAGE) from None

    @property
    def candidate_snapshot_digest(self) -> str:
        return _BUILTIN_CANONICAL_DIGEST(
            _BUILTIN_CANDIDATE_SNAPSHOT_PROJECTION(self)
        )

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_CANDIDATE_SNAPSHOT_PROJECTION(self)

    def to_mapping(self) -> dict[str, Any]:
        mapping = _BUILTIN_CANDIDATE_SNAPSHOT_PROJECTION(self)
        mapping.update(
            {
                "authority_granted": False,
                "candidate_capture_authority_granted": False,
                "candidate_filesystem_captured": True,
                "candidate_origin_proven": False,
                "dispatch_enabled": False,
                "patch_application_implemented": False,
                "patch_reconciliation_implemented": False,
                "stable_double_capture_verified": True,
                "worker_execution_permitted": False,
                "candidate_snapshot_digest": self.candidate_snapshot_digest,
            }
        )
        return mapping


_BUILTIN_CANDIDATE_SNAPSHOT_POST_INIT = (
    RepositoryWorkerJobTreeCandidateSnapshot.__post_init__
)
_CANDIDATE_SNAPSHOT_TYPE = RepositoryWorkerJobTreeCandidateSnapshot


def _candidate_snapshot_projection(
    snapshot: RepositoryWorkerJobTreeCandidateSnapshot,
) -> dict[str, Any]:
    _BUILTIN_CANDIDATE_SNAPSHOT_POST_INIT(snapshot)
    return {
        "candidate_bundle_digest": snapshot.candidate_bundle_digest,
        "candidate_directory_count": snapshot.candidate_directory_count,
        "candidate_file_count": snapshot.candidate_file_count,
        "candidate_snapshot_scope": snapshot.candidate_snapshot_scope,
        "candidate_total_bytes": snapshot.candidate_total_bytes,
        "candidate_tree_digest": snapshot.candidate_tree_digest,
        "job_tree_contract_digest": snapshot.job_tree_contract_digest,
        "kind": snapshot.kind,
        "materialization_receipt_digest": snapshot.materialization_receipt_digest,
        "path_policy_digest": snapshot.path_policy_digest,
        "resource_limits_digest": snapshot.resource_limits_digest,
        "schema_version": snapshot.schema_version,
        "source_bundle_digest": snapshot.source_bundle_digest,
        "source_file_count": snapshot.source_file_count,
        "source_snapshot_digest": snapshot.source_snapshot_digest,
        "source_total_bytes": snapshot.source_total_bytes,
    }


_BUILTIN_CANDIDATE_SNAPSHOT_PROJECTION = _candidate_snapshot_projection


def _descriptor_support_is_available() -> bool:
    return (
        all(hasattr(os, name) for name in _REQUIRED_DESCRIPTOR_FLAGS)
        and os.open in os.supports_dir_fd
        and os.stat in os.supports_dir_fd
        and os.stat in os.supports_follow_symlinks
    )


_BUILTIN_DESCRIPTOR_SUPPORT_IS_AVAILABLE = _descriptor_support_is_available


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | os.O_CLOEXEC
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | os.O_NONBLOCK
    )


def _regular_read_flags() -> int:
    return os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK


_BUILTIN_DIRECTORY_FLAGS = _directory_flags
_BUILTIN_REGULAR_READ_FLAGS = _regular_read_flags


def _metadata_signature(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        stat.S_IMODE(metadata.st_mode),
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _root_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    if not stat.S_ISDIR(metadata.st_mode):
        raise _InvalidCandidateSnapshot
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
    )


_BUILTIN_METADATA_SIGNATURE = _metadata_signature
_BUILTIN_ROOT_IDENTITY = _root_identity


def _close_descriptor(descriptor: int | None) -> bool:
    if descriptor is None:
        return True
    try:
        os.close(descriptor)
    except OSError:
        return False
    return True


_BUILTIN_CLOSE_DESCRIPTOR = _close_descriptor


def _directory_entry_names(descriptor: int) -> tuple[str, ...]:
    scan_descriptor: int | None = None
    try:
        scan_descriptor = os.open(
            ".",
            _BUILTIN_DIRECTORY_FLAGS(),
            dir_fd=descriptor,
        )
        original = os.fstat(descriptor)
        reopened = os.fstat(scan_descriptor)
        if (original.st_dev, original.st_ino) != (
            reopened.st_dev,
            reopened.st_ino,
        ) or os.get_inheritable(scan_descriptor):
            raise _InvalidCandidateSnapshot
        entries = os.scandir(scan_descriptor)
        scan_descriptor = None
        with entries:
            names = tuple(entry.name for entry in entries)
    except OSError:
        raise _InvalidCandidateSnapshot from None
    finally:
        if scan_descriptor is not None:
            _BUILTIN_CLOSE_DESCRIPTOR(scan_descriptor)
    if (
        any(type(name) is not str or not name for name in names)
        or len(names) != len(set(names))
    ):
        raise _InvalidCandidateSnapshot
    folded_names: set[str] = set()
    for name in names:
        folded = unicodedata.normalize("NFC", name).casefold()
        if folded in folded_names:
            raise _InvalidCandidateSnapshot
        folded_names.add(folded)
    return tuple(sorted(names))


_BUILTIN_DIRECTORY_ENTRY_NAMES = _directory_entry_names


def _entry_metadata(parent_descriptor: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return None
    except OSError:
        raise _InvalidCandidateSnapshot from None


_BUILTIN_ENTRY_METADATA = _entry_metadata


def _open_directory_at(
    parent_descriptor: int,
    name: str,
    *,
    require_private_mode: bool,
) -> int:
    descriptor: int | None = None
    try:
        named_before = _BUILTIN_ENTRY_METADATA(parent_descriptor, name)
        if named_before is None or not stat.S_ISDIR(named_before.st_mode):
            raise _InvalidCandidateSnapshot
        descriptor = os.open(
            name,
            _BUILTIN_DIRECTORY_FLAGS(),
            dir_fd=parent_descriptor,
        )
        opened = os.fstat(descriptor)
        named_after = _BUILTIN_ENTRY_METADATA(parent_descriptor, name)
        if (
            named_after is None
            or not stat.S_ISDIR(opened.st_mode)
            or _BUILTIN_METADATA_SIGNATURE(named_before)
            != _BUILTIN_METADATA_SIGNATURE(opened)
            or _BUILTIN_METADATA_SIGNATURE(opened)
            != _BUILTIN_METADATA_SIGNATURE(named_after)
            or opened.st_nlink <= 0
            or os.get_inheritable(descriptor)
            or (
                require_private_mode
                and (
                    opened.st_uid != os.geteuid()
                    or stat.S_IMODE(opened.st_mode) != _DIRECTORY_MODE
                )
            )
        ):
            raise _InvalidCandidateSnapshot
        return descriptor
    except (OSError, _InvalidCandidateSnapshot):
        if descriptor is not None:
            _BUILTIN_CLOSE_DESCRIPTOR(descriptor)
        raise _InvalidCandidateSnapshot from None


_BUILTIN_OPEN_DIRECTORY_AT = _open_directory_at


def _open_absolute_directory(value: Path) -> int:
    if (
        type(value) is not _CONCRETE_PATH_TYPE
        or not value.is_absolute()
        or value.anchor != "/"
        or any(part in {"", ".", ".."} for part in value.parts[1:])
    ):
        raise _InvalidCandidateSnapshot
    descriptor: int | None = None
    try:
        descriptor = os.open("/", _BUILTIN_DIRECTORY_FLAGS())
        for component in value.parts[1:]:
            child = _BUILTIN_OPEN_DIRECTORY_AT(
                descriptor,
                component,
                require_private_mode=False,
            )
            if not _BUILTIN_CLOSE_DESCRIPTOR(descriptor):
                _BUILTIN_CLOSE_DESCRIPTOR(child)
                raise _InvalidCandidateSnapshot
            descriptor = child
        return descriptor
    except (OSError, _InvalidCandidateSnapshot):
        if descriptor is not None:
            _BUILTIN_CLOSE_DESCRIPTOR(descriptor)
        raise _InvalidCandidateSnapshot from None


_BUILTIN_OPEN_ABSOLUTE_DIRECTORY = _open_absolute_directory


def _root_path_matches(
    canonical_root: Path,
    expected_identity: tuple[int, int, int, int, int],
) -> bool:
    descriptor: int | None = None
    matched = False
    try:
        descriptor = _BUILTIN_OPEN_ABSOLUTE_DIRECTORY(canonical_root)
        matched = (
            _BUILTIN_ROOT_IDENTITY(os.fstat(descriptor)) == expected_identity
        )
    except (OSError, _InvalidCandidateSnapshot):
        pass
    finally:
        if descriptor is not None and not _BUILTIN_CLOSE_DESCRIPTOR(descriptor):
            matched = False
    return matched


_BUILTIN_ROOT_PATH_MATCHES = _root_path_matches


def _held_root_matches(
    descriptor: int,
    expected_identity: tuple[int, int, int, int, int],
) -> bool:
    try:
        metadata = os.fstat(descriptor)
        return bool(
            _BUILTIN_ROOT_IDENTITY(metadata) == expected_identity
            and metadata.st_uid == os.geteuid()
            and stat.S_IMODE(metadata.st_mode) == _DIRECTORY_MODE
            and metadata.st_nlink > 0
            and not os.get_inheritable(descriptor)
        )
    except (OSError, _InvalidCandidateSnapshot):
        return False


_BUILTIN_HELD_ROOT_MATCHES = _held_root_matches


def _read_exact(descriptor: int, expected_size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = expected_size
    while remaining:
        try:
            chunk = os.read(descriptor, min(remaining, _READ_CHUNK_BYTES))
        except OSError:
            raise _InvalidCandidateSnapshot from None
        if not chunk:
            raise _InvalidCandidateSnapshot
        chunks.append(chunk)
        remaining -= len(chunk)
    try:
        if os.read(descriptor, 1):
            raise _InvalidCandidateSnapshot
    except OSError:
        raise _InvalidCandidateSnapshot from None
    return b"".join(chunks)


_BUILTIN_READ_EXACT = _read_exact


def _read_candidate_file(
    parent_descriptor: int,
    *,
    name: str,
    relative_path: str,
    remaining_workspace_bytes: int,
) -> RepositoryWorkerJobTreeSourceFile:
    descriptor: int | None = None
    try:
        named_before = _BUILTIN_ENTRY_METADATA(parent_descriptor, name)
        if (
            named_before is None
            or not stat.S_ISREG(named_before.st_mode)
            or named_before.st_nlink != 1
            or named_before.st_uid != os.geteuid()
            or stat.S_IMODE(named_before.st_mode)
            not in {_REGULAR_FILE_MODE, _EXECUTABLE_FILE_MODE}
            or named_before.st_size < 0
            or named_before.st_size > _MAX_SOURCE_FILE_BYTES
            or named_before.st_size > remaining_workspace_bytes
        ):
            raise _InvalidCandidateSnapshot
        descriptor = os.open(
            name,
            _BUILTIN_REGULAR_READ_FLAGS(),
            dir_fd=parent_descriptor,
        )
        opened_before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened_before.st_mode)
            or opened_before.st_nlink != 1
            or opened_before.st_uid != os.geteuid()
            or stat.S_IMODE(opened_before.st_mode)
            not in {_REGULAR_FILE_MODE, _EXECUTABLE_FILE_MODE}
            or _BUILTIN_METADATA_SIGNATURE(named_before)
            != _BUILTIN_METADATA_SIGNATURE(opened_before)
            or os.get_inheritable(descriptor)
        ):
            raise _InvalidCandidateSnapshot
        content = _BUILTIN_READ_EXACT(descriptor, opened_before.st_size)
        opened_after = os.fstat(descriptor)
        named_after = _BUILTIN_ENTRY_METADATA(parent_descriptor, name)
        if (
            _BUILTIN_METADATA_SIGNATURE(opened_before)
            != _BUILTIN_METADATA_SIGNATURE(opened_after)
            or named_after is None
            or _BUILTIN_METADATA_SIGNATURE(opened_after)
            != _BUILTIN_METADATA_SIGNATURE(named_after)
        ):
            raise _InvalidCandidateSnapshot
        return _SOURCE_FILE_TYPE(
            relative_path=relative_path,
            content=content,
            executable=(stat.S_IMODE(opened_after.st_mode) == _EXECUTABLE_FILE_MODE),
        )
    except (OSError, _InvalidCandidateSnapshot, ValidationError):
        raise _InvalidCandidateSnapshot from None
    finally:
        if descriptor is not None and not _BUILTIN_CLOSE_DESCRIPTOR(descriptor):
            raise _InvalidCandidateSnapshot


_BUILTIN_READ_CANDIDATE_FILE = _read_candidate_file


def _capture_candidate_tree(
    root_descriptor: int,
    *,
    source_bundle: RepositoryWorkerJobTreeSourceBundle,
    path_policy: dict[str, list[str]],
    resource_limits: dict[str, int],
) -> tuple[RepositoryWorkerJobTreeCandidateBundle, tuple[str, ...]]:
    files: list[RepositoryWorkerJobTreeSourceFile] = []
    directory_paths: list[str] = []
    node_count = [0]
    total_bytes = [0]

    def descend(descriptor: int, prefix: str) -> None:
        for name in _BUILTIN_DIRECTORY_ENTRY_NAMES(descriptor):
            node_count[0] += 1
            if node_count[0] > _MAX_SOURCE_NODES:
                raise _InvalidCandidateSnapshot
            relative_path = name if not prefix else f"{prefix}/{name}"
            _BUILTIN_VALIDATE_CANDIDATE_RELATIVE_PATH(
                relative_path,
                path_policy=path_policy,
            )
            metadata = _BUILTIN_ENTRY_METADATA(descriptor, name)
            if metadata is None:
                raise _InvalidCandidateSnapshot
            if stat.S_ISDIR(metadata.st_mode):
                child = _BUILTIN_OPEN_DIRECTORY_AT(
                    descriptor,
                    name,
                    require_private_mode=True,
                )
                directory_paths.append(relative_path)
                try:
                    descend(child, relative_path)
                finally:
                    if not _BUILTIN_CLOSE_DESCRIPTOR(child):
                        raise _InvalidCandidateSnapshot
            elif stat.S_ISREG(metadata.st_mode):
                if len(files) >= _MAX_SOURCE_FILES:
                    raise _InvalidCandidateSnapshot
                file = _BUILTIN_READ_CANDIDATE_FILE(
                    descriptor,
                    name=name,
                    relative_path=relative_path,
                    remaining_workspace_bytes=(
                        resource_limits["workspace_bytes"] - total_bytes[0]
                    ),
                )
                total_bytes[0] += len(file.content)
                files.append(file)
            else:
                raise _InvalidCandidateSnapshot

    descend(root_descriptor, "")
    candidate_bundle = _CANDIDATE_BUNDLE_TYPE(
        files=tuple(sorted(files, key=lambda item: item.relative_path))
    )
    directories = tuple(sorted(directory_paths))
    _BUILTIN_VALIDATE_CANDIDATE_BUNDLE_POLICY(
        candidate_bundle,
        path_policy=path_policy,
        resource_limits=resource_limits,
    )
    _BUILTIN_VALIDATE_DIRECTORY_PATHS(
        directories,
        source_bundle=source_bundle,
        candidate_bundle=candidate_bundle,
        path_policy=path_policy,
    )
    return candidate_bundle, directories


_BUILTIN_CAPTURE_CANDIDATE_TREE = _capture_candidate_tree


def _validated_lineage(
    snapshot: RepositoryWorkerJobTreeSourceSnapshot,
    *,
    contract: RepositoryWorkerJobTreeContract,
    materialization_receipt: RepositoryWorkerJobTreeMaterializationReceipt,
    path_policy: dict[str, Any],
    resource_limits: dict[str, Any],
) -> tuple[
    RepositoryWorkerJobTreeSourceBundle,
    str,
    str,
    str,
    dict[str, list[str]],
    dict[str, int],
]:
    if (
        type(snapshot) is not _SOURCE_SNAPSHOT_TYPE
        or type(contract) is not _CONTRACT_TYPE
    ):
        raise _InvalidCandidateSnapshot
    (
        source_bundle,
        source_snapshot_digest,
        contract_digest,
        _source_root_components,
        _source_root_metadata,
    ) = _BUILTIN_VALIDATED_INPUTS(snapshot, contract)
    checked_policy = _BUILTIN_PATH_POLICY_SNAPSHOT(path_policy)
    checked_limits = _BUILTIN_RESOURCE_LIMITS_SNAPSHOT(resource_limits)
    path_policy_digest = _BUILTIN_CANONICAL_DIGEST(checked_policy)
    resource_limits_digest = _BUILTIN_CANONICAL_DIGEST(checked_limits)
    if (
        path_policy_digest != snapshot.path_policy_digest
        or resource_limits_digest != snapshot.resource_limits_digest
        or path_policy_digest != contract.path_policy_digest
        or resource_limits_digest != contract.resource_limits_digest
    ):
        raise _InvalidCandidateSnapshot
    _BUILTIN_VALIDATE_SOURCE_BUNDLE_POLICY(
        source_bundle,
        path_policy=checked_policy,
        resource_limits=checked_limits,
    )
    receipt_projection = _BUILTIN_MATERIALIZATION_RECEIPT_PROJECTION(
        materialization_receipt
    )
    receipt_digest = _BUILTIN_CANONICAL_DIGEST(receipt_projection)
    if (
        receipt_projection["source_snapshot_digest"] != source_snapshot_digest
        or receipt_projection["job_tree_contract_digest"] != contract_digest
        or receipt_projection["source_bundle_digest"]
        != _BUILTIN_SOURCE_BUNDLE_DIGEST(source_bundle)
        or receipt_projection["source_file_count"] != len(source_bundle.files)
        or receipt_projection["source_total_bytes"]
        != sum(len(item.content) for item in source_bundle.files)
    ):
        raise _InvalidCandidateSnapshot
    return (
        source_bundle,
        source_snapshot_digest,
        contract_digest,
        receipt_digest,
        checked_policy,
        checked_limits,
    )


_BUILTIN_VALIDATED_LINEAGE = _validated_lineage


def _lease_root_descriptor(
    lease: RepositoryWorkerJobTreeMaterializationLease,
    *,
    materialization_receipt: RepositoryWorkerJobTreeMaterializationReceipt,
) -> tuple[int, Path, tuple[int, int, int, int, int]]:
    if (
        type(lease) is not _MATERIALIZATION_LEASE_TYPE
        or lease._state != "active"
        or lease._owner_pid != os.getpid()
        or lease._receipt is not materialization_receipt
        or type(lease._root_descriptor) is not int
        or lease._root_descriptor < 0
        or type(lease._root_identity) is not tuple
        or len(lease._root_identity) != 5
        or any(type(item) is not int or item < 0 for item in lease._root_identity)
        or type(lease._canonical_root) is not _CONCRETE_PATH_TYPE
    ):
        raise _InvalidCandidateSnapshot
    descriptor: int | None = None
    expected_identity = lease._root_identity
    canonical_root = lease._canonical_root
    try:
        descriptor = os.dup(lease._root_descriptor)
        if (
            not _BUILTIN_HELD_ROOT_MATCHES(descriptor, expected_identity)
            or not _BUILTIN_ROOT_PATH_MATCHES(
                canonical_root,
                expected_identity,
            )
        ):
            raise _InvalidCandidateSnapshot
        return descriptor, canonical_root, expected_identity
    except (OSError, _InvalidCandidateSnapshot):
        if descriptor is not None:
            _BUILTIN_CLOSE_DESCRIPTOR(descriptor)
        raise _InvalidCandidateSnapshot from None


_BUILTIN_LEASE_ROOT_DESCRIPTOR = _lease_root_descriptor


def capture_repository_worker_job_tree_candidate_snapshot(
    snapshot: RepositoryWorkerJobTreeSourceSnapshot,
    *,
    contract: RepositoryWorkerJobTreeContract,
    materialization_receipt: RepositoryWorkerJobTreeMaterializationReceipt,
    lease: RepositoryWorkerJobTreeMaterializationLease,
    path_policy: dict[str, Any],
    resource_limits: dict[str, Any],
) -> RepositoryWorkerJobTreeCandidateSnapshot:
    """Capture one stable, bounded candidate tree through a held descriptor.

    The captured bytes are only an input to later controller review.  This
    function does not prove that a worker was contained or that the candidate
    is safe to apply, and it deliberately leaves the materialization lease
    active for a future lifecycle boundary to own.
    """

    root_descriptor: int | None = None
    try:
        if not _BUILTIN_DESCRIPTOR_SUPPORT_IS_AVAILABLE():
            raise _InvalidCandidateSnapshot
        (
            source_bundle,
            source_snapshot_digest,
            contract_digest,
            materialization_receipt_digest,
            checked_policy,
            checked_limits,
        ) = _BUILTIN_VALIDATED_LINEAGE(
            snapshot,
            contract=contract,
            materialization_receipt=materialization_receipt,
            path_policy=path_policy,
            resource_limits=resource_limits,
        )
        root_descriptor, canonical_root, root_identity = (
            _BUILTIN_LEASE_ROOT_DESCRIPTOR(
                lease,
                materialization_receipt=materialization_receipt,
            )
        )
        first_bundle, first_directories = _BUILTIN_CAPTURE_CANDIDATE_TREE(
            root_descriptor,
            source_bundle=source_bundle,
            path_policy=checked_policy,
            resource_limits=checked_limits,
        )
        if (
            not _BUILTIN_HELD_ROOT_MATCHES(root_descriptor, root_identity)
            or not _BUILTIN_ROOT_PATH_MATCHES(canonical_root, root_identity)
        ):
            raise _InvalidCandidateSnapshot
        second_bundle, second_directories = _BUILTIN_CAPTURE_CANDIDATE_TREE(
            root_descriptor,
            source_bundle=source_bundle,
            path_policy=checked_policy,
            resource_limits=checked_limits,
        )
        if (
            first_bundle != second_bundle
            or first_directories != second_directories
            or not _BUILTIN_HELD_ROOT_MATCHES(root_descriptor, root_identity)
            or not _BUILTIN_ROOT_PATH_MATCHES(canonical_root, root_identity)
        ):
            raise _InvalidCandidateSnapshot
        return _CANDIDATE_SNAPSHOT_TYPE(
            kind=REPOSITORY_WORKER_JOB_TREE_CANDIDATE_SNAPSHOT_KIND,
            schema_version=REPOSITORY_WORKER_JOB_TREE_CANDIDATE_SNAPSHOT_SCHEMA_VERSION,
            candidate_snapshot_scope=CANDIDATE_SNAPSHOT_SCOPE,
            source_snapshot_digest=source_snapshot_digest,
            job_tree_contract_digest=contract_digest,
            materialization_receipt_digest=materialization_receipt_digest,
            source_bundle_digest=_BUILTIN_SOURCE_BUNDLE_DIGEST(source_bundle),
            candidate_bundle_digest=_BUILTIN_CANDIDATE_BUNDLE_DIGEST(second_bundle),
            candidate_tree_digest=_BUILTIN_CANDIDATE_TREE_DIGEST(
                candidate_bundle=second_bundle,
                directory_paths=second_directories,
            ),
            path_policy_digest=_BUILTIN_CANONICAL_DIGEST(checked_policy),
            resource_limits_digest=_BUILTIN_CANONICAL_DIGEST(checked_limits),
            source_bundle=source_bundle,
            candidate_bundle=second_bundle,
            materialization_receipt=materialization_receipt,
            path_policy=checked_policy,
            resource_limits=checked_limits,
            directory_paths=second_directories,
            source_file_count=len(source_bundle.files),
            source_total_bytes=sum(len(item.content) for item in source_bundle.files),
            candidate_file_count=len(second_bundle.files),
            candidate_directory_count=len(second_directories),
            candidate_total_bytes=sum(
                len(item.content) for item in second_bundle.files
            ),
        )
    except (
        AttributeError,
        TypeError,
        UnicodeError,
        ValidationError,
        ValueError,
    ):
        raise ValidationError(_INVALID_MESSAGE) from None
    finally:
        if root_descriptor is not None and not _BUILTIN_CLOSE_DESCRIPTOR(
            root_descriptor
        ):
            raise ValidationError(_INVALID_MESSAGE) from None


__all__ = [
    "CANDIDATE_SNAPSHOT_SCOPE",
    "REPOSITORY_WORKER_JOB_TREE_CANDIDATE_SNAPSHOT_KIND",
    "REPOSITORY_WORKER_JOB_TREE_CANDIDATE_SNAPSHOT_SCHEMA_VERSION",
    "RepositoryWorkerJobTreeCandidateSnapshot",
    "capture_repository_worker_job_tree_candidate_snapshot",
]
