"""Read-only source snapshots for a future controller-owned no-Git job tree.

This module is deliberately one stage before materialization.  It walks only
the caller-selected, policy-allowed source paths through no-follow directory
descriptors and returns detached, bounded in-memory bytes.  It cannot create a
job tree, mutate the source checkout, launch a worker, invoke a process, or
authorize dispatch.

The resulting bundle must still be bound to fresh registration evidence by
``derive_repository_worker_job_tree_contract`` before a future materializer may
consider it.  Capturing bytes is not containment evidence or execution
authority.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import stat
from typing import Any
import unicodedata

from .authorization import canonical_digest
from .errors import ValidationError
from .repository_worker_job_tree import (
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


REPOSITORY_WORKER_JOB_TREE_SOURCE_SNAPSHOT_SCHEMA_VERSION = 1
REPOSITORY_WORKER_JOB_TREE_SOURCE_SNAPSHOT_KIND = (
    "repository_worker_job_tree_source_snapshot"
)

_INVALID_SNAPSHOT_MESSAGE = "repository worker job tree source snapshot is invalid"
_MAX_READ_CHUNK_BYTES = 64 * 1024
_MAX_SOURCE_NODES = _MAX_SOURCE_FILES * 8
_REQUIRED_DESCRIPTOR_FLAGS = (
    "O_CLOEXEC",
    "O_DIRECTORY",
    "O_NOFOLLOW",
    "O_NONBLOCK",
)
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")

# Capture the pure source-bundle validators at import.  A later replacement of
# a public helper must not relax the policy checked by this snapshot boundary.
_BUILTIN_CANONICAL_DIGEST = canonical_digest
_BUILTIN_PATH_POLICY_SNAPSHOT = _path_policy_snapshot
_BUILTIN_RESOURCE_LIMITS_SNAPSHOT = _resource_limits_snapshot
_BUILTIN_IS_AT_OR_BELOW = _is_at_or_below
_BUILTIN_IS_CANONICAL_RELATIVE_PATH = _is_canonical_relative_path
_BUILTIN_PROHIBITED_COMPONENT = _prohibited_component


class _InvalidSourceSnapshot(ValueError):
    """Private sentinel that keeps failures fixed and value-free."""


def _descriptor_support_is_available() -> bool:
    return (
        all(hasattr(os, name) for name in _REQUIRED_DESCRIPTOR_FLAGS)
        and os.open in os.supports_dir_fd
        and os.stat in os.supports_dir_fd
        and os.stat in os.supports_follow_symlinks
    )


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_CLOEXEC
        | os.O_NOFOLLOW
        | os.O_NONBLOCK
    )


def _node_flags() -> int:
    return os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK


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


def _directory_signature(metadata: os.stat_result) -> tuple[int, ...]:
    if not stat.S_ISDIR(metadata.st_mode):
        raise _InvalidSourceSnapshot
    return _metadata_signature(metadata)


def _file_signature(metadata: os.stat_result) -> tuple[int, ...]:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size < 0
        or metadata.st_nlink != 1
    ):
        raise _InvalidSourceSnapshot
    return _metadata_signature(metadata)


def _absolute_path_components(
    value: Any,
) -> tuple[tuple[str, ...], tuple[int, ...]]:
    if type(value) is str:
        path = Path(value)
    elif type(value) is type(Path()):
        path = value
    else:
        raise _InvalidSourceSnapshot
    if not path.is_absolute() or path.anchor != "/":
        raise _InvalidSourceSnapshot
    try:
        supplied_metadata = os.lstat(path)
        if (
            stat.S_ISLNK(supplied_metadata.st_mode)
            or not stat.S_ISDIR(supplied_metadata.st_mode)
        ):
            raise _InvalidSourceSnapshot
        supplied_signature = _metadata_signature(supplied_metadata)
        path = path.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        raise _InvalidSourceSnapshot from None
    parts = path.parts
    if not parts or parts[0] != "/" or any(
        not part or part in {".", ".."} for part in parts[1:]
    ):
        raise _InvalidSourceSnapshot
    return tuple(parts[1:]), supplied_signature


def _directory_entry_names(directory_descriptor: int) -> tuple[str, ...]:
    try:
        duplicate_descriptor = os.dup(directory_descriptor)
    except OSError:
        raise _InvalidSourceSnapshot from None
    try:
        try:
            entries = os.scandir(duplicate_descriptor)
        except OSError:
            raise _InvalidSourceSnapshot from None
        duplicate_descriptor = -1
        try:
            with entries:
                names_list: list[str] = []
                for entry in entries:
                    if len(names_list) >= _MAX_SOURCE_NODES:
                        raise _InvalidSourceSnapshot
                    names_list.append(entry.name)
                names = tuple(names_list)
        except OSError:
            raise _InvalidSourceSnapshot from None
    finally:
        if duplicate_descriptor >= 0:
            try:
                os.close(duplicate_descriptor)
            except OSError:
                raise _InvalidSourceSnapshot from None
    if (
        any(type(name) is not str or not name for name in names)
        or len(names) != len(set(names))
    ):
        raise _InvalidSourceSnapshot
    folded_names: set[str] = set()
    for name in names:
        folded = unicodedata.normalize("NFC", name).casefold()
        if folded in folded_names:
            raise _InvalidSourceSnapshot
        folded_names.add(folded)
    return tuple(sorted(names))


def _open_named_node(
    parent_descriptor: int,
    name: str,
    *,
    names: tuple[str, ...] | None = None,
    require_directory: bool = False,
) -> int:
    if type(name) is not str or not name:
        raise _InvalidSourceSnapshot
    available_names = (
        _directory_entry_names(parent_descriptor) if names is None else names
    )
    if name not in available_names:
        raise _InvalidSourceSnapshot
    flags = _node_flags() | (os.O_DIRECTORY if require_directory else 0)
    try:
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    except OSError:
        raise _InvalidSourceSnapshot from None
    try:
        metadata = os.fstat(descriptor)
        if require_directory and not stat.S_ISDIR(metadata.st_mode):
            raise _InvalidSourceSnapshot
        namespace_metadata = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if _metadata_signature(metadata) != _metadata_signature(namespace_metadata):
            raise _InvalidSourceSnapshot
        return descriptor
    except (OSError, _InvalidSourceSnapshot):
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _open_absolute_source_root(value: Any) -> int:
    components, expected_signature = _absolute_path_components(value)
    try:
        descriptor = os.open("/", _directory_flags())
    except OSError:
        raise _InvalidSourceSnapshot from None
    try:
        for component in components:
            child = _open_named_node(
                descriptor,
                component,
                require_directory=True,
            )
            try:
                os.close(descriptor)
            except OSError:
                try:
                    os.close(child)
                except OSError:
                    pass
                raise _InvalidSourceSnapshot from None
            descriptor = child
        opened_signature = _directory_signature(os.fstat(descriptor))
        if opened_signature != expected_signature:
            raise _InvalidSourceSnapshot
        return descriptor
    except (OSError, _InvalidSourceSnapshot):
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _open_allowed_path(
    root_descriptor: int,
    relative_path: str,
) -> tuple[int, int, tuple[int, ...]]:
    parts = relative_path.split("/")
    descriptor = root_descriptor
    owned_descriptors: list[int] = []
    try:
        for part in parts[:-1]:
            child = _open_named_node(
                descriptor,
                part,
                require_directory=True,
            )
            owned_descriptors.append(child)
            descriptor = child
        node_descriptor = _open_named_node(descriptor, parts[-1])
        return node_descriptor, descriptor, tuple(owned_descriptors)
    except BaseException:
        for owned_descriptor in reversed(owned_descriptors):
            try:
                os.close(owned_descriptor)
            except OSError:
                pass
        raise


def _is_excluded(relative_path: str, path_policy: dict[str, list[str]]) -> bool:
    return any(
        _BUILTIN_IS_AT_OR_BELOW(relative_path, excluded_path)
        for excluded_path in (
            path_policy["protected_paths"]
            + path_policy["generated_paths"]
            + path_policy["vendor_paths"]
        )
    )


def _read_exact_file(descriptor: int, expected_size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = expected_size
    while remaining:
        try:
            chunk = os.read(descriptor, min(remaining, _MAX_READ_CHUNK_BYTES))
        except OSError:
            raise _InvalidSourceSnapshot from None
        if not chunk:
            raise _InvalidSourceSnapshot
        chunks.append(chunk)
        remaining -= len(chunk)
    try:
        if os.read(descriptor, 1):
            raise _InvalidSourceSnapshot
    except OSError:
        raise _InvalidSourceSnapshot from None
    return b"".join(chunks)


def _capture_regular_file(
    descriptor: int,
    *,
    parent_descriptor: int,
    name: str,
    relative_path: str,
    remaining_workspace_bytes: int,
) -> RepositoryWorkerJobTreeSourceFile:
    try:
        before = os.fstat(descriptor)
        before_signature = _file_signature(before)
        if before.st_size > min(
            remaining_workspace_bytes,
            _MAX_SOURCE_FILE_BYTES,
        ):
            raise _InvalidSourceSnapshot
        content = _read_exact_file(descriptor, before.st_size)
        after = os.fstat(descriptor)
        after_signature = _file_signature(after)
        namespace_metadata = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except OSError:
        raise _InvalidSourceSnapshot from None
    if (
        before_signature != after_signature
        or after_signature != _metadata_signature(namespace_metadata)
        or len(content) != before.st_size
    ):
        raise _InvalidSourceSnapshot
    return RepositoryWorkerJobTreeSourceFile(
        relative_path=relative_path,
        content=content,
        executable=bool(before.st_mode & 0o111),
    )


def _capture_directory(
    descriptor: int,
    *,
    relative_path: str,
    path_policy: dict[str, list[str]],
    remaining_workspace_bytes: int,
    remaining_nodes: list[int],
    files: list[RepositoryWorkerJobTreeSourceFile],
) -> int:
    try:
        before_signature = _directory_signature(os.fstat(descriptor))
        names = _directory_entry_names(descriptor)
    except OSError:
        raise _InvalidSourceSnapshot from None
    remaining = remaining_workspace_bytes
    for name in names:
        child_relative_path = f"{relative_path}/{name}"
        if _is_excluded(child_relative_path, path_policy):
            continue
        if remaining_nodes[0] <= 0:
            raise _InvalidSourceSnapshot
        remaining_nodes[0] -= 1
        if (
            not _BUILTIN_IS_CANONICAL_RELATIVE_PATH(child_relative_path)
            or _BUILTIN_PROHIBITED_COMPONENT(child_relative_path)
        ):
            raise _InvalidSourceSnapshot
        child_descriptor = _open_named_node(descriptor, name, names=names)
        try:
            child_metadata = os.fstat(child_descriptor)
            if stat.S_ISDIR(child_metadata.st_mode):
                child_before_signature = _directory_signature(child_metadata)
                remaining = _capture_directory(
                    child_descriptor,
                    relative_path=child_relative_path,
                    path_policy=path_policy,
                    remaining_workspace_bytes=remaining,
                    remaining_nodes=remaining_nodes,
                    files=files,
                )
                child_after_signature = _directory_signature(
                    os.fstat(child_descriptor)
                )
                namespace_metadata = os.stat(
                    name,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
                if (
                    child_before_signature != child_after_signature
                    or child_after_signature
                    != _metadata_signature(namespace_metadata)
                ):
                    raise _InvalidSourceSnapshot
            else:
                if len(files) >= _MAX_SOURCE_FILES:
                    raise _InvalidSourceSnapshot
                source_file = _capture_regular_file(
                    child_descriptor,
                    parent_descriptor=descriptor,
                    name=name,
                    relative_path=child_relative_path,
                    remaining_workspace_bytes=remaining,
                )
                files.append(source_file)
                remaining -= len(source_file.content)
        finally:
            try:
                os.close(child_descriptor)
            except OSError:
                raise _InvalidSourceSnapshot from None
    try:
        after_signature = _directory_signature(os.fstat(descriptor))
    except OSError:
        raise _InvalidSourceSnapshot from None
    if before_signature != after_signature:
        raise _InvalidSourceSnapshot
    return remaining


def _capture_allowed_path(
    root_descriptor: int,
    *,
    relative_path: str,
    path_policy: dict[str, list[str]],
    remaining_workspace_bytes: int,
    remaining_nodes: list[int],
    files: list[RepositoryWorkerJobTreeSourceFile],
) -> int:
    if (
        _is_excluded(relative_path, path_policy)
        or not _BUILTIN_IS_CANONICAL_RELATIVE_PATH(relative_path)
        or _BUILTIN_PROHIBITED_COMPONENT(relative_path)
        or remaining_nodes[0] <= 0
    ):
        raise _InvalidSourceSnapshot
    remaining_nodes[0] -= 1
    descriptor, parent_descriptor, owned_descriptors = _open_allowed_path(
        root_descriptor,
        relative_path,
    )
    try:
        metadata = os.fstat(descriptor)
        if stat.S_ISDIR(metadata.st_mode):
            before_signature = _directory_signature(metadata)
            remaining = _capture_directory(
                descriptor,
                relative_path=relative_path,
                path_policy=path_policy,
                remaining_workspace_bytes=remaining_workspace_bytes,
                remaining_nodes=remaining_nodes,
                files=files,
            )
            after_signature = _directory_signature(os.fstat(descriptor))
            namespace_metadata = os.stat(
                relative_path.split("/")[-1],
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if (
                before_signature != after_signature
                or after_signature != _metadata_signature(namespace_metadata)
            ):
                raise _InvalidSourceSnapshot
            return remaining
        if len(files) >= _MAX_SOURCE_FILES:
            raise _InvalidSourceSnapshot
        source_file = _capture_regular_file(
            descriptor,
            parent_descriptor=parent_descriptor,
            name=relative_path.split("/")[-1],
            relative_path=relative_path,
            remaining_workspace_bytes=remaining_workspace_bytes,
        )
        files.append(source_file)
        return remaining_workspace_bytes - len(source_file.content)
    finally:
        try:
            os.close(descriptor)
        except OSError:
            raise _InvalidSourceSnapshot from None
        for owned_descriptor in reversed(owned_descriptors):
            try:
                os.close(owned_descriptor)
            except OSError:
                raise _InvalidSourceSnapshot from None


@dataclass(frozen=True, slots=True)
class RepositoryWorkerJobTreeSourceSnapshot:
    """Detached controller bytes plus digest-only capture metadata."""

    source_bundle: RepositoryWorkerJobTreeSourceBundle = field(repr=False)
    source_root_identity_digest: str
    path_policy_digest: str
    resource_limits_digest: str
    source_bundle_digest: str
    source_file_count: int
    source_total_bytes: int

    def __post_init__(self) -> None:
        if type(self.source_bundle) is not RepositoryWorkerJobTreeSourceBundle:
            raise ValidationError(_INVALID_SNAPSHOT_MESSAGE)
        try:
            self.source_bundle.__post_init__()
            valid_digests = all(
                type(getattr(self, name)) is str
                and _DIGEST_PATTERN.fullmatch(getattr(self, name)) is not None
                for name in (
                    "source_root_identity_digest",
                    "path_policy_digest",
                    "resource_limits_digest",
                    "source_bundle_digest",
                )
            )
            valid_counts = (
                type(self.source_file_count) is int
                and self.source_file_count == self.source_bundle.source_file_count
                and type(self.source_total_bytes) is int
                and self.source_total_bytes == self.source_bundle.source_total_bytes
            )
            if (
                not valid_digests
                or not valid_counts
                or self.source_bundle_digest != self.source_bundle.source_bundle_digest
            ):
                raise _InvalidSourceSnapshot
        except (
            AttributeError,
            TypeError,
            UnicodeError,
            ValidationError,
            ValueError,
        ):
            raise ValidationError(_INVALID_SNAPSHOT_MESSAGE) from None

    @property
    def snapshot_digest(self) -> str:
        return _BUILTIN_CANONICAL_DIGEST(self.to_contract_mapping())

    def to_contract_mapping(self) -> dict[str, Any]:
        self.__post_init__()
        return {
            "kind": REPOSITORY_WORKER_JOB_TREE_SOURCE_SNAPSHOT_KIND,
            "path_policy_digest": self.path_policy_digest,
            "resource_limits_digest": self.resource_limits_digest,
            "schema_version": REPOSITORY_WORKER_JOB_TREE_SOURCE_SNAPSHOT_SCHEMA_VERSION,
            "source_bundle_digest": self.source_bundle_digest,
            "source_file_count": self.source_file_count,
            "source_root_identity_digest": self.source_root_identity_digest,
            "source_total_bytes": self.source_total_bytes,
        }

    def to_mapping(self) -> dict[str, Any]:
        mapping = self.to_contract_mapping()
        mapping.update(
            {
                "authority_granted": False,
                "dispatch_enabled": False,
                "materialization_implemented": False,
                "source_snapshot_captured": True,
                "source_snapshot_registration_bound": False,
                "worker_execution_permitted": False,
            }
        )
        mapping["snapshot_digest"] = self.snapshot_digest
        return mapping


def capture_repository_worker_job_tree_source_snapshot(
    source_root: str | Path,
    *,
    path_policy: dict[str, Any],
    resource_limits: dict[str, Any],
) -> RepositoryWorkerJobTreeSourceSnapshot:
    """Capture bounded allowed source bytes with no-follow read-only traversal.

    This function is controller-side plumbing only.  It writes nothing and
    does not bind the result to authoritative registration evidence, create a
    worktree, or give a worker any path or authority.
    """

    root_descriptor: int | None = None
    try:
        if not _descriptor_support_is_available():
            raise _InvalidSourceSnapshot
        checked_policy = _BUILTIN_PATH_POLICY_SNAPSHOT(path_policy)
        checked_limits = _BUILTIN_RESOURCE_LIMITS_SNAPSHOT(resource_limits)
        root_descriptor = _open_absolute_source_root(source_root)
        root_before = _directory_signature(os.fstat(root_descriptor))
        source_root_identity_digest = _BUILTIN_CANONICAL_DIGEST(
            {
                "kind": REPOSITORY_WORKER_JOB_TREE_SOURCE_SNAPSHOT_KIND,
                "metadata": list(root_before),
                "schema_version": (
                    REPOSITORY_WORKER_JOB_TREE_SOURCE_SNAPSHOT_SCHEMA_VERSION
                ),
            }
        )
        files: list[RepositoryWorkerJobTreeSourceFile] = []
        remaining_workspace_bytes = min(
            checked_limits["workspace_bytes"],
            _MAX_SOURCE_BYTES,
        )
        remaining_nodes = [_MAX_SOURCE_NODES]
        for allowed_path in checked_policy["allowed_paths"]:
            remaining_workspace_bytes = _capture_allowed_path(
                root_descriptor,
                relative_path=allowed_path,
                path_policy=checked_policy,
                remaining_workspace_bytes=remaining_workspace_bytes,
                remaining_nodes=remaining_nodes,
                files=files,
            )
        root_after = _directory_signature(os.fstat(root_descriptor))
        if root_before != root_after:
            raise _InvalidSourceSnapshot
        source_bundle = RepositoryWorkerJobTreeSourceBundle(files=tuple(files))
        return RepositoryWorkerJobTreeSourceSnapshot(
            source_bundle=source_bundle,
            source_root_identity_digest=source_root_identity_digest,
            path_policy_digest=_BUILTIN_CANONICAL_DIGEST(checked_policy),
            resource_limits_digest=_BUILTIN_CANONICAL_DIGEST(checked_limits),
            source_bundle_digest=source_bundle.source_bundle_digest,
            source_file_count=source_bundle.source_file_count,
            source_total_bytes=source_bundle.source_total_bytes,
        )
    except (
        OSError,
        TypeError,
        UnicodeError,
        ValidationError,
        ValueError,
    ):
        raise ValidationError(_INVALID_SNAPSHOT_MESSAGE) from None
    finally:
        if root_descriptor is not None:
            try:
                os.close(root_descriptor)
            except OSError:
                raise ValidationError(_INVALID_SNAPSHOT_MESSAGE) from None


__all__ = [
    "REPOSITORY_WORKER_JOB_TREE_SOURCE_SNAPSHOT_KIND",
    "REPOSITORY_WORKER_JOB_TREE_SOURCE_SNAPSHOT_SCHEMA_VERSION",
    "RepositoryWorkerJobTreeSourceSnapshot",
    "capture_repository_worker_job_tree_source_snapshot",
]
