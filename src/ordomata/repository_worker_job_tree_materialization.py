"""Descriptor-safe materialization of a detached no-Git worker job tree.

This library-only Class 1 primitive writes an already detached source snapshot
into one caller-provided, empty, owner-private directory.  It deliberately
stops before a worker boundary: it does not create a container, execute a
command, invoke Git, persist state, reconcile a candidate, or authorize
dispatch.  The target root is accessed only through no-follow descriptors and
the public receipt contains no path, source bytes, inode, or descriptor value.
The target must also be disjoint from the captured source-root hierarchy.

The target-root checks prove a narrow local property, not a complete custody
claim.  They do not exclude a same-UID writer, an external descriptor, mount
aliases, crash cleanup gaps, or a future worker escape.  A later controller
PEP and reconciler must establish those remaining properties independently.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Any, Literal
import unicodedata

from .authorization import canonical_digest
from .errors import ConfigurationError, ValidationError
from .repository_worker_job_tree import (
    REPOSITORY_WORKER_JOB_TREE_CONTRACT_KIND,
    REPOSITORY_WORKER_JOB_TREE_SCHEMA_VERSION,
    RepositoryWorkerJobTreeContract,
    RepositoryWorkerJobTreeSourceBundle,
    RepositoryWorkerJobTreeSourceFile,
)
from .repository_worker_job_tree_snapshot import (
    REPOSITORY_WORKER_JOB_TREE_SOURCE_SNAPSHOT_KIND,
    REPOSITORY_WORKER_JOB_TREE_SOURCE_SNAPSHOT_SCHEMA_VERSION,
    RepositoryWorkerJobTreeSourceSnapshot,
)


REPOSITORY_WORKER_JOB_TREE_MATERIALIZATION_SCHEMA_VERSION = 1
REPOSITORY_WORKER_JOB_TREE_MATERIALIZATION_KIND = (
    "repository_worker_no_git_job_tree_materialization"
)
MATERIALIZATION_SCOPE = "posix_descriptor_no_git_job_tree_v1"

_INVALID_MESSAGE = "repository worker job tree materialization is invalid"
_CLEANUP_UNCERTAIN_MESSAGE = (
    "repository worker job tree materialization cleanup is uncertain"
)
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CONCRETE_PATH_TYPE = type(Path())
_TARGET_ROOT_MODE = 0o700
_DIRECTORY_MODE = 0o700
_REGULAR_FILE_MODE = 0o600
_EXECUTABLE_FILE_MODE = 0o700
_READ_CHUNK_BYTES = 64 * 1024
_REQUIRED_DESCRIPTOR_FLAGS = (
    "O_CLOEXEC",
    "O_DIRECTORY",
    "O_NOFOLLOW",
    "O_NONBLOCK",
)

_LeaseState = Literal["new", "active", "closed", "cleanup_unverifiable"]

# This boundary deliberately freezes its own digest implementation and exact
# type objects.  Public dataclass methods and module attributes remain
# patchable, so later monkeypatches are not used to validate the input chain.
_BUILTIN_CANONICAL_DIGEST = canonical_digest
_SOURCE_SNAPSHOT_TYPE = RepositoryWorkerJobTreeSourceSnapshot
_JOB_TREE_CONTRACT_TYPE = RepositoryWorkerJobTreeContract
_SOURCE_BUNDLE_TYPE = RepositoryWorkerJobTreeSourceBundle
_SOURCE_FILE_TYPE = RepositoryWorkerJobTreeSourceFile


class _InvalidMaterialization(ValueError):
    """Private sentinel that keeps public failures value-free."""


@dataclass(frozen=True, slots=True)
class RepositoryWorkerJobTreeMaterializationReceipt:
    """Digest-only evidence for one verified controller materialization."""

    kind: str
    schema_version: int
    materialization_scope: str
    source_snapshot_digest: str = field(repr=False)
    job_tree_contract_digest: str = field(repr=False)
    source_bundle_digest: str = field(repr=False)
    source_file_count: int
    source_total_bytes: int
    materialized_file_count: int
    materialized_total_bytes: int
    executable_file_count: int
    regular_file_count: int

    def __post_init__(self) -> None:
        try:
            valid_digests = all(
                type(getattr(self, name)) is str
                and _DIGEST_PATTERN.fullmatch(getattr(self, name)) is not None
                for name in (
                    "source_snapshot_digest",
                    "job_tree_contract_digest",
                    "source_bundle_digest",
                )
            )
            valid_counts = (
                type(self.source_file_count) is int
                and self.source_file_count >= 1
                and type(self.source_total_bytes) is int
                and self.source_total_bytes >= 0
                and type(self.materialized_file_count) is int
                and self.materialized_file_count == self.source_file_count
                and type(self.materialized_total_bytes) is int
                and self.materialized_total_bytes == self.source_total_bytes
                and type(self.executable_file_count) is int
                and self.executable_file_count >= 0
                and type(self.regular_file_count) is int
                and self.regular_file_count >= 0
                and self.executable_file_count + self.regular_file_count
                == self.source_file_count
            )
            if (
                self.kind != REPOSITORY_WORKER_JOB_TREE_MATERIALIZATION_KIND
                or self.schema_version
                != REPOSITORY_WORKER_JOB_TREE_MATERIALIZATION_SCHEMA_VERSION
                or self.materialization_scope != MATERIALIZATION_SCOPE
                or not valid_digests
                or not valid_counts
            ):
                raise _InvalidMaterialization
        except (AttributeError, TypeError, ValueError):
            raise ValidationError(_INVALID_MESSAGE) from None

    @property
    def receipt_digest(self) -> str:
        return _BUILTIN_CANONICAL_DIGEST(_receipt_projection(self))

    def to_canonical(self) -> dict[str, Any]:
        return _receipt_projection(self)

    def to_mapping(self) -> dict[str, Any]:
        mapping = _receipt_projection(self)
        mapping.update(
            {
                "authority_granted": False,
                "dispatch_enabled": False,
                "git_metadata_prohibited": True,
                "job_tree_materialized": True,
                "materialization_authority_granted": False,
                "patch_reconciliation_implemented": False,
                "receipt_digest": self.receipt_digest,
                "worker_execution_permitted": False,
            }
        )
        return mapping


@dataclass(slots=True)
class RepositoryWorkerJobTreeMaterializationLease:
    """A process-local handle to one caller-owned materialized job root.

    Constructing a lease performs no I/O.  The materializer validates and opens
    ``job_tree_root`` only after it has detached and checked the source input.
    ``close`` releases the retained descriptor but intentionally does not
    remove the materialized tree; lifecycle cleanup is a later controller
    boundary and must not be inferred from descriptor release.
    """

    job_tree_root: Path = field(repr=False)
    _state: _LeaseState = field(default="new", init=False, repr=False)
    _owner_pid: int = field(default_factory=os.getpid, init=False, repr=False)
    _receipt: RepositoryWorkerJobTreeMaterializationReceipt | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _root_descriptor: int | None = field(default=None, init=False, repr=False)
    _root_identity: tuple[int, int, int, int, int] | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _canonical_root: Path | None = field(default=None, init=False, repr=False)

    @property
    def state(self) -> str:
        return self._state

    @property
    def receipt(self) -> RepositoryWorkerJobTreeMaterializationReceipt | None:
        return self._receipt

    def close(self) -> None:
        """Release only the retained descriptor for an active materialization."""

        descriptor = self._root_descriptor
        self._root_descriptor = None
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                self._state = "cleanup_unverifiable"
                raise ConfigurationError(_CLEANUP_UNCERTAIN_MESSAGE) from None
        if self._state == "active":
            self._state = "closed"

    def __del__(self) -> None:
        try:
            self.close()
        except (ConfigurationError, AttributeError):
            pass


@dataclass(frozen=True, slots=True)
class _DirectoryRecord:
    components: tuple[str, ...]
    descriptor: int = field(repr=False)
    identity: tuple[int, int] = field(repr=False)


@dataclass(frozen=True, slots=True)
class _FileRecord:
    relative_path: str = field(repr=False)
    parent_components: tuple[str, ...] = field(repr=False)
    name: str = field(repr=False)
    identity: tuple[int, int] = field(repr=False)
    expected_mode: int = field(repr=False)
    content: bytes = field(repr=False)


def _descriptor_support_is_available() -> bool:
    return (
        all(hasattr(os, name) for name in _REQUIRED_DESCRIPTOR_FLAGS)
        and os.open in os.supports_dir_fd
        and os.stat in os.supports_dir_fd
        and os.stat in os.supports_follow_symlinks
        and os.mkdir in os.supports_dir_fd
        and os.unlink in os.supports_dir_fd
        and os.rmdir in os.supports_dir_fd
    )


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


def _regular_write_flags() -> int:
    return (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_CLOEXEC
        | os.O_NOFOLLOW
        | os.O_NONBLOCK
    )


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
        raise _InvalidMaterialization
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
    )


def _is_digest(value: Any) -> bool:
    return type(value) is str and _DIGEST_PATTERN.fullmatch(value) is not None


def _path_components_overlap(
    first: tuple[str, ...],
    second: tuple[str, ...],
) -> bool:
    shared = min(len(first), len(second))
    return (
        tuple(
            unicodedata.normalize("NFC", component).casefold()
            for component in first[:shared]
        )
        == tuple(
            unicodedata.normalize("NFC", component).casefold()
            for component in second[:shared]
        )
        and (len(first) == shared or len(second) == shared)
    )


def _close_descriptor(descriptor: int | None) -> bool:
    if descriptor is None:
        return True
    try:
        os.close(descriptor)
    except OSError:
        return False
    return True


def _directory_entry_names(descriptor: int) -> tuple[str, ...]:
    duplicate: int | None = None
    try:
        duplicate = os.dup(descriptor)
        with os.scandir(duplicate) as entries:
            duplicate = None
            names = tuple(entry.name for entry in entries)
    except OSError:
        raise _InvalidMaterialization from None
    finally:
        if duplicate is not None:
            _close_descriptor(duplicate)
    if (
        any(type(name) is not str or not name for name in names)
        or len(names) != len(set(names))
    ):
        raise _InvalidMaterialization
    return tuple(sorted(names))


def _directory_is_empty(descriptor: int) -> bool:
    return not _directory_entry_names(descriptor)


def _entry_metadata(
    parent_descriptor: int,
    name: str,
) -> os.stat_result | None:
    try:
        return os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return None
    except OSError:
        raise _InvalidMaterialization from None


def _open_directory_at(parent_descriptor: int, name: str) -> int:
    descriptor: int | None = None
    try:
        descriptor = os.open(name, _directory_flags(), dir_fd=parent_descriptor)
        opened = os.fstat(descriptor)
        named = _entry_metadata(parent_descriptor, name)
        if (
            named is None
            or not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise _InvalidMaterialization
        return descriptor
    except (OSError, _InvalidMaterialization):
        if descriptor is not None:
            _close_descriptor(descriptor)
        raise _InvalidMaterialization from None


def _absolute_directory_components(value: Any) -> tuple[Path, tuple[int, ...]]:
    if (
        type(value) is not _CONCRETE_PATH_TYPE
        or not value.is_absolute()
        or value.anchor != "/"
    ):
        raise _InvalidMaterialization
    try:
        supplied = os.lstat(value)
        if (
            stat.S_ISLNK(supplied.st_mode)
            or not stat.S_ISDIR(supplied.st_mode)
        ):
            raise _InvalidMaterialization
        resolved = value.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        raise _InvalidMaterialization from None
    if (
        type(resolved) is not _CONCRETE_PATH_TYPE
        or not resolved.is_absolute()
        or resolved.anchor != "/"
        or any(part in {"", ".", ".."} for part in resolved.parts[1:])
    ):
        raise _InvalidMaterialization
    return resolved, _metadata_signature(supplied)


def _open_absolute_directory(value: Any) -> tuple[int, Path]:
    resolved, expected_signature = _absolute_directory_components(value)
    descriptor: int | None = None
    try:
        descriptor = os.open("/", _directory_flags())
        for component in resolved.parts[1:]:
            child = _open_directory_at(descriptor, component)
            if not _close_descriptor(descriptor):
                _close_descriptor(child)
                raise _InvalidMaterialization
            descriptor = child
        if _metadata_signature(os.fstat(descriptor)) != expected_signature:
            raise _InvalidMaterialization
        return descriptor, resolved
    except (OSError, _InvalidMaterialization):
        if descriptor is not None:
            _close_descriptor(descriptor)
        raise _InvalidMaterialization from None


def _directory_record_is_valid(record: _DirectoryRecord) -> bool:
    try:
        metadata = os.fstat(record.descriptor)
        return bool(
            stat.S_ISDIR(metadata.st_mode)
            and (metadata.st_dev, metadata.st_ino) == record.identity
            and metadata.st_uid == os.geteuid()
            and stat.S_IMODE(metadata.st_mode) == _DIRECTORY_MODE
            and metadata.st_nlink > 0
            and not os.get_inheritable(record.descriptor)
        )
    except OSError:
        return False


def _root_path_matches(
    canonical_root: Path,
    expected_identity: tuple[int, int, int, int, int],
) -> bool:
    descriptor: int | None = None
    matched = False
    try:
        descriptor, reopened = _open_absolute_directory(canonical_root)
        if reopened == canonical_root:
            matched = _root_identity(os.fstat(descriptor)) == expected_identity
    except (OSError, _InvalidMaterialization):
        pass
    finally:
        if descriptor is not None and not _close_descriptor(descriptor):
            matched = False
    return matched


def _prepare_target_root(
    lease: RepositoryWorkerJobTreeMaterializationLease,
) -> tuple[int, Path, tuple[int, int, int, int, int]]:
    if (
        type(lease) is not RepositoryWorkerJobTreeMaterializationLease
        or lease._state != "new"
        or lease._owner_pid != os.getpid()
        or lease._receipt is not None
        or lease._root_descriptor is not None
        or lease._root_identity is not None
        or lease._canonical_root is not None
    ):
        raise _InvalidMaterialization
    descriptor: int | None = None
    try:
        descriptor, canonical_root = _open_absolute_directory(lease.job_tree_root)
        metadata = os.fstat(descriptor)
        root_identity = _root_identity(metadata)
        if (
            metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != _TARGET_ROOT_MODE
            or metadata.st_nlink <= 0
            or os.get_inheritable(descriptor)
            or not _directory_is_empty(descriptor)
        ):
            raise _InvalidMaterialization
        return descriptor, canonical_root, root_identity
    except (OSError, _InvalidMaterialization):
        if descriptor is not None:
            _close_descriptor(descriptor)
        raise _InvalidMaterialization from None


def _bundle_digest(bundle: RepositoryWorkerJobTreeSourceBundle) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "files": [
                {
                    "content_bytes": len(item.content),
                    "content_digest": (
                        f"sha256:{hashlib.sha256(item.content).hexdigest()}"
                    ),
                    "executable": item.executable,
                    "relative_path": item.relative_path,
                }
                for item in bundle.files
            ],
            "kind": "repository_worker_job_tree_source_bundle",
            "schema_version": REPOSITORY_WORKER_JOB_TREE_SCHEMA_VERSION,
        }
    )


def _detached_source_bundle(
    snapshot: RepositoryWorkerJobTreeSourceSnapshot,
) -> tuple[
    RepositoryWorkerJobTreeSourceBundle,
    dict[str, Any],
    tuple[str, ...],
    tuple[int, ...],
]:
    if type(snapshot) is not _SOURCE_SNAPSHOT_TYPE:
        raise _InvalidMaterialization
    try:
        source_bundle = snapshot.source_bundle
        if type(source_bundle) is not _SOURCE_BUNDLE_TYPE:
            raise _InvalidMaterialization
        source_files = source_bundle.files
        if type(source_files) is not tuple:
            raise _InvalidMaterialization
        detached_files = tuple(
            _SOURCE_FILE_TYPE(
                relative_path=item.relative_path,
                content=item.content,
                executable=item.executable,
            )
            for item in source_files
            if type(item) is _SOURCE_FILE_TYPE
        )
        if len(detached_files) != len(source_files):
            raise _InvalidMaterialization
        detached_bundle = _SOURCE_BUNDLE_TYPE(files=detached_files)
        source_bundle_digest = _bundle_digest(detached_bundle)
        source_file_count = len(detached_files)
        source_total_bytes = sum(len(item.content) for item in detached_files)
        source_root_components = snapshot.source_root_components
        source_root_metadata = snapshot.source_root_metadata
        snapshot_projection = {
            "kind": REPOSITORY_WORKER_JOB_TREE_SOURCE_SNAPSHOT_KIND,
            "path_policy_digest": snapshot.path_policy_digest,
            "resource_limits_digest": snapshot.resource_limits_digest,
            "schema_version": (
                REPOSITORY_WORKER_JOB_TREE_SOURCE_SNAPSHOT_SCHEMA_VERSION
            ),
            "source_bundle_digest": snapshot.source_bundle_digest,
            "source_file_count": snapshot.source_file_count,
            "source_root_identity_digest": snapshot.source_root_identity_digest,
            "source_total_bytes": snapshot.source_total_bytes,
        }
        if (
            snapshot.source_bundle is not source_bundle
            or source_bundle.files is not source_files
            or not all(
                _is_digest(snapshot_projection[name])
                for name in (
                    "path_policy_digest",
                    "resource_limits_digest",
                    "source_bundle_digest",
                    "source_root_identity_digest",
                )
            )
            or type(snapshot_projection["source_file_count"]) is not int
            or snapshot_projection["source_file_count"] != source_file_count
            or type(snapshot_projection["source_total_bytes"]) is not int
            or snapshot_projection["source_total_bytes"] != source_total_bytes
            or snapshot_projection["source_bundle_digest"] != source_bundle_digest
            or type(source_root_components) is not tuple
            or not all(
                type(component) is str
                and component
                and "/" not in component
                and component not in {".", ".."}
                for component in source_root_components
            )
            or type(source_root_metadata) is not tuple
            or len(source_root_metadata) != 8
            or not all(
                type(item) is int and item >= 0
                for item in source_root_metadata
            )
            or source_root_metadata[2] != stat.S_IFDIR
            or source_root_metadata[4] <= 0
            or snapshot_projection["source_root_identity_digest"]
            != _BUILTIN_CANONICAL_DIGEST(
                {
                    "kind": REPOSITORY_WORKER_JOB_TREE_SOURCE_SNAPSHOT_KIND,
                    "metadata": list(source_root_metadata),
                    "path_components": list(source_root_components),
                    "schema_version": (
                        REPOSITORY_WORKER_JOB_TREE_SOURCE_SNAPSHOT_SCHEMA_VERSION
                    ),
                }
            )
        ):
            raise _InvalidMaterialization
        return (
            detached_bundle,
            snapshot_projection,
            source_root_components,
            source_root_metadata,
        )
    except (
        AttributeError,
        TypeError,
        UnicodeError,
        ValidationError,
        ValueError,
    ):
        raise _InvalidMaterialization from None


def _contract_projection(
    contract: RepositoryWorkerJobTreeContract,
) -> dict[str, Any]:
    if type(contract) is not _JOB_TREE_CONTRACT_TYPE:
        raise _InvalidMaterialization
    try:
        projection = {
            "containment_contract_digest": contract.containment_contract_digest,
            "filesystem_identity_ref": contract.filesystem_identity_ref,
            "git_metadata_prohibited": True,
            "kind": REPOSITORY_WORKER_JOB_TREE_CONTRACT_KIND,
            "path_policy_digest": contract.path_policy_digest,
            "registration_digest": contract.registration_digest,
            "registration_evidence_digest": contract.registration_evidence_digest,
            "registration_ref": contract.registration_ref,
            "repository_ref": contract.repository_ref,
            "required_job_tree_mode": "controller_owned_no_git",
            "required_patch_reconciliation": "controller_owned",
            "resource_limits_digest": contract.resource_limits_digest,
            "schema_version": REPOSITORY_WORKER_JOB_TREE_SCHEMA_VERSION,
            "source_bundle_digest": contract.source_bundle_digest,
            "source_file_count": contract.source_file_count,
            "source_total_bytes": contract.source_total_bytes,
        }
        if (
            not all(
                _is_digest(projection[name])
                for name in (
                    "containment_contract_digest",
                    "filesystem_identity_ref",
                    "path_policy_digest",
                    "registration_digest",
                    "registration_evidence_digest",
                    "registration_ref",
                    "repository_ref",
                    "resource_limits_digest",
                    "source_bundle_digest",
                )
            )
            or type(projection["source_file_count"]) is not int
            or projection["source_file_count"] < 1
            or type(projection["source_total_bytes"]) is not int
            or projection["source_total_bytes"] < 0
        ):
            raise _InvalidMaterialization
        return projection
    except (AttributeError, TypeError, ValueError):
        raise _InvalidMaterialization from None


def _validated_inputs(
    snapshot: RepositoryWorkerJobTreeSourceSnapshot,
    contract: RepositoryWorkerJobTreeContract,
) -> tuple[
    RepositoryWorkerJobTreeSourceBundle,
    str,
    str,
    tuple[str, ...],
    tuple[int, ...],
]:
    (
        bundle,
        snapshot_projection,
        source_root_components,
        source_root_metadata,
    ) = _detached_source_bundle(snapshot)
    contract_projection = _contract_projection(contract)
    source_snapshot_digest = _BUILTIN_CANONICAL_DIGEST(snapshot_projection)
    contract_digest = _BUILTIN_CANONICAL_DIGEST(contract_projection)
    if (
        snapshot_projection["path_policy_digest"]
        != contract_projection["path_policy_digest"]
        or snapshot_projection["resource_limits_digest"]
        != contract_projection["resource_limits_digest"]
        or snapshot_projection["source_bundle_digest"]
        != contract_projection["source_bundle_digest"]
        or snapshot_projection["source_file_count"]
        != contract_projection["source_file_count"]
        or snapshot_projection["source_total_bytes"]
        != contract_projection["source_total_bytes"]
        or snapshot_projection["source_bundle_digest"] != _bundle_digest(bundle)
    ):
        raise _InvalidMaterialization
    return (
        bundle,
        source_snapshot_digest,
        contract_digest,
        source_root_components,
        source_root_metadata,
    )


def _create_directory(
    parent: _DirectoryRecord,
    name: str,
) -> _DirectoryRecord:
    if not _directory_record_is_valid(parent) or _entry_metadata(
        parent.descriptor,
        name,
    ) is not None:
        raise _InvalidMaterialization
    descriptor: int | None = None
    identity: tuple[int, int] | None = None
    created = False
    try:
        os.mkdir(name, _DIRECTORY_MODE, dir_fd=parent.descriptor)
        created = True
        descriptor = _open_directory_at(parent.descriptor, name)
        metadata = os.fstat(descriptor)
        identity = (metadata.st_dev, metadata.st_ino)
        os.fchmod(descriptor, _DIRECTORY_MODE)
        metadata = os.fstat(descriptor)
        named = _entry_metadata(parent.descriptor, name)
        if (
            named is None
            or not stat.S_ISDIR(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino) != (named.st_dev, named.st_ino)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != _DIRECTORY_MODE
            or metadata.st_nlink <= 0
            or os.get_inheritable(descriptor)
        ):
            raise _InvalidMaterialization
        os.fsync(parent.descriptor)
        record = _DirectoryRecord(
            components=parent.components + (name,),
            descriptor=descriptor,
            identity=(metadata.st_dev, metadata.st_ino),
        )
        descriptor = None
        return record
    except BaseException as exc:
        if created and identity is not None:
            try:
                named = _entry_metadata(parent.descriptor, name)
                if (
                    named is not None
                    and stat.S_ISDIR(named.st_mode)
                    and (named.st_dev, named.st_ino) == identity
                    and descriptor is not None
                    and _directory_is_empty(descriptor)
                ):
                    os.rmdir(name, dir_fd=parent.descriptor)
                    os.fsync(parent.descriptor)
            except (OSError, _InvalidMaterialization):
                pass
        if descriptor is not None:
            _close_descriptor(descriptor)
        if isinstance(exc, (OSError, _InvalidMaterialization)):
            raise _InvalidMaterialization from None
        raise


def _write_exact(descriptor: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        try:
            written = os.write(descriptor, content[offset:])
        except OSError:
            raise _InvalidMaterialization from None
        if type(written) is not int or written <= 0:
            raise _InvalidMaterialization
        offset += written


def _read_exact(descriptor: int, expected_size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = expected_size
    while remaining:
        try:
            chunk = os.read(descriptor, min(remaining, _READ_CHUNK_BYTES))
        except OSError:
            raise _InvalidMaterialization from None
        if not chunk:
            raise _InvalidMaterialization
        chunks.append(chunk)
        remaining -= len(chunk)
    try:
        if os.read(descriptor, 1):
            raise _InvalidMaterialization
    except OSError:
        raise _InvalidMaterialization from None
    return b"".join(chunks)


def _materialize_file(
    parent: _DirectoryRecord,
    source_file: RepositoryWorkerJobTreeSourceFile,
) -> _FileRecord:
    if not _directory_record_is_valid(parent):
        raise _InvalidMaterialization
    components = tuple(source_file.relative_path.split("/"))
    name = components[-1]
    if _entry_metadata(parent.descriptor, name) is not None:
        raise _InvalidMaterialization
    expected_mode = (
        _EXECUTABLE_FILE_MODE if source_file.executable else _REGULAR_FILE_MODE
    )
    descriptor: int | None = None
    identity: tuple[int, int] | None = None
    try:
        descriptor = os.open(
            name,
            _regular_write_flags(),
            expected_mode,
            dir_fd=parent.descriptor,
        )
        before = os.fstat(descriptor)
        identity = (before.st_dev, before.st_ino)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or os.get_inheritable(descriptor)
        ):
            raise _InvalidMaterialization
        _write_exact(descriptor, source_file.content)
        os.fsync(descriptor)
        os.fchmod(descriptor, expected_mode)
        after = os.fstat(descriptor)
        named = _entry_metadata(parent.descriptor, name)
        if (
            not stat.S_ISREG(after.st_mode)
            or after.st_nlink != 1
            or after.st_uid != os.geteuid()
            or stat.S_IMODE(after.st_mode) != expected_mode
            or after.st_size != len(source_file.content)
            or (after.st_dev, after.st_ino) != identity
            or named is None
            or (named.st_dev, named.st_ino) != identity
        ):
            raise _InvalidMaterialization
        os.fsync(parent.descriptor)
        record = _FileRecord(
            relative_path=source_file.relative_path,
            parent_components=components[:-1],
            name=name,
            identity=identity,
            expected_mode=expected_mode,
            content=source_file.content,
        )
        if not _close_descriptor(descriptor):
            descriptor = None
            raise _InvalidMaterialization
        descriptor = None
        return record
    except BaseException as exc:
        if identity is not None:
            try:
                named = _entry_metadata(parent.descriptor, name)
                if (
                    named is not None
                    and stat.S_ISREG(named.st_mode)
                    and named.st_nlink == 1
                    and (named.st_dev, named.st_ino) == identity
                ):
                    os.unlink(name, dir_fd=parent.descriptor)
                    os.fsync(parent.descriptor)
            except (OSError, _InvalidMaterialization):
                pass
        if isinstance(exc, (OSError, _InvalidMaterialization)):
            raise _InvalidMaterialization from None
        raise
    finally:
        if descriptor is not None:
            _close_descriptor(descriptor)


def _verify_file(
    parent: _DirectoryRecord,
    file_record: _FileRecord,
) -> None:
    if not _directory_record_is_valid(parent):
        raise _InvalidMaterialization
    descriptor: int | None = None
    try:
        named_before = _entry_metadata(parent.descriptor, file_record.name)
        if (
            named_before is None
            or not stat.S_ISREG(named_before.st_mode)
            or named_before.st_nlink != 1
            or stat.S_IMODE(named_before.st_mode) != file_record.expected_mode
            or (named_before.st_dev, named_before.st_ino) != file_record.identity
            or named_before.st_size != len(file_record.content)
        ):
            raise _InvalidMaterialization
        descriptor = os.open(
            file_record.name,
            _regular_read_flags(),
            dir_fd=parent.descriptor,
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != file_record.expected_mode
            or (before.st_dev, before.st_ino) != file_record.identity
            or before.st_size != len(file_record.content)
        ):
            raise _InvalidMaterialization
        content = _read_exact(descriptor, before.st_size)
        after = os.fstat(descriptor)
        named_after = _entry_metadata(parent.descriptor, file_record.name)
        if (
            content != file_record.content
            or hashlib.sha256(content).digest()
            != hashlib.sha256(file_record.content).digest()
            or _metadata_signature(before) != _metadata_signature(after)
            or named_after is None
            or _metadata_signature(after) != _metadata_signature(named_after)
        ):
            raise _InvalidMaterialization
    except (OSError, _InvalidMaterialization):
        raise _InvalidMaterialization from None
    finally:
        if descriptor is not None and not _close_descriptor(descriptor):
            raise _InvalidMaterialization


def _verify_materialized_tree(
    root: _DirectoryRecord,
    directories: dict[tuple[str, ...], _DirectoryRecord],
    files: tuple[_FileRecord, ...],
) -> None:
    if not _directory_record_is_valid(root):
        raise _InvalidMaterialization
    expected_children: dict[tuple[str, ...], set[str]] = {
        components: set() for components in directories
    }
    for components in directories:
        if components:
            expected_children[components[:-1]].add(components[-1])
    files_by_parent: dict[tuple[str, ...], list[_FileRecord]] = {}
    for file_record in files:
        expected_children[file_record.parent_components].add(file_record.name)
        files_by_parent.setdefault(file_record.parent_components, []).append(
            file_record
        )
    for components in sorted(directories, key=lambda item: (len(item), item)):
        directory = directories[components]
        if not _directory_record_is_valid(directory):
            raise _InvalidMaterialization
        if _directory_entry_names(directory.descriptor) != tuple(
            sorted(expected_children[components])
        ):
            raise _InvalidMaterialization
        for child_name in expected_children[components]:
            metadata = _entry_metadata(directory.descriptor, child_name)
            if metadata is None:
                raise _InvalidMaterialization
        for file_record in files_by_parent.get(components, []):
            _verify_file(directory, file_record)
        for child_components in sorted(
            (
                item
                for item in directories
                if len(item) == len(components) + 1
                and item[:-1] == components
            )
        ):
            child = directories[child_components]
            metadata = _entry_metadata(directory.descriptor, child_components[-1])
            if (
                metadata is None
                or not stat.S_ISDIR(metadata.st_mode)
                or (metadata.st_dev, metadata.st_ino) != child.identity
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != _DIRECTORY_MODE
            ):
                raise _InvalidMaterialization


def _remove_owned_file(parent: _DirectoryRecord, record: _FileRecord) -> bool:
    try:
        if not _directory_record_is_valid(parent):
            return False
        metadata = _entry_metadata(parent.descriptor, record.name)
        if metadata is None:
            return False
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (metadata.st_dev, metadata.st_ino) != record.identity
        ):
            return False
        os.unlink(record.name, dir_fd=parent.descriptor)
        if _entry_metadata(parent.descriptor, record.name) is not None:
            return False
        os.fsync(parent.descriptor)
        return True
    except (OSError, _InvalidMaterialization):
        return False


def _remove_owned_directory(
    parent: _DirectoryRecord,
    record: _DirectoryRecord,
) -> bool:
    if not record.components:
        return False
    name = record.components[-1]
    try:
        if not _directory_record_is_valid(parent) or not _directory_record_is_valid(
            record
        ):
            return False
        metadata = _entry_metadata(parent.descriptor, name)
        if (
            metadata is None
            or not stat.S_ISDIR(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino) != record.identity
            or not _directory_is_empty(record.descriptor)
        ):
            return False
        os.rmdir(name, dir_fd=parent.descriptor)
        if _entry_metadata(parent.descriptor, name) is not None:
            return False
        os.fsync(parent.descriptor)
        return True
    except (OSError, _InvalidMaterialization):
        return False


def _rollback_materialization(
    root: _DirectoryRecord,
    directories: dict[tuple[str, ...], _DirectoryRecord],
    files: tuple[_FileRecord, ...],
) -> bool:
    success = True
    for file_record in reversed(files):
        parent = directories.get(file_record.parent_components)
        if parent is None or not _remove_owned_file(parent, file_record):
            success = False
    for components in sorted(directories, key=lambda item: (len(item), item), reverse=True):
        if not components:
            continue
        parent = directories.get(components[:-1])
        record = directories[components]
        if parent is None or not _remove_owned_directory(parent, record):
            success = False
    try:
        if not _directory_record_is_valid(root) or not _directory_is_empty(
            root.descriptor
        ):
            return False
        os.fsync(root.descriptor)
    except (OSError, _InvalidMaterialization):
        return False
    return success


def _close_directory_records(
    directories: dict[tuple[str, ...], _DirectoryRecord],
    *,
    retain_root: bool,
) -> bool:
    success = True
    for components in sorted(directories, key=lambda item: (len(item), item), reverse=True):
        if retain_root and not components:
            continue
        if not _close_descriptor(directories[components].descriptor):
            success = False
    return success


def _receipt_projection(
    receipt: RepositoryWorkerJobTreeMaterializationReceipt,
) -> dict[str, Any]:
    receipt.__post_init__()
    return {
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


def materialize_repository_worker_job_tree(
    snapshot: RepositoryWorkerJobTreeSourceSnapshot,
    *,
    contract: RepositoryWorkerJobTreeContract,
    lease: RepositoryWorkerJobTreeMaterializationLease,
) -> RepositoryWorkerJobTreeMaterializationReceipt:
    """Materialize one detached source snapshot through a private root FD.

    The returned receipt is historical local evidence only.  It does not bind
    fresh registration evidence, approve the target root for a worker, make
    the tree immutable, or authorize execution, dispatch, or reconciliation.
    """

    root_descriptor: int | None = None
    root_record: _DirectoryRecord | None = None
    directories: dict[tuple[str, ...], _DirectoryRecord] = {}
    files: tuple[_FileRecord, ...] = ()
    canonical_root: Path | None = None
    root_identity: tuple[int, int, int, int, int] | None = None
    try:
        if not _descriptor_support_is_available():
            raise _InvalidMaterialization
        (
            bundle,
            source_snapshot_digest,
            contract_digest,
            source_root_components,
            source_root_metadata,
        ) = _validated_inputs(snapshot, contract)
        root_descriptor, canonical_root, root_identity = _prepare_target_root(
            lease
        )
        if (
            _path_components_overlap(
                tuple(canonical_root.parts[1:]),
                source_root_components,
            )
            or (root_identity[0], root_identity[1])
            == (source_root_metadata[0], source_root_metadata[1])
        ):
            raise _InvalidMaterialization
        root_record = _DirectoryRecord(
            components=(),
            descriptor=root_descriptor,
            identity=(root_identity[0], root_identity[1]),
        )
        directories[()] = root_record

        required_directories = sorted(
            {
                components[:index]
                for source_file in bundle.files
                for components in [
                    tuple(source_file.relative_path.split("/")[:-1])
                ]
                for index in range(1, len(components) + 1)
            },
            key=lambda item: (len(item), item),
        )
        for components in required_directories:
            parent = directories.get(components[:-1])
            if parent is None:
                raise _InvalidMaterialization
            directories[components] = _create_directory(parent, components[-1])

        for source_file in bundle.files:
            components = tuple(source_file.relative_path.split("/")[:-1])
            parent = directories.get(components)
            if parent is None:
                raise _InvalidMaterialization
            files += (_materialize_file(parent, source_file),)

        if (
            canonical_root is None
            or root_identity is None
            or not _root_path_matches(canonical_root, root_identity)
        ):
            raise _InvalidMaterialization
        _verify_materialized_tree(root_record, directories, files)
        if not _root_path_matches(canonical_root, root_identity):
            raise _InvalidMaterialization
        for components in sorted(directories, key=lambda item: (len(item), item), reverse=True):
            os.fsync(directories[components].descriptor)
        _verify_materialized_tree(root_record, directories, files)
        if not _root_path_matches(canonical_root, root_identity):
            raise _InvalidMaterialization

        receipt = RepositoryWorkerJobTreeMaterializationReceipt(
            kind=REPOSITORY_WORKER_JOB_TREE_MATERIALIZATION_KIND,
            schema_version=REPOSITORY_WORKER_JOB_TREE_MATERIALIZATION_SCHEMA_VERSION,
            materialization_scope=MATERIALIZATION_SCOPE,
            source_snapshot_digest=source_snapshot_digest,
            job_tree_contract_digest=contract_digest,
            source_bundle_digest=_bundle_digest(bundle),
            source_file_count=len(bundle.files),
            source_total_bytes=sum(len(item.content) for item in bundle.files),
            materialized_file_count=len(files),
            materialized_total_bytes=sum(len(item.content) for item in bundle.files),
            executable_file_count=sum(1 for item in bundle.files if item.executable),
            regular_file_count=sum(1 for item in bundle.files if not item.executable),
        )
        lease._root_descriptor = root_descriptor
        lease._root_identity = root_identity
        lease._canonical_root = canonical_root
        lease._receipt = receipt
        lease._state = "active"
        root_descriptor = None
        if not _close_directory_records(directories, retain_root=True):
            lease._state = "cleanup_unverifiable"
            raise ConfigurationError(_CLEANUP_UNCERTAIN_MESSAGE)
        return receipt
    except ConfigurationError:
        raise
    except BaseException as exc:
        rollback_succeeded = True
        if root_record is not None:
            rollback_succeeded = _rollback_materialization(
                root_record,
                directories,
                files,
            )
        close_succeeded = _close_directory_records(
            directories,
            retain_root=False,
        )
        root_descriptor = None
        if not rollback_succeeded or not close_succeeded:
            if type(lease) is RepositoryWorkerJobTreeMaterializationLease:
                lease._state = "cleanup_unverifiable"
            raise ConfigurationError(_CLEANUP_UNCERTAIN_MESSAGE) from None
        if isinstance(
            exc,
            (OSError, _InvalidMaterialization, TypeError, UnicodeError, ValueError),
        ):
            raise ValidationError(_INVALID_MESSAGE) from None
        raise
    finally:
        if root_descriptor is not None:
            _close_descriptor(root_descriptor)


__all__ = [
    "MATERIALIZATION_SCOPE",
    "REPOSITORY_WORKER_JOB_TREE_MATERIALIZATION_KIND",
    "REPOSITORY_WORKER_JOB_TREE_MATERIALIZATION_SCHEMA_VERSION",
    "RepositoryWorkerJobTreeMaterializationLease",
    "RepositoryWorkerJobTreeMaterializationReceipt",
    "materialize_repository_worker_job_tree",
]
