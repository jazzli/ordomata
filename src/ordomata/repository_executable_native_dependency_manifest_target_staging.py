"""Stage exact native-dependency manifest targets into detached local files.

This Class 1 primitive accepts only a previously measured, controller-owned
native-dependency manifest target set.  A caller supplies a pre-existing,
empty, owner-only staging directory; the primitive opens that directory without
following links, copies bytes only while the no-follow source descriptor is
pinned, and unlinks every staging name before retaining a read-only descriptor.
It never resolves loader search state, loads a target, executes a process, or
authorizes a later effect.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import fcntl
import hashlib
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Any, Literal

from .authorization import canonical_json
from .errors import ConfigurationError, ValidationError
from .repository_executable_native_dependency_manifest import (
    RepositoryExecutableNativeDependencyManifestEntry,
    RepositoryExecutableNativeDependencyManifestReceipt,
    _manifest_target_ref,
    _receipt_projection as _manifest_receipt_projection,
)
from .repository_executable_native_dependency_manifest_targets import (
    RepositoryExecutableNativeDependencyManifestTargetMeasurement,
    RepositoryExecutableNativeDependencyManifestTargetsReceipt,
    _public_measurement,
    _receipt_projection as _targets_receipt_projection,
    inspect_staged_executable_native_dependency_manifest_targets,
)
from .repository_executable_native_dependency_requirements import (
    RepositoryExecutableNativeDependencyRequirementsReceipt,
    _receipt_projection as _requirements_receipt_projection,
)
from .repository_executable_runtime_manifest import (
    RepositoryExecutableRuntimeManifestReceipt,
    _runtime_manifest_projection,
)
from .repository_executable_shebang_target_resolution import (
    _MeasuredTarget,
    _measure_target_set_with_consumer,
)
from .repository_executable_staging import (
    RepositoryExecutableStageLease,
    RepositoryExecutableStagingReceipt,
    _staging_receipt_projection,
)


REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_STAGING_SCHEMA_VERSION = 1
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_STAGING_KIND = (
    "repository_executable_native_dependency_manifest_target_staging"
)
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_STAGING_EVIDENCE_KIND = (
    "repository_executable_native_dependency_manifest_target_staging_validation"
)
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_STAGED_FILE_KIND = (
    "repository_executable_native_dependency_manifest_target_staged_file"
)
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_STAGE_CLEANUP_KIND = (
    "repository_executable_native_dependency_manifest_target_stage_cleanup"
)

MEASUREMENT_SOURCE = "controller_measured"
STAGING_SOURCE = "controller_descriptor_copy"
STAGING_SCOPE = "explicit_manifest_target_detached_descriptor_copy_v1"

_FIXED_SCHEMA_VERSION = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_STAGING_SCHEMA_VERSION
_FIXED_RECEIPT_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_STAGING_KIND
_FIXED_EVIDENCE_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_STAGING_EVIDENCE_KIND
_FIXED_FILE_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_STAGED_FILE_KIND
_FIXED_CLEANUP_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_STAGE_CLEANUP_KIND
_FIXED_MEASUREMENT_SOURCE = MEASUREMENT_SOURCE
_FIXED_STAGING_SOURCE = STAGING_SOURCE
_FIXED_STAGING_SCOPE = STAGING_SCOPE
_INVALID_MESSAGE = "repository executable native dependency manifest target staging is invalid"
_CLEANUP_UNCERTAIN_MESSAGE = "repository executable native dependency manifest target staging cleanup is unverifiable"
_COPY_ERROR_MESSAGE = "repository executable native dependency manifest target stage leases cannot be copied"
_DIGEST_PREFIX = "sha256:"
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_TARGET_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_TARGET_BYTES = 256 * 1024 * 1024
_READ_CHUNK_BYTES = 64 * 1024
_STAGING_ROOT_MODE = 0o700
_STAGED_FILE_MODE = 0o400
_STAGE_NAME_ATTEMPTS = 16
_CONCRETE_PATH_TYPE = type(Path())
_LeaseState = Literal["new", "active", "cleaned", "cleanup_unverifiable"]


def _captured_canonical_digest(value: Any) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


# Freeze the concrete dependencies used at this policy boundary.  Public module
# attributes are deliberately not treated as policy inputs.
_BUILTIN_CANONICAL_DIGEST = _captured_canonical_digest
_BUILTIN_SHA256 = hashlib.sha256
_BUILTIN_TARGETS_PROJECTION = _targets_receipt_projection
_BUILTIN_MANIFEST_PROJECTION = _manifest_receipt_projection
_BUILTIN_REQUIREMENTS_PROJECTION = _requirements_receipt_projection
_BUILTIN_RUNTIME_PROJECTION = _runtime_manifest_projection
_BUILTIN_STAGING_PROJECTION = _staging_receipt_projection
_BUILTIN_INSPECT_TARGETS = inspect_staged_executable_native_dependency_manifest_targets
_BUILTIN_PUBLIC_MEASUREMENT = _public_measurement
_BUILTIN_MEASURE_WITH_CONSUMER = _measure_target_set_with_consumer
_BUILTIN_MANIFEST_TARGET_REF = _manifest_target_ref
_FIXED_TARGETS_TYPE = RepositoryExecutableNativeDependencyManifestTargetsReceipt
_FIXED_TARGET_MEASUREMENT_TYPE = RepositoryExecutableNativeDependencyManifestTargetMeasurement
_FIXED_MANIFEST_TYPE = RepositoryExecutableNativeDependencyManifestReceipt
_FIXED_MANIFEST_ENTRY_TYPE = RepositoryExecutableNativeDependencyManifestEntry
_FIXED_REQUIREMENTS_TYPE = RepositoryExecutableNativeDependencyRequirementsReceipt
_FIXED_RUNTIME_TYPE = RepositoryExecutableRuntimeManifestReceipt
_FIXED_STAGING_TYPE = RepositoryExecutableStagingReceipt
_FIXED_EXECUTABLE_LEASE_TYPE = RepositoryExecutableStageLease
_FIXED_MEASURED_TARGET_TYPE = _MeasuredTarget
_FIXED_VALIDATION_ERROR = ValidationError


class _InvalidTargetStaging(ValueError):
    """Private sentinel whose detail never crosses this boundary."""


class _CleanupUncertain(ConfigurationError):
    """The caller-owned root cannot be proven free of this operation's names."""


def _is_digest(value: Any) -> bool:
    return type(value) is str and _DIGEST_PATTERN.fullmatch(value) is not None


def _metadata_signature(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _path_parts(path: Path) -> tuple[str, ...]:
    if type(path) is not _CONCRETE_PATH_TYPE:
        raise _InvalidTargetStaging
    try:
        spelling = os.fspath(path)
        encoded = spelling.encode("ascii")
    except (AttributeError, TypeError, UnicodeEncodeError):
        raise _InvalidTargetStaging from None
    if (
        not spelling.startswith("/")
        or spelling == "/"
        or spelling.endswith("/")
        or "//" in spelling
        or not encoded
    ):
        raise _InvalidTargetStaging
    parts = tuple(spelling[1:].split("/"))
    if any(not part or part in {".", ".."} for part in parts):
        raise _InvalidTargetStaging
    return parts


def _paths_overlap(left: Path, right: Path) -> bool:
    left_parts = _path_parts(left)
    right_parts = _path_parts(right)
    return left_parts[: len(right_parts)] == right_parts or right_parts[: len(left_parts)] == left_parts


def _directory_empty(descriptor: int) -> bool:
    try:
        return os.listdir(descriptor) == []
    except (OSError, TypeError):
        raise _InvalidTargetStaging from None


def _close_descriptor(descriptor: int) -> bool:
    try:
        os.close(descriptor)
    except OSError:
        return False
    return True


def _root_context_digest(metadata: os.stat_result) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "directory_identity_ref": _BUILTIN_CANONICAL_DIGEST(
                {
                    "device": metadata.st_dev,
                    "inode": metadata.st_ino,
                    "kind": "repository_executable_native_dependency_manifest_target_staging_root_identity",
                    "schema_version": _FIXED_SCHEMA_VERSION,
                }
            ),
            "directory_mode": stat.S_IMODE(metadata.st_mode),
            "directory_owner": metadata.st_uid,
            "kind": "repository_executable_native_dependency_manifest_target_staging_context",
            "schema_version": _FIXED_SCHEMA_VERSION,
            "staging_root_used": True,
            "staging_scope": _FIXED_STAGING_SCOPE,
        }
    )


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeDependencyManifestTargetStagedFile:
    """One detached descriptor copy of an exact measured manifest target."""

    kind: str
    manifest_target_ref: str = field(repr=False)
    source_filesystem_identity_ref: str = field(repr=False)
    source_metadata_digest: str = field(repr=False)
    target_measurement_ref: str = field(repr=False)
    staged_file_ref: str = field(repr=False)
    staged_filesystem_identity_ref: str = field(repr=False)
    staged_metadata_digest: str = field(repr=False)
    content_digest: str = field(repr=False)
    content_bytes: int

    def to_canonical(self) -> dict[str, Any]:
        return _staged_file_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeDependencyManifestTargetStagingReceipt:
    """Digest-only evidence for one Class 1 detached-copy lease."""

    kind: str
    schema_version: int
    measurement_source: str
    staging_source: str
    staging_scope: str
    native_dependency_manifest_targets_receipt_digest: str = field(repr=False)
    native_dependency_manifest_receipt_digest: str = field(repr=False)
    native_dependency_requirements_receipt_digest: str = field(repr=False)
    runtime_manifest_receipt_digest: str = field(repr=False)
    staging_receipt_digest: str = field(repr=False)
    registration_digest: str = field(repr=False)
    repository_ref: str = field(repr=False)
    verification_commands_digest: str = field(repr=False)
    resolution_context_digest: str = field(repr=False)
    source_staging_context_digest: str = field(repr=False)
    manifest_context_digest: str = field(repr=False)
    action_measurements_digest: str = field(repr=False)
    post_stage_targets_receipt_digest: str = field(repr=False)
    target_staging_context_digest: str = field(repr=False)
    staging_root_used: bool
    staged_files: tuple[RepositoryExecutableNativeDependencyManifestTargetStagedFile, ...] = field(repr=False)
    unique_target_count: int
    total_staged_bytes: int

    def to_canonical(self) -> dict[str, Any]:
        return _staging_receipt_projection(self)

    @property
    def receipt_digest(self) -> str:
        return _BUILTIN_CANONICAL_DIGEST(_staging_receipt_projection(self))

    def to_evidence(self) -> dict[str, Any]:
        return _staging_evidence_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeDependencyManifestTargetStageCleanupReceipt:
    """Bounded evidence that a detached-copy lease released its descriptors."""

    kind: str
    schema_version: int
    outcome: Literal["released", "unverifiable"]
    target_staging_receipt_digest: str | None = field(repr=False)
    owned_namespace_absence_verified: bool
    descriptor_release_complete: bool

    def to_canonical(self) -> dict[str, Any]:
        return _cleanup_receipt_projection(self)


@dataclass(frozen=True, slots=True)
class _CapturedTarget:
    measurement: RepositoryExecutableNativeDependencyManifestTargetMeasurement = field(repr=False)
    content: tuple[bytes, ...] = field(repr=False)


@dataclass(frozen=True, slots=True)
class _RetainedTarget:
    staged_file: RepositoryExecutableNativeDependencyManifestTargetStagedFile = field(repr=False)
    descriptor: int = field(repr=False)
    metadata: tuple[int, ...] = field(repr=False)


@dataclass(slots=True)
class RepositoryExecutableNativeDependencyManifestTargetStageLease:
    """A single-process, one-shot lease over unlinked, read-only staged bytes."""

    staging_root: Path = field(repr=False)
    _state: _LeaseState = field(default="new", init=False, repr=False)
    _owner_pid: int = field(default_factory=os.getpid, init=False, repr=False)
    _root_descriptor: int | None = field(default=None, init=False, repr=False)
    _root_metadata: tuple[int, ...] | None = field(default=None, init=False, repr=False)
    _files: tuple[_RetainedTarget, ...] = field(default=(), init=False, repr=False)
    _receipt: RepositoryExecutableNativeDependencyManifestTargetStagingReceipt | None = field(default=None, init=False, repr=False)
    _receipt_anchor: RepositoryExecutableNativeDependencyManifestTargetStagingReceipt | None = field(default=None, init=False, repr=False)
    _receipt_digest_anchor: str | None = field(default=None, init=False, repr=False)
    _files_anchor: tuple[_RetainedTarget, ...] | None = field(default=None, init=False, repr=False)
    _cleanup_receipt: RepositoryExecutableNativeDependencyManifestTargetStageCleanupReceipt | None = field(default=None, init=False, repr=False)
    _cleanup_anchor: RepositoryExecutableNativeDependencyManifestTargetStageCleanupReceipt | None = field(default=None, init=False, repr=False)
    _cleanup_digest_anchor: str | None = field(default=None, init=False, repr=False)

    @property
    def state(self) -> str:
        return self._state

    @property
    def receipt(self) -> RepositoryExecutableNativeDependencyManifestTargetStagingReceipt | None:
        return self._receipt

    @property
    def cleanup_receipt(self) -> RepositoryExecutableNativeDependencyManifestTargetStageCleanupReceipt | None:
        return self._cleanup_receipt

    def cleanup(self) -> RepositoryExecutableNativeDependencyManifestTargetStageCleanupReceipt:
        return cleanup_repository_executable_native_dependency_manifest_target_stage(self)

    def close(self) -> RepositoryExecutableNativeDependencyManifestTargetStageCleanupReceipt:
        return cleanup_repository_executable_native_dependency_manifest_target_stage(self)

    def __enter__(self) -> RepositoryExecutableNativeDependencyManifestTargetStageLease:
        if self._state != "active" or self._owner_pid != os.getpid():
            raise ValidationError(_INVALID_MESSAGE)
        return self

    def __exit__(self, *unused: object) -> None:
        cleanup_repository_executable_native_dependency_manifest_target_stage(self)

    def __copy__(self) -> None:
        raise TypeError(_COPY_ERROR_MESSAGE)

    def __deepcopy__(self, memo: object) -> None:
        raise TypeError(_COPY_ERROR_MESSAGE)

    def __reduce__(self) -> None:
        raise TypeError(_COPY_ERROR_MESSAGE)

    def __reduce_ex__(self, protocol: int) -> None:
        raise TypeError(_COPY_ERROR_MESSAGE)


_FIXED_STAGE_LEASE_TYPE = RepositoryExecutableNativeDependencyManifestTargetStageLease
_FIXED_STAGED_FILE_TYPE = RepositoryExecutableNativeDependencyManifestTargetStagedFile
_FIXED_RECEIPT_TYPE = RepositoryExecutableNativeDependencyManifestTargetStagingReceipt
_FIXED_CLEANUP_TYPE = RepositoryExecutableNativeDependencyManifestTargetStageCleanupReceipt


def _staged_file_projection(value: RepositoryExecutableNativeDependencyManifestTargetStagedFile) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_STAGED_FILE_TYPE
        or value.kind != _FIXED_FILE_KIND
        or not all(
            _is_digest(item)
            for item in (
                value.manifest_target_ref,
                value.source_filesystem_identity_ref,
                value.source_metadata_digest,
                value.target_measurement_ref,
                value.staged_file_ref,
                value.staged_filesystem_identity_ref,
                value.staged_metadata_digest,
                value.content_digest,
            )
        )
        or type(value.content_bytes) is not int
        or not 0 <= value.content_bytes <= _MAX_TARGET_BYTES
    ):
        raise _InvalidTargetStaging
    return {
        "content_bytes": value.content_bytes,
        "content_digest": value.content_digest,
        "kind": value.kind,
        "manifest_target_ref": value.manifest_target_ref,
        "source_filesystem_identity_ref": value.source_filesystem_identity_ref,
        "source_metadata_digest": value.source_metadata_digest,
        "staged_file_ref": value.staged_file_ref,
        "staged_filesystem_identity_ref": value.staged_filesystem_identity_ref,
        "staged_metadata_digest": value.staged_metadata_digest,
        "target_measurement_ref": value.target_measurement_ref,
    }


def _staging_receipt_projection(value: RepositoryExecutableNativeDependencyManifestTargetStagingReceipt) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_RECEIPT_TYPE
        or value.kind != _FIXED_RECEIPT_KIND
        or value.schema_version != _FIXED_SCHEMA_VERSION
        or value.measurement_source != _FIXED_MEASUREMENT_SOURCE
        or value.staging_source != _FIXED_STAGING_SOURCE
        or value.staging_scope != _FIXED_STAGING_SCOPE
        or type(value.staging_root_used) is not bool
        or type(value.staged_files) is not tuple
        or type(value.unique_target_count) is not int
        or type(value.total_staged_bytes) is not int
        or not all(
            _is_digest(item)
            for item in (
                value.native_dependency_manifest_targets_receipt_digest,
                value.native_dependency_manifest_receipt_digest,
                value.native_dependency_requirements_receipt_digest,
                value.runtime_manifest_receipt_digest,
                value.staging_receipt_digest,
                value.registration_digest,
                value.repository_ref,
                value.verification_commands_digest,
                value.resolution_context_digest,
                value.source_staging_context_digest,
                value.manifest_context_digest,
                value.action_measurements_digest,
                value.post_stage_targets_receipt_digest,
                value.target_staging_context_digest,
            )
        )
        or len(value.staged_files) != value.unique_target_count
        or sum(item.content_bytes for item in value.staged_files) != value.total_staged_bytes
        or value.total_staged_bytes < 0
        or value.total_staged_bytes > _MAX_TOTAL_TARGET_BYTES
        or (value.unique_target_count == 0 and value.staging_root_used)
        or (value.unique_target_count > 0 and not value.staging_root_used)
    ):
        raise _InvalidTargetStaging
    files = tuple(_staged_file_projection(item) for item in value.staged_files)
    if len({item["staged_file_ref"] for item in files}) != len(files):
        raise _InvalidTargetStaging
    return {
        "action_measurements_digest": value.action_measurements_digest,
        "kind": value.kind,
        "manifest_context_digest": value.manifest_context_digest,
        "measurement_source": value.measurement_source,
        "native_dependency_manifest_receipt_digest": value.native_dependency_manifest_receipt_digest,
        "native_dependency_manifest_targets_receipt_digest": value.native_dependency_manifest_targets_receipt_digest,
        "native_dependency_requirements_receipt_digest": value.native_dependency_requirements_receipt_digest,
        "post_stage_targets_receipt_digest": value.post_stage_targets_receipt_digest,
        "registration_digest": value.registration_digest,
        "repository_ref": value.repository_ref,
        "resolution_context_digest": value.resolution_context_digest,
        "runtime_manifest_receipt_digest": value.runtime_manifest_receipt_digest,
        "schema_version": value.schema_version,
        "source_staging_context_digest": value.source_staging_context_digest,
        "staged_files": files,
        "staging_receipt_digest": value.staging_receipt_digest,
        "staging_root_used": value.staging_root_used,
        "staging_scope": value.staging_scope,
        "staging_source": value.staging_source,
        "target_staging_context_digest": value.target_staging_context_digest,
        "total_staged_bytes": value.total_staged_bytes,
        "unique_target_count": value.unique_target_count,
        "verification_commands_digest": value.verification_commands_digest,
    }


def _staging_evidence_projection(value: RepositoryExecutableNativeDependencyManifestTargetStagingReceipt) -> dict[str, Any]:
    canonical = _staging_receipt_projection(value)
    return {
        "action_measurement_matches_expected": True,
        "ambient_loader_environment_consulted": False,
        "authority_granted": False,
        "authorization_verified": False,
        "billing_eligible": False,
        "capacity_eligible": False,
        "circuit_eligible": False,
        "controller_explicit_manifest_reproduced": True,
        "descriptor_staging_performed": bool(value.staged_files),
        "dispatch_enabled": False,
        "effect_class": 1,
        "execution_enabled": False,
        "harness_invocation_performed": False,
        "kind": _FIXED_EVIDENCE_KIND,
        "loader_invocation_performed": False,
        "manifest_target_raw_values_exposed": False,
        "model_invocation_performed": False,
        "network_access_performed": False,
        "post_stage_measurement_matches_expected": True,
        "receipt_digest": _BUILTIN_CANONICAL_DIGEST(canonical),
        "source_path_reopen_performed": False,
        "staged_names_retained": False,
        "subprocess_invocation_performed": False,
        "target_nofollow_measurement_complete": True,
        "total_staged_bytes": value.total_staged_bytes,
        "unique_target_count": value.unique_target_count,
        "validation_mode": "local_draft",
    }


def _cleanup_receipt_projection(value: RepositoryExecutableNativeDependencyManifestTargetStageCleanupReceipt) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_CLEANUP_TYPE
        or value.kind != _FIXED_CLEANUP_KIND
        or value.schema_version != _FIXED_SCHEMA_VERSION
        or value.outcome not in {"released", "unverifiable"}
        or (value.target_staging_receipt_digest is not None and not _is_digest(value.target_staging_receipt_digest))
        or type(value.owned_namespace_absence_verified) is not bool
        or type(value.descriptor_release_complete) is not bool
    ):
        raise _InvalidTargetStaging
    return {
        "descriptor_release_complete": value.descriptor_release_complete,
        "kind": value.kind,
        "outcome": value.outcome,
        "owned_namespace_absence_verified": value.owned_namespace_absence_verified,
        "schema_version": value.schema_version,
        "target_staging_receipt_digest": value.target_staging_receipt_digest,
    }


def _require_new_lease(lease: RepositoryExecutableNativeDependencyManifestTargetStageLease) -> RepositoryExecutableNativeDependencyManifestTargetStageLease:
    if (
        type(lease) is not _FIXED_STAGE_LEASE_TYPE
        or lease._state != "new"
        or lease._owner_pid != os.getpid()
        or type(lease.staging_root) is not _CONCRETE_PATH_TYPE
        or lease._root_descriptor is not None
        or lease._root_metadata is not None
        or lease._files
        or lease._receipt is not None
        or lease._cleanup_receipt is not None
    ):
        raise _InvalidTargetStaging
    _path_parts(lease.staging_root)
    return lease


def _prepare_root(lease: RepositoryExecutableNativeDependencyManifestTargetStageLease, paths: tuple[Path, ...]) -> str:
    if any(_paths_overlap(lease.staging_root, path) for path in paths):
        raise _InvalidTargetStaging
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(os.fspath(lease.staging_root), flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != _STAGING_ROOT_MODE
            or metadata.st_nlink <= 0
            or os.get_inheritable(descriptor)
            or not _directory_empty(descriptor)
        ):
            raise _InvalidTargetStaging
        lease._root_descriptor = descriptor
        lease._root_metadata = _metadata_signature(metadata)
        return _root_context_digest(metadata)
    except BaseException:
        if descriptor is not None and lease._root_descriptor != descriptor:
            _close_descriptor(descriptor)
        raise


def _new_stage_name() -> str:
    token = secrets.token_hex(16)
    if type(token) is not str or len(token) != 32 or any(char not in "0123456789abcdef" for char in token):
        raise _InvalidTargetStaging
    return ".ordomata-manifest-target-" + token


def _entry_metadata(root_descriptor: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError:
        raise _InvalidTargetStaging from None


def _digest_descriptor(descriptor: int, content_bytes: int) -> str:
    digest = _BUILTIN_SHA256()
    offset = 0
    while offset < content_bytes:
        try:
            chunk = os.pread(descriptor, min(_READ_CHUNK_BYTES, content_bytes - offset), offset)
        except (BlockingIOError, InterruptedError, OSError):
            raise _InvalidTargetStaging from None
        if not chunk or len(chunk) > content_bytes - offset:
            raise _InvalidTargetStaging
        digest.update(chunk)
        offset += len(chunk)
    return _DIGEST_PREFIX + digest.hexdigest()


def _write_all(descriptor: int, chunks: tuple[bytes, ...]) -> None:
    for chunk in chunks:
        offset = 0
        while offset < len(chunk):
            try:
                written = os.write(descriptor, chunk[offset:])
            except (BlockingIOError, InterruptedError, OSError):
                raise _InvalidTargetStaging from None
            if written <= 0:
                raise _InvalidTargetStaging
            offset += written


def _capture_target(descriptor: int, metadata: os.stat_result, measured: _MeasuredTarget, captures: list[_CapturedTarget], manifest_ref_by_path: dict[Path, str]) -> None:
    if (
        type(measured) is not _FIXED_MEASURED_TARGET_TYPE
        or _metadata_signature(metadata) != measured.metadata
        or measured.path not in manifest_ref_by_path
        or len(captures) >= 80
    ):
        raise _InvalidTargetStaging
    chunks: list[bytes] = []
    remaining = measured.content_bytes
    offset = 0
    digest = _BUILTIN_SHA256()
    while remaining:
        try:
            chunk = os.pread(descriptor, min(_READ_CHUNK_BYTES, remaining), offset)
        except (BlockingIOError, InterruptedError, OSError):
            raise _InvalidTargetStaging from None
        if not chunk or len(chunk) > remaining:
            raise _InvalidTargetStaging
        chunks.append(chunk)
        digest.update(chunk)
        remaining -= len(chunk)
        offset += len(chunk)
    if _DIGEST_PREFIX + digest.hexdigest() != measured.content_digest:
        raise _InvalidTargetStaging
    public = _BUILTIN_PUBLIC_MEASUREMENT(measured, manifest_target_ref=manifest_ref_by_path[measured.path])
    captures.append(_CapturedTarget(measurement=public, content=tuple(chunks)))


def _staged_identity_ref(metadata: os.stat_result) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "kind": "repository_executable_native_dependency_manifest_target_staged_file_identity",
            "schema_version": _FIXED_SCHEMA_VERSION,
        }
    )


def _staged_metadata_digest(metadata: os.stat_result, identity_ref: str) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "change_time_ns": metadata.st_ctime_ns,
            "filesystem_identity_ref": identity_ref,
            "group_id": metadata.st_gid,
            "kind": "repository_executable_native_dependency_manifest_target_staged_file_metadata",
            "link_count": metadata.st_nlink,
            "mode": metadata.st_mode,
            "modified_time_ns": metadata.st_mtime_ns,
            "owner_id": metadata.st_uid,
            "schema_version": _FIXED_SCHEMA_VERSION,
            "size_bytes": metadata.st_size,
        }
    )


def _stage_file_ref(capture: _CapturedTarget, staged_identity_ref: str, staged_metadata: str, root_context: str) -> str:
    measurement = capture.measurement
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "content_digest": measurement.content_digest,
            "kind": "repository_executable_native_dependency_manifest_target_staged_file_ref",
            "manifest_target_ref": measurement.manifest_target_ref,
            "schema_version": _FIXED_SCHEMA_VERSION,
            "source_filesystem_identity_ref": measurement.filesystem_identity_ref,
            "source_metadata_digest": measurement.metadata_digest,
            "staged_filesystem_identity_ref": staged_identity_ref,
            "staged_metadata_digest": staged_metadata,
            "target_measurement_ref": measurement.measurement_ref,
            "target_staging_context_digest": root_context,
        }
    )


def _stage_capture(lease: RepositoryExecutableNativeDependencyManifestTargetStageLease, capture: _CapturedTarget, root_context: str) -> None:
    root_descriptor = lease._root_descriptor
    if root_descriptor is None:
        raise _InvalidTargetStaging
    writer: int | None = None
    reader: int | None = None
    name: str | None = None
    unlinked = False
    try:
        for _ in range(_STAGE_NAME_ATTEMPTS):
            candidate = _new_stage_name()
            if _entry_metadata(root_descriptor, candidate) is not None:
                continue
            try:
                writer = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                    dir_fd=root_descriptor,
                )
            except FileExistsError:
                continue
            except OSError:
                raise _InvalidTargetStaging from None
            name = candidate
            break
        if writer is None or name is None:
            raise _InvalidTargetStaging
        os.fchmod(writer, 0o600)
        writer_metadata = os.fstat(writer)
        if (
            not stat.S_ISREG(writer_metadata.st_mode)
            or writer_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(writer_metadata.st_mode) != 0o600
            or writer_metadata.st_nlink != 1
            or writer_metadata.st_size != 0
            or os.get_inheritable(writer)
        ):
            raise _InvalidTargetStaging
        entry = _entry_metadata(root_descriptor, name)
        if entry is None or stat.S_ISLNK(entry.st_mode) or (entry.st_dev, entry.st_ino) != (writer_metadata.st_dev, writer_metadata.st_ino):
            raise _InvalidTargetStaging
        reader = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_descriptor)
        reader_metadata = os.fstat(reader)
        if (
            _metadata_signature(reader_metadata) != _metadata_signature(writer_metadata)
            or os.get_inheritable(reader)
            or fcntl.fcntl(reader, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
        ):
            raise _InvalidTargetStaging
        os.unlink(name, dir_fd=root_descriptor)
        unlinked = True
        if (
            _entry_metadata(root_descriptor, name) is not None
            or os.fstat(writer).st_nlink != 0
            or os.fstat(reader).st_nlink != 0
        ):
            raise _CleanupUncertain
        os.fsync(root_descriptor)
        _write_all(writer, capture.content)
        os.fchmod(writer, _STAGED_FILE_MODE)
        os.fsync(writer)
        content_bytes = sum(len(item) for item in capture.content)
        if (
            content_bytes != capture.measurement.content_bytes
            or _digest_descriptor(reader, content_bytes) != capture.measurement.content_digest
        ):
            raise _InvalidTargetStaging
        final_metadata = os.fstat(reader)
        if (
            not stat.S_ISREG(final_metadata.st_mode)
            or final_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(final_metadata.st_mode) != _STAGED_FILE_MODE
            or final_metadata.st_nlink != 0
            or final_metadata.st_size != content_bytes
            or _metadata_signature(os.fstat(writer)) != _metadata_signature(final_metadata)
        ):
            raise _InvalidTargetStaging
        if not _close_descriptor(writer):
            # Keep the descriptor in local cleanup scope for the exception
            # path; clearing it here would make a failed close untrackable.
            raise _CleanupUncertain
        writer = None
        identity_ref = _staged_identity_ref(final_metadata)
        metadata_digest = _staged_metadata_digest(final_metadata, identity_ref)
        staged = _FIXED_STAGED_FILE_TYPE(
            kind=_FIXED_FILE_KIND,
            manifest_target_ref=capture.measurement.manifest_target_ref,
            source_filesystem_identity_ref=capture.measurement.filesystem_identity_ref,
            source_metadata_digest=capture.measurement.metadata_digest,
            target_measurement_ref=capture.measurement.measurement_ref,
            staged_file_ref=_stage_file_ref(capture, identity_ref, metadata_digest, root_context),
            staged_filesystem_identity_ref=identity_ref,
            staged_metadata_digest=metadata_digest,
            content_digest=capture.measurement.content_digest,
            content_bytes=content_bytes,
        )
        _staged_file_projection(staged)
        lease._files = lease._files + (_RetainedTarget(staged, reader, _metadata_signature(final_metadata)),)
        reader = None
    except BaseException:
        if not unlinked and name is not None:
            try:
                current = _entry_metadata(root_descriptor, name)
                if current is not None:
                    os.unlink(name, dir_fd=root_descriptor)
                    os.fsync(root_descriptor)
            except Exception:
                lease._state = "cleanup_unverifiable"
        for descriptor in (writer, reader):
            if descriptor is not None and not _close_descriptor(descriptor):
                lease._state = "cleanup_unverifiable"
        raise


def _close_root(lease: RepositoryExecutableNativeDependencyManifestTargetStageLease) -> bool:
    descriptor = lease._root_descriptor
    if descriptor is None:
        return True
    if not _close_descriptor(descriptor):
        return False
    lease._root_descriptor = None
    lease._root_metadata = None
    return True


def _abort(lease: RepositoryExecutableNativeDependencyManifestTargetStageLease) -> bool:
    if lease._root_descriptor is not None:
        try:
            if not _directory_empty(lease._root_descriptor):
                lease._state = "cleanup_unverifiable"
                return False
        except _InvalidTargetStaging:
            lease._state = "cleanup_unverifiable"
            return False
    success = True
    for retained in lease._files:
        success = _close_descriptor(retained.descriptor) and success
    lease._files = ()
    success = _close_root(lease) and success
    if not success:
        lease._state = "cleanup_unverifiable"
    return success


def _store_cleanup(lease: RepositoryExecutableNativeDependencyManifestTargetStageLease, receipt: RepositoryExecutableNativeDependencyManifestTargetStageCleanupReceipt) -> None:
    canonical = _cleanup_receipt_projection(receipt)
    lease._cleanup_receipt = receipt
    lease._cleanup_anchor = receipt
    lease._cleanup_digest_anchor = _BUILTIN_CANONICAL_DIGEST(canonical)


def cleanup_repository_executable_native_dependency_manifest_target_stage(lease: RepositoryExecutableNativeDependencyManifestTargetStageLease) -> RepositoryExecutableNativeDependencyManifestTargetStageCleanupReceipt:
    """Release a one-shot target staging lease without attempting secure erasure."""

    if type(lease) is not _FIXED_STAGE_LEASE_TYPE or lease._owner_pid != os.getpid():
        raise _FIXED_VALIDATION_ERROR(_INVALID_MESSAGE)
    if lease._state == "cleaned":
        if lease._cleanup_receipt is None or lease._cleanup_receipt is not lease._cleanup_anchor:
            raise _FIXED_VALIDATION_ERROR(_INVALID_MESSAGE)
        try:
            if lease._cleanup_digest_anchor != _BUILTIN_CANONICAL_DIGEST(_cleanup_receipt_projection(lease._cleanup_receipt)):
                raise _InvalidTargetStaging
        except Exception:
            raise _FIXED_VALIDATION_ERROR(_INVALID_MESSAGE) from None
        return lease._cleanup_receipt
    if lease._state == "cleanup_unverifiable":
        receipt = _FIXED_CLEANUP_TYPE(
            kind=_FIXED_CLEANUP_KIND,
            schema_version=_FIXED_SCHEMA_VERSION,
            outcome="unverifiable",
            target_staging_receipt_digest=lease._receipt_digest_anchor,
            owned_namespace_absence_verified=False,
            descriptor_release_complete=False,
        )
        _store_cleanup(lease, receipt)
        raise ConfigurationError(_CLEANUP_UNCERTAIN_MESSAGE)
    if lease._state not in {"new", "active"}:
        raise _FIXED_VALIDATION_ERROR(_INVALID_MESSAGE)
    success = _abort(lease)
    if not success:
        receipt = _FIXED_CLEANUP_TYPE(
            kind=_FIXED_CLEANUP_KIND,
            schema_version=_FIXED_SCHEMA_VERSION,
            outcome="unverifiable",
            target_staging_receipt_digest=lease._receipt_digest_anchor,
            owned_namespace_absence_verified=False,
            descriptor_release_complete=False,
        )
        _store_cleanup(lease, receipt)
        raise ConfigurationError(_CLEANUP_UNCERTAIN_MESSAGE)
    lease._state = "cleaned"
    receipt = _FIXED_CLEANUP_TYPE(
        kind=_FIXED_CLEANUP_KIND,
        schema_version=_FIXED_SCHEMA_VERSION,
        outcome="released",
        target_staging_receipt_digest=lease._receipt_digest_anchor,
        owned_namespace_absence_verified=True,
        descriptor_release_complete=True,
    )
    _store_cleanup(lease, receipt)
    return receipt


def stage_repository_executable_native_dependency_manifest_target_bytes(
    expected_targets: RepositoryExecutableNativeDependencyManifestTargetsReceipt,
    *,
    expected_manifest: RepositoryExecutableNativeDependencyManifestReceipt,
    expected_requirements: RepositoryExecutableNativeDependencyRequirementsReceipt,
    expected_runtime: RepositoryExecutableRuntimeManifestReceipt,
    expected_staging: RepositoryExecutableStagingReceipt,
    executable_lease: RepositoryExecutableStageLease,
    expected_non_absolute_dependency_manifest: tuple[RepositoryExecutableNativeDependencyManifestEntry, ...],
    lease: RepositoryExecutableNativeDependencyManifestTargetStageLease,
) -> RepositoryExecutableNativeDependencyManifestTargetStagingReceipt:
    """Freshly reproduce and detach exact manifest-target bytes into a Class 1 lease.

    This is non-authorizing local staging only.  The caller must explicitly
    supply an empty, ``0700`` directory outside every manifest target path.
    """

    validated = False
    try:
        lease = _require_new_lease(lease)
        validated = True
        if (
            type(expected_targets) is not _FIXED_TARGETS_TYPE
            or type(expected_manifest) is not _FIXED_MANIFEST_TYPE
            or type(expected_requirements) is not _FIXED_REQUIREMENTS_TYPE
            or type(expected_runtime) is not _FIXED_RUNTIME_TYPE
            or type(expected_staging) is not _FIXED_STAGING_TYPE
            or type(executable_lease) is not _FIXED_EXECUTABLE_LEASE_TYPE
            or type(expected_non_absolute_dependency_manifest) is not tuple
        ):
            raise _InvalidTargetStaging
        expected_canonical = _BUILTIN_TARGETS_PROJECTION(expected_targets)
        manifest_canonical = _BUILTIN_MANIFEST_PROJECTION(expected_manifest)
        requirements_canonical = _BUILTIN_REQUIREMENTS_PROJECTION(expected_requirements)
        runtime_canonical = _BUILTIN_RUNTIME_PROJECTION(expected_runtime)
        staging_canonical = _BUILTIN_STAGING_PROJECTION(expected_staging)
        first = _BUILTIN_INSPECT_TARGETS(
            expected_manifest,
            expected_requirements=expected_requirements,
            expected_runtime=expected_runtime,
            expected_staging=expected_staging,
            lease=executable_lease,
            expected_non_absolute_dependency_manifest=expected_non_absolute_dependency_manifest,
        )
        if _BUILTIN_TARGETS_PROJECTION(first) != expected_canonical:
            raise _InvalidTargetStaging
        paths: list[Path] = []
        manifest_ref_by_path: dict[Path, str] = {}
        for entry in expected_non_absolute_dependency_manifest:
            if type(entry) is not _FIXED_MANIFEST_ENTRY_TYPE or type(entry.target_path) is not _CONCRETE_PATH_TYPE:
                raise _InvalidTargetStaging
            ref = _BUILTIN_MANIFEST_TARGET_REF(entry.target_path)
            existing = manifest_ref_by_path.get(entry.target_path)
            if existing is None:
                paths.append(entry.target_path)
                manifest_ref_by_path[entry.target_path] = ref
            elif existing != ref:
                raise _InvalidTargetStaging
        if tuple(item.manifest_target_ref for item in expected_targets.measurements) != tuple(manifest_ref_by_path[path] for path in paths):
            raise _InvalidTargetStaging
        captures: list[_CapturedTarget] = []

        def consumer(descriptor: int, metadata: os.stat_result, measured: _MeasuredTarget) -> None:
            _capture_target(descriptor, metadata, measured, captures, manifest_ref_by_path)

        action_measured = _BUILTIN_MEASURE_WITH_CONSUMER(tuple(paths), consumer)
        action_public = tuple(
            _BUILTIN_PUBLIC_MEASUREMENT(item, manifest_target_ref=manifest_ref_by_path[item.path])
            for item in action_measured
        )
        if (
            action_public != expected_targets.measurements
            or len(captures) != len(action_public)
            or any(capture.measurement != measurement for capture, measurement in zip(captures, action_public, strict=True))
            or sum(measurement.content_bytes for measurement in action_public) != expected_targets.total_measured_bytes
        ):
            raise _InvalidTargetStaging
        action_digest = _BUILTIN_CANONICAL_DIGEST(
            {
                "kind": "repository_executable_native_dependency_manifest_target_staging_action_measurements",
                "measurements": [item.to_canonical() for item in action_public],
                "schema_version": _FIXED_SCHEMA_VERSION,
            }
        )
        if action_public:
            root_context = _prepare_root(lease, tuple(paths))
            for capture in captures:
                _stage_capture(lease, capture, root_context)
            if lease._root_descriptor is None or not _directory_empty(lease._root_descriptor):
                raise _InvalidTargetStaging
            os.fsync(lease._root_descriptor)
        else:
            root_context = _BUILTIN_CANONICAL_DIGEST(
                {
                    "kind": "repository_executable_native_dependency_manifest_target_staging_context",
                    "schema_version": _FIXED_SCHEMA_VERSION,
                    "staging_root_used": False,
                    "staging_scope": _FIXED_STAGING_SCOPE,
                }
            )
        post = _BUILTIN_INSPECT_TARGETS(
            expected_manifest,
            expected_requirements=expected_requirements,
            expected_runtime=expected_runtime,
            expected_staging=expected_staging,
            lease=executable_lease,
            expected_non_absolute_dependency_manifest=expected_non_absolute_dependency_manifest,
        )
        post_canonical = _BUILTIN_TARGETS_PROJECTION(post)
        if post_canonical != expected_canonical:
            raise _InvalidTargetStaging
        if lease._root_descriptor is not None and not _close_root(lease):
            raise _CleanupUncertain
        files = tuple(item.staged_file for item in lease._files)
        receipt = _FIXED_RECEIPT_TYPE(
            kind=_FIXED_RECEIPT_KIND,
            schema_version=_FIXED_SCHEMA_VERSION,
            measurement_source=_FIXED_MEASUREMENT_SOURCE,
            staging_source=_FIXED_STAGING_SOURCE,
            staging_scope=_FIXED_STAGING_SCOPE,
            native_dependency_manifest_targets_receipt_digest=_BUILTIN_CANONICAL_DIGEST(expected_canonical),
            native_dependency_manifest_receipt_digest=_BUILTIN_CANONICAL_DIGEST(manifest_canonical),
            native_dependency_requirements_receipt_digest=_BUILTIN_CANONICAL_DIGEST(requirements_canonical),
            runtime_manifest_receipt_digest=_BUILTIN_CANONICAL_DIGEST(runtime_canonical),
            staging_receipt_digest=_BUILTIN_CANONICAL_DIGEST(staging_canonical),
            registration_digest=expected_targets.registration_digest,
            repository_ref=expected_targets.repository_ref,
            verification_commands_digest=expected_targets.verification_commands_digest,
            resolution_context_digest=expected_targets.resolution_context_digest,
            source_staging_context_digest=expected_targets.staging_context_digest,
            manifest_context_digest=expected_targets.manifest_context_digest,
            action_measurements_digest=action_digest,
            post_stage_targets_receipt_digest=_BUILTIN_CANONICAL_DIGEST(post_canonical),
            target_staging_context_digest=root_context,
            staging_root_used=bool(action_public),
            staged_files=files,
            unique_target_count=len(files),
            total_staged_bytes=sum(item.content_bytes for item in files),
        )
        canonical = _staging_receipt_projection(receipt)
        lease._receipt = receipt
        lease._receipt_anchor = receipt
        lease._receipt_digest_anchor = _BUILTIN_CANONICAL_DIGEST(canonical)
        lease._files_anchor = lease._files
        lease._state = "active"
        return receipt
    except (KeyboardInterrupt, SystemExit):
        raise
    except _CleanupUncertain:
        if validated:
            _abort(lease)
        raise ConfigurationError(_CLEANUP_UNCERTAIN_MESSAGE) from None
    except Exception:
        if validated and not _abort(lease):
            raise ConfigurationError(_CLEANUP_UNCERTAIN_MESSAGE) from None
        raise _FIXED_VALIDATION_ERROR(_INVALID_MESSAGE) from None


__all__ = [
    "MEASUREMENT_SOURCE",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_STAGE_CLEANUP_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_STAGED_FILE_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_STAGING_EVIDENCE_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_STAGING_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_STAGING_SCHEMA_VERSION",
    "STAGING_SCOPE",
    "STAGING_SOURCE",
    "RepositoryExecutableNativeDependencyManifestTargetStageCleanupReceipt",
    "RepositoryExecutableNativeDependencyManifestTargetStageLease",
    "RepositoryExecutableNativeDependencyManifestTargetStagedFile",
    "RepositoryExecutableNativeDependencyManifestTargetStagingReceipt",
    "cleanup_repository_executable_native_dependency_manifest_target_stage",
    "stage_repository_executable_native_dependency_manifest_target_bytes",
]
