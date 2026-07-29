"""Ephemeral descriptor staging for freshly remeasured executable bytes.

The boundary in this module is library-only and non-authorizing.  It compares
an exact typed preflight resolution receipt with a fresh action-boundary
measurement, copies the bytes observed through those pinned source
descriptors, and retains only read-only, close-on-exec descriptors for
namespace-detached copies.  It never executes a command or makes the copies
eligible for execution.

"Controller sealed" has a deliberately narrow meaning here: controller
write descriptors were closed, the retained descriptors were opened read-only,
and their names were absent at the final observation.  Portable POSIX does not
prove kernel immutability, exclusion of another process with the same uid, or
absence of an external writable descriptor.  Those properties remain explicit
nonclaims.
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

from .authorization import canonical_digest
from .errors import ConfigurationError, ValidationError
from .repository_executable_resolution import (
    MEASUREMENT_SOURCE,
    REPOSITORY_EXECUTABLE_RESOLUTION_SCOPE,
    RepositoryExecutableResolutionReceipt,
    _InvalidResolution,
    _MeasuredFile,
    _absolute_path_parts,
    _metadata_signature,
    _open_absolute_directory,
    _receipt_projection,
    _resolve_repository_executables,
)
from .repository_registration import (
    RepositoryRegistration,
    _baseline_command_results_projection,
    _executable_toolchain_identities_projection,
    _registration_canonical_projection,
    revalidate_repository_registration,
)


REPOSITORY_EXECUTABLE_STAGING_SCHEMA_VERSION = 1
REPOSITORY_EXECUTABLE_STAGING_KIND = "repository_executable_staging"
REPOSITORY_EXECUTABLE_STAGING_EVIDENCE_KIND = (
    "repository_executable_staging_validation"
)
REPOSITORY_EXECUTABLE_STAGED_FILE_KIND = (
    "repository_executable_staged_file"
)
REPOSITORY_EXECUTABLE_STAGE_BINDING_KIND = (
    "repository_executable_stage_binding"
)
REPOSITORY_EXECUTABLE_STAGE_CLEANUP_KIND = (
    "repository_executable_stage_cleanup"
)
STAGING_SOURCE = "controller_copied"
STAGING_SCOPE = "posix_unlinked_readonly_v1"

_INVALID_MESSAGE = "repository executable staging is invalid"
_CLEANUP_UNCERTAIN_MESSAGE = (
    "repository executable staging cleanup is uncertain"
)
_COPY_ERROR_MESSAGE = "repository executable staging lease cannot be copied"
_COMMAND_KINDS = ("format", "lint", "type_check", "test", "build")
_CONCRETE_PATH_TYPE = type(Path())
_DIGEST_PREFIX = "sha256:"
_MAX_EXECUTABLE_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_EXECUTABLE_BYTES = 256 * 1024 * 1024
_MAX_UNIQUE_FILES = 80
_READ_CHUNK_BYTES = 1024 * 1024
_STAGED_FILE_MODE = 0o400
_STAGING_ROOT_MODE = 0o700
_STAGE_NAME_ATTEMPTS = 8
_IDENTIFIER_PATTERN = re.compile(r"[a-z][a-z0-9_.-]{0,119}\Z")

_LeaseState = Literal[
    "new",
    "active",
    "cleaned",
    "cleanup_unverifiable",
]
_CleanupOutcome = Literal[
    "removed",
    "already_absent_verified",
    "unverifiable",
]

# Capture the shipped implementations.  Public methods on transparent
# dataclasses and module attributes remain patchable and are not trusted as
# canonicalization or revalidation boundaries here.
_BUILTIN_REVALIDATE_REPOSITORY_REGISTRATION = (
    revalidate_repository_registration
)
_BUILTIN_REGISTRATION_CANONICAL_PROJECTION = (
    _registration_canonical_projection
)
_BUILTIN_BASELINE_PROJECTION = _baseline_command_results_projection
_BUILTIN_TOOLCHAIN_PROJECTION = (
    _executable_toolchain_identities_projection
)
_BUILTIN_RESOLUTION_PROJECTION = _receipt_projection
_BUILTIN_RESOLVE_REPOSITORY_EXECUTABLES = (
    _resolve_repository_executables
)


class _InvalidStaging(ValueError):
    """Internal invalid-input sentinel with no public details."""


class _CleanupUncertain(ConfigurationError):
    """Internal marker for an unproved local staging outcome."""


@dataclass(frozen=True, slots=True)
class RepositoryExecutableStagedFile:
    """One unique source file and its namespace-detached staged copy."""

    kind: str
    source_filesystem_identity_ref: str = field(repr=False)
    source_metadata_digest: str = field(repr=False)
    staged_file_ref: str = field(repr=False)
    staged_filesystem_identity_ref: str = field(repr=False)
    staged_metadata_digest: str = field(repr=False)
    content_digest: str = field(repr=False)
    content_bytes: int

    def to_canonical(self) -> dict[str, Any]:
        return _staged_file_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableStageBinding:
    """One command declaration bound to one staged file reference."""

    kind: str
    command_kind: str
    command_id: str = field(repr=False)
    command_digest: str = field(repr=False)
    declared_executable_ref: str = field(repr=False)
    resolved_executable_ref: str = field(repr=False)
    staged_file_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _stage_binding_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableStagingReceipt:
    """Historical receipt for a successfully established process-local lease."""

    kind: str
    schema_version: int
    measurement_source: str
    resolution_scope: str
    staging_source: str
    staging_scope: str
    registration_digest: str = field(repr=False)
    repository_ref: str = field(repr=False)
    verification_commands_digest: str = field(repr=False)
    baseline_command_results_digest: str = field(repr=False)
    executable_toolchain_identities_digest: str = field(repr=False)
    resolution_context_digest: str = field(repr=False)
    expected_resolution_receipt_digest: str = field(repr=False)
    action_resolution_receipt_digest: str = field(repr=False)
    post_stage_resolution_receipt_digest: str = field(repr=False)
    staging_context_digest: str = field(repr=False)
    staged_files: tuple[RepositoryExecutableStagedFile, ...] = field(
        repr=False
    )
    bindings: tuple[RepositoryExecutableStageBinding, ...] = field(
        repr=False
    )
    unique_file_count: int
    total_staged_bytes: int

    def to_canonical(self) -> dict[str, Any]:
        return _staging_receipt_projection(self)

    @property
    def receipt_digest(self) -> str:
        return canonical_digest(_staging_receipt_projection(self))

    def to_evidence(self) -> dict[str, Any]:
        return _staging_evidence_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableStageCleanupReceipt:
    """Bounded cleanup result for controller-owned staging names and FDs."""

    kind: str
    schema_version: int
    outcome: _CleanupOutcome
    staging_receipt_digest: str | None = field(repr=False)
    owned_namespace_absence_verified: bool
    descriptor_release_complete: bool
    staging_root_identity_verified: bool
    staging_root_metadata_restored: bool
    secure_erasure_verified: bool

    def to_canonical(self) -> dict[str, Any]:
        return _cleanup_receipt_projection(self)


@dataclass(frozen=True, slots=True)
class _CapturedExecutable:
    source_filesystem_identity_ref: str = field(repr=False)
    source_metadata: tuple[int, ...] = field(repr=False)
    source_metadata_digest: str = field(repr=False)
    content_digest: str = field(repr=False)
    content: tuple[bytes, ...] = field(repr=False)


@dataclass(frozen=True, slots=True)
class _RetainedStagedFile:
    staged_file: RepositoryExecutableStagedFile = field(repr=False)
    descriptor: int = field(repr=False)
    metadata: tuple[int, ...] = field(repr=False)


@dataclass(slots=True)
class RepositoryExecutableStageLease:
    """Caller-scoped, one-shot lease for namespace-detached byte copies.

    Constructing a lease performs no filesystem access.  The staging function
    validates and opens ``staging_root`` only after the expected resolution has
    matched a fresh action-boundary measurement.
    """

    staging_root: Path = field(repr=False)
    _receipt: RepositoryExecutableStagingReceipt | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _cleanup_receipt: RepositoryExecutableStageCleanupReceipt | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _receipt_digest_anchor: str | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _receipt_staged_file_refs_anchor: tuple[str, ...] = field(
        default=(),
        init=False,
        repr=False,
    )
    _cleanup_receipt_digest_anchor: str | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _state: _LeaseState = field(default="new", init=False, repr=False)
    _owner_pid: int = field(
        default_factory=os.getpid,
        init=False,
        repr=False,
    )
    _files: tuple[_RetainedStagedFile, ...] = field(
        default=(),
        init=False,
        repr=False,
    )
    _root_descriptor: int | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _root_metadata: tuple[int, ...] | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _pending_name: str | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _pending_identity: tuple[int, int] | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _pending_descriptors: tuple[int, ...] = field(
        default=(),
        init=False,
        repr=False,
    )
    _descriptor_release_unverifiable: bool = field(
        default=False,
        init=False,
        repr=False,
    )

    @property
    def state(self) -> str:
        return self._state

    @property
    def receipt(self) -> RepositoryExecutableStagingReceipt | None:
        return self._receipt

    @property
    def cleanup_receipt(
        self,
    ) -> RepositoryExecutableStageCleanupReceipt | None:
        return self._cleanup_receipt

    def cleanup(self) -> RepositoryExecutableStageCleanupReceipt:
        return cleanup_repository_executable_stage(self)

    def close(self) -> RepositoryExecutableStageCleanupReceipt:
        return cleanup_repository_executable_stage(self)

    def __enter__(self) -> RepositoryExecutableStageLease:
        if self._state != "active" or self._owner_pid != os.getpid():
            raise ValidationError(_INVALID_MESSAGE)
        return self

    def __exit__(self, *unused: object) -> None:
        cleanup_repository_executable_stage(self)

    def __copy__(self) -> None:
        raise TypeError(_COPY_ERROR_MESSAGE)

    def __deepcopy__(self, memo: object) -> None:
        raise TypeError(_COPY_ERROR_MESSAGE)

    def __reduce__(self) -> None:
        raise TypeError(_COPY_ERROR_MESSAGE)

    def __reduce_ex__(self, protocol: int) -> None:
        raise TypeError(_COPY_ERROR_MESSAGE)


def _is_digest(value: Any) -> bool:
    return bool(
        type(value) is str
        and value.startswith(_DIGEST_PREFIX)
        and len(value) == len(_DIGEST_PREFIX) + 64
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _staged_file_projection(
    staged_file: RepositoryExecutableStagedFile,
) -> dict[str, Any]:
    if (
        type(staged_file) is not RepositoryExecutableStagedFile
        or staged_file.kind != REPOSITORY_EXECUTABLE_STAGED_FILE_KIND
        or not _is_digest(staged_file.source_filesystem_identity_ref)
        or not _is_digest(staged_file.source_metadata_digest)
        or not _is_digest(staged_file.staged_file_ref)
        or not _is_digest(staged_file.staged_filesystem_identity_ref)
        or not _is_digest(staged_file.staged_metadata_digest)
        or not _is_digest(staged_file.content_digest)
        or type(staged_file.content_bytes) is not int
        or not 0 <= staged_file.content_bytes <= _MAX_EXECUTABLE_BYTES
    ):
        raise _InvalidStaging
    return {
        "content_bytes": staged_file.content_bytes,
        "content_digest": staged_file.content_digest,
        "kind": staged_file.kind,
        "source_filesystem_identity_ref": (
            staged_file.source_filesystem_identity_ref
        ),
        "source_metadata_digest": staged_file.source_metadata_digest,
        "staged_file_ref": staged_file.staged_file_ref,
        "staged_filesystem_identity_ref": (
            staged_file.staged_filesystem_identity_ref
        ),
        "staged_metadata_digest": staged_file.staged_metadata_digest,
    }


def _stage_binding_projection(
    binding: RepositoryExecutableStageBinding,
) -> dict[str, Any]:
    if (
        type(binding) is not RepositoryExecutableStageBinding
        or binding.kind != REPOSITORY_EXECUTABLE_STAGE_BINDING_KIND
        or binding.command_kind not in _COMMAND_KINDS
        or type(binding.command_id) is not str
        or _IDENTIFIER_PATTERN.fullmatch(binding.command_id) is None
        or not _is_digest(binding.command_digest)
        or not _is_digest(binding.declared_executable_ref)
        or not _is_digest(binding.resolved_executable_ref)
        or not _is_digest(binding.staged_file_ref)
    ):
        raise _InvalidStaging
    return {
        "command_digest": binding.command_digest,
        "command_id": binding.command_id,
        "command_kind": binding.command_kind,
        "declared_executable_ref": binding.declared_executable_ref,
        "kind": binding.kind,
        "resolved_executable_ref": binding.resolved_executable_ref,
        "staged_file_ref": binding.staged_file_ref,
    }


def _staging_receipt_projection(
    receipt: RepositoryExecutableStagingReceipt,
) -> dict[str, Any]:
    digest_fields = (
        receipt.registration_digest,
        receipt.repository_ref,
        receipt.verification_commands_digest,
        receipt.baseline_command_results_digest,
        receipt.executable_toolchain_identities_digest,
        receipt.resolution_context_digest,
        receipt.expected_resolution_receipt_digest,
        receipt.action_resolution_receipt_digest,
        receipt.post_stage_resolution_receipt_digest,
        receipt.staging_context_digest,
    )
    if (
        type(receipt) is not RepositoryExecutableStagingReceipt
        or receipt.kind != REPOSITORY_EXECUTABLE_STAGING_KIND
        or type(receipt.schema_version) is not int
        or receipt.schema_version
        != REPOSITORY_EXECUTABLE_STAGING_SCHEMA_VERSION
        or receipt.measurement_source != MEASUREMENT_SOURCE
        or receipt.resolution_scope
        != REPOSITORY_EXECUTABLE_RESOLUTION_SCOPE
        or receipt.staging_source != STAGING_SOURCE
        or receipt.staging_scope != STAGING_SCOPE
        or not all(_is_digest(value) for value in digest_fields)
        or receipt.expected_resolution_receipt_digest
        != receipt.action_resolution_receipt_digest
        or receipt.action_resolution_receipt_digest
        != receipt.post_stage_resolution_receipt_digest
        or type(receipt.staged_files) is not tuple
        or not 1 <= len(receipt.staged_files) <= _MAX_UNIQUE_FILES
        or type(receipt.bindings) is not tuple
        or not 1 <= len(receipt.bindings) <= _MAX_UNIQUE_FILES
        or type(receipt.unique_file_count) is not int
        or receipt.unique_file_count != len(receipt.staged_files)
        or type(receipt.total_staged_bytes) is not int
        or not 0
        <= receipt.total_staged_bytes
        <= _MAX_TOTAL_EXECUTABLE_BYTES
    ):
        raise _InvalidStaging
    staged_files = [
        _staged_file_projection(value) for value in receipt.staged_files
    ]
    bindings = [
        _stage_binding_projection(value) for value in receipt.bindings
    ]
    file_by_ref: dict[str, RepositoryExecutableStagedFile] = {}
    source_refs: set[str] = set()
    total = 0
    for value in receipt.staged_files:
        if (
            value.staged_file_ref in file_by_ref
            or value.source_filesystem_identity_ref in source_refs
        ):
            raise _InvalidStaging
        file_by_ref[value.staged_file_ref] = value
        source_refs.add(value.source_filesystem_identity_ref)
        total += value.content_bytes
    command_ids: set[str] = set()
    prior_kind_index = -1
    bound_refs: set[str] = set()
    for binding in receipt.bindings:
        kind_index = _COMMAND_KINDS.index(binding.command_kind)
        if (
            kind_index < prior_kind_index
            or binding.command_id in command_ids
            or binding.staged_file_ref not in file_by_ref
        ):
            raise _InvalidStaging
        prior_kind_index = kind_index
        command_ids.add(binding.command_id)
        bound_refs.add(binding.staged_file_ref)
    if (
        total != receipt.total_staged_bytes
        or bound_refs != set(file_by_ref)
    ):
        raise _InvalidStaging
    return {
        "action_resolution_receipt_digest": (
            receipt.action_resolution_receipt_digest
        ),
        "baseline_command_results_digest": (
            receipt.baseline_command_results_digest
        ),
        "bindings": bindings,
        "executable_toolchain_identities_digest": (
            receipt.executable_toolchain_identities_digest
        ),
        "expected_resolution_receipt_digest": (
            receipt.expected_resolution_receipt_digest
        ),
        "kind": receipt.kind,
        "measurement_source": receipt.measurement_source,
        "post_stage_resolution_receipt_digest": (
            receipt.post_stage_resolution_receipt_digest
        ),
        "registration_digest": receipt.registration_digest,
        "repository_ref": receipt.repository_ref,
        "resolution_context_digest": receipt.resolution_context_digest,
        "resolution_scope": receipt.resolution_scope,
        "schema_version": receipt.schema_version,
        "staged_files": staged_files,
        "staging_context_digest": receipt.staging_context_digest,
        "staging_scope": receipt.staging_scope,
        "staging_source": receipt.staging_source,
        "total_staged_bytes": receipt.total_staged_bytes,
        "unique_file_count": receipt.unique_file_count,
        "verification_commands_digest": (
            receipt.verification_commands_digest
        ),
    }


def _staging_evidence_projection(
    receipt: RepositoryExecutableStagingReceipt,
) -> dict[str, Any]:
    canonical = _staging_receipt_projection(receipt)
    return {
        "acl_privacy_verified": False,
        "action_boundary_remeasurement_complete": True,
        "action_receipt_issued": False,
        "atomic_snapshot_verified": False,
        "authority_granted": False,
        "authorization_verified": False,
        "baseline_execution_correspondence_verified": False,
        "billing_eligible": False,
        "capacity_eligible": False,
        "circuit_eligible": False,
        "configuration_coverage_verified": False,
        "controller_write_descriptors_closed": True,
        "crash_cleanup_verified": False,
        "current_lease_activity_verified": False,
        "current_source_freshness_verified": False,
        "current_staged_namespace_presence_verified": False,
        "dependency_environment_coverage_verified": False,
        "dispatch_enabled": False,
        "durable_control_plane_persistence_enabled": False,
        "dynamic_loader_identity_verified": False,
        "effect_class": 1,
        "effective_invocability_verified": False,
        "environment_coverage_verified": False,
        "executable_authenticity_verified": False,
        "executable_provenance_verified": False,
        "execution_enabled": False,
        "expected_resolution_authenticity_verified": False,
        "expected_resolution_correspondence_verified": True,
        "external_writable_descriptor_absence_verified": False,
        "filesystem_immutability_verified": False,
        "fork_descriptor_inheritance_excluded": False,
        "future_execution_correspondence_verified": False,
        "interpreter_identity_verified": False,
        "kind": REPOSITORY_EXECUTABLE_STAGING_EVIDENCE_KIND,
        "launcher_identity_verified": False,
        "lease_scoped_filesystem_stage_established": True,
        "lease_process_binding_established": True,
        "live_execution_eligible": False,
        "measurement_source": receipt.measurement_source,
        "module_identity_verified": False,
        "mount_alias_exclusion_verified": False,
        "package_identity_verified": False,
        "plugin_identity_verified": False,
        "post_stage_resolution_correspondence_verified": True,
        "proposal_lineage_extended": False,
        "read_only_descriptor_lease_established": True,
        "receipt_authenticity_verified": False,
        "receipt_digest": canonical_digest(canonical),
        "registration_digest": receipt.registration_digest,
        "repository_ref": receipt.repository_ref,
        "resolution_context_digest": receipt.resolution_context_digest,
        "resolution_scope": receipt.resolution_scope,
        "route_eligible": False,
        "same_user_tamper_resistance_verified": False,
        "schema_version": receipt.schema_version,
        "secure_erasure_verified": False,
        "shared_library_identity_verified": False,
        "shebang_identity_verified": False,
        "staged_byte_correspondence_verified": True,
        "staged_file_count": receipt.unique_file_count,
        "staged_readback_complete": True,
        "staging_root_metadata_restored": False,
        "staging_scope": receipt.staging_scope,
        "staging_source": receipt.staging_source,
        "toolchain_completeness_verified": False,
        "total_staged_bytes": receipt.total_staged_bytes,
        "validation_mode": "local_staging",
    }


def _cleanup_receipt_projection(
    receipt: RepositoryExecutableStageCleanupReceipt,
) -> dict[str, Any]:
    if (
        type(receipt) is not RepositoryExecutableStageCleanupReceipt
        or receipt.kind != REPOSITORY_EXECUTABLE_STAGE_CLEANUP_KIND
        or type(receipt.schema_version) is not int
        or receipt.schema_version
        != REPOSITORY_EXECUTABLE_STAGING_SCHEMA_VERSION
        or receipt.outcome
        not in {"removed", "already_absent_verified", "unverifiable"}
        or (
            receipt.staging_receipt_digest is not None
            and not _is_digest(receipt.staging_receipt_digest)
        )
        or type(receipt.owned_namespace_absence_verified) is not bool
        or type(receipt.descriptor_release_complete) is not bool
        or type(receipt.staging_root_identity_verified) is not bool
        or type(receipt.staging_root_metadata_restored) is not bool
        or receipt.staging_root_metadata_restored
        or type(receipt.secure_erasure_verified) is not bool
        or receipt.secure_erasure_verified
        or (
            receipt.outcome == "unverifiable"
            and (
                receipt.owned_namespace_absence_verified
                or receipt.descriptor_release_complete
            )
        )
        or (
            receipt.outcome != "unverifiable"
            and (
                not receipt.owned_namespace_absence_verified
                or not receipt.descriptor_release_complete
            )
        )
    ):
        raise _InvalidStaging
    return {
        "descriptor_release_complete": receipt.descriptor_release_complete,
        "kind": receipt.kind,
        "outcome": receipt.outcome,
        "owned_namespace_absence_verified": (
            receipt.owned_namespace_absence_verified
        ),
        "schema_version": receipt.schema_version,
        "secure_erasure_verified": receipt.secure_erasure_verified,
        "staging_receipt_digest": receipt.staging_receipt_digest,
        "staging_root_identity_verified": (
            receipt.staging_root_identity_verified
        ),
        "staging_root_metadata_restored": (
            receipt.staging_root_metadata_restored
        ),
    }


def _store_cleanup_receipt(
    lease: RepositoryExecutableStageLease,
    receipt: RepositoryExecutableStageCleanupReceipt,
) -> None:
    canonical = _cleanup_receipt_projection(receipt)
    lease._cleanup_receipt = receipt
    lease._cleanup_receipt_digest_anchor = canonical_digest(canonical)


def _require_supported_platform() -> None:
    required_flags = (
        "O_ACCMODE",
        "O_CLOEXEC",
        "O_NOFOLLOW",
        "O_NONBLOCK",
    )
    if (
        os.name != "posix"
        or any(not hasattr(os, name) for name in required_flags)
        or not hasattr(os, "pread")
        or not hasattr(os, "geteuid")
        or not hasattr(os, "fchmod")
        or not hasattr(os, "get_inheritable")
        or not hasattr(fcntl, "F_GETFL")
        or os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.stat not in os.supports_follow_symlinks
        or os.unlink not in os.supports_dir_fd
    ):
        raise _InvalidStaging


def _require_new_lease(lease: Any) -> RepositoryExecutableStageLease:
    if (
        type(lease) is not RepositoryExecutableStageLease
        or lease._receipt is not None
        or lease._cleanup_receipt is not None
        or lease._receipt_digest_anchor is not None
        or lease._receipt_staged_file_refs_anchor != ()
        or lease._cleanup_receipt_digest_anchor is not None
        or lease._state != "new"
        or type(lease._owner_pid) is not int
        or lease._owner_pid <= 0
        or lease._owner_pid != os.getpid()
        or lease._files != ()
        or lease._root_descriptor is not None
        or lease._root_metadata is not None
        or lease._pending_name is not None
        or lease._pending_identity is not None
        or lease._pending_descriptors != ()
        or lease._descriptor_release_unverifiable is not False
    ):
        raise _InvalidStaging
    return lease


def _validate_registration_and_expected(
    registration: Any,
    expected_resolution: Any,
) -> tuple[
    RepositoryRegistration,
    dict[str, Any],
    dict[str, Any],
]:
    # Preserve the resolver's version-gate ordering.  Older registrations fail
    # before the expected receipt or any filesystem staging input is inspected.
    if (
        type(registration) is not RepositoryRegistration
        or type(registration.schema_version) is not int
        or registration.schema_version != 4
    ):
        raise _InvalidStaging
    refreshed = _BUILTIN_REVALIDATE_REPOSITORY_REGISTRATION(registration)
    if refreshed.schema_version != 4:
        raise _InvalidStaging
    canonical_registration = _BUILTIN_REGISTRATION_CANONICAL_PROJECTION(
        refreshed
    )
    expected = _BUILTIN_RESOLUTION_PROJECTION(expected_resolution)
    baseline = refreshed.baseline_command_results
    identities = refreshed.executable_toolchain_identities
    if baseline is None or identities is None:
        raise _InvalidStaging
    if (
        expected["registration_digest"]
        != canonical_digest(canonical_registration)
        or expected["repository_ref"]
        != refreshed.repository.repository_ref
        or expected["verification_commands_digest"]
        != canonical_digest(canonical_registration["verification_commands"])
        or expected["baseline_command_results_digest"]
        != canonical_digest(_BUILTIN_BASELINE_PROJECTION(baseline))
        or expected["executable_toolchain_identities_digest"]
        != canonical_digest(_BUILTIN_TOOLCHAIN_PROJECTION(identities))
    ):
        raise _InvalidStaging
    return refreshed, canonical_registration, expected


class _CaptureSink:
    """Capture immutable chunks while the resolver's source FD is pinned."""

    def __init__(self) -> None:
        self.by_identity_ref: dict[str, _CapturedExecutable] = {}
        self.total_bytes = 0

    def __call__(
        self,
        descriptor: int,
        metadata: os.stat_result,
        measured: _MeasuredFile,
    ) -> None:
        if (
            measured.filesystem_identity_ref in self.by_identity_ref
            or len(self.by_identity_ref) >= _MAX_UNIQUE_FILES
            or measured.content_bytes != metadata.st_size
            or measured.content_bytes < 0
            or measured.content_bytes > _MAX_EXECUTABLE_BYTES
            or self.total_bytes + measured.content_bytes
            > _MAX_TOTAL_EXECUTABLE_BYTES
        ):
            raise _InvalidStaging
        try:
            if os.lseek(descriptor, 0, os.SEEK_SET) != 0:
                raise _InvalidStaging
            before = os.fstat(descriptor)
        except OSError:
            raise _InvalidStaging from None
        if _metadata_signature(before) != measured.metadata:
            raise _InvalidStaging
        remaining = measured.content_bytes
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        while remaining:
            try:
                chunk = os.read(
                    descriptor,
                    min(_READ_CHUNK_BYTES, remaining),
                )
            except (BlockingIOError, InterruptedError, OSError):
                raise _InvalidStaging from None
            if not chunk:
                raise _InvalidStaging
            chunks.append(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
        try:
            if os.read(descriptor, 1) != b"":
                raise _InvalidStaging
            after = os.fstat(descriptor)
        except OSError:
            raise _InvalidStaging from None
        content_digest = _DIGEST_PREFIX + digest.hexdigest()
        if (
            _metadata_signature(after) != measured.metadata
            or content_digest != measured.content_digest
        ):
            raise _InvalidStaging
        self.by_identity_ref[measured.filesystem_identity_ref] = (
            _CapturedExecutable(
                source_filesystem_identity_ref=(
                    measured.filesystem_identity_ref
                ),
                source_metadata=measured.metadata,
                source_metadata_digest=measured.metadata_digest,
                content_digest=content_digest,
                content=tuple(chunks),  # type: ignore[arg-type]
            )
        )
        self.total_bytes += measured.content_bytes

    def clear(self) -> None:
        self.by_identity_ref.clear()
        self.total_bytes = 0


def _path_components_overlap(first: Path, second: Path) -> bool:
    first_parts = first.parts
    second_parts = second.parts
    shared = min(len(first_parts), len(second_parts))
    return (
        first_parts[:shared] == second_parts[:shared]
        and (len(first_parts) == shared or len(second_parts) == shared)
    )


def _directory_is_empty(descriptor: int) -> bool:
    try:
        with os.scandir(descriptor) as entries:
            return next(entries, None) is None
    except OSError:
        raise _InvalidStaging from None


def _same_directory_identity(
    first: os.stat_result,
    second: os.stat_result,
) -> bool:
    return (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)


def _root_path_identity_matches(lease: RepositoryExecutableStageLease) -> bool:
    if lease._root_metadata is None:
        return False
    reopened = None
    try:
        reopened = _open_absolute_directory(lease.staging_root)
        metadata = os.fstat(reopened.descriptor)
        expected = lease._root_metadata
        return bool(
            (metadata.st_dev, metadata.st_ino) == expected[:2]
            and metadata.st_uid == expected[4]
            and metadata.st_gid == expected[5]
            and stat.S_IMODE(metadata.st_mode)
            == stat.S_IMODE(expected[2])
        )
    except (OSError, TypeError, ValueError, _InvalidResolution):
        return False
    finally:
        if reopened is not None:
            try:
                os.close(reopened.descriptor)
            except OSError:
                pass


def _prepare_staging_root(
    lease: RepositoryExecutableStageLease,
    *,
    repository_root: Path,
    search_directories: tuple[Path, ...],
) -> str:
    if (
        type(lease.staging_root) is not _CONCRETE_PATH_TYPE
        or not lease.staging_root.is_absolute()
        or type(search_directories) is not tuple
    ):
        raise _InvalidStaging
    _absolute_path_parts(lease.staging_root)
    protected_paths = (repository_root, *search_directories)
    for path in protected_paths:
        _absolute_path_parts(path)
        if _path_components_overlap(lease.staging_root, path):
            raise _InvalidStaging

    # Keep the freshly opened descriptor locally owned until the lease has
    # both the metadata needed to recognize it and the descriptor itself.
    # Either attribute assignment may raise a BaseException (including an
    # asynchronous KeyboardInterrupt); in that case, close the still-local
    # descriptor instead of leaving an untracked root handle behind.
    pinned = None
    try:
        pinned = _open_absolute_directory(lease.staging_root)
        metadata = os.fstat(pinned.descriptor)
        lease._root_metadata = _metadata_signature(metadata)
        lease._root_descriptor = pinned.descriptor
    except BaseException:
        if (
            pinned is not None
            and lease._root_descriptor != pinned.descriptor
        ):
            if not _close_descriptor(pinned.descriptor):
                lease._descriptor_release_unverifiable = True
                _mark_cleanup_unverifiable(lease)
                raise _CleanupUncertain from None
            lease._root_metadata = None
        raise
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != _STAGING_ROOT_MODE
        or metadata.st_nlink <= 0
        or os.get_inheritable(pinned.descriptor)
        or not _directory_is_empty(pinned.descriptor)
    ):
        raise _InvalidStaging

    for path in protected_paths:
        other = _open_absolute_directory(path)
        try:
            if _same_directory_identity(metadata, os.fstat(other.descriptor)):
                raise _InvalidStaging
        finally:
            try:
                os.close(other.descriptor)
            except OSError:
                pass

    return canonical_digest(
        {
            "directory_device": metadata.st_dev,
            "directory_inode": metadata.st_ino,
            "directory_mode": stat.S_IMODE(metadata.st_mode),
            "directory_owner": metadata.st_uid,
            "kind": "repository_executable_staging_context",
            "schema_version": 1,
            "staging_scope": STAGING_SCOPE,
        }
    )


def _new_stage_name() -> str:
    value = secrets.token_hex(16)
    if (
        type(value) is not str
        or len(value) != 32
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise _InvalidStaging
    return ".ordomata-executable-" + value


def _entry_metadata(
    directory_descriptor: int,
    name: str,
) -> os.stat_result | None:
    try:
        return os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return None
    except OSError:
        raise _InvalidStaging from None


def _write_all(descriptor: int, chunks: tuple[bytes, ...]) -> None:
    for chunk in chunks:
        offset = 0
        while offset < len(chunk):
            try:
                written = os.write(descriptor, chunk[offset:])
            except (BlockingIOError, InterruptedError, OSError):
                raise _InvalidStaging from None
            if written <= 0:
                raise _InvalidStaging
            offset += written


def _descriptor_digest(
    descriptor: int,
    *,
    content_bytes: int,
) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < content_bytes:
        try:
            chunk = os.pread(
                descriptor,
                min(_READ_CHUNK_BYTES, content_bytes - offset),
                offset,
            )
        except (BlockingIOError, InterruptedError, OSError):
            raise _InvalidStaging from None
        if not chunk:
            raise _InvalidStaging
        digest.update(chunk)
        offset += len(chunk)
    try:
        if os.pread(descriptor, 1, content_bytes) != b"":
            raise _InvalidStaging
    except (BlockingIOError, InterruptedError, OSError):
        raise _InvalidStaging from None
    return _DIGEST_PREFIX + digest.hexdigest()


def _staged_identity_ref(metadata: os.stat_result) -> str:
    return canonical_digest(
        {
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "kind": "repository_executable_staged_file_identity",
            "schema_version": 1,
        }
    )


def _staged_metadata_digest(
    metadata: os.stat_result,
    *,
    staged_filesystem_identity_ref: str,
) -> str:
    return canonical_digest(
        {
            "change_time_ns": metadata.st_ctime_ns,
            "filesystem_identity_ref": staged_filesystem_identity_ref,
            "group_id": metadata.st_gid,
            "kind": "repository_executable_staged_file_metadata",
            "link_count": metadata.st_nlink,
            "mode": metadata.st_mode,
            "modified_time_ns": metadata.st_mtime_ns,
            "owner_id": metadata.st_uid,
            "schema_version": 1,
            "size_bytes": metadata.st_size,
        }
    )


def _stage_file_ref(
    *,
    captured: _CapturedExecutable,
    staged_filesystem_identity_ref: str,
    staged_metadata_digest: str,
    staging_context_digest: str,
) -> str:
    return canonical_digest(
        {
            "content_bytes": sum(len(chunk) for chunk in captured.content),
            "content_digest": captured.content_digest,
            "kind": "repository_executable_staged_file_ref",
            "schema_version": 1,
            "source_filesystem_identity_ref": (
                captured.source_filesystem_identity_ref
            ),
            "source_metadata_digest": captured.source_metadata_digest,
            "staged_filesystem_identity_ref": (
                staged_filesystem_identity_ref
            ),
            "staged_metadata_digest": staged_metadata_digest,
            "staging_context_digest": staging_context_digest,
        }
    )


def _close_descriptor(descriptor: int) -> bool:
    try:
        os.close(descriptor)
    except OSError:
        return False
    return True


def _pending_identity_from_descriptors(
    descriptors: tuple[int, ...],
) -> tuple[int, int] | None:
    identity: tuple[int, int] | None = None
    for descriptor in descriptors:
        try:
            metadata = os.fstat(descriptor)
        except OSError:
            return None
        current = (metadata.st_dev, metadata.st_ino)
        if identity is None:
            identity = current
        elif current != identity:
            return None
    return identity


def _attempt_pending_name_cleanup(
    lease: RepositoryExecutableStageLease,
) -> Literal["removed", "already_absent_verified"] | None:
    root_descriptor = lease._root_descriptor
    name = lease._pending_name
    descriptors = lease._pending_descriptors
    if root_descriptor is None or name is None or not descriptors:
        return None
    expected_identity = lease._pending_identity
    if expected_identity is None:
        expected_identity = _pending_identity_from_descriptors(descriptors)
    if expected_identity is None:
        return None
    try:
        root_metadata = os.fstat(root_descriptor)
        if (
            lease._root_metadata is None
            or not stat.S_ISDIR(root_metadata.st_mode)
            or (root_metadata.st_dev, root_metadata.st_ino)
            != lease._root_metadata[:2]
        ):
            return None
        entry = _entry_metadata(root_descriptor, name)
        removed = False
        if entry is not None:
            if (
                not stat.S_ISREG(entry.st_mode)
                or (entry.st_dev, entry.st_ino) != expected_identity
            ):
                return None
            os.unlink(name, dir_fd=root_descriptor)
            removed = True
        if _entry_metadata(root_descriptor, name) is not None:
            return None
        for descriptor in descriptors:
            metadata = os.fstat(descriptor)
            if (
                (metadata.st_dev, metadata.st_ino) != expected_identity
                or metadata.st_nlink != 0
            ):
                return None
        os.fsync(root_descriptor)
        if not _root_path_identity_matches(lease):
            return None
        close_failed = False
        for value in descriptors:
            if not _close_descriptor(value):
                close_failed = True
        lease._pending_name = None
        lease._pending_identity = None
        lease._pending_descriptors = ()
        if close_failed:
            lease._descriptor_release_unverifiable = True
            return None
        return "removed" if removed else "already_absent_verified"
    except (OSError, TypeError, ValueError, _InvalidStaging):
        return None


def _mark_cleanup_unverifiable(
    lease: RepositoryExecutableStageLease,
) -> None:
    lease._state = "cleanup_unverifiable"
    receipt = RepositoryExecutableStageCleanupReceipt(
        kind=REPOSITORY_EXECUTABLE_STAGE_CLEANUP_KIND,
        schema_version=REPOSITORY_EXECUTABLE_STAGING_SCHEMA_VERSION,
        outcome="unverifiable",
        staging_receipt_digest=(
            None
            if lease._receipt is None
            else lease._receipt_digest_anchor
        ),
        owned_namespace_absence_verified=False,
        descriptor_release_complete=False,
        staging_root_identity_verified=False,
        staging_root_metadata_restored=False,
        secure_erasure_verified=False,
    )
    _store_cleanup_receipt(lease, receipt)


def _stage_captured_file(
    lease: RepositoryExecutableStageLease,
    captured: _CapturedExecutable,
    *,
    staging_context_digest: str,
) -> _RetainedStagedFile:
    root_descriptor = lease._root_descriptor
    if root_descriptor is None:
        raise _InvalidStaging
    writer: int | None = None
    reader: int | None = None
    detached = False
    name: str | None = None
    identity: tuple[int, int] | None = None
    retained: _RetainedStagedFile | None = None
    installed_files: tuple[_RetainedStagedFile, ...] | None = None
    try:
        for _ in range(_STAGE_NAME_ATTEMPTS):
            candidate = _new_stage_name()
            if _entry_metadata(root_descriptor, candidate) is not None:
                continue
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_NOFOLLOW
                | os.O_CLOEXEC
            )
            try:
                writer = os.open(
                    candidate,
                    flags,
                    0o600,
                    dir_fd=root_descriptor,
                )
            except FileExistsError:
                continue
            except OSError:
                raise _InvalidStaging from None
            name = candidate
            lease._pending_name = name
            lease._pending_descriptors = (writer,)
            break
        if writer is None or name is None:
            raise _InvalidStaging

        try:
            os.fchmod(writer, 0o600)
            writer_metadata = os.fstat(writer)
        except OSError:
            raise _InvalidStaging from None
        identity = (writer_metadata.st_dev, writer_metadata.st_ino)
        lease._pending_identity = identity
        if (
            not stat.S_ISREG(writer_metadata.st_mode)
            or writer_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(writer_metadata.st_mode) != 0o600
            or writer_metadata.st_nlink != 1
            or writer_metadata.st_size != 0
            or os.get_inheritable(writer)
        ):
            raise _InvalidStaging

        entry = _entry_metadata(root_descriptor, name)
        if (
            entry is None
            or stat.S_ISLNK(entry.st_mode)
            or (entry.st_dev, entry.st_ino) != identity
        ):
            raise _InvalidStaging
        reader = os.open(
            name,
            os.O_RDONLY
            | os.O_NOFOLLOW
            | os.O_CLOEXEC
            | os.O_NONBLOCK,
            dir_fd=root_descriptor,
        )
        lease._pending_descriptors = (writer, reader)
        reader_metadata = os.fstat(reader)
        if (
            (reader_metadata.st_dev, reader_metadata.st_ino) != identity
            or os.get_inheritable(reader)
            or fcntl.fcntl(reader, fcntl.F_GETFL) & os.O_ACCMODE
            != os.O_RDONLY
        ):
            raise _InvalidStaging

        # The name is removed before executable bytes are written.  A failure
        # after this point releases an anonymous inode by closing descriptors;
        # it cannot leave the captured content under a pathname owned here.
        current = _entry_metadata(root_descriptor, name)
        if (
            current is None
            or (current.st_dev, current.st_ino) != identity
        ):
            raise _CleanupUncertain
        os.unlink(name, dir_fd=root_descriptor)
        if (
            _entry_metadata(root_descriptor, name) is not None
            or os.fstat(writer).st_nlink != 0
            or os.fstat(reader).st_nlink != 0
        ):
            raise _CleanupUncertain
        os.fsync(root_descriptor)
        detached = True
        lease._pending_name = None
        lease._pending_identity = None
        lease._pending_descriptors = ()

        _write_all(writer, captured.content)
        try:
            os.fchmod(writer, _STAGED_FILE_MODE)
            os.fsync(writer)
        except OSError:
            raise _InvalidStaging from None
        content_bytes = sum(len(chunk) for chunk in captured.content)
        if (
            content_bytes > _MAX_EXECUTABLE_BYTES
            or _descriptor_digest(reader, content_bytes=content_bytes)
            != captured.content_digest
        ):
            raise _InvalidStaging
        final_writer_metadata = os.fstat(writer)
        final_reader_metadata = os.fstat(reader)
        if (
            _metadata_signature(final_writer_metadata)
            != _metadata_signature(final_reader_metadata)
            or not stat.S_ISREG(final_reader_metadata.st_mode)
            or final_reader_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(final_reader_metadata.st_mode)
            != _STAGED_FILE_MODE
            or final_reader_metadata.st_nlink != 0
            or final_reader_metadata.st_size != content_bytes
        ):
            raise _InvalidStaging

        if not _close_descriptor(writer):
            lease._descriptor_release_unverifiable = True
            lease._pending_identity = identity
            lease._pending_descriptors = (reader,)
            writer = None
            reader = None
            raise _CleanupUncertain
        writer = None
        final_metadata = os.fstat(reader)
        if (
            _metadata_signature(final_metadata)
            != _metadata_signature(final_reader_metadata)
            or os.get_inheritable(reader)
            or fcntl.fcntl(reader, fcntl.F_GETFL) & os.O_ACCMODE
            != os.O_RDONLY
        ):
            raise _InvalidStaging
        staged_filesystem_identity_ref = _staged_identity_ref(final_metadata)
        metadata_digest = _staged_metadata_digest(
            final_metadata,
            staged_filesystem_identity_ref=(
                staged_filesystem_identity_ref
            ),
        )
        staged_file = RepositoryExecutableStagedFile(
            kind=REPOSITORY_EXECUTABLE_STAGED_FILE_KIND,
            source_filesystem_identity_ref=(
                captured.source_filesystem_identity_ref
            ),
            source_metadata_digest=captured.source_metadata_digest,
            staged_file_ref=_stage_file_ref(
                captured=captured,
                staged_filesystem_identity_ref=(
                    staged_filesystem_identity_ref
                ),
                staged_metadata_digest=metadata_digest,
                staging_context_digest=staging_context_digest,
            ),
            staged_filesystem_identity_ref=(
                staged_filesystem_identity_ref
            ),
            staged_metadata_digest=metadata_digest,
            content_digest=captured.content_digest,
            content_bytes=content_bytes,
        )
        retained = _RetainedStagedFile(
            staged_file=staged_file,
            descriptor=reader,
            metadata=_metadata_signature(final_metadata),
        )
        installed_files = lease._files + (retained,)
        lease._files = installed_files
        reader = None
        return retained
    except BaseException:
        # Assignment either installed the complete tuple or did not happen.
        # If it did, the lease owns the reader and the outer cleanup path will
        # release it; otherwise this frame must retain and close it below.
        if installed_files is not None and lease._files is installed_files:
            reader = None
        if not detached and lease._pending_name is not None:
            if _attempt_pending_name_cleanup(lease) is None:
                if (
                    not lease._descriptor_release_unverifiable
                    and (writer is not None or reader is not None)
                ):
                    lease._pending_descriptors = tuple(
                        value
                        for value in (writer, reader)
                        if value is not None
                    )
                    writer = None
                    reader = None
                else:
                    # A failed close makes the numeric descriptor unsafe to
                    # retry because it may already have been reused.
                    writer = None
                    reader = None
                _mark_cleanup_unverifiable(lease)
                raise _CleanupUncertain from None
            writer = None
            reader = None
        if detached:
            detached_descriptors = tuple(
                value
                for value in (writer, reader)
                if value is not None
            )
            try:
                unexpected_links = any(
                    os.fstat(value).st_nlink != 0
                    for value in detached_descriptors
                )
            except OSError:
                unexpected_links = True
            if unexpected_links:
                lease._pending_identity = identity
                lease._pending_descriptors = detached_descriptors
                writer = None
                reader = None
                _mark_cleanup_unverifiable(lease)
                raise _CleanupUncertain from None
        close_ok = True
        for descriptor in (writer, reader):
            if descriptor is not None:
                close_ok = _close_descriptor(descriptor) and close_ok
        if not close_ok:
            lease._descriptor_release_unverifiable = True
            lease._pending_descriptors = ()
            _mark_cleanup_unverifiable(lease)
            raise _CleanupUncertain from None
        raise


def _verify_retained_file(value: _RetainedStagedFile) -> None:
    if type(value) is not _RetainedStagedFile:
        raise _InvalidStaging
    _staged_file_projection(value.staged_file)
    try:
        metadata = os.fstat(value.descriptor)
        flags = fcntl.fcntl(value.descriptor, fcntl.F_GETFL)
        inheritable = os.get_inheritable(value.descriptor)
    except OSError:
        raise _InvalidStaging from None
    if (
        _metadata_signature(metadata) != value.metadata
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != _STAGED_FILE_MODE
        or metadata.st_nlink != 0
        or metadata.st_size != value.staged_file.content_bytes
        or flags & os.O_ACCMODE != os.O_RDONLY
        or inheritable
        or _descriptor_digest(
            value.descriptor,
            content_bytes=value.staged_file.content_bytes,
        )
        != value.staged_file.content_digest
    ):
        raise _InvalidStaging


def _build_staging_receipt(
    *,
    expected: RepositoryExecutableResolutionReceipt,
    action: RepositoryExecutableResolutionReceipt,
    post_stage: RepositoryExecutableResolutionReceipt,
    retained_files: tuple[_RetainedStagedFile, ...],
    staging_context_digest: str,
) -> RepositoryExecutableStagingReceipt:
    file_by_source_ref = {
        value.staged_file.source_filesystem_identity_ref: value.staged_file
        for value in retained_files
    }
    bindings: list[RepositoryExecutableStageBinding] = []
    for measurement in action.measurements:
        staged_file = file_by_source_ref.get(
            measurement.filesystem_identity_ref
        )
        if staged_file is None:
            raise _InvalidStaging
        bindings.append(
            RepositoryExecutableStageBinding(
                kind=REPOSITORY_EXECUTABLE_STAGE_BINDING_KIND,
                command_kind=measurement.command_kind,
                command_id=measurement.command_id,
                command_digest=measurement.command_digest,
                declared_executable_ref=(
                    measurement.declared_executable_ref
                ),
                resolved_executable_ref=(
                    measurement.resolved_executable_ref
                ),
                staged_file_ref=staged_file.staged_file_ref,
            )
        )
    receipt = RepositoryExecutableStagingReceipt(
        kind=REPOSITORY_EXECUTABLE_STAGING_KIND,
        schema_version=REPOSITORY_EXECUTABLE_STAGING_SCHEMA_VERSION,
        measurement_source=action.measurement_source,
        resolution_scope=action.resolution_scope,
        staging_source=STAGING_SOURCE,
        staging_scope=STAGING_SCOPE,
        registration_digest=action.registration_digest,
        repository_ref=action.repository_ref,
        verification_commands_digest=(
            action.verification_commands_digest
        ),
        baseline_command_results_digest=(
            action.baseline_command_results_digest
        ),
        executable_toolchain_identities_digest=(
            action.executable_toolchain_identities_digest
        ),
        resolution_context_digest=action.resolution_context_digest,
        expected_resolution_receipt_digest=canonical_digest(
            _BUILTIN_RESOLUTION_PROJECTION(expected)
        ),
        action_resolution_receipt_digest=canonical_digest(
            _BUILTIN_RESOLUTION_PROJECTION(action)
        ),
        post_stage_resolution_receipt_digest=canonical_digest(
            _BUILTIN_RESOLUTION_PROJECTION(post_stage)
        ),
        staging_context_digest=staging_context_digest,
        staged_files=tuple(value.staged_file for value in retained_files),
        bindings=tuple(bindings),
        unique_file_count=len(retained_files),
        total_staged_bytes=sum(
            value.staged_file.content_bytes for value in retained_files
        ),
    )
    _staging_receipt_projection(receipt)
    return receipt


def _verified_cleanup_receipt(
    lease: RepositoryExecutableStageLease,
    *,
    outcome: Literal["removed", "already_absent_verified"],
    root_identity_verified: bool,
) -> RepositoryExecutableStageCleanupReceipt:
    receipt = RepositoryExecutableStageCleanupReceipt(
        kind=REPOSITORY_EXECUTABLE_STAGE_CLEANUP_KIND,
        schema_version=REPOSITORY_EXECUTABLE_STAGING_SCHEMA_VERSION,
        outcome=outcome,
        staging_receipt_digest=(
            None
            if lease._receipt is None
            else lease._receipt_digest_anchor
        ),
        owned_namespace_absence_verified=True,
        descriptor_release_complete=True,
        staging_root_identity_verified=root_identity_verified,
        staging_root_metadata_restored=False,
        secure_erasure_verified=False,
    )
    _cleanup_receipt_projection(receipt)
    return receipt


def _release_retained_files(
    lease: RepositoryExecutableStageLease,
) -> bool:
    remaining: list[_RetainedStagedFile] = []
    success = True
    for value in lease._files:
        try:
            metadata = os.fstat(value.descriptor)
            identity_matches = (
                metadata.st_dev,
                metadata.st_ino,
            ) == value.metadata[:2]
            namespace_absent = metadata.st_nlink == 0
        except OSError:
            lease._descriptor_release_unverifiable = True
            success = False
            continue
        if not identity_matches:
            # The numeric descriptor may have been closed and reused outside
            # the lease.  Never close an object that is no longer ours.
            lease._descriptor_release_unverifiable = True
            success = False
            continue
        if not namespace_absent:
            success = False
            remaining.append(value)
            continue
        if (
            _close_descriptor(value.descriptor)
        ):
            continue
        lease._descriptor_release_unverifiable = True
        success = False
    lease._files = tuple(remaining)
    return success and not lease._descriptor_release_unverifiable


def _close_root_descriptor(
    lease: RepositoryExecutableStageLease,
) -> bool:
    descriptor = lease._root_descriptor
    if descriptor is None:
        return not lease._descriptor_release_unverifiable
    try:
        metadata = os.fstat(descriptor)
    except OSError:
        lease._descriptor_release_unverifiable = True
        lease._root_descriptor = None
        return False
    if (
        lease._root_metadata is None
        or not stat.S_ISDIR(metadata.st_mode)
        or (metadata.st_dev, metadata.st_ino) != lease._root_metadata[:2]
    ):
        lease._descriptor_release_unverifiable = True
        lease._root_descriptor = None
        return False
    if not _close_descriptor(descriptor):
        lease._descriptor_release_unverifiable = True
        lease._root_descriptor = None
        return False
    lease._root_descriptor = None
    return True


def _abort_staging(lease: RepositoryExecutableStageLease) -> bool:
    if type(lease) is not RepositoryExecutableStageLease:
        return True
    if lease._state == "cleanup_unverifiable":
        return False
    root_identity_verified = False
    pending_outcome: Literal[
        "removed",
        "already_absent_verified",
    ] | None = None
    if lease._pending_name is not None or lease._pending_descriptors:
        pending_outcome = _attempt_pending_name_cleanup(lease)
        if pending_outcome is None:
            _mark_cleanup_unverifiable(lease)
            return False
    if lease._root_descriptor is not None:
        try:
            root_identity_verified = bool(
                _directory_is_empty(lease._root_descriptor)
                and _root_path_identity_matches(lease)
            )
        except _InvalidStaging:
            root_identity_verified = False
        if not root_identity_verified:
            _mark_cleanup_unverifiable(lease)
            return False
    if not _release_retained_files(lease):
        _mark_cleanup_unverifiable(lease)
        return False
    if not _close_root_descriptor(lease):
        _mark_cleanup_unverifiable(lease)
        return False
    lease._state = "cleaned"
    _store_cleanup_receipt(
        lease,
        _verified_cleanup_receipt(
            lease,
            outcome=pending_outcome or "already_absent_verified",
            root_identity_verified=root_identity_verified,
        ),
    )
    return True


def cleanup_repository_executable_stage(
    lease: RepositoryExecutableStageLease,
) -> RepositoryExecutableStageCleanupReceipt:
    """Release a lease or conservatively retry an uncertain local cleanup."""

    if type(lease) is not RepositoryExecutableStageLease:
        raise ValidationError(_INVALID_MESSAGE)
    if lease._owner_pid != os.getpid():
        raise ValidationError(_INVALID_MESSAGE)
    if lease._state == "cleaned":
        if lease._cleanup_receipt is None:
            raise ValidationError(_INVALID_MESSAGE)
        try:
            canonical = _cleanup_receipt_projection(
                lease._cleanup_receipt
            )
            if (
                lease._cleanup_receipt_digest_anchor
                != canonical_digest(canonical)
            ):
                raise _InvalidStaging
        except (AttributeError, TypeError, ValueError):
            raise ValidationError(_INVALID_MESSAGE) from None
        return lease._cleanup_receipt
    if lease._state == "new":
        if not _abort_staging(lease):
            raise ConfigurationError(_CLEANUP_UNCERTAIN_MESSAGE) from None
        assert lease._cleanup_receipt is not None
        return lease._cleanup_receipt
    if lease._state == "active":
        try:
            if lease._receipt is None:
                raise _InvalidStaging
            canonical = _staging_receipt_projection(lease._receipt)
            staged_file_refs = tuple(
                value.staged_file_ref for value in lease._receipt.staged_files
            )
            retained_refs = tuple(
                value.staged_file.staged_file_ref for value in lease._files
            )
            if (
                lease._receipt_digest_anchor
                != canonical_digest(canonical)
                or staged_file_refs
                != lease._receipt_staged_file_refs_anchor
                or retained_refs != staged_file_refs
                or len(lease._files) != lease._receipt.unique_file_count
            ):
                raise _InvalidStaging
            for value in lease._files:
                _verify_retained_file(value)
        except (AttributeError, OSError, TypeError, ValueError):
            _mark_cleanup_unverifiable(lease)
            raise ConfigurationError(_CLEANUP_UNCERTAIN_MESSAGE) from None
        if not _release_retained_files(lease):
            _mark_cleanup_unverifiable(lease)
            raise ConfigurationError(_CLEANUP_UNCERTAIN_MESSAGE) from None
        lease._state = "cleaned"
        _store_cleanup_receipt(
            lease,
            _verified_cleanup_receipt(
                lease,
                outcome="already_absent_verified",
                root_identity_verified=False,
            ),
        )
        assert lease._cleanup_receipt is not None
        return lease._cleanup_receipt
    if lease._state == "cleanup_unverifiable":
        pending_outcome: Literal[
            "removed",
            "already_absent_verified",
        ] | None = None
        if lease._pending_name is not None or lease._pending_descriptors:
            if lease._pending_name is not None:
                pending_outcome = _attempt_pending_name_cleanup(lease)
                if pending_outcome is None:
                    _mark_cleanup_unverifiable(lease)
                    assert lease.cleanup_receipt is not None
                    return lease.cleanup_receipt
            else:
                remaining: list[int] = []
                expected_identity = lease._pending_identity
                if expected_identity is None:
                    expected_identity = _pending_identity_from_descriptors(
                        lease._pending_descriptors
                    )
                for descriptor in lease._pending_descriptors:
                    try:
                        metadata = os.fstat(descriptor)
                    except OSError:
                        lease._descriptor_release_unverifiable = True
                        continue
                    if (
                        expected_identity is None
                        or (metadata.st_dev, metadata.st_ino)
                        != expected_identity
                    ):
                        lease._descriptor_release_unverifiable = True
                        continue
                    namespace_absent = metadata.st_nlink == 0
                    if (
                        not namespace_absent
                    ):
                        remaining.append(descriptor)
                    elif not _close_descriptor(descriptor):
                        lease._descriptor_release_unverifiable = True
                lease._pending_descriptors = tuple(remaining)
                if remaining:
                    _mark_cleanup_unverifiable(lease)
                    assert lease.cleanup_receipt is not None
                    return lease.cleanup_receipt
                lease._pending_identity = None
        if not _release_retained_files(lease):
            _mark_cleanup_unverifiable(lease)
            assert lease.cleanup_receipt is not None
            return lease.cleanup_receipt
        root_identity_verified = False
        if lease._root_descriptor is not None:
            try:
                root_identity_verified = bool(
                    _directory_is_empty(lease._root_descriptor)
                    and _root_path_identity_matches(lease)
                )
            except _InvalidStaging:
                root_identity_verified = False
            if not root_identity_verified or not _close_root_descriptor(lease):
                _mark_cleanup_unverifiable(lease)
                assert lease.cleanup_receipt is not None
                return lease.cleanup_receipt
        if lease._descriptor_release_unverifiable:
            _mark_cleanup_unverifiable(lease)
            assert lease.cleanup_receipt is not None
            return lease.cleanup_receipt
        lease._state = "cleaned"
        _store_cleanup_receipt(
            lease,
            _verified_cleanup_receipt(
                lease,
                outcome=pending_outcome or "already_absent_verified",
                root_identity_verified=root_identity_verified,
            ),
        )
        assert lease._cleanup_receipt is not None
        return lease._cleanup_receipt
    raise ValidationError(_INVALID_MESSAGE)


def stage_repository_executable_bytes(
    registration: RepositoryRegistration,
    *,
    search_directories: tuple[Path, ...],
    expected_resolution: RepositoryExecutableResolutionReceipt,
    lease: RepositoryExecutableStageLease,
) -> RepositoryExecutableStagingReceipt:
    """Freshly remeasure and establish a non-executing descriptor lease.

    The caller must own any required Class 1 authorization before invoking this
    filesystem primitive.  The returned receipt is evidence, not authority.
    """

    capture = _CaptureSink()
    staging_started = False
    lease_validated = False
    try:
        _require_supported_platform()
        lease = _require_new_lease(lease)
        lease_validated = True
        refreshed, canonical_registration, expected_canonical = (
            _validate_registration_and_expected(
                registration,
                expected_resolution,
            )
        )

        # Capturing immutable byte chunks is process-local and precedes the
        # first filesystem staging mutation.  The resolver performs its full
        # namespace, precedence, and registration rechecks before returning.
        action = _BUILTIN_RESOLVE_REPOSITORY_EXECUTABLES(
            refreshed,
            search_directories=search_directories,
            unique_file_consumer=capture,
        )
        action_canonical = _BUILTIN_RESOLUTION_PROJECTION(action)
        if (
            action_canonical != expected_canonical
            or len(capture.by_identity_ref) != action.unique_file_count
            or capture.total_bytes != action.total_measured_bytes
            or _BUILTIN_REGISTRATION_CANONICAL_PROJECTION(refreshed)
            != canonical_registration
        ):
            raise _InvalidStaging

        staging_context_digest = _prepare_staging_root(
            lease,
            repository_root=refreshed.repository.canonical_root,
            search_directories=search_directories,
        )
        staging_started = True
        for captured in capture.by_identity_ref.values():
            _stage_captured_file(
                lease,
                captured,
                staging_context_digest=staging_context_digest,
            )
        retained = lease._files

        # Bracket the local staging effect with a second full resolver pass.
        # This detects source or search-precedence drift during multi-file
        # staging without claiming an atomic filesystem snapshot.
        post_stage = _BUILTIN_RESOLVE_REPOSITORY_EXECUTABLES(
            refreshed,
            search_directories=search_directories,
        )
        if (
            _BUILTIN_RESOLUTION_PROJECTION(post_stage) != expected_canonical
            or canonical_digest(_BUILTIN_RESOLUTION_PROJECTION(post_stage))
            != canonical_digest(action_canonical)
            or not _directory_is_empty(lease._root_descriptor)
            or not _root_path_identity_matches(lease)
        ):
            raise _InvalidStaging
        try:
            os.fsync(lease._root_descriptor)
        except OSError:
            raise _InvalidStaging from None
        for value in retained:
            _verify_retained_file(value)

        receipt = _build_staging_receipt(
            expected=expected_resolution,
            action=action,
            post_stage=post_stage,
            retained_files=tuple(retained),
            staging_context_digest=staging_context_digest,
        )
        if not _close_root_descriptor(lease):
            raise _CleanupUncertain
        receipt_digest_anchor = canonical_digest(
            _staging_receipt_projection(receipt)
        )
        receipt_file_refs_anchor = tuple(
            value.staged_file_ref for value in receipt.staged_files
        )
        lease._receipt = receipt
        lease._receipt_digest_anchor = receipt_digest_anchor
        lease._receipt_staged_file_refs_anchor = receipt_file_refs_anchor
        lease._state = "active"
        capture.clear()
        return receipt
    except BaseException as exc:
        capture.clear()
        cleanup_verified = True
        if lease_validated and (
            staging_started
            or lease._state == "cleanup_unverifiable"
            or lease._descriptor_release_unverifiable
            or lease._root_descriptor is not None
            or lease._files
            or lease._pending_name is not None
            or lease._pending_descriptors
        ):
            cleanup_verified = _abort_staging(lease)
        if not cleanup_verified:
            if lease_validated and lease._state != "cleanup_unverifiable":
                _mark_cleanup_unverifiable(lease)
            raise ConfigurationError(_CLEANUP_UNCERTAIN_MESSAGE) from None
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise ValidationError(_INVALID_MESSAGE) from None
