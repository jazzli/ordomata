"""Ephemeral descriptor staging for guarded nested shebang-target bytes.

This library-only Class 1 primitive consumes the exact nested-target
resolution and known-chain guard lineage, captures each unique depth-two
target through the guarded action measurement's still-pinned descriptor, and
creates namespace-detached read-only copies for later controller inspection.
It does not parse the copied bytes, recurse, execute, persist, or authorize
anything.  The caller remains responsible for separate Class 1 authorization.
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
from .repository_executable_resolution import (
    _InvalidResolution,
    _PinnedDirectory,
    _absolute_path_parts,
    _open_absolute_directory,
    _reopen_directory_matches,
    _resolution_context_digest,
    _validate_search_directories,
)
from .repository_executable_shebang_nested_target_chain_guard import (
    GUARD_SCOPE,
    INSPECTION_SOURCE,
    RepositoryExecutableShebangNestedTargetChainGuardReceipt,
    _inspect_staged_executable_shebang_nested_target_chain_guard,
    _receipt_projection as _chain_guard_projection_v1,
)
from .repository_executable_shebang_nested_target_resolution import (
    MAXIMUM_RESOLUTION_DEPTH,
    RESOLUTION_DEPTH,
    RepositoryExecutableShebangNestedTargetResolutionReceipt,
    _MeasuredNestedTarget,
    _receipt_projection as _nested_resolution_projection_v1,
)
from .repository_executable_shebang_target_requirements import (
    RepositoryExecutableShebangTargetRequirementsReceipt,
)
from .repository_executable_shebang_target_runtime_manifest import (
    RepositoryExecutableShebangTargetRuntimeManifestReceipt,
)
from .repository_executable_shebang_target_staging import (
    STAGING_SCOPE as TARGET_STAGING_SCOPE,
    RepositoryExecutableShebangTargetStageLease,
    RepositoryExecutableShebangTargetStagingReceipt,
    _staging_receipt_projection as _target_staging_projection_v1,
)
from .repository_executable_staging import (
    STAGING_SCOPE as SOURCE_STAGING_SCOPE,
    RepositoryExecutableStageLease,
    RepositoryExecutableStagingReceipt,
    _staging_receipt_projection as _source_staging_projection_v1,
)
from .repository_registration import (
    RepositoryRegistration,
    _registration_canonical_projection,
    revalidate_repository_registration,
)


REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_STAGING_SCHEMA_VERSION = 1
REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_STAGING_KIND = (
    "repository_executable_shebang_nested_target_staging"
)
REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_STAGING_EVIDENCE_KIND = (
    "repository_executable_shebang_nested_target_staging_validation"
)
REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_STAGED_FILE_KIND = (
    "repository_executable_shebang_nested_target_staged_file"
)
REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_STAGE_REQUIREMENT_KIND = (
    "repository_executable_shebang_nested_target_stage_requirement"
)
REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_STAGE_BINDING_KIND = (
    "repository_executable_shebang_nested_target_stage_binding"
)
REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_STAGE_CLEANUP_KIND = (
    "repository_executable_shebang_nested_target_stage_cleanup"
)
STAGING_SOURCE = "controller_copied"
STAGING_SCOPE = "posix_shebang_nested_target_unlinked_readonly_v1"

_INVALID_MESSAGE = (
    "repository executable shebang nested target staging is invalid"
)
_CLEANUP_UNCERTAIN_MESSAGE = (
    "repository executable shebang nested target staging cleanup is uncertain"
)
_COPY_ERROR_MESSAGE = (
    "repository executable shebang nested target staging lease cannot be copied"
)
_DIGEST_PREFIX = "sha256:"
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER_PATTERN = re.compile(r"[a-z][a-z0-9_.-]{0,119}\Z")
_COMMAND_KINDS = ("format", "lint", "type_check", "test", "build")
_STAGE_DISPOSITIONS = (
    "source_native_not_applicable",
    "target_native_not_applicable",
    "known_chain_guard_staged",
)
_MAX_FILES = 80
_MAX_REQUIREMENTS = 80
_MAX_COMMANDS = 80
_MAX_FILE_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_BYTES = 256 * 1024 * 1024
_READ_CHUNK_BYTES = 1024 * 1024
_STAGED_FILE_MODE = 0o400
_STAGING_ROOT_MODE = 0o700
_STAGE_NAME_ATTEMPTS = 8
_CONCRETE_PATH_TYPE = type(Path())

_LeaseState = Literal["new", "active", "cleaned", "cleanup_unverifiable"]
_CleanupOutcome = Literal[
    "removed",
    "already_absent_verified",
    "unverifiable",
]

# Freeze every imported proof boundary before callers can monkeypatch public
# module attributes.  These values validate evidence; they grant no authority.
_BUILTIN_CANONICAL_JSON = canonical_json
_BUILTIN_SHA256 = hashlib.sha256
_BUILTIN_CHAIN_GUARD_PROJECTION = _chain_guard_projection_v1
_BUILTIN_NESTED_RESOLUTION_PROJECTION = _nested_resolution_projection_v1
_BUILTIN_SOURCE_STAGING_PROJECTION = _source_staging_projection_v1
_BUILTIN_TARGET_STAGING_PROJECTION = _target_staging_projection_v1
_BUILTIN_INSPECT_CHAIN_GUARD = (
    _inspect_staged_executable_shebang_nested_target_chain_guard
)
_BUILTIN_ABSOLUTE_PATH_PARTS = _absolute_path_parts
_BUILTIN_OPEN_ABSOLUTE_DIRECTORY = _open_absolute_directory
_BUILTIN_REOPEN_DIRECTORY_MATCHES = _reopen_directory_matches
_BUILTIN_RESOLUTION_CONTEXT_DIGEST = _resolution_context_digest
_BUILTIN_VALIDATE_SEARCH_DIRECTORIES = _validate_search_directories
_BUILTIN_REVALIDATE_REGISTRATION = revalidate_repository_registration
_BUILTIN_REGISTRATION_PROJECTION = _registration_canonical_projection
_FIXED_REGISTRATION_TYPE = RepositoryRegistration
_FIXED_CHAIN_GUARD_TYPE = (
    RepositoryExecutableShebangNestedTargetChainGuardReceipt
)
_FIXED_NESTED_RESOLUTION_TYPE = (
    RepositoryExecutableShebangNestedTargetResolutionReceipt
)
_FIXED_TARGET_REQUIREMENTS_TYPE = (
    RepositoryExecutableShebangTargetRequirementsReceipt
)
_FIXED_TARGET_RUNTIME_TYPE = (
    RepositoryExecutableShebangTargetRuntimeManifestReceipt
)
_FIXED_TARGET_STAGING_TYPE = RepositoryExecutableShebangTargetStagingReceipt
_FIXED_TARGET_LEASE_TYPE = RepositoryExecutableShebangTargetStageLease
_FIXED_SOURCE_STAGING_TYPE = RepositoryExecutableStagingReceipt
_FIXED_SOURCE_LEASE_TYPE = RepositoryExecutableStageLease
_FIXED_MEASURED_NESTED_TARGET_TYPE = _MeasuredNestedTarget


def _canonical_digest(value: Any) -> str:
    encoded = _BUILTIN_CANONICAL_JSON(value).encode("utf-8")
    return _DIGEST_PREFIX + _BUILTIN_SHA256(encoded).hexdigest()


_BUILTIN_CANONICAL_DIGEST = _canonical_digest


class _InvalidNestedTargetStaging(ValueError):
    """Private invalid-input sentinel whose details never cross the API."""


class _CleanupUncertain(ConfigurationError):
    """Private marker for an unproved local cleanup outcome."""


@dataclass(frozen=True, slots=True)
class RepositoryExecutableShebangNestedTargetStagedFile:
    """One guarded nested measurement and its detached byte copy."""

    kind: str
    nested_target_path_ref: str = field(repr=False)
    source_filesystem_identity_ref: str = field(repr=False)
    source_metadata_digest: str = field(repr=False)
    nested_target_measurement_ref: str = field(repr=False)
    guarded_measurement_ref: str = field(repr=False)
    nested_target_staged_file_ref: str = field(repr=False)
    staged_filesystem_identity_ref: str = field(repr=False)
    staged_metadata_digest: str = field(repr=False)
    content_digest: str = field(repr=False)
    content_bytes: int

    def to_canonical(self) -> dict[str, Any]:
        return _staged_file_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableShebangNestedTargetStageRequirement:
    """One guarded requirement's nested-target staging disposition."""

    kind: str
    staged_file_ref: str = field(repr=False)
    runtime_file_ref: str = field(repr=False)
    requirement_ref: str = field(repr=False)
    target_requirement_ref: str = field(repr=False)
    target_stage_requirement_ref: str = field(repr=False)
    target_runtime_requirement_ref: str = field(repr=False)
    target_shebang_requirement_ref: str = field(repr=False)
    nested_target_requirement_ref: str = field(repr=False)
    chain_guard_requirement_ref: str = field(repr=False)
    disposition: str
    nested_target_measurement_ref: str | None = field(repr=False)
    guarded_measurement_ref: str | None = field(repr=False)
    nested_target_staged_file_ref: str | None = field(repr=False)
    nested_target_stage_requirement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _stage_requirement_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableShebangNestedTargetStageBinding:
    """One command bound through one nested-target staging requirement."""

    kind: str
    command_kind: str
    command_id: str = field(repr=False)
    command_digest: str = field(repr=False)
    staged_file_ref: str = field(repr=False)
    runtime_file_ref: str = field(repr=False)
    requirement_ref: str = field(repr=False)
    target_requirement_ref: str = field(repr=False)
    target_stage_requirement_ref: str = field(repr=False)
    target_runtime_requirement_ref: str = field(repr=False)
    target_shebang_requirement_ref: str = field(repr=False)
    nested_target_requirement_ref: str = field(repr=False)
    chain_guard_requirement_ref: str = field(repr=False)
    nested_target_stage_requirement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _stage_binding_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableShebangNestedTargetStagingReceipt:
    """Historical evidence for one guarded nested-target staging lease."""

    kind: str
    schema_version: int
    staging_source: str
    staging_scope: str
    inspection_source: str
    guard_scope: str
    resolution_depth: int
    maximum_resolution_depth: int
    nested_target_resolution_receipt_digest: str = field(repr=False)
    expected_chain_guard_receipt_digest: str = field(repr=False)
    action_chain_guard_receipt_digest: str = field(repr=False)
    post_stage_chain_guard_receipt_digest: str = field(repr=False)
    target_shebang_requirements_receipt_digest: str = field(repr=False)
    target_runtime_manifest_receipt_digest: str = field(repr=False)
    target_staging_receipt_digest: str = field(repr=False)
    target_resolution_receipt_digest: str = field(repr=False)
    shebang_requirements_receipt_digest: str = field(repr=False)
    runtime_manifest_receipt_digest: str = field(repr=False)
    source_staging_receipt_digest: str = field(repr=False)
    registration_digest: str = field(repr=False)
    repository_ref: str = field(repr=False)
    verification_commands_digest: str = field(repr=False)
    resolution_context_digest: str = field(repr=False)
    source_staging_context_digest: str = field(repr=False)
    target_path_context_digest: str = field(repr=False)
    target_staging_context_digest: str = field(repr=False)
    nested_target_path_context_digest: str = field(repr=False)
    known_source_identity_set_digest: str = field(repr=False)
    known_target_identity_set_digest: str = field(repr=False)
    protected_staging_root_identity_set_digest: str = field(repr=False)
    guard_summary_ref: str = field(repr=False)
    nested_target_staging_context_digest: str = field(repr=False)
    staging_root_used: bool
    staged_files: tuple[
        RepositoryExecutableShebangNestedTargetStagedFile, ...
    ] = field(repr=False)
    requirements: tuple[
        RepositoryExecutableShebangNestedTargetStageRequirement, ...
    ] = field(repr=False)
    bindings: tuple[
        RepositoryExecutableShebangNestedTargetStageBinding, ...
    ] = field(repr=False)
    requirement_count: int
    command_count: int
    known_chain_guard_staged_count: int
    target_native_not_applicable_count: int
    source_native_not_applicable_count: int
    unique_nested_target_count: int
    total_staged_bytes: int

    def to_canonical(self) -> dict[str, Any]:
        return _staging_receipt_projection(self)

    @property
    def receipt_digest(self) -> str:
        return _BUILTIN_CANONICAL_DIGEST(_staging_receipt_projection(self))

    def to_evidence(self) -> dict[str, Any]:
        return _staging_evidence_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableShebangNestedTargetStageCleanupReceipt:
    """Bounded cleanup evidence for one nested-target staging lease."""

    kind: str
    schema_version: int
    outcome: _CleanupOutcome
    nested_target_staging_receipt_digest: str | None = field(repr=False)
    owned_namespace_absence_verified: bool
    descriptor_release_complete: bool
    staging_root_identity_verified: bool
    staging_root_metadata_restored: bool
    secure_erasure_verified: bool

    def to_canonical(self) -> dict[str, Any]:
        return _cleanup_receipt_projection(self)


@dataclass(frozen=True, slots=True)
class _CapturedNestedTarget:
    nested_target_path_ref: str = field(repr=False)
    source_identity: tuple[int, int] = field(repr=False)
    source_filesystem_identity_ref: str = field(repr=False)
    source_metadata: tuple[int, ...] = field(repr=False)
    source_metadata_digest: str = field(repr=False)
    content_digest: str = field(repr=False)
    content: tuple[bytes, ...] = field(repr=False)


@dataclass(frozen=True, slots=True)
class _RetainedStagedNestedTarget:
    staged_file: RepositoryExecutableShebangNestedTargetStagedFile = field(
        repr=False
    )
    descriptor: int = field(repr=False)
    metadata: tuple[int, ...] = field(repr=False)


@dataclass(slots=True)
class RepositoryExecutableShebangNestedTargetStageLease:
    """Caller-scoped one-shot lease for detached nested-target bytes."""

    staging_root: Path = field(repr=False)
    _receipt: RepositoryExecutableShebangNestedTargetStagingReceipt | None = (
        field(default=None, init=False, repr=False)
    )
    _cleanup_receipt: (
        RepositoryExecutableShebangNestedTargetStageCleanupReceipt | None
    ) = field(default=None, init=False, repr=False)
    _receipt_digest_anchor: str | None = field(
        default=None, init=False, repr=False
    )
    _receipt_object_anchor: (
        RepositoryExecutableShebangNestedTargetStagingReceipt | None
    ) = field(default=None, init=False, repr=False)
    _receipt_file_refs_anchor: tuple[str, ...] = field(
        default=(), init=False, repr=False
    )
    _files_object_anchor: (
        tuple[_RetainedStagedNestedTarget, ...] | None
    ) = field(default=None, init=False, repr=False)
    _cleanup_receipt_digest_anchor: str | None = field(
        default=None, init=False, repr=False
    )
    _cleanup_receipt_object_anchor: (
        RepositoryExecutableShebangNestedTargetStageCleanupReceipt | None
    ) = field(default=None, init=False, repr=False)
    _state: _LeaseState = field(default="new", init=False, repr=False)
    _owner_pid: int = field(default_factory=os.getpid, init=False, repr=False)
    _files: tuple[_RetainedStagedNestedTarget, ...] = field(
        default=(), init=False, repr=False
    )
    _root_descriptor: int | None = field(
        default=None, init=False, repr=False
    )
    _root_metadata: tuple[int, ...] | None = field(
        default=None, init=False, repr=False
    )
    _pending_name: str | None = field(
        default=None, init=False, repr=False
    )
    _pending_identity: tuple[int, int] | None = field(
        default=None, init=False, repr=False
    )
    _pending_descriptors: tuple[int, ...] = field(
        default=(), init=False, repr=False
    )
    _descriptor_release_unverifiable: bool = field(
        default=False, init=False, repr=False
    )

    @property
    def state(self) -> str:
        return self._state

    @property
    def receipt(
        self,
    ) -> RepositoryExecutableShebangNestedTargetStagingReceipt | None:
        return self._receipt

    @property
    def cleanup_receipt(
        self,
    ) -> RepositoryExecutableShebangNestedTargetStageCleanupReceipt | None:
        return self._cleanup_receipt

    def cleanup(
        self,
    ) -> RepositoryExecutableShebangNestedTargetStageCleanupReceipt:
        return cleanup_repository_executable_shebang_nested_target_stage(self)

    def close(
        self,
    ) -> RepositoryExecutableShebangNestedTargetStageCleanupReceipt:
        return cleanup_repository_executable_shebang_nested_target_stage(self)

    def __enter__(
        self,
    ) -> "RepositoryExecutableShebangNestedTargetStageLease":
        if self._state != "active" or self._owner_pid != os.getpid():
            raise ValidationError(_INVALID_MESSAGE)
        return self

    def __exit__(self, *unused: object) -> None:
        cleanup_repository_executable_shebang_nested_target_stage(self)

    def __copy__(self) -> None:
        raise TypeError(_COPY_ERROR_MESSAGE)

    def __deepcopy__(self, memo: object) -> None:
        raise TypeError(_COPY_ERROR_MESSAGE)

    def __reduce__(self) -> None:
        raise TypeError(_COPY_ERROR_MESSAGE)

    def __reduce_ex__(self, protocol: int) -> None:
        raise TypeError(_COPY_ERROR_MESSAGE)


_FIXED_STAGED_FILE_TYPE = (
    RepositoryExecutableShebangNestedTargetStagedFile
)
_FIXED_STAGE_REQUIREMENT_TYPE = (
    RepositoryExecutableShebangNestedTargetStageRequirement
)
_FIXED_STAGE_BINDING_TYPE = (
    RepositoryExecutableShebangNestedTargetStageBinding
)
_FIXED_STAGING_RECEIPT_TYPE = (
    RepositoryExecutableShebangNestedTargetStagingReceipt
)
_FIXED_CLEANUP_RECEIPT_TYPE = (
    RepositoryExecutableShebangNestedTargetStageCleanupReceipt
)
_FIXED_LEASE_TYPE = RepositoryExecutableShebangNestedTargetStageLease
_FIXED_RETAINED_TYPE = _RetainedStagedNestedTarget
_FIXED_CAPTURED_TYPE = _CapturedNestedTarget


def _is_digest(value: Any) -> bool:
    return type(value) is str and _DIGEST_PATTERN.fullmatch(value) is not None


def _staged_file_ref_projection(
    *,
    nested_target_path_ref: str,
    source_filesystem_identity_ref: str,
    source_metadata_digest: str,
    nested_target_measurement_ref: str,
    guarded_measurement_ref: str,
    staged_filesystem_identity_ref: str,
    staged_metadata_digest: str,
    content_digest: str,
    content_bytes: int,
    nested_target_staging_context_digest: str,
) -> dict[str, Any]:
    digests = (
        nested_target_path_ref,
        source_filesystem_identity_ref,
        source_metadata_digest,
        nested_target_measurement_ref,
        guarded_measurement_ref,
        staged_filesystem_identity_ref,
        staged_metadata_digest,
        content_digest,
        nested_target_staging_context_digest,
    )
    if (
        not all(_is_digest(item) for item in digests)
        or type(content_bytes) is not int
        or not 0 <= content_bytes <= _MAX_FILE_BYTES
    ):
        raise _InvalidNestedTargetStaging
    return {
        "content_bytes": content_bytes,
        "content_digest": content_digest,
        "guarded_measurement_ref": guarded_measurement_ref,
        "kind": (
            "repository_executable_shebang_nested_target_staged_file_ref"
        ),
        "nested_target_measurement_ref": nested_target_measurement_ref,
        "nested_target_path_ref": nested_target_path_ref,
        "nested_target_staging_context_digest": (
            nested_target_staging_context_digest
        ),
        "schema_version": (
            REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_STAGING_SCHEMA_VERSION
        ),
        "source_filesystem_identity_ref": source_filesystem_identity_ref,
        "source_metadata_digest": source_metadata_digest,
        "staged_filesystem_identity_ref": staged_filesystem_identity_ref,
        "staged_metadata_digest": staged_metadata_digest,
    }


def _staged_file_projection(
    value: RepositoryExecutableShebangNestedTargetStagedFile,
    *,
    staging_context_digest: str | None = None,
) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_STAGED_FILE_TYPE
        or value.kind
        != REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_STAGED_FILE_KIND
        or any(
            not _is_digest(item)
            for item in (
                value.nested_target_path_ref,
                value.source_filesystem_identity_ref,
                value.source_metadata_digest,
                value.nested_target_measurement_ref,
                value.guarded_measurement_ref,
                value.nested_target_staged_file_ref,
                value.staged_filesystem_identity_ref,
                value.staged_metadata_digest,
                value.content_digest,
            )
        )
        or type(value.content_bytes) is not int
        or not 0 <= value.content_bytes <= _MAX_FILE_BYTES
    ):
        raise _InvalidNestedTargetStaging
    if staging_context_digest is not None:
        reference = _staged_file_ref_projection(
            nested_target_path_ref=value.nested_target_path_ref,
            source_filesystem_identity_ref=(
                value.source_filesystem_identity_ref
            ),
            source_metadata_digest=value.source_metadata_digest,
            nested_target_measurement_ref=(
                value.nested_target_measurement_ref
            ),
            guarded_measurement_ref=value.guarded_measurement_ref,
            staged_filesystem_identity_ref=(
                value.staged_filesystem_identity_ref
            ),
            staged_metadata_digest=value.staged_metadata_digest,
            content_digest=value.content_digest,
            content_bytes=value.content_bytes,
            nested_target_staging_context_digest=staging_context_digest,
        )
        if (
            value.nested_target_staged_file_ref
            != _BUILTIN_CANONICAL_DIGEST(reference)
        ):
            raise _InvalidNestedTargetStaging
    return {
        "content_bytes": value.content_bytes,
        "content_digest": value.content_digest,
        "guarded_measurement_ref": value.guarded_measurement_ref,
        "kind": value.kind,
        "nested_target_measurement_ref": value.nested_target_measurement_ref,
        "nested_target_path_ref": value.nested_target_path_ref,
        "nested_target_staged_file_ref": (
            value.nested_target_staged_file_ref
        ),
        "source_filesystem_identity_ref": (
            value.source_filesystem_identity_ref
        ),
        "source_metadata_digest": value.source_metadata_digest,
        "staged_filesystem_identity_ref": (
            value.staged_filesystem_identity_ref
        ),
        "staged_metadata_digest": value.staged_metadata_digest,
    }


def _stage_requirement_ref_projection(
    *,
    chain_guard_requirement_ref: str,
    disposition: str,
    nested_target_measurement_ref: str | None,
    guarded_measurement_ref: str | None,
    nested_target_staged_file_ref: str | None,
) -> dict[str, Any]:
    if (
        not _is_digest(chain_guard_requirement_ref)
        or disposition not in _STAGE_DISPOSITIONS
        or any(
            item is not None and not _is_digest(item)
            for item in (
                nested_target_measurement_ref,
                guarded_measurement_ref,
                nested_target_staged_file_ref,
            )
        )
        or (
            disposition == "known_chain_guard_staged"
            and (
                nested_target_measurement_ref is None
                or guarded_measurement_ref is None
                or nested_target_staged_file_ref is None
            )
        )
        or (
            disposition != "known_chain_guard_staged"
            and any(
                item is not None
                for item in (
                    nested_target_measurement_ref,
                    guarded_measurement_ref,
                    nested_target_staged_file_ref,
                )
            )
        )
    ):
        raise _InvalidNestedTargetStaging
    return {
        "chain_guard_requirement_ref": chain_guard_requirement_ref,
        "disposition": disposition,
        "guarded_measurement_ref": guarded_measurement_ref,
        "kind": (
            "repository_executable_shebang_nested_target_"
            "stage_requirement_ref"
        ),
        "nested_target_measurement_ref": nested_target_measurement_ref,
        "nested_target_staged_file_ref": nested_target_staged_file_ref,
        "schema_version": (
            REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_STAGING_SCHEMA_VERSION
        ),
        "staging_scope": STAGING_SCOPE,
    }


def _stage_requirement_projection(
    value: RepositoryExecutableShebangNestedTargetStageRequirement,
) -> dict[str, Any]:
    lineage = (
        value.staged_file_ref,
        value.runtime_file_ref,
        value.requirement_ref,
        value.target_requirement_ref,
        value.target_stage_requirement_ref,
        value.target_runtime_requirement_ref,
        value.target_shebang_requirement_ref,
        value.nested_target_requirement_ref,
        value.chain_guard_requirement_ref,
    )
    if (
        type(value) is not _FIXED_STAGE_REQUIREMENT_TYPE
        or value.kind
        != REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_STAGE_REQUIREMENT_KIND
        or not all(_is_digest(item) for item in lineage)
    ):
        raise _InvalidNestedTargetStaging
    reference = _stage_requirement_ref_projection(
        chain_guard_requirement_ref=value.chain_guard_requirement_ref,
        disposition=value.disposition,
        nested_target_measurement_ref=value.nested_target_measurement_ref,
        guarded_measurement_ref=value.guarded_measurement_ref,
        nested_target_staged_file_ref=value.nested_target_staged_file_ref,
    )
    if (
        value.nested_target_stage_requirement_ref
        != _BUILTIN_CANONICAL_DIGEST(reference)
    ):
        raise _InvalidNestedTargetStaging
    return {
        "chain_guard_requirement_ref": value.chain_guard_requirement_ref,
        "disposition": value.disposition,
        "guarded_measurement_ref": value.guarded_measurement_ref,
        "kind": value.kind,
        "nested_target_measurement_ref": value.nested_target_measurement_ref,
        "nested_target_requirement_ref": value.nested_target_requirement_ref,
        "nested_target_stage_requirement_ref": (
            value.nested_target_stage_requirement_ref
        ),
        "nested_target_staged_file_ref": (
            value.nested_target_staged_file_ref
        ),
        "requirement_ref": value.requirement_ref,
        "runtime_file_ref": value.runtime_file_ref,
        "staged_file_ref": value.staged_file_ref,
        "target_requirement_ref": value.target_requirement_ref,
        "target_runtime_requirement_ref": (
            value.target_runtime_requirement_ref
        ),
        "target_shebang_requirement_ref": (
            value.target_shebang_requirement_ref
        ),
        "target_stage_requirement_ref": value.target_stage_requirement_ref,
    }


def _stage_binding_projection(
    value: RepositoryExecutableShebangNestedTargetStageBinding,
) -> dict[str, Any]:
    lineage = (
        value.command_digest,
        value.staged_file_ref,
        value.runtime_file_ref,
        value.requirement_ref,
        value.target_requirement_ref,
        value.target_stage_requirement_ref,
        value.target_runtime_requirement_ref,
        value.target_shebang_requirement_ref,
        value.nested_target_requirement_ref,
        value.chain_guard_requirement_ref,
        value.nested_target_stage_requirement_ref,
    )
    if (
        type(value) is not _FIXED_STAGE_BINDING_TYPE
        or value.kind
        != REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_STAGE_BINDING_KIND
        or value.command_kind not in _COMMAND_KINDS
        or type(value.command_id) is not str
        or _IDENTIFIER_PATTERN.fullmatch(value.command_id) is None
        or not all(_is_digest(item) for item in lineage)
    ):
        raise _InvalidNestedTargetStaging
    return {
        "chain_guard_requirement_ref": value.chain_guard_requirement_ref,
        "command_digest": value.command_digest,
        "command_id": value.command_id,
        "command_kind": value.command_kind,
        "kind": value.kind,
        "nested_target_requirement_ref": value.nested_target_requirement_ref,
        "nested_target_stage_requirement_ref": (
            value.nested_target_stage_requirement_ref
        ),
        "requirement_ref": value.requirement_ref,
        "runtime_file_ref": value.runtime_file_ref,
        "staged_file_ref": value.staged_file_ref,
        "target_requirement_ref": value.target_requirement_ref,
        "target_runtime_requirement_ref": (
            value.target_runtime_requirement_ref
        ),
        "target_shebang_requirement_ref": (
            value.target_shebang_requirement_ref
        ),
        "target_stage_requirement_ref": value.target_stage_requirement_ref,
    }


def _staging_receipt_projection(
    value: RepositoryExecutableShebangNestedTargetStagingReceipt,
) -> dict[str, Any]:
    digest_fields = (
        value.nested_target_resolution_receipt_digest,
        value.expected_chain_guard_receipt_digest,
        value.action_chain_guard_receipt_digest,
        value.post_stage_chain_guard_receipt_digest,
        value.target_shebang_requirements_receipt_digest,
        value.target_runtime_manifest_receipt_digest,
        value.target_staging_receipt_digest,
        value.target_resolution_receipt_digest,
        value.shebang_requirements_receipt_digest,
        value.runtime_manifest_receipt_digest,
        value.source_staging_receipt_digest,
        value.registration_digest,
        value.repository_ref,
        value.verification_commands_digest,
        value.resolution_context_digest,
        value.source_staging_context_digest,
        value.target_path_context_digest,
        value.target_staging_context_digest,
        value.nested_target_path_context_digest,
        value.known_source_identity_set_digest,
        value.known_target_identity_set_digest,
        value.protected_staging_root_identity_set_digest,
        value.guard_summary_ref,
        value.nested_target_staging_context_digest,
    )
    counts = (
        value.requirement_count,
        value.command_count,
        value.known_chain_guard_staged_count,
        value.target_native_not_applicable_count,
        value.source_native_not_applicable_count,
        value.unique_nested_target_count,
        value.total_staged_bytes,
    )
    if (
        type(value) is not _FIXED_STAGING_RECEIPT_TYPE
        or value.kind
        != REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_STAGING_KIND
        or value.schema_version
        != REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_STAGING_SCHEMA_VERSION
        or value.staging_source != STAGING_SOURCE
        or value.staging_scope != STAGING_SCOPE
        or value.inspection_source != INSPECTION_SOURCE
        or value.guard_scope != GUARD_SCOPE
        or value.resolution_depth != RESOLUTION_DEPTH
        or value.maximum_resolution_depth != MAXIMUM_RESOLUTION_DEPTH
        or not all(_is_digest(item) for item in digest_fields)
        or value.expected_chain_guard_receipt_digest
        != value.action_chain_guard_receipt_digest
        or value.expected_chain_guard_receipt_digest
        != value.post_stage_chain_guard_receipt_digest
        or type(value.staging_root_used) is not bool
        or type(value.staged_files) is not tuple
        or len(value.staged_files) > _MAX_FILES
        or type(value.requirements) is not tuple
        or len(value.requirements) > _MAX_REQUIREMENTS
        or type(value.bindings) is not tuple
        or len(value.bindings) > _MAX_COMMANDS
        or any(type(item) is not int or item < 0 for item in counts)
        or value.requirement_count != len(value.requirements)
        or value.command_count != len(value.bindings)
        or value.unique_nested_target_count != len(value.staged_files)
        or value.total_staged_bytes > _MAX_TOTAL_BYTES
        or value.staging_root_used != bool(value.staged_files)
    ):
        raise _InvalidNestedTargetStaging

    staged_files = [
        _staged_file_projection(
            item,
            staging_context_digest=(
                value.nested_target_staging_context_digest
            ),
        )
        for item in value.staged_files
    ]
    requirements = [
        _stage_requirement_projection(item) for item in value.requirements
    ]
    bindings = [_stage_binding_projection(item) for item in value.bindings]

    files_by_measurement: dict[
        str,
        RepositoryExecutableShebangNestedTargetStagedFile,
    ] = {}
    staged_refs: set[str] = set()
    identities: set[str] = set()
    total_bytes = 0
    for item in value.staged_files:
        if (
            item.nested_target_measurement_ref in files_by_measurement
            or item.nested_target_staged_file_ref in staged_refs
            or item.staged_filesystem_identity_ref in identities
        ):
            raise _InvalidNestedTargetStaging
        files_by_measurement[item.nested_target_measurement_ref] = item
        staged_refs.add(item.nested_target_staged_file_ref)
        identities.add(item.staged_filesystem_identity_ref)
        total_bytes += item.content_bytes

    requirements_by_guard: dict[
        str,
        RepositoryExecutableShebangNestedTargetStageRequirement,
    ] = {}
    stage_requirement_refs: set[str] = set()
    used_staged_refs: list[str] = []
    seen_staged_refs: set[str] = set()
    disposition_counts = {item: 0 for item in _STAGE_DISPOSITIONS}
    for item in value.requirements:
        if (
            item.chain_guard_requirement_ref in requirements_by_guard
            or item.nested_target_stage_requirement_ref
            in stage_requirement_refs
        ):
            raise _InvalidNestedTargetStaging
        if item.disposition == "known_chain_guard_staged":
            if item.nested_target_measurement_ref is None:
                raise _InvalidNestedTargetStaging
            staged = files_by_measurement.get(
                item.nested_target_measurement_ref
            )
            if (
                staged is None
                or item.guarded_measurement_ref
                != staged.guarded_measurement_ref
                or item.nested_target_staged_file_ref
                != staged.nested_target_staged_file_ref
            ):
                raise _InvalidNestedTargetStaging
            if staged.nested_target_staged_file_ref not in seen_staged_refs:
                used_staged_refs.append(staged.nested_target_staged_file_ref)
                seen_staged_refs.add(staged.nested_target_staged_file_ref)
        requirements_by_guard[item.chain_guard_requirement_ref] = item
        stage_requirement_refs.add(item.nested_target_stage_requirement_ref)
        disposition_counts[item.disposition] += 1
    if (
        tuple(used_staged_refs)
        != tuple(
            item.nested_target_staged_file_ref for item in value.staged_files
        )
        or disposition_counts["known_chain_guard_staged"]
        != value.known_chain_guard_staged_count
        or disposition_counts["target_native_not_applicable"]
        != value.target_native_not_applicable_count
        or disposition_counts["source_native_not_applicable"]
        != value.source_native_not_applicable_count
        or total_bytes != value.total_staged_bytes
    ):
        raise _InvalidNestedTargetStaging

    command_ids: set[str] = set()
    bound_guards: set[str] = set()
    prior_kind_index = -1
    for item in value.bindings:
        expected = requirements_by_guard.get(
            item.chain_guard_requirement_ref
        )
        kind_index = _COMMAND_KINDS.index(item.command_kind)
        if (
            expected is None
            or item.command_id in command_ids
            or kind_index < prior_kind_index
            or item.nested_target_stage_requirement_ref
            != expected.nested_target_stage_requirement_ref
            or item.nested_target_requirement_ref
            != expected.nested_target_requirement_ref
            or item.staged_file_ref != expected.staged_file_ref
            or item.runtime_file_ref != expected.runtime_file_ref
            or item.requirement_ref != expected.requirement_ref
            or item.target_requirement_ref != expected.target_requirement_ref
            or item.target_stage_requirement_ref
            != expected.target_stage_requirement_ref
            or item.target_runtime_requirement_ref
            != expected.target_runtime_requirement_ref
            or item.target_shebang_requirement_ref
            != expected.target_shebang_requirement_ref
        ):
            raise _InvalidNestedTargetStaging
        command_ids.add(item.command_id)
        bound_guards.add(item.chain_guard_requirement_ref)
        prior_kind_index = kind_index
    if bound_guards != set(requirements_by_guard):
        raise _InvalidNestedTargetStaging

    return {
        "action_chain_guard_receipt_digest": (
            value.action_chain_guard_receipt_digest
        ),
        "bindings": bindings,
        "command_count": value.command_count,
        "expected_chain_guard_receipt_digest": (
            value.expected_chain_guard_receipt_digest
        ),
        "guard_scope": value.guard_scope,
        "guard_summary_ref": value.guard_summary_ref,
        "inspection_source": value.inspection_source,
        "kind": value.kind,
        "known_chain_guard_staged_count": (
            value.known_chain_guard_staged_count
        ),
        "known_source_identity_set_digest": (
            value.known_source_identity_set_digest
        ),
        "known_target_identity_set_digest": (
            value.known_target_identity_set_digest
        ),
        "maximum_resolution_depth": value.maximum_resolution_depth,
        "nested_target_path_context_digest": (
            value.nested_target_path_context_digest
        ),
        "nested_target_resolution_receipt_digest": (
            value.nested_target_resolution_receipt_digest
        ),
        "nested_target_staging_context_digest": (
            value.nested_target_staging_context_digest
        ),
        "post_stage_chain_guard_receipt_digest": (
            value.post_stage_chain_guard_receipt_digest
        ),
        "protected_staging_root_identity_set_digest": (
            value.protected_staging_root_identity_set_digest
        ),
        "registration_digest": value.registration_digest,
        "repository_ref": value.repository_ref,
        "requirement_count": value.requirement_count,
        "requirements": requirements,
        "resolution_context_digest": value.resolution_context_digest,
        "resolution_depth": value.resolution_depth,
        "runtime_manifest_receipt_digest": (
            value.runtime_manifest_receipt_digest
        ),
        "schema_version": value.schema_version,
        "shebang_requirements_receipt_digest": (
            value.shebang_requirements_receipt_digest
        ),
        "source_native_not_applicable_count": (
            value.source_native_not_applicable_count
        ),
        "source_staging_context_digest": (
            value.source_staging_context_digest
        ),
        "source_staging_receipt_digest": value.source_staging_receipt_digest,
        "staged_files": staged_files,
        "staging_root_used": value.staging_root_used,
        "staging_scope": value.staging_scope,
        "staging_source": value.staging_source,
        "target_native_not_applicable_count": (
            value.target_native_not_applicable_count
        ),
        "target_path_context_digest": value.target_path_context_digest,
        "target_resolution_receipt_digest": (
            value.target_resolution_receipt_digest
        ),
        "target_runtime_manifest_receipt_digest": (
            value.target_runtime_manifest_receipt_digest
        ),
        "target_shebang_requirements_receipt_digest": (
            value.target_shebang_requirements_receipt_digest
        ),
        "target_staging_context_digest": (
            value.target_staging_context_digest
        ),
        "target_staging_receipt_digest": value.target_staging_receipt_digest,
        "total_staged_bytes": value.total_staged_bytes,
        "unique_nested_target_count": value.unique_nested_target_count,
        "verification_commands_digest": value.verification_commands_digest,
    }


def _staging_evidence_projection(
    value: RepositoryExecutableShebangNestedTargetStagingReceipt,
) -> dict[str, Any]:
    canonical = _staging_receipt_projection(value)
    return {
        "action_boundary_guarded_nested_remeasurement_complete": True,
        "action_receipt_issued": False,
        "atomic_snapshot_verified": False,
        "authority_granted": False,
        "authorization_verified": False,
        "billing_eligible": False,
        "broader_protected_root_exclusion_verified": False,
        "capacity_eligible": False,
        "circuit_eligible": False,
        "command_count": canonical["command_count"],
        "controller_write_descriptors_closed": canonical[
            "staging_root_used"
        ],
        "crash_cleanup_verified": False,
        "current_freshness_verified": False,
        "current_lease_activity_verified": False,
        "dependency_environment_coverage_verified": False,
        "dispatch_enabled": False,
        "durable_control_plane_persistence_enabled": False,
        "dynamic_loader_identity_verified": False,
        "effect_class": 1,
        "effective_interpreter_resolution_verified": False,
        "effective_invocability_verified": False,
        "environment_coverage_verified": False,
        "exact_chain_guard_correspondence_verified": True,
        "exact_receipt_chain_verified": True,
        "execution_enabled": False,
        "external_hardlink_alias_excluded": False,
        "external_writable_descriptor_absence_verified": False,
        "filesystem_immutability_verified": False,
        "fork_descriptor_inheritance_excluded": False,
        "future_execution_correspondence_verified": False,
        "generic_cycle_closure_verified": False,
        "guard_scope": canonical["guard_scope"],
        "harness_invocation_performed": False,
        "hardlink_alias_exclusion_verified": False,
        "interpreter_argument_semantics_verified": False,
        "interpreter_authenticity_verified": False,
        "interpreter_compatibility_verified": False,
        "interpreter_identity_verified": False,
        "interpreter_provenance_verified": False,
        "kind": (
            REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_STAGING_EVIDENCE_KIND
        ),
        "known_chain_guard_staged_count": canonical[
            "known_chain_guard_staged_count"
        ],
        "lease_process_binding_established": True,
        "live_execution_eligible": False,
        "maximum_resolution_depth": canonical[
            "maximum_resolution_depth"
        ],
        "model_invocation_performed": False,
        "mount_alias_exclusion_verified": False,
        "nested_target_paths_exposed": False,
        "post_stage_chain_guard_correspondence_verified": True,
        "proposal_lineage_extended": False,
        "read_only_descriptor_lease_established": canonical[
            "staging_root_used"
        ],
        "receipt_authenticity_verified": False,
        "receipt_digest": _BUILTIN_CANONICAL_DIGEST(canonical),
        "registration_digest": canonical["registration_digest"],
        "repository_ref": canonical["repository_ref"],
        "requirement_count": canonical["requirement_count"],
        "resolution_depth": canonical["resolution_depth"],
        "resolution_context_digest": canonical[
            "resolution_context_digest"
        ],
        "route_eligible": False,
        "same_uid_tamper_exclusion_verified": False,
        "schema_version": canonical["schema_version"],
        "secure_erasure_verified": False,
        "shared_library_identity_verified": False,
        "source_native_not_applicable_count": canonical[
            "source_native_not_applicable_count"
        ],
        "staged_byte_correspondence_verified": True,
        "staged_readback_complete": canonical["staging_root_used"],
        "staging_root_used": canonical["staging_root_used"],
        "staging_scope": canonical["staging_scope"],
        "staging_source": canonical["staging_source"],
        "subprocess_invocation_performed": False,
        "target_native_not_applicable_count": canonical[
            "target_native_not_applicable_count"
        ],
        "target_semantics_verified": False,
        "temporary_names_exposed": False,
        "toolchain_completeness_verified": False,
        "total_staged_bytes": canonical["total_staged_bytes"],
        "unique_nested_target_count": canonical[
            "unique_nested_target_count"
        ],
        "validation_mode": "local_staging",
        "worktree_integration_enabled": False,
        "worker_enabled": False,
    }


def _cleanup_receipt_projection(
    value: RepositoryExecutableShebangNestedTargetStageCleanupReceipt,
) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_CLEANUP_RECEIPT_TYPE
        or value.kind
        != REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_STAGE_CLEANUP_KIND
        or value.schema_version
        != REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_STAGING_SCHEMA_VERSION
        or value.outcome
        not in {"removed", "already_absent_verified", "unverifiable"}
        or (
            value.nested_target_staging_receipt_digest is not None
            and not _is_digest(
                value.nested_target_staging_receipt_digest
            )
        )
        or any(
            type(item) is not bool
            for item in (
                value.owned_namespace_absence_verified,
                value.descriptor_release_complete,
                value.staging_root_identity_verified,
                value.staging_root_metadata_restored,
                value.secure_erasure_verified,
            )
        )
        or value.staging_root_metadata_restored
        or value.secure_erasure_verified
        or (
            value.outcome == "unverifiable"
            and (
                value.owned_namespace_absence_verified
                or value.descriptor_release_complete
            )
        )
        or (
            value.outcome != "unverifiable"
            and (
                not value.owned_namespace_absence_verified
                or not value.descriptor_release_complete
            )
        )
    ):
        raise _InvalidNestedTargetStaging
    return {
        "descriptor_release_complete": value.descriptor_release_complete,
        "kind": value.kind,
        "nested_target_staging_receipt_digest": (
            value.nested_target_staging_receipt_digest
        ),
        "outcome": value.outcome,
        "owned_namespace_absence_verified": (
            value.owned_namespace_absence_verified
        ),
        "schema_version": value.schema_version,
        "secure_erasure_verified": value.secure_erasure_verified,
        "staging_root_identity_verified": (
            value.staging_root_identity_verified
        ),
        "staging_root_metadata_restored": (
            value.staging_root_metadata_restored
        ),
    }


_BUILTIN_STAGING_RECEIPT_PROJECTION = _staging_receipt_projection
_BUILTIN_CLEANUP_RECEIPT_PROJECTION = _cleanup_receipt_projection


def _require_supported_platform() -> None:
    required = (
        getattr(os, "O_RDONLY", None),
        getattr(os, "O_WRONLY", None),
        getattr(os, "O_CREAT", None),
        getattr(os, "O_EXCL", None),
        getattr(os, "O_NOFOLLOW", None),
        getattr(os, "O_CLOEXEC", None),
        getattr(os, "O_NONBLOCK", None),
        getattr(os, "O_ACCMODE", None),
    )
    if (
        os.name != "posix"
        or any(type(item) is not int or item < 0 for item in required)
        or os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.stat not in os.supports_follow_symlinks
        or os.unlink not in os.supports_dir_fd
    ):
        raise _InvalidNestedTargetStaging


def _metadata_signature(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _require_new_lease(
    value: Any,
) -> RepositoryExecutableShebangNestedTargetStageLease:
    if (
        type(value) is not _FIXED_LEASE_TYPE
        or value._state != "new"
        or type(value._owner_pid) is not int
        or value._owner_pid <= 0
        or value._owner_pid != os.getpid()
        or value._receipt is not None
        or value._cleanup_receipt is not None
        or value._receipt_digest_anchor is not None
        or value._receipt_object_anchor is not None
        or value._receipt_file_refs_anchor != ()
        or value._files_object_anchor is not None
        or value._cleanup_receipt_digest_anchor is not None
        or value._cleanup_receipt_object_anchor is not None
        or value._files != ()
        or value._root_descriptor is not None
        or value._root_metadata is not None
        or value._pending_name is not None
        or value._pending_identity is not None
        or value._pending_descriptors != ()
        or value._descriptor_release_unverifiable
    ):
        raise _InvalidNestedTargetStaging
    return value


class _NestedTargetCaptureSink:
    """Copy bounded bytes through each guarded action measurement's FD."""

    def __init__(self) -> None:
        self.by_path_ref: dict[str, _CapturedNestedTarget] = {}
        self.total_bytes = 0

    def __call__(
        self,
        descriptor: int,
        metadata: os.stat_result,
        measured: _MeasuredNestedTarget,
    ) -> None:
        if (
            type(measured) is not _FIXED_MEASURED_NESTED_TARGET_TYPE
            or measured.path_ref in self.by_path_ref
            or len(self.by_path_ref) >= _MAX_FILES
            or type(measured.metadata) is not tuple
            or len(measured.metadata) != 9
            or measured.content_bytes != metadata.st_size
            or measured.content_bytes < 0
            or measured.content_bytes > _MAX_FILE_BYTES
            or self.total_bytes + measured.content_bytes > _MAX_TOTAL_BYTES
        ):
            raise _InvalidNestedTargetStaging
        try:
            before = os.fstat(descriptor)
            status_flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
            descriptor_flags = fcntl.fcntl(descriptor, fcntl.F_GETFD)
            position = os.lseek(descriptor, 0, os.SEEK_CUR)
            inheritable = os.get_inheritable(descriptor)
        except (OSError, ValueError):
            raise _InvalidNestedTargetStaging from None
        if (
            _metadata_signature(before) != measured.metadata
            or _metadata_signature(metadata) != measured.metadata
            or (before.st_dev, before.st_ino) != measured.identity
            or status_flags & os.O_ACCMODE != os.O_RDONLY
            or position != measured.content_bytes
            or inheritable
        ):
            raise _InvalidNestedTargetStaging

        digest = _BUILTIN_SHA256()
        chunks: list[bytes] = []
        offset = 0
        while offset < measured.content_bytes:
            try:
                chunk = os.pread(
                    descriptor,
                    min(
                        _READ_CHUNK_BYTES,
                        measured.content_bytes - offset,
                    ),
                    offset,
                )
            except (BlockingIOError, InterruptedError, OSError):
                raise _InvalidNestedTargetStaging from None
            if not chunk or len(chunk) > measured.content_bytes - offset:
                raise _InvalidNestedTargetStaging
            chunks.append(chunk)
            digest.update(chunk)
            offset += len(chunk)
        try:
            boundary = os.pread(descriptor, 1, measured.content_bytes)
            after = os.fstat(descriptor)
            after_status_flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
            after_descriptor_flags = fcntl.fcntl(descriptor, fcntl.F_GETFD)
            after_position = os.lseek(descriptor, 0, os.SEEK_CUR)
            after_inheritable = os.get_inheritable(descriptor)
        except (OSError, ValueError):
            raise _InvalidNestedTargetStaging from None
        content_digest = _DIGEST_PREFIX + digest.hexdigest()
        if (
            boundary != b""
            or _metadata_signature(after) != measured.metadata
            or after_status_flags != status_flags
            or after_descriptor_flags != descriptor_flags
            or after_position != position
            or after_inheritable != inheritable
            or content_digest != measured.content_digest
        ):
            raise _InvalidNestedTargetStaging
        self.by_path_ref[measured.path_ref] = _FIXED_CAPTURED_TYPE(
            nested_target_path_ref=measured.path_ref,
            source_identity=measured.identity,
            source_filesystem_identity_ref=measured.filesystem_identity_ref,
            source_metadata=measured.metadata,
            source_metadata_digest=measured.metadata_digest,
            content_digest=content_digest,
            content=tuple(chunks),
        )
        self.total_bytes += measured.content_bytes

    def clear(self) -> None:
        self.by_path_ref.clear()
        self.total_bytes = 0


@dataclass(frozen=True, slots=True)
class _ProtectedContext:
    registration: RepositoryRegistration = field(repr=False)
    registration_canonical: dict[str, Any] = field(repr=False)
    repository: _PinnedDirectory = field(repr=False)
    searches: tuple[_PinnedDirectory, ...] = field(repr=False)
    source_staging_root: _PinnedDirectory = field(repr=False)
    target_staging_root: _PinnedDirectory | None = field(repr=False)
    resolution_context_digest: str = field(repr=False)

    @property
    def all_directories(self) -> tuple[_PinnedDirectory, ...]:
        target = (
            ()
            if self.target_staging_root is None
            else (self.target_staging_root,)
        )
        return (
            self.repository,
            *self.searches,
            self.source_staging_root,
            *target,
        )


def _close_protected_context(context: _ProtectedContext | None) -> None:
    if context is None:
        return
    for directory in reversed(context.all_directories):
        try:
            os.close(directory.descriptor)
        except OSError:
            pass


def _registration_and_search_context(
    registration: RepositoryRegistration,
    *,
    search_directories: tuple[Path, ...],
    expected_guard: (
        RepositoryExecutableShebangNestedTargetChainGuardReceipt
    ),
    expected_nested: RepositoryExecutableShebangNestedTargetResolutionReceipt,
    expected_source_staging: RepositoryExecutableStagingReceipt,
    source_lease: RepositoryExecutableStageLease,
    expected_target_staging: RepositoryExecutableShebangTargetStagingReceipt,
    target_lease: RepositoryExecutableShebangTargetStageLease,
) -> _ProtectedContext:
    if (
        type(registration) is not _FIXED_REGISTRATION_TYPE
        or type(registration.schema_version) is not int
        or registration.schema_version != 4
        or type(expected_guard) is not _FIXED_CHAIN_GUARD_TYPE
        or type(expected_nested) is not _FIXED_NESTED_RESOLUTION_TYPE
        or type(expected_source_staging) is not _FIXED_SOURCE_STAGING_TYPE
        or type(source_lease) is not _FIXED_SOURCE_LEASE_TYPE
        or type(expected_target_staging) is not _FIXED_TARGET_STAGING_TYPE
        or type(target_lease) is not _FIXED_TARGET_LEASE_TYPE
    ):
        raise _InvalidNestedTargetStaging
    source_canonical = _BUILTIN_SOURCE_STAGING_PROJECTION(
        expected_source_staging
    )
    target_canonical = _BUILTIN_TARGET_STAGING_PROJECTION(
        expected_target_staging
    )
    if (
        _BUILTIN_CANONICAL_DIGEST(source_canonical)
        != expected_guard.source_staging_receipt_digest
        or _BUILTIN_CANONICAL_DIGEST(target_canonical)
        != expected_guard.target_staging_receipt_digest
    ):
        raise _InvalidNestedTargetStaging
    refreshed = _BUILTIN_REVALIDATE_REGISTRATION(registration)
    if refreshed.schema_version != 4:
        raise _InvalidNestedTargetStaging
    canonical = _BUILTIN_REGISTRATION_PROJECTION(refreshed)
    registration_digest = _BUILTIN_CANONICAL_DIGEST(canonical)
    commands_digest = _BUILTIN_CANONICAL_DIGEST(
        canonical["verification_commands"]
    )
    if (
        registration_digest != expected_guard.registration_digest
        or registration_digest != expected_nested.registration_digest
        or registration_digest != expected_source_staging.registration_digest
        or registration_digest != expected_target_staging.registration_digest
        or refreshed.repository.repository_ref != expected_guard.repository_ref
        or refreshed.repository.repository_ref
        != expected_nested.repository_ref
        or refreshed.repository.repository_ref
        != expected_source_staging.repository_ref
        or refreshed.repository.repository_ref
        != expected_target_staging.repository_ref
        or commands_digest != expected_guard.verification_commands_digest
        or commands_digest != expected_nested.verification_commands_digest
        or commands_digest
        != expected_source_staging.verification_commands_digest
        or commands_digest
        != expected_target_staging.verification_commands_digest
    ):
        raise _InvalidNestedTargetStaging

    paths = _BUILTIN_VALIDATE_SEARCH_DIRECTORIES(search_directories)
    repository: _PinnedDirectory | None = None
    searches: list[_PinnedDirectory] = []
    source_root: _PinnedDirectory | None = None
    target_root: _PinnedDirectory | None = None
    try:
        repository = _BUILTIN_OPEN_ABSOLUTE_DIRECTORY(
            refreshed.repository.canonical_root
        )
        if refreshed.repository.root_ref != _BUILTIN_CANONICAL_DIGEST(
            {
                "root_device": repository.metadata[0],
                "root_inode": repository.metadata[1],
            }
        ):
            raise _InvalidNestedTargetStaging
        for path in paths:
            pinned = _BUILTIN_OPEN_ABSOLUTE_DIRECTORY(path)
            if any(
                existing.metadata[:2] == pinned.metadata[:2]
                for existing in (repository, *searches)
            ):
                try:
                    os.close(pinned.descriptor)
                except OSError:
                    pass
                raise _InvalidNestedTargetStaging
            searches.append(pinned)
        context_digest = _BUILTIN_RESOLUTION_CONTEXT_DIGEST(tuple(searches))
        if (
            context_digest != expected_guard.resolution_context_digest
            or context_digest != expected_nested.resolution_context_digest
            or context_digest
            != expected_source_staging.resolution_context_digest
            or context_digest
            != expected_target_staging.resolution_context_digest
        ):
            raise _InvalidNestedTargetStaging

        source_root = _BUILTIN_OPEN_ABSOLUTE_DIRECTORY(
            source_lease.staging_root
        )
        source_metadata = os.fstat(source_root.descriptor)
        source_context_digest = _BUILTIN_CANONICAL_DIGEST(
            {
                "directory_device": source_metadata.st_dev,
                "directory_inode": source_metadata.st_ino,
                "directory_mode": stat.S_IMODE(source_metadata.st_mode),
                "directory_owner": source_metadata.st_uid,
                "kind": "repository_executable_staging_context",
                "schema_version": 1,
                "staging_scope": SOURCE_STAGING_SCOPE,
            }
        )
        if (
            source_lease._root_metadata is None
            or source_root.metadata[:2] != source_lease._root_metadata[:2]
            or source_root.metadata[4:6]
            != source_lease._root_metadata[4:6]
            or stat.S_IMODE(source_root.metadata[2])
            != stat.S_IMODE(source_lease._root_metadata[2])
            or source_context_digest
            != expected_source_staging.staging_context_digest
            or source_context_digest
            != expected_guard.source_staging_context_digest
        ):
            raise _InvalidNestedTargetStaging

        if target_canonical["staging_root_used"]:
            target_root = _BUILTIN_OPEN_ABSOLUTE_DIRECTORY(
                target_lease.staging_root
            )
            target_metadata = os.fstat(target_root.descriptor)
            target_context_digest = _BUILTIN_CANONICAL_DIGEST(
                {
                    "directory_device": target_metadata.st_dev,
                    "directory_inode": target_metadata.st_ino,
                    "directory_mode": stat.S_IMODE(target_metadata.st_mode),
                    "directory_owner": target_metadata.st_uid,
                    "kind": (
                        "repository_executable_shebang_target_"
                        "staging_context"
                    ),
                    "schema_version": 1,
                    "staging_root_used": True,
                    "staging_scope": TARGET_STAGING_SCOPE,
                }
            )
            if (
                target_lease._root_metadata is None
                or target_root.metadata[:2]
                != target_lease._root_metadata[:2]
                or target_root.metadata[4:6]
                != target_lease._root_metadata[4:6]
                or stat.S_IMODE(target_root.metadata[2])
                != stat.S_IMODE(target_lease._root_metadata[2])
                or target_context_digest
                != expected_target_staging.target_staging_context_digest
                or target_context_digest
                != expected_guard.target_staging_context_digest
            ):
                raise _InvalidNestedTargetStaging
        elif (
            target_lease._root_metadata is not None
            or target_lease._root_descriptor is not None
        ):
            raise _InvalidNestedTargetStaging

        all_directories = (
            repository,
            *searches,
            source_root,
            *((target_root,) if target_root is not None else ()),
        )
        if len({item.metadata[:2] for item in all_directories}) != len(
            all_directories
        ):
            raise _InvalidNestedTargetStaging
        return _ProtectedContext(
            registration=refreshed,
            registration_canonical=canonical,
            repository=repository,
            searches=tuple(searches),
            source_staging_root=source_root,
            target_staging_root=target_root,
            resolution_context_digest=context_digest,
        )
    except BaseException:
        for directory in reversed(
            (
                *((target_root,) if target_root is not None else ()),
                *((source_root,) if source_root is not None else ()),
                *searches,
                *((repository,) if repository is not None else ()),
            )
        ):
            try:
                os.close(directory.descriptor)
            except OSError:
                pass
        raise


def _protected_context_still_matches(context: _ProtectedContext) -> bool:
    try:
        refreshed = _BUILTIN_REVALIDATE_REGISTRATION(context.registration)
        return bool(
            _BUILTIN_REGISTRATION_PROJECTION(refreshed)
            == context.registration_canonical
            and all(
                _BUILTIN_REOPEN_DIRECTORY_MATCHES(directory)
                for directory in context.all_directories
            )
            and _BUILTIN_RESOLUTION_CONTEXT_DIGEST(context.searches)
            == context.resolution_context_digest
        )
    except (AttributeError, OSError, TypeError, ValueError):
        return False


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
        raise _InvalidNestedTargetStaging from None


def _root_path_identity_matches(
    lease: RepositoryExecutableShebangNestedTargetStageLease,
) -> bool:
    expected = lease._root_metadata
    if expected is None:
        return False
    reopened: _PinnedDirectory | None = None
    try:
        reopened = _BUILTIN_OPEN_ABSOLUTE_DIRECTORY(lease.staging_root)
        metadata = os.fstat(reopened.descriptor)
        return bool(
            _metadata_signature(metadata)[:2] == expected[:2]
            and metadata.st_uid == expected[4]
            and metadata.st_gid == expected[5]
            and stat.S_IMODE(metadata.st_mode) == stat.S_IMODE(expected[2])
        )
    except (OSError, TypeError, ValueError, _InvalidResolution):
        return False
    finally:
        if reopened is not None:
            try:
                os.close(reopened.descriptor)
            except OSError:
                pass


def _nested_target_ancestor_aliases_root(
    paths: tuple[Path, ...],
    *,
    root_metadata: os.stat_result,
) -> bool:
    checked: set[tuple[str, ...]] = set()
    for path in paths:
        components = _BUILTIN_ABSOLUTE_PATH_PARTS(path)
        for count in range(len(components)):
            prefix = components[:count]
            if prefix in checked:
                continue
            checked.add(prefix)
            ancestor = Path(os.sep).joinpath(*prefix)
            pinned = _BUILTIN_OPEN_ABSOLUTE_DIRECTORY(ancestor)
            try:
                if (
                    pinned.metadata[0],
                    pinned.metadata[1],
                ) == (root_metadata.st_dev, root_metadata.st_ino):
                    return True
            finally:
                try:
                    os.close(pinned.descriptor)
                except OSError:
                    pass
    return False


def _noop_staging_context_digest() -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "kind": (
                "repository_executable_shebang_nested_target_"
                "staging_context"
            ),
            "schema_version": (
                REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_STAGING_SCHEMA_VERSION
            ),
            "staging_root_used": False,
            "staging_scope": STAGING_SCOPE,
        }
    )


def _prepare_staging_root(
    lease: RepositoryExecutableShebangNestedTargetStageLease,
    *,
    protected: _ProtectedContext,
    source_lease: RepositoryExecutableStageLease,
    target_lease: RepositoryExecutableShebangTargetStageLease,
    expected_nested_target_paths: tuple[Path, ...],
) -> str:
    if (
        type(lease.staging_root) is not _CONCRETE_PATH_TYPE
        or not lease.staging_root.is_absolute()
        or type(expected_nested_target_paths) is not tuple
        or any(
            type(path) is not _CONCRETE_PATH_TYPE
            for path in expected_nested_target_paths
        )
        or type(source_lease.staging_root) is not _CONCRETE_PATH_TYPE
        or type(target_lease.staging_root) is not _CONCRETE_PATH_TYPE
    ):
        raise _InvalidNestedTargetStaging
    _BUILTIN_ABSOLUTE_PATH_PARTS(lease.staging_root)
    protected_paths = (
        protected.repository.path,
        *(item.path for item in protected.searches),
        source_lease.staging_root,
        target_lease.staging_root,
        *expected_nested_target_paths,
    )
    for path in protected_paths:
        _BUILTIN_ABSOLUTE_PATH_PARTS(path)
        if _path_components_overlap(lease.staging_root, path):
            raise _InvalidNestedTargetStaging

    pinned: _PinnedDirectory | None = None
    try:
        pinned = _BUILTIN_OPEN_ABSOLUTE_DIRECTORY(lease.staging_root)
        metadata = os.fstat(pinned.descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != _STAGING_ROOT_MODE
            or metadata.st_nlink <= 0
            or os.get_inheritable(pinned.descriptor)
            or not _directory_is_empty(pinned.descriptor)
            or any(
                directory.metadata[:2] == (metadata.st_dev, metadata.st_ino)
                for directory in protected.all_directories
            )
            or _nested_target_ancestor_aliases_root(
                expected_nested_target_paths,
                root_metadata=metadata,
            )
        ):
            raise _InvalidNestedTargetStaging

        # Cleanup owns only roots that passed every non-mutating validation.
        lease._root_metadata = _metadata_signature(metadata)
        lease._root_descriptor = pinned.descriptor
    except BaseException:
        if pinned is not None and lease._root_descriptor != pinned.descriptor:
            try:
                os.close(pinned.descriptor)
            except OSError:
                lease._descriptor_release_unverifiable = True
        raise
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "directory_device": metadata.st_dev,
            "directory_inode": metadata.st_ino,
            "directory_mode": stat.S_IMODE(metadata.st_mode),
            "directory_owner": metadata.st_uid,
            "kind": (
                "repository_executable_shebang_nested_target_"
                "staging_context"
            ),
            "schema_version": (
                REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_STAGING_SCHEMA_VERSION
            ),
            "staging_root_used": True,
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
        raise _InvalidNestedTargetStaging
    return ".ordomata-shebang-nested-target-" + value


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
        raise _InvalidNestedTargetStaging from None


def _write_all(descriptor: int, chunks: tuple[bytes, ...]) -> None:
    for chunk in chunks:
        offset = 0
        while offset < len(chunk):
            try:
                written = os.write(descriptor, chunk[offset:])
            except (BlockingIOError, InterruptedError, OSError):
                raise _InvalidNestedTargetStaging from None
            if written <= 0:
                raise _InvalidNestedTargetStaging
            offset += written


def _descriptor_digest(descriptor: int, *, content_bytes: int) -> str:
    digest = _BUILTIN_SHA256()
    offset = 0
    while offset < content_bytes:
        try:
            chunk = os.pread(
                descriptor,
                min(_READ_CHUNK_BYTES, content_bytes - offset),
                offset,
            )
        except (BlockingIOError, InterruptedError, OSError):
            raise _InvalidNestedTargetStaging from None
        if not chunk or len(chunk) > content_bytes - offset:
            raise _InvalidNestedTargetStaging
        digest.update(chunk)
        offset += len(chunk)
    try:
        boundary = os.pread(descriptor, 1, content_bytes)
    except (BlockingIOError, InterruptedError, OSError):
        raise _InvalidNestedTargetStaging from None
    if boundary != b"":
        raise _InvalidNestedTargetStaging
    return _DIGEST_PREFIX + digest.hexdigest()


def _staged_identity_ref(metadata: os.stat_result) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "kind": (
                "repository_executable_shebang_nested_target_"
                "staged_file_identity"
            ),
            "schema_version": 1,
        }
    )


def _staged_metadata_digest(
    metadata: os.stat_result,
    *,
    identity_ref: str,
) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "change_time_ns": metadata.st_ctime_ns,
            "filesystem_identity_ref": identity_ref,
            "group_id": metadata.st_gid,
            "kind": (
                "repository_executable_shebang_nested_target_"
                "staged_file_metadata"
            ),
            "link_count": metadata.st_nlink,
            "mode": metadata.st_mode,
            "modified_time_ns": metadata.st_mtime_ns,
            "owner_id": metadata.st_uid,
            "schema_version": 1,
            "size_bytes": metadata.st_size,
        }
    )


def _close_descriptor(descriptor: int) -> bool:
    try:
        os.close(descriptor)
        return True
    except OSError:
        return False


def _cleanup_pending_handoff(
    lease: RepositoryExecutableShebangNestedTargetStageLease,
) -> bool:
    root = lease._root_descriptor
    name = lease._pending_name
    descriptors = lease._pending_descriptors
    identity = lease._pending_identity
    if root is None or name is None or identity is None:
        return not (name is not None or descriptors)
    try:
        entry = _entry_metadata(root, name)
        if entry is not None:
            if (entry.st_dev, entry.st_ino) != identity:
                return False
            os.unlink(name, dir_fd=root)
            os.fsync(root)
            if _entry_metadata(root, name) is not None:
                return False
        for descriptor in descriptors:
            metadata = os.fstat(descriptor)
            if (
                (metadata.st_dev, metadata.st_ino) != identity
                or metadata.st_nlink != 0
            ):
                return False
    except (OSError, ValueError, _InvalidNestedTargetStaging):
        return False
    close_ok = True
    for descriptor in descriptors:
        close_ok = _close_descriptor(descriptor) and close_ok
    if not close_ok:
        lease._descriptor_release_unverifiable = True
        return False
    lease._pending_name = None
    lease._pending_identity = None
    lease._pending_descriptors = ()
    return True


def _pending_identity_from_descriptors(
    descriptors: tuple[int, ...],
) -> tuple[int, int] | None:
    if not descriptors:
        return None
    identity: tuple[int, int] | None = None
    try:
        for descriptor in descriptors:
            metadata = os.fstat(descriptor)
            current = (metadata.st_dev, metadata.st_ino)
            if identity is None:
                identity = current
            elif current != identity:
                return None
    except OSError:
        return None
    return identity


def _recover_pending_handoff(
    lease: RepositoryExecutableShebangNestedTargetStageLease,
    *,
    name: str,
    descriptors: tuple[int, ...],
) -> bool:
    identity = _pending_identity_from_descriptors(descriptors)
    if identity is None:
        lease._descriptor_release_unverifiable = True
        lease._state = "cleanup_unverifiable"
        return False
    object.__setattr__(lease, "_pending_name", name)
    object.__setattr__(lease, "_pending_identity", identity)
    object.__setattr__(lease, "_pending_descriptors", descriptors)
    if not _cleanup_pending_handoff(lease):
        lease._state = "cleanup_unverifiable"
        return False
    return True


def _open_pending_writer(
    lease: RepositoryExecutableShebangNestedTargetStageLease,
    *,
    root_descriptor: int,
    name: str,
) -> int | None:
    descriptor: int | None = None
    try:
        try:
            descriptor = os.open(
                name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_NOFOLLOW
                | os.O_CLOEXEC,
                0o600,
                dir_fd=root_descriptor,
            )
        except FileExistsError:
            return None
        metadata = os.fstat(descriptor)
        lease._pending_name = name
        lease._pending_identity = (metadata.st_dev, metadata.st_ino)
        lease._pending_descriptors = (descriptor,)
        return descriptor
    except BaseException:
        if descriptor is not None and not _recover_pending_handoff(
            lease,
            name=name,
            descriptors=(descriptor,),
        ):
            raise _CleanupUncertain from None
        raise


def _open_pending_reader(
    lease: RepositoryExecutableShebangNestedTargetStageLease,
    *,
    root_descriptor: int,
    name: str,
    writer: int,
) -> int:
    reader: int | None = None
    try:
        reader = os.open(
            name,
            os.O_RDONLY
            | os.O_NOFOLLOW
            | os.O_CLOEXEC
            | os.O_NONBLOCK,
            dir_fd=root_descriptor,
        )
        lease._pending_descriptors = (writer, reader)
        return reader
    except BaseException:
        descriptors = (writer,) if reader is None else (writer, reader)
        if not _recover_pending_handoff(
            lease,
            name=name,
            descriptors=descriptors,
        ):
            raise _CleanupUncertain from None
        raise


def _stage_captured_nested_target(
    lease: RepositoryExecutableShebangNestedTargetStageLease,
    captured: _CapturedNestedTarget,
    *,
    nested_target_measurement_ref: str,
    guarded_measurement_ref: str,
    staging_context_digest: str,
) -> _RetainedStagedNestedTarget:
    root = lease._root_descriptor
    if (
        root is None
        or type(captured) is not _FIXED_CAPTURED_TYPE
        or not _is_digest(nested_target_measurement_ref)
        or not _is_digest(guarded_measurement_ref)
    ):
        raise _InvalidNestedTargetStaging
    writer: int | None = None
    reader: int | None = None
    name: str | None = None
    detached = False
    identity: tuple[int, int] | None = None
    try:
        for _ in range(_STAGE_NAME_ATTEMPTS):
            candidate = _new_stage_name()
            if _entry_metadata(root, candidate) is not None:
                continue
            try:
                writer = _open_pending_writer(
                    lease,
                    root_descriptor=root,
                    name=candidate,
                )
            except OSError:
                raise _InvalidNestedTargetStaging from None
            if writer is None:
                continue
            name = candidate
            break
        if writer is None or name is None:
            raise _InvalidNestedTargetStaging
        try:
            os.fchmod(writer, 0o600)
            writer_metadata = os.fstat(writer)
        except OSError:
            raise _InvalidNestedTargetStaging from None
        identity = (writer_metadata.st_dev, writer_metadata.st_ino)
        if (
            lease._pending_name != name
            or lease._pending_identity != identity
            or lease._pending_descriptors != (writer,)
        ):
            raise _InvalidNestedTargetStaging
        if (
            identity == captured.source_identity
            or any(item.metadata[:2] == identity for item in lease._files)
            or not stat.S_ISREG(writer_metadata.st_mode)
            or writer_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(writer_metadata.st_mode) != 0o600
            or writer_metadata.st_nlink != 1
            or writer_metadata.st_size != 0
            or os.get_inheritable(writer)
        ):
            raise _InvalidNestedTargetStaging
        entry = _entry_metadata(root, name)
        if (
            entry is None
            or stat.S_ISLNK(entry.st_mode)
            or (entry.st_dev, entry.st_ino) != identity
        ):
            raise _InvalidNestedTargetStaging
        try:
            reader = _open_pending_reader(
                lease,
                root_descriptor=root,
                name=name,
                writer=writer,
            )
        except BaseException:
            # The helper either closed the exact linked ownership set or
            # retained it in the lease as explicit cleanup uncertainty.
            writer = None
            reader = None
            raise
        reader_metadata = os.fstat(reader)
        if (
            (reader_metadata.st_dev, reader_metadata.st_ino) != identity
            or os.get_inheritable(reader)
            or fcntl.fcntl(reader, fcntl.F_GETFL) & os.O_ACCMODE
            != os.O_RDONLY
        ):
            raise _InvalidNestedTargetStaging
        current = _entry_metadata(root, name)
        if current is None or (current.st_dev, current.st_ino) != identity:
            raise _CleanupUncertain
        try:
            os.unlink(name, dir_fd=root)
            os.fsync(root)
        except OSError:
            raise _CleanupUncertain from None
        if (
            _entry_metadata(root, name) is not None
            or os.fstat(writer).st_nlink != 0
            or os.fstat(reader).st_nlink != 0
        ):
            raise _CleanupUncertain
        detached = True
        lease._pending_name = None
        lease._pending_identity = None
        lease._pending_descriptors = ()

        _write_all(writer, captured.content)
        try:
            os.fchmod(writer, _STAGED_FILE_MODE)
            os.fsync(writer)
        except OSError:
            raise _InvalidNestedTargetStaging from None
        content_bytes = sum(len(chunk) for chunk in captured.content)
        if (
            content_bytes > _MAX_FILE_BYTES
            or _descriptor_digest(reader, content_bytes=content_bytes)
            != captured.content_digest
        ):
            raise _InvalidNestedTargetStaging
        writer_final = os.fstat(writer)
        reader_final = os.fstat(reader)
        if (
            _metadata_signature(writer_final)
            != _metadata_signature(reader_final)
            or not stat.S_ISREG(reader_final.st_mode)
            or reader_final.st_uid != os.geteuid()
            or stat.S_IMODE(reader_final.st_mode) != _STAGED_FILE_MODE
            or reader_final.st_nlink != 0
            or reader_final.st_size != content_bytes
        ):
            raise _InvalidNestedTargetStaging
        if not _close_descriptor(writer):
            lease._descriptor_release_unverifiable = True
            writer = None
            raise _CleanupUncertain
        writer = None
        final_metadata = os.fstat(reader)
        if (
            _metadata_signature(final_metadata)
            != _metadata_signature(reader_final)
            or os.get_inheritable(reader)
            or fcntl.fcntl(reader, fcntl.F_GETFL) & os.O_ACCMODE
            != os.O_RDONLY
        ):
            raise _InvalidNestedTargetStaging
        staged_identity_ref = _staged_identity_ref(final_metadata)
        staged_metadata_digest = _staged_metadata_digest(
            final_metadata,
            identity_ref=staged_identity_ref,
        )
        reference = _staged_file_ref_projection(
            nested_target_path_ref=captured.nested_target_path_ref,
            source_filesystem_identity_ref=(
                captured.source_filesystem_identity_ref
            ),
            source_metadata_digest=captured.source_metadata_digest,
            nested_target_measurement_ref=nested_target_measurement_ref,
            guarded_measurement_ref=guarded_measurement_ref,
            staged_filesystem_identity_ref=staged_identity_ref,
            staged_metadata_digest=staged_metadata_digest,
            content_digest=captured.content_digest,
            content_bytes=content_bytes,
            nested_target_staging_context_digest=staging_context_digest,
        )
        staged_file = _FIXED_STAGED_FILE_TYPE(
            kind=(
                REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_STAGED_FILE_KIND
            ),
            nested_target_path_ref=captured.nested_target_path_ref,
            source_filesystem_identity_ref=(
                captured.source_filesystem_identity_ref
            ),
            source_metadata_digest=captured.source_metadata_digest,
            nested_target_measurement_ref=nested_target_measurement_ref,
            guarded_measurement_ref=guarded_measurement_ref,
            nested_target_staged_file_ref=_BUILTIN_CANONICAL_DIGEST(
                reference
            ),
            staged_filesystem_identity_ref=staged_identity_ref,
            staged_metadata_digest=staged_metadata_digest,
            content_digest=captured.content_digest,
            content_bytes=content_bytes,
        )
        _staged_file_projection(
            staged_file,
            staging_context_digest=staging_context_digest,
        )
        retained = _FIXED_RETAINED_TYPE(
            staged_file=staged_file,
            descriptor=reader,
            metadata=_metadata_signature(final_metadata),
        )
        lease._files = lease._files + (retained,)
        reader = None
        return retained
    except BaseException:
        if not detached and lease._pending_name is not None:
            if not _cleanup_pending_handoff(lease):
                lease._state = "cleanup_unverifiable"
                raise _CleanupUncertain from None
            writer = None
            reader = None
        if detached:
            for descriptor in (writer, reader):
                if descriptor is None:
                    continue
                try:
                    if os.fstat(descriptor).st_nlink != 0:
                        lease._state = "cleanup_unverifiable"
                        raise _CleanupUncertain
                except OSError:
                    lease._state = "cleanup_unverifiable"
                    raise _CleanupUncertain from None
        close_ok = True
        for descriptor in (writer, reader):
            if descriptor is not None:
                close_ok = _close_descriptor(descriptor) and close_ok
        if not close_ok:
            lease._descriptor_release_unverifiable = True
            lease._state = "cleanup_unverifiable"
            raise _CleanupUncertain from None
        raise


def _verify_retained_nested_target(
    value: _RetainedStagedNestedTarget,
    *,
    staging_context_digest: str,
) -> None:
    if type(value) is not _FIXED_RETAINED_TYPE:
        raise _InvalidNestedTargetStaging
    _staged_file_projection(
        value.staged_file,
        staging_context_digest=staging_context_digest,
    )
    try:
        metadata = os.fstat(value.descriptor)
        flags = fcntl.fcntl(value.descriptor, fcntl.F_GETFL)
        inheritable = os.get_inheritable(value.descriptor)
    except (OSError, ValueError):
        raise _InvalidNestedTargetStaging from None
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
        raise _InvalidNestedTargetStaging


def _close_root_descriptor(
    lease: RepositoryExecutableShebangNestedTargetStageLease,
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
        or not _close_descriptor(descriptor)
    ):
        lease._descriptor_release_unverifiable = True
        lease._root_descriptor = None
        return False
    lease._root_descriptor = None
    return True


def _captures_in_action_order(
    capture: _NestedTargetCaptureSink,
    action_guard: RepositoryExecutableShebangNestedTargetChainGuardReceipt,
    expected_nested: RepositoryExecutableShebangNestedTargetResolutionReceipt,
) -> tuple[
    tuple[
        _CapturedNestedTarget,
        str,
        str,
    ],
    ...,
]:
    measurement_by_ref = {
        item.nested_target_measurement_ref: item
        for item in expected_nested.measurements
    }
    ordered: list[tuple[_CapturedNestedTarget, str, str]] = []
    seen_paths: set[str] = set()
    for guarded in action_guard.guarded_measurements:
        measurement = measurement_by_ref.get(
            guarded.nested_target_measurement_ref
        )
        if measurement is None:
            raise _InvalidNestedTargetStaging
        captured = capture.by_path_ref.get(
            measurement.nested_target_path_ref
        )
        if (
            captured is None
            or captured.nested_target_path_ref in seen_paths
            or captured.source_filesystem_identity_ref
            != measurement.filesystem_identity_ref
            or captured.source_metadata_digest
            != measurement.metadata_digest
            or captured.content_digest != measurement.content_digest
            or sum(len(chunk) for chunk in captured.content)
            != measurement.content_bytes
        ):
            raise _InvalidNestedTargetStaging
        seen_paths.add(captured.nested_target_path_ref)
        ordered.append(
            (
                captured,
                guarded.nested_target_measurement_ref,
                guarded.guarded_measurement_ref,
            )
        )
    if (
        len(ordered) != len(capture.by_path_ref)
        or sum(
            sum(len(chunk) for chunk in item[0].content)
            for item in ordered
        )
        != capture.total_bytes
    ):
        raise _InvalidNestedTargetStaging
    return tuple(ordered)


def _build_staging_receipt(
    *,
    expected_guard: (
        RepositoryExecutableShebangNestedTargetChainGuardReceipt
    ),
    action_guard: (
        RepositoryExecutableShebangNestedTargetChainGuardReceipt
    ),
    post_stage_guard: (
        RepositoryExecutableShebangNestedTargetChainGuardReceipt
    ),
    retained_files: tuple[_RetainedStagedNestedTarget, ...],
    staging_context_digest: str,
) -> RepositoryExecutableShebangNestedTargetStagingReceipt:
    expected_canonical = _BUILTIN_CHAIN_GUARD_PROJECTION(expected_guard)
    action_canonical = _BUILTIN_CHAIN_GUARD_PROJECTION(action_guard)
    post_canonical = _BUILTIN_CHAIN_GUARD_PROJECTION(post_stage_guard)
    if not (
        expected_canonical == action_canonical == post_canonical
    ):
        raise _InvalidNestedTargetStaging
    files_by_measurement = {
        item.staged_file.nested_target_measurement_ref: item.staged_file
        for item in retained_files
    }
    if tuple(files_by_measurement) != tuple(
        item.nested_target_measurement_ref
        for item in action_guard.guarded_measurements
    ):
        raise _InvalidNestedTargetStaging

    requirements: list[
        RepositoryExecutableShebangNestedTargetStageRequirement
    ] = []
    for upstream in action_guard.requirements:
        if upstream.disposition == "known_chain_guard_verified":
            if upstream.nested_target_measurement_ref is None:
                raise _InvalidNestedTargetStaging
            staged = files_by_measurement.get(
                upstream.nested_target_measurement_ref
            )
            if (
                staged is None
                or staged.guarded_measurement_ref
                != upstream.guarded_measurement_ref
            ):
                raise _InvalidNestedTargetStaging
            disposition = "known_chain_guard_staged"
            measurement_ref = upstream.nested_target_measurement_ref
            guarded_ref = upstream.guarded_measurement_ref
            staged_ref = staged.nested_target_staged_file_ref
        elif upstream.disposition in {
            "target_native_not_applicable",
            "source_native_not_applicable",
        }:
            disposition = upstream.disposition
            measurement_ref = None
            guarded_ref = None
            staged_ref = None
        else:
            raise _InvalidNestedTargetStaging
        reference = _stage_requirement_ref_projection(
            chain_guard_requirement_ref=(
                upstream.chain_guard_requirement_ref
            ),
            disposition=disposition,
            nested_target_measurement_ref=measurement_ref,
            guarded_measurement_ref=guarded_ref,
            nested_target_staged_file_ref=staged_ref,
        )
        requirement = _FIXED_STAGE_REQUIREMENT_TYPE(
            kind=(
                REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_STAGE_REQUIREMENT_KIND
            ),
            staged_file_ref=upstream.staged_file_ref,
            runtime_file_ref=upstream.runtime_file_ref,
            requirement_ref=upstream.requirement_ref,
            target_requirement_ref=upstream.target_requirement_ref,
            target_stage_requirement_ref=(
                upstream.target_stage_requirement_ref
            ),
            target_runtime_requirement_ref=(
                upstream.target_runtime_requirement_ref
            ),
            target_shebang_requirement_ref=(
                upstream.target_shebang_requirement_ref
            ),
            nested_target_requirement_ref=(
                upstream.nested_target_requirement_ref
            ),
            chain_guard_requirement_ref=(
                upstream.chain_guard_requirement_ref
            ),
            disposition=disposition,
            nested_target_measurement_ref=measurement_ref,
            guarded_measurement_ref=guarded_ref,
            nested_target_staged_file_ref=staged_ref,
            nested_target_stage_requirement_ref=(
                _BUILTIN_CANONICAL_DIGEST(reference)
            ),
        )
        _stage_requirement_projection(requirement)
        requirements.append(requirement)

    requirement_by_guard = {
        item.chain_guard_requirement_ref: item for item in requirements
    }
    bindings: list[RepositoryExecutableShebangNestedTargetStageBinding] = []
    for upstream in action_guard.bindings:
        requirement = requirement_by_guard.get(
            upstream.chain_guard_requirement_ref
        )
        if requirement is None:
            raise _InvalidNestedTargetStaging
        binding = _FIXED_STAGE_BINDING_TYPE(
            kind=(
                REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_STAGE_BINDING_KIND
            ),
            command_kind=upstream.command_kind,
            command_id=upstream.command_id,
            command_digest=upstream.command_digest,
            staged_file_ref=upstream.staged_file_ref,
            runtime_file_ref=upstream.runtime_file_ref,
            requirement_ref=upstream.requirement_ref,
            target_requirement_ref=upstream.target_requirement_ref,
            target_stage_requirement_ref=(
                upstream.target_stage_requirement_ref
            ),
            target_runtime_requirement_ref=(
                upstream.target_runtime_requirement_ref
            ),
            target_shebang_requirement_ref=(
                upstream.target_shebang_requirement_ref
            ),
            nested_target_requirement_ref=(
                upstream.nested_target_requirement_ref
            ),
            chain_guard_requirement_ref=(
                upstream.chain_guard_requirement_ref
            ),
            nested_target_stage_requirement_ref=(
                requirement.nested_target_stage_requirement_ref
            ),
        )
        _stage_binding_projection(binding)
        bindings.append(binding)

    expected_digest = _BUILTIN_CANONICAL_DIGEST(expected_canonical)
    receipt = _FIXED_STAGING_RECEIPT_TYPE(
        kind=REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_STAGING_KIND,
        schema_version=(
            REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_STAGING_SCHEMA_VERSION
        ),
        staging_source=STAGING_SOURCE,
        staging_scope=STAGING_SCOPE,
        inspection_source=action_guard.inspection_source,
        guard_scope=action_guard.guard_scope,
        resolution_depth=action_guard.resolution_depth,
        maximum_resolution_depth=action_guard.maximum_resolution_depth,
        nested_target_resolution_receipt_digest=(
            action_guard.nested_target_resolution_receipt_digest
        ),
        expected_chain_guard_receipt_digest=expected_digest,
        action_chain_guard_receipt_digest=(
            _BUILTIN_CANONICAL_DIGEST(action_canonical)
        ),
        post_stage_chain_guard_receipt_digest=(
            _BUILTIN_CANONICAL_DIGEST(post_canonical)
        ),
        target_shebang_requirements_receipt_digest=(
            action_guard.target_shebang_requirements_receipt_digest
        ),
        target_runtime_manifest_receipt_digest=(
            action_guard.target_runtime_manifest_receipt_digest
        ),
        target_staging_receipt_digest=(
            action_guard.target_staging_receipt_digest
        ),
        target_resolution_receipt_digest=(
            action_guard.target_resolution_receipt_digest
        ),
        shebang_requirements_receipt_digest=(
            action_guard.shebang_requirements_receipt_digest
        ),
        runtime_manifest_receipt_digest=(
            action_guard.runtime_manifest_receipt_digest
        ),
        source_staging_receipt_digest=(
            action_guard.source_staging_receipt_digest
        ),
        registration_digest=action_guard.registration_digest,
        repository_ref=action_guard.repository_ref,
        verification_commands_digest=(
            action_guard.verification_commands_digest
        ),
        resolution_context_digest=action_guard.resolution_context_digest,
        source_staging_context_digest=(
            action_guard.source_staging_context_digest
        ),
        target_path_context_digest=action_guard.target_path_context_digest,
        target_staging_context_digest=(
            action_guard.target_staging_context_digest
        ),
        nested_target_path_context_digest=(
            action_guard.nested_target_path_context_digest
        ),
        known_source_identity_set_digest=(
            action_guard.known_source_identity_set_digest
        ),
        known_target_identity_set_digest=(
            action_guard.known_target_identity_set_digest
        ),
        protected_staging_root_identity_set_digest=(
            action_guard.protected_staging_root_identity_set_digest
        ),
        guard_summary_ref=action_guard.guard_summary_ref,
        nested_target_staging_context_digest=staging_context_digest,
        staging_root_used=bool(retained_files),
        staged_files=tuple(item.staged_file for item in retained_files),
        requirements=tuple(requirements),
        bindings=tuple(bindings),
        requirement_count=len(requirements),
        command_count=len(bindings),
        known_chain_guard_staged_count=sum(
            item.disposition == "known_chain_guard_staged"
            for item in requirements
        ),
        target_native_not_applicable_count=sum(
            item.disposition == "target_native_not_applicable"
            for item in requirements
        ),
        source_native_not_applicable_count=sum(
            item.disposition == "source_native_not_applicable"
            for item in requirements
        ),
        unique_nested_target_count=len(retained_files),
        total_staged_bytes=sum(
            item.staged_file.content_bytes for item in retained_files
        ),
    )
    _BUILTIN_STAGING_RECEIPT_PROJECTION(receipt)
    return receipt


def _cleanup_receipt(
    lease: RepositoryExecutableShebangNestedTargetStageLease,
    *,
    outcome: _CleanupOutcome,
    namespace_absence: bool,
    descriptor_release: bool,
    root_identity: bool,
) -> RepositoryExecutableShebangNestedTargetStageCleanupReceipt:
    receipt = _FIXED_CLEANUP_RECEIPT_TYPE(
        kind=(
            REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_STAGE_CLEANUP_KIND
        ),
        schema_version=(
            REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_STAGING_SCHEMA_VERSION
        ),
        outcome=outcome,
        nested_target_staging_receipt_digest=(
            lease._receipt_digest_anchor
        ),
        owned_namespace_absence_verified=namespace_absence,
        descriptor_release_complete=descriptor_release,
        staging_root_identity_verified=root_identity,
        staging_root_metadata_restored=False,
        secure_erasure_verified=False,
    )
    _BUILTIN_CLEANUP_RECEIPT_PROJECTION(receipt)
    return receipt


def _store_cleanup_receipt(
    lease: RepositoryExecutableShebangNestedTargetStageLease,
    receipt: RepositoryExecutableShebangNestedTargetStageCleanupReceipt,
) -> None:
    canonical = _BUILTIN_CLEANUP_RECEIPT_PROJECTION(receipt)
    lease._cleanup_receipt = receipt
    lease._cleanup_receipt_object_anchor = receipt
    lease._cleanup_receipt_digest_anchor = _BUILTIN_CANONICAL_DIGEST(canonical)


def _mark_cleanup_unverifiable(
    lease: RepositoryExecutableShebangNestedTargetStageLease,
) -> None:
    lease._state = "cleanup_unverifiable"
    _store_cleanup_receipt(
        lease,
        _cleanup_receipt(
            lease,
            outcome="unverifiable",
            namespace_absence=False,
            descriptor_release=False,
            root_identity=False,
        ),
    )


def _release_retained(
    lease: RepositoryExecutableShebangNestedTargetStageLease,
) -> bool:
    remaining: list[_RetainedStagedNestedTarget] = []
    ok = True
    for item in lease._files:
        try:
            metadata = os.fstat(item.descriptor)
        except OSError:
            lease._descriptor_release_unverifiable = True
            remaining.append(item)
            ok = False
            continue
        if (metadata.st_dev, metadata.st_ino) != item.metadata[:2]:
            lease._descriptor_release_unverifiable = True
            remaining.append(item)
            ok = False
            continue
        if metadata.st_nlink != 0:
            remaining.append(item)
            ok = False
            continue
        if not _close_descriptor(item.descriptor):
            lease._descriptor_release_unverifiable = True
            remaining.append(item)
            ok = False
    lease._files = tuple(remaining)
    if remaining:
        ok = False
    return ok and not lease._descriptor_release_unverifiable


def _abort_staging(
    lease: RepositoryExecutableShebangNestedTargetStageLease,
) -> bool:
    if type(lease) is not _FIXED_LEASE_TYPE:
        return True
    if lease._state == "cleanup_unverifiable":
        return False
    pending_removed = False
    if lease._pending_name is not None or lease._pending_descriptors:
        pending_removed = True
        if not _cleanup_pending_handoff(lease):
            _mark_cleanup_unverifiable(lease)
            return False
    root_verified = False
    if lease._root_descriptor is not None:
        try:
            root_verified = bool(
                _directory_is_empty(lease._root_descriptor)
                and _root_path_identity_matches(lease)
            )
        except _InvalidNestedTargetStaging:
            root_verified = False
        if not root_verified:
            _mark_cleanup_unverifiable(lease)
            return False
    if not _release_retained(lease):
        _mark_cleanup_unverifiable(lease)
        return False
    lease._files_object_anchor = None
    if not _close_root_descriptor(lease):
        _mark_cleanup_unverifiable(lease)
        return False
    lease._state = "cleaned"
    _store_cleanup_receipt(
        lease,
        _cleanup_receipt(
            lease,
            outcome="removed" if pending_removed else "already_absent_verified",
            namespace_absence=True,
            descriptor_release=True,
            root_identity=root_verified,
        ),
    )
    return True


def cleanup_repository_executable_shebang_nested_target_stage(
    lease: RepositoryExecutableShebangNestedTargetStageLease,
) -> RepositoryExecutableShebangNestedTargetStageCleanupReceipt:
    """Release one nested-target lease with conservative cleanup evidence."""

    if (
        type(lease) is not _FIXED_LEASE_TYPE
        or lease._owner_pid != os.getpid()
    ):
        raise ValidationError(_INVALID_MESSAGE)
    if lease._state == "cleaned":
        receipt = lease._cleanup_receipt
        if receipt is None:
            raise ValidationError(_INVALID_MESSAGE)
        try:
            canonical = _BUILTIN_CLEANUP_RECEIPT_PROJECTION(receipt)
            if (
                receipt is not lease._cleanup_receipt_object_anchor
                or lease._cleanup_receipt_digest_anchor
                != _BUILTIN_CANONICAL_DIGEST(canonical)
            ):
                raise _InvalidNestedTargetStaging
        except (AttributeError, TypeError, ValueError):
            raise ValidationError(_INVALID_MESSAGE) from None
        return receipt
    if lease._state == "new":
        if not _abort_staging(lease):
            raise ConfigurationError(_CLEANUP_UNCERTAIN_MESSAGE) from None
        assert lease._cleanup_receipt is not None
        return lease._cleanup_receipt
    if lease._state == "active":
        try:
            receipt = lease._receipt
            if receipt is None:
                raise _InvalidNestedTargetStaging
            canonical = _BUILTIN_STAGING_RECEIPT_PROJECTION(receipt)
            file_refs = tuple(
                item.nested_target_staged_file_ref
                for item in receipt.staged_files
            )
            retained_refs = tuple(
                item.staged_file.nested_target_staged_file_ref
                for item in lease._files
            )
            if (
                receipt is not lease._receipt_object_anchor
                or lease._receipt_digest_anchor
                != _BUILTIN_CANONICAL_DIGEST(canonical)
                or file_refs != lease._receipt_file_refs_anchor
                or lease._files is not lease._files_object_anchor
                or retained_refs != file_refs
                or len(lease._files) != receipt.unique_nested_target_count
                or any(
                    retained.staged_file is not anchored
                    for retained, anchored in zip(
                        lease._files,
                        receipt.staged_files,
                        strict=True,
                    )
                )
            ):
                raise _InvalidNestedTargetStaging
            for item in lease._files:
                _verify_retained_nested_target(
                    item,
                    staging_context_digest=(
                        receipt.nested_target_staging_context_digest
                    ),
                )
        except (AttributeError, OSError, TypeError, ValueError):
            _mark_cleanup_unverifiable(lease)
            raise ConfigurationError(_CLEANUP_UNCERTAIN_MESSAGE) from None
        if not _release_retained(lease):
            _mark_cleanup_unverifiable(lease)
            raise ConfigurationError(_CLEANUP_UNCERTAIN_MESSAGE) from None
        lease._files_object_anchor = None
        lease._state = "cleaned"
        _store_cleanup_receipt(
            lease,
            _cleanup_receipt(
                lease,
                outcome="already_absent_verified",
                namespace_absence=True,
                descriptor_release=True,
                root_identity=False,
            ),
        )
        assert lease._cleanup_receipt is not None
        return lease._cleanup_receipt
    if lease._state == "cleanup_unverifiable":
        # Bounded best effort releases every exact owned handle.  Failure
        # remains explicit and never becomes a successful cleanup receipt.
        if lease._pending_name is not None or lease._pending_descriptors:
            if not _cleanup_pending_handoff(lease):
                assert lease._cleanup_receipt is not None
                return lease._cleanup_receipt
        if not _release_retained(lease):
            assert lease._cleanup_receipt is not None
            return lease._cleanup_receipt
        lease._files_object_anchor = None
        root_verified = False
        if lease._root_descriptor is not None:
            try:
                root_verified = bool(
                    _directory_is_empty(lease._root_descriptor)
                    and _root_path_identity_matches(lease)
                )
            except _InvalidNestedTargetStaging:
                root_verified = False
            if not root_verified or not _close_root_descriptor(lease):
                assert lease._cleanup_receipt is not None
                return lease._cleanup_receipt
        if lease._descriptor_release_unverifiable:
            assert lease._cleanup_receipt is not None
            return lease._cleanup_receipt
        lease._state = "cleaned"
        _store_cleanup_receipt(
            lease,
            _cleanup_receipt(
                lease,
                outcome="already_absent_verified",
                namespace_absence=True,
                descriptor_release=True,
                root_identity=root_verified,
            ),
        )
        assert lease._cleanup_receipt is not None
        return lease._cleanup_receipt
    raise ValidationError(_INVALID_MESSAGE)


def stage_repository_executable_shebang_nested_target_bytes(
    registration: RepositoryRegistration,
    *,
    search_directories: tuple[Path, ...],
    expected_chain_guard: (
        RepositoryExecutableShebangNestedTargetChainGuardReceipt
    ),
    expected_nested_resolution: (
        RepositoryExecutableShebangNestedTargetResolutionReceipt
    ),
    expected_target_requirements: (
        RepositoryExecutableShebangTargetRequirementsReceipt
    ),
    expected_target_runtime: (
        RepositoryExecutableShebangTargetRuntimeManifestReceipt
    ),
    expected_target_staging: RepositoryExecutableShebangTargetStagingReceipt,
    target_lease: RepositoryExecutableShebangTargetStageLease,
    expected_source_staging: RepositoryExecutableStagingReceipt,
    source_lease: RepositoryExecutableStageLease,
    expected_nested_target_paths: tuple[Path, ...],
    lease: RepositoryExecutableShebangNestedTargetStageLease,
) -> RepositoryExecutableShebangNestedTargetStagingReceipt:
    """Freshly reproduce, guardedly capture, and stage one depth-two set."""

    capture = _NestedTargetCaptureSink()
    protected: _ProtectedContext | None = None
    staging_started = False
    lease_validated = False
    try:
        _require_supported_platform()
        lease = _require_new_lease(lease)
        lease_validated = True
        if (
            type(expected_chain_guard) is not _FIXED_CHAIN_GUARD_TYPE
            or type(expected_nested_resolution)
            is not _FIXED_NESTED_RESOLUTION_TYPE
            or type(expected_target_requirements)
            is not _FIXED_TARGET_REQUIREMENTS_TYPE
            or type(expected_target_runtime) is not _FIXED_TARGET_RUNTIME_TYPE
            or type(expected_target_staging) is not _FIXED_TARGET_STAGING_TYPE
            or type(target_lease) is not _FIXED_TARGET_LEASE_TYPE
            or type(expected_source_staging)
            is not _FIXED_SOURCE_STAGING_TYPE
            or type(source_lease) is not _FIXED_SOURCE_LEASE_TYPE
            or type(expected_nested_target_paths) is not tuple
        ):
            raise _InvalidNestedTargetStaging
        expected_guard_canonical = _BUILTIN_CHAIN_GUARD_PROJECTION(
            expected_chain_guard
        )
        nested_canonical = _BUILTIN_NESTED_RESOLUTION_PROJECTION(
            expected_nested_resolution
        )
        if (
            expected_chain_guard.nested_target_resolution_receipt_digest
            != _BUILTIN_CANONICAL_DIGEST(nested_canonical)
        ):
            raise _InvalidNestedTargetStaging
        source_files_anchor = source_lease._files
        target_files_anchor = target_lease._files
        protected = _registration_and_search_context(
            registration,
            search_directories=search_directories,
            expected_guard=expected_chain_guard,
            expected_nested=expected_nested_resolution,
            expected_source_staging=expected_source_staging,
            source_lease=source_lease,
            expected_target_staging=expected_target_staging,
            target_lease=target_lease,
        )
        action_guard = _BUILTIN_INSPECT_CHAIN_GUARD(
            expected_nested_resolution,
            expected_target_requirements=expected_target_requirements,
            expected_target_runtime=expected_target_runtime,
            expected_target_staging=expected_target_staging,
            target_lease=target_lease,
            expected_source_staging=expected_source_staging,
            source_lease=source_lease,
            expected_nested_target_paths=expected_nested_target_paths,
            unique_nested_target_consumer=capture,
        )
        action_canonical = _BUILTIN_CHAIN_GUARD_PROJECTION(action_guard)
        if (
            action_canonical != expected_guard_canonical
            or source_lease._files is not source_files_anchor
            or target_lease._files is not target_files_anchor
            or not _protected_context_still_matches(protected)
        ):
            raise _InvalidNestedTargetStaging
        ordered_captures = _captures_in_action_order(
            capture,
            action_guard,
            expected_nested_resolution,
        )
        if (
            len(ordered_captures) != action_guard.guarded_measurement_count
            or capture.total_bytes != action_guard.total_guarded_bytes
        ):
            raise _InvalidNestedTargetStaging

        if ordered_captures:
            staging_context_digest = _prepare_staging_root(
                lease,
                protected=protected,
                source_lease=source_lease,
                target_lease=target_lease,
                expected_nested_target_paths=expected_nested_target_paths,
            )
            staging_started = True
            for (
                captured,
                nested_measurement_ref,
                guarded_measurement_ref,
            ) in ordered_captures:
                _stage_captured_nested_target(
                    lease,
                    captured,
                    nested_target_measurement_ref=nested_measurement_ref,
                    guarded_measurement_ref=guarded_measurement_ref,
                    staging_context_digest=staging_context_digest,
                )
        else:
            staging_context_digest = _noop_staging_context_digest()

        retained = lease._files
        post_stage_guard = _BUILTIN_INSPECT_CHAIN_GUARD(
            expected_nested_resolution,
            expected_target_requirements=expected_target_requirements,
            expected_target_runtime=expected_target_runtime,
            expected_target_staging=expected_target_staging,
            target_lease=target_lease,
            expected_source_staging=expected_source_staging,
            source_lease=source_lease,
            expected_nested_target_paths=expected_nested_target_paths,
        )
        post_canonical = _BUILTIN_CHAIN_GUARD_PROJECTION(post_stage_guard)
        if (
            post_canonical != expected_guard_canonical
            or post_canonical != action_canonical
            or source_lease._files is not source_files_anchor
            or target_lease._files is not target_files_anchor
            or not _protected_context_still_matches(protected)
        ):
            raise _InvalidNestedTargetStaging
        if ordered_captures:
            root = lease._root_descriptor
            if (
                root is None
                or not _directory_is_empty(root)
                or not _root_path_identity_matches(lease)
            ):
                raise _InvalidNestedTargetStaging
            try:
                os.fsync(root)
            except OSError:
                raise _InvalidNestedTargetStaging from None
        elif (
            lease._root_descriptor is not None
            or lease._root_metadata is not None
            or retained
        ):
            raise _InvalidNestedTargetStaging
        for item in retained:
            _verify_retained_nested_target(
                item,
                staging_context_digest=staging_context_digest,
            )
        receipt = _build_staging_receipt(
            expected_guard=expected_chain_guard,
            action_guard=action_guard,
            post_stage_guard=post_stage_guard,
            retained_files=retained,
            staging_context_digest=staging_context_digest,
        )
        if (
            not _protected_context_still_matches(protected)
            or source_lease._files is not source_files_anchor
            or target_lease._files is not target_files_anchor
            or not _close_root_descriptor(lease)
        ):
            raise _CleanupUncertain
        receipt_canonical = _BUILTIN_STAGING_RECEIPT_PROJECTION(receipt)
        lease._receipt = receipt
        lease._receipt_object_anchor = receipt
        lease._receipt_digest_anchor = _BUILTIN_CANONICAL_DIGEST(
            receipt_canonical
        )
        lease._receipt_file_refs_anchor = tuple(
            item.nested_target_staged_file_ref
            for item in receipt.staged_files
        )
        lease._files_object_anchor = lease._files
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
            or lease._root_metadata is not None
            or lease._files
            or lease._receipt is not None
            or lease._receipt_object_anchor is not None
            or lease._receipt_digest_anchor is not None
            or lease._receipt_file_refs_anchor
            or lease._files_object_anchor is not None
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
    finally:
        _close_protected_context(protected)


__all__ = [
    "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_STAGED_FILE_KIND",
    "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_STAGE_BINDING_KIND",
    "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_STAGE_CLEANUP_KIND",
    "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_STAGE_REQUIREMENT_KIND",
    "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_STAGING_EVIDENCE_KIND",
    "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_STAGING_KIND",
    "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_STAGING_SCHEMA_VERSION",
    "STAGING_SCOPE",
    "STAGING_SOURCE",
    "RepositoryExecutableShebangNestedTargetStagedFile",
    "RepositoryExecutableShebangNestedTargetStageBinding",
    "RepositoryExecutableShebangNestedTargetStageCleanupReceipt",
    "RepositoryExecutableShebangNestedTargetStageLease",
    "RepositoryExecutableShebangNestedTargetStageRequirement",
    "RepositoryExecutableShebangNestedTargetStagingReceipt",
    "cleanup_repository_executable_shebang_nested_target_stage",
    "stage_repository_executable_shebang_nested_target_bytes",
]
