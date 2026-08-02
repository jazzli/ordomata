"""Ephemeral descriptor staging for direct shebang-target bytes.

This library-only Class 1 primitive consumes an exact target-resolution chain,
captures each unique direct target through the same read-only descriptor used
for its action-boundary measurement, and creates namespace-detached read-only
copies for later controller inspection.  It does not interpret a shebang,
select an interpreter, execute a command, or grant authority.

The retained descriptors are deliberately described as read-only rather than
immutable.  POSIX descriptor staging cannot exclude another same-uid process,
an external writable descriptor, inherited descriptors, external hardlink or
mount aliases, or kernel-level mutation.  It does not establish target
provenance or effective invocability.  The receipt is historical evidence and
never reusable authorization.
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
    _InvalidResolution,
    _PinnedDirectory,
    _absolute_path_parts,
    _metadata_signature,
    _open_absolute_directory,
    _reopen_directory_matches,
    _resolution_context_digest,
    _validate_search_directories,
)
from .repository_executable_shebang_requirements import (
    RepositoryExecutableShebangRequirementsReceipt,
)
from .repository_executable_shebang_target_resolution import (
    MEASUREMENT_SOURCE,
    RESOLUTION_SCOPE,
    RepositoryExecutableShebangTargetResolutionReceipt,
    _InvalidShebangTargetResolution,
    _MeasuredTarget,
    _inspect_staged_executable_shebang_targets,
    _receipt_projection as _target_resolution_projection,
)
from .repository_executable_runtime_manifest import (
    RepositoryExecutableRuntimeManifestReceipt,
)
from .repository_executable_staging import (
    STAGING_SCOPE as SOURCE_STAGING_SCOPE,
    RepositoryExecutableStageLease,
    RepositoryExecutableStagingReceipt,
)
from .repository_registration import (
    RepositoryRegistration,
    _registration_canonical_projection,
    revalidate_repository_registration,
)


REPOSITORY_EXECUTABLE_SHEBANG_TARGET_STAGING_SCHEMA_VERSION = 1
REPOSITORY_EXECUTABLE_SHEBANG_TARGET_STAGING_KIND = (
    "repository_executable_shebang_target_staging"
)
REPOSITORY_EXECUTABLE_SHEBANG_TARGET_STAGING_EVIDENCE_KIND = (
    "repository_executable_shebang_target_staging_validation"
)
REPOSITORY_EXECUTABLE_SHEBANG_TARGET_STAGED_FILE_KIND = (
    "repository_executable_shebang_target_staged_file"
)
REPOSITORY_EXECUTABLE_SHEBANG_TARGET_STAGE_REQUIREMENT_KIND = (
    "repository_executable_shebang_target_stage_requirement"
)
REPOSITORY_EXECUTABLE_SHEBANG_TARGET_STAGE_BINDING_KIND = (
    "repository_executable_shebang_target_stage_binding"
)
REPOSITORY_EXECUTABLE_SHEBANG_TARGET_STAGE_CLEANUP_KIND = (
    "repository_executable_shebang_target_stage_cleanup"
)
STAGING_SOURCE = "controller_copied"
STAGING_SCOPE = "posix_shebang_target_unlinked_readonly_v1"

_INVALID_MESSAGE = "repository executable shebang target staging is invalid"
_CLEANUP_UNCERTAIN_MESSAGE = (
    "repository executable shebang target staging cleanup is uncertain"
)
_COPY_ERROR_MESSAGE = (
    "repository executable shebang target staging lease cannot be copied"
)
_COMMAND_KINDS = ("format", "lint", "type_check", "test", "build")
_RUNTIME_CLASSIFICATIONS = ("elf", "mach_o", "posix_shebang")
_STAGE_DISPOSITIONS = (
    "direct_absolute_target_staged",
    "native_not_applicable",
)
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER_PATTERN = re.compile(r"[a-z][a-z0-9_.-]{0,119}\Z")
_CONCRETE_PATH_TYPE = type(Path())
_MAX_TARGETS = 80
_MAX_REQUIREMENTS = 80
_MAX_COMMANDS = 80
_MAX_TARGET_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_TARGET_BYTES = 256 * 1024 * 1024
_READ_CHUNK_BYTES = 1024 * 1024
_STAGED_FILE_MODE = 0o400
_STAGING_ROOT_MODE = 0o700
_STAGE_NAME_ATTEMPTS = 8

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

# Freeze the shipped implementations.  Transparent dataclass methods and
# public module attributes are patchable and are not trusted at this boundary.
_BUILTIN_CANONICAL_DIGEST = canonical_digest
_BUILTIN_SHA256 = hashlib.sha256
_BUILTIN_REVALIDATE_REGISTRATION = revalidate_repository_registration
_BUILTIN_REGISTRATION_PROJECTION = _registration_canonical_projection
_BUILTIN_VALIDATE_SEARCH_DIRECTORIES = _validate_search_directories
_BUILTIN_OPEN_ABSOLUTE_DIRECTORY = _open_absolute_directory
_BUILTIN_REOPEN_DIRECTORY_MATCHES = _reopen_directory_matches
_BUILTIN_RESOLUTION_CONTEXT_DIGEST = _resolution_context_digest
_BUILTIN_TARGET_RESOLUTION_PROJECTION = _target_resolution_projection
_BUILTIN_INSPECT_TARGETS = _inspect_staged_executable_shebang_targets


class _InvalidTargetStaging(ValueError):
    """Private invalid-input sentinel whose details never cross the API."""


class _CleanupUncertain(ConfigurationError):
    """Private marker for an unproved local cleanup outcome."""


@dataclass(frozen=True, slots=True)
class RepositoryExecutableShebangTargetStagedFile:
    """One unique target measurement and its detached staged copy."""

    kind: str
    target_path_ref: str = field(repr=False)
    source_filesystem_identity_ref: str = field(repr=False)
    source_metadata_digest: str = field(repr=False)
    target_measurement_ref: str = field(repr=False)
    target_staged_file_ref: str = field(repr=False)
    staged_filesystem_identity_ref: str = field(repr=False)
    staged_metadata_digest: str = field(repr=False)
    content_digest: str = field(repr=False)
    content_bytes: int

    def to_canonical(self) -> dict[str, Any]:
        return _staged_file_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableShebangTargetStageRequirement:
    """One upstream target requirement's staging disposition."""

    kind: str
    staged_file_ref: str = field(repr=False)
    runtime_file_ref: str = field(repr=False)
    requirement_ref: str = field(repr=False)
    target_requirement_ref: str = field(repr=False)
    runtime_classification: str
    disposition: str
    target_measurement_ref: str | None = field(repr=False)
    target_staged_file_ref: str | None = field(repr=False)
    target_stage_requirement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _stage_requirement_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableShebangTargetStageBinding:
    """One registered command bound to one target-stage requirement."""

    kind: str
    command_kind: str
    command_id: str = field(repr=False)
    command_digest: str = field(repr=False)
    staged_file_ref: str = field(repr=False)
    runtime_file_ref: str = field(repr=False)
    requirement_ref: str = field(repr=False)
    target_requirement_ref: str = field(repr=False)
    target_stage_requirement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _stage_binding_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableShebangTargetStagingReceipt:
    """Historical evidence for one target descriptor-staging lease."""

    kind: str
    schema_version: int
    measurement_source: str
    resolution_scope: str
    staging_source: str
    staging_scope: str
    shebang_requirements_receipt_digest: str = field(repr=False)
    runtime_manifest_receipt_digest: str = field(repr=False)
    staging_receipt_digest: str = field(repr=False)
    registration_digest: str = field(repr=False)
    repository_ref: str = field(repr=False)
    verification_commands_digest: str = field(repr=False)
    resolution_context_digest: str = field(repr=False)
    source_staging_context_digest: str = field(repr=False)
    target_path_context_digest: str = field(repr=False)
    expected_target_resolution_receipt_digest: str = field(repr=False)
    action_target_resolution_receipt_digest: str = field(repr=False)
    post_stage_target_resolution_receipt_digest: str = field(repr=False)
    target_staging_context_digest: str = field(repr=False)
    staging_root_used: bool
    staged_files: tuple[
        RepositoryExecutableShebangTargetStagedFile, ...
    ] = field(repr=False)
    requirements: tuple[
        RepositoryExecutableShebangTargetStageRequirement, ...
    ] = field(repr=False)
    bindings: tuple[RepositoryExecutableShebangTargetStageBinding, ...] = field(
        repr=False
    )
    requirement_count: int
    command_count: int
    direct_target_requirement_count: int
    native_not_applicable_count: int
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
class RepositoryExecutableShebangTargetStageCleanupReceipt:
    """Bounded cleanup evidence for target staging names and descriptors."""

    kind: str
    schema_version: int
    outcome: _CleanupOutcome
    target_staging_receipt_digest: str | None = field(repr=False)
    owned_namespace_absence_verified: bool
    descriptor_release_complete: bool
    staging_root_identity_verified: bool
    staging_root_metadata_restored: bool
    secure_erasure_verified: bool

    def to_canonical(self) -> dict[str, Any]:
        return _cleanup_receipt_projection(self)


@dataclass(frozen=True, slots=True)
class _CapturedTarget:
    target_path_ref: str = field(repr=False)
    source_identity: tuple[int, int] = field(repr=False)
    source_filesystem_identity_ref: str = field(repr=False)
    source_metadata: tuple[int, ...] = field(repr=False)
    source_metadata_digest: str = field(repr=False)
    content_digest: str = field(repr=False)
    content: tuple[bytes, ...] = field(repr=False)


@dataclass(frozen=True, slots=True)
class _RetainedStagedTarget:
    staged_file: RepositoryExecutableShebangTargetStagedFile = field(
        repr=False
    )
    descriptor: int = field(repr=False)
    metadata: tuple[int, ...] = field(repr=False)


@dataclass(slots=True)
class RepositoryExecutableShebangTargetStageLease:
    """Caller-scoped one-shot lease for detached target byte copies."""

    staging_root: Path = field(repr=False)
    _receipt: RepositoryExecutableShebangTargetStagingReceipt | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _cleanup_receipt: (
        RepositoryExecutableShebangTargetStageCleanupReceipt | None
    ) = field(default=None, init=False, repr=False)
    _receipt_digest_anchor: str | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _receipt_object_anchor: (
        RepositoryExecutableShebangTargetStagingReceipt | None
    ) = field(default=None, init=False, repr=False)
    _receipt_file_refs_anchor: tuple[str, ...] = field(
        default=(),
        init=False,
        repr=False,
    )
    _files_object_anchor: tuple[_RetainedStagedTarget, ...] | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _cleanup_receipt_digest_anchor: str | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _cleanup_receipt_object_anchor: (
        RepositoryExecutableShebangTargetStageCleanupReceipt | None
    ) = field(default=None, init=False, repr=False)
    _state: _LeaseState = field(default="new", init=False, repr=False)
    _owner_pid: int = field(default_factory=os.getpid, init=False, repr=False)
    _files: tuple[_RetainedStagedTarget, ...] = field(
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
    def receipt(self) -> RepositoryExecutableShebangTargetStagingReceipt | None:
        return self._receipt

    @property
    def cleanup_receipt(
        self,
    ) -> RepositoryExecutableShebangTargetStageCleanupReceipt | None:
        return self._cleanup_receipt

    def cleanup(
        self,
    ) -> RepositoryExecutableShebangTargetStageCleanupReceipt:
        return cleanup_repository_executable_shebang_target_stage(self)

    def close(self) -> RepositoryExecutableShebangTargetStageCleanupReceipt:
        return cleanup_repository_executable_shebang_target_stage(self)

    def __enter__(self) -> RepositoryExecutableShebangTargetStageLease:
        if self._state != "active" or self._owner_pid != os.getpid():
            raise ValidationError(_INVALID_MESSAGE)
        return self

    def __exit__(self, *unused: object) -> None:
        cleanup_repository_executable_shebang_target_stage(self)

    def __copy__(self) -> None:
        raise TypeError(_COPY_ERROR_MESSAGE)

    def __deepcopy__(self, memo: object) -> None:
        raise TypeError(_COPY_ERROR_MESSAGE)

    def __reduce__(self) -> None:
        raise TypeError(_COPY_ERROR_MESSAGE)

    def __reduce_ex__(self, protocol: int) -> None:
        raise TypeError(_COPY_ERROR_MESSAGE)


def _is_digest(value: Any) -> bool:
    return type(value) is str and _DIGEST_PATTERN.fullmatch(value) is not None


def _staged_file_projection(
    value: RepositoryExecutableShebangTargetStagedFile,
) -> dict[str, Any]:
    digest_fields = (
        value.target_path_ref,
        value.source_filesystem_identity_ref,
        value.source_metadata_digest,
        value.target_measurement_ref,
        value.target_staged_file_ref,
        value.staged_filesystem_identity_ref,
        value.staged_metadata_digest,
        value.content_digest,
    )
    if (
        type(value) is not RepositoryExecutableShebangTargetStagedFile
        or value.kind != REPOSITORY_EXECUTABLE_SHEBANG_TARGET_STAGED_FILE_KIND
        or not all(_is_digest(item) for item in digest_fields)
        or type(value.content_bytes) is not int
        or not 0 <= value.content_bytes <= _MAX_TARGET_BYTES
    ):
        raise _InvalidTargetStaging
    return {
        "content_bytes": value.content_bytes,
        "content_digest": value.content_digest,
        "kind": value.kind,
        "source_filesystem_identity_ref": (
            value.source_filesystem_identity_ref
        ),
        "source_metadata_digest": value.source_metadata_digest,
        "staged_filesystem_identity_ref": (
            value.staged_filesystem_identity_ref
        ),
        "staged_metadata_digest": value.staged_metadata_digest,
        "target_measurement_ref": value.target_measurement_ref,
        "target_path_ref": value.target_path_ref,
        "target_staged_file_ref": value.target_staged_file_ref,
    }


def _stage_requirement_ref_projection(
    *,
    staged_file_ref: str,
    runtime_file_ref: str,
    requirement_ref: str,
    target_requirement_ref: str,
    runtime_classification: str,
    disposition: str,
    target_measurement_ref: str | None,
    target_staged_file_ref: str | None,
) -> dict[str, Any]:
    return {
        "disposition": disposition,
        "kind": "repository_executable_shebang_target_stage_requirement_ref",
        "requirement_ref": requirement_ref,
        "runtime_classification": runtime_classification,
        "runtime_file_ref": runtime_file_ref,
        "schema_version": 1,
        "staged_file_ref": staged_file_ref,
        "target_measurement_ref": target_measurement_ref,
        "target_requirement_ref": target_requirement_ref,
        "target_staged_file_ref": target_staged_file_ref,
    }


def _stage_requirement_projection(
    value: RepositoryExecutableShebangTargetStageRequirement,
) -> dict[str, Any]:
    if (
        type(value) is not RepositoryExecutableShebangTargetStageRequirement
        or value.kind
        != REPOSITORY_EXECUTABLE_SHEBANG_TARGET_STAGE_REQUIREMENT_KIND
        or not all(
            _is_digest(item)
            for item in (
                value.staged_file_ref,
                value.runtime_file_ref,
                value.requirement_ref,
                value.target_requirement_ref,
                value.target_stage_requirement_ref,
            )
        )
        or value.runtime_classification not in _RUNTIME_CLASSIFICATIONS
        or value.disposition not in _STAGE_DISPOSITIONS
        or (
            value.target_measurement_ref is not None
            and not _is_digest(value.target_measurement_ref)
        )
        or (
            value.target_staged_file_ref is not None
            and not _is_digest(value.target_staged_file_ref)
        )
        or (
            value.disposition == "direct_absolute_target_staged"
            and (
                value.runtime_classification != "posix_shebang"
                or value.target_measurement_ref is None
                or value.target_staged_file_ref is None
            )
        )
        or (
            value.disposition == "native_not_applicable"
            and (
                value.runtime_classification not in {"elf", "mach_o"}
                or value.target_measurement_ref is not None
                or value.target_staged_file_ref is not None
            )
        )
    ):
        raise _InvalidTargetStaging
    reference = _stage_requirement_ref_projection(
        staged_file_ref=value.staged_file_ref,
        runtime_file_ref=value.runtime_file_ref,
        requirement_ref=value.requirement_ref,
        target_requirement_ref=value.target_requirement_ref,
        runtime_classification=value.runtime_classification,
        disposition=value.disposition,
        target_measurement_ref=value.target_measurement_ref,
        target_staged_file_ref=value.target_staged_file_ref,
    )
    if value.target_stage_requirement_ref != _BUILTIN_CANONICAL_DIGEST(reference):
        raise _InvalidTargetStaging
    return {
        **reference,
        "kind": value.kind,
        "target_stage_requirement_ref": value.target_stage_requirement_ref,
    }


def _stage_binding_projection(
    value: RepositoryExecutableShebangTargetStageBinding,
) -> dict[str, Any]:
    if (
        type(value) is not RepositoryExecutableShebangTargetStageBinding
        or value.kind != REPOSITORY_EXECUTABLE_SHEBANG_TARGET_STAGE_BINDING_KIND
        or value.command_kind not in _COMMAND_KINDS
        or type(value.command_id) is not str
        or _IDENTIFIER_PATTERN.fullmatch(value.command_id) is None
        or not all(
            _is_digest(item)
            for item in (
                value.command_digest,
                value.staged_file_ref,
                value.runtime_file_ref,
                value.requirement_ref,
                value.target_requirement_ref,
                value.target_stage_requirement_ref,
            )
        )
    ):
        raise _InvalidTargetStaging
    return {
        "command_digest": value.command_digest,
        "command_id": value.command_id,
        "command_kind": value.command_kind,
        "kind": value.kind,
        "requirement_ref": value.requirement_ref,
        "runtime_file_ref": value.runtime_file_ref,
        "staged_file_ref": value.staged_file_ref,
        "target_requirement_ref": value.target_requirement_ref,
        "target_stage_requirement_ref": value.target_stage_requirement_ref,
    }


def _staging_receipt_projection(
    value: RepositoryExecutableShebangTargetStagingReceipt,
) -> dict[str, Any]:
    digest_fields = (
        value.shebang_requirements_receipt_digest,
        value.runtime_manifest_receipt_digest,
        value.staging_receipt_digest,
        value.registration_digest,
        value.repository_ref,
        value.verification_commands_digest,
        value.resolution_context_digest,
        value.source_staging_context_digest,
        value.target_path_context_digest,
        value.expected_target_resolution_receipt_digest,
        value.action_target_resolution_receipt_digest,
        value.post_stage_target_resolution_receipt_digest,
        value.target_staging_context_digest,
    )
    if (
        type(value) is not RepositoryExecutableShebangTargetStagingReceipt
        or value.kind != REPOSITORY_EXECUTABLE_SHEBANG_TARGET_STAGING_KIND
        or type(value.schema_version) is not int
        or value.schema_version
        != REPOSITORY_EXECUTABLE_SHEBANG_TARGET_STAGING_SCHEMA_VERSION
        or value.measurement_source != MEASUREMENT_SOURCE
        or value.resolution_scope != RESOLUTION_SCOPE
        or value.staging_source != STAGING_SOURCE
        or value.staging_scope != STAGING_SCOPE
        or not all(_is_digest(item) for item in digest_fields)
        or value.expected_target_resolution_receipt_digest
        != value.action_target_resolution_receipt_digest
        or value.action_target_resolution_receipt_digest
        != value.post_stage_target_resolution_receipt_digest
        or type(value.staging_root_used) is not bool
        or type(value.staged_files) is not tuple
        or not 0 <= len(value.staged_files) <= _MAX_TARGETS
        or type(value.requirements) is not tuple
        or not 1 <= len(value.requirements) <= _MAX_REQUIREMENTS
        or type(value.bindings) is not tuple
        or not 1 <= len(value.bindings) <= _MAX_COMMANDS
        or type(value.requirement_count) is not int
        or value.requirement_count != len(value.requirements)
        or type(value.command_count) is not int
        or value.command_count != len(value.bindings)
        or type(value.direct_target_requirement_count) is not int
        or type(value.native_not_applicable_count) is not int
        or type(value.unique_target_count) is not int
        or value.unique_target_count != len(value.staged_files)
        or type(value.total_staged_bytes) is not int
        or not 0 <= value.total_staged_bytes <= _MAX_TOTAL_TARGET_BYTES
        or value.staging_root_used != bool(value.unique_target_count)
        or (
            not value.staging_root_used
            and value.target_staging_context_digest
            != _noop_staging_context_digest()
        )
    ):
        raise _InvalidTargetStaging

    staged_files = [_staged_file_projection(item) for item in value.staged_files]
    requirements = [
        _stage_requirement_projection(item) for item in value.requirements
    ]
    bindings = [_stage_binding_projection(item) for item in value.bindings]

    file_by_ref: dict[str, RepositoryExecutableShebangTargetStagedFile] = {}
    file_by_measurement: dict[
        str, RepositoryExecutableShebangTargetStagedFile
    ] = {}
    path_refs: set[str] = set()
    source_refs: set[str] = set()
    staged_identity_refs: set[str] = set()
    total_bytes = 0
    for item in value.staged_files:
        if (
            item.target_staged_file_ref in file_by_ref
            or item.target_measurement_ref in file_by_measurement
            or item.target_path_ref in path_refs
            or item.source_filesystem_identity_ref in source_refs
            or item.staged_filesystem_identity_ref in staged_identity_refs
        ):
            raise _InvalidTargetStaging
        file_by_ref[item.target_staged_file_ref] = item
        file_by_measurement[item.target_measurement_ref] = item
        path_refs.add(item.target_path_ref)
        source_refs.add(item.source_filesystem_identity_ref)
        staged_identity_refs.add(item.staged_filesystem_identity_ref)
        total_bytes += item.content_bytes

    requirement_by_ref: dict[
        str, RepositoryExecutableShebangTargetStageRequirement
    ] = {}
    stage_requirement_refs: set[str] = set()
    first_use_measurements: list[str] = []
    used_file_refs: set[str] = set()
    direct_count = 0
    native_count = 0
    for item in value.requirements:
        if (
            item.requirement_ref in requirement_by_ref
            or item.target_stage_requirement_ref in stage_requirement_refs
        ):
            raise _InvalidTargetStaging
        requirement_by_ref[item.requirement_ref] = item
        stage_requirement_refs.add(item.target_stage_requirement_ref)
        if item.disposition == "direct_absolute_target_staged":
            direct_count += 1
            assert item.target_measurement_ref is not None
            assert item.target_staged_file_ref is not None
            staged = file_by_measurement.get(item.target_measurement_ref)
            if (
                staged is None
                or staged.target_staged_file_ref != item.target_staged_file_ref
            ):
                raise _InvalidTargetStaging
            if item.target_measurement_ref not in first_use_measurements:
                first_use_measurements.append(item.target_measurement_ref)
            used_file_refs.add(item.target_staged_file_ref)
        else:
            native_count += 1
    if (
        tuple(first_use_measurements)
        != tuple(item.target_measurement_ref for item in value.staged_files)
        or used_file_refs != set(file_by_ref)
    ):
        raise _InvalidTargetStaging

    command_ids: set[str] = set()
    bound_stage_requirement_refs: set[str] = set()
    ordered_stage_requirement_refs: list[str] = []
    prior_kind_index = -1
    for binding in value.bindings:
        requirement = requirement_by_ref.get(binding.requirement_ref)
        kind_index = _COMMAND_KINDS.index(binding.command_kind)
        if (
            requirement is None
            or binding.staged_file_ref != requirement.staged_file_ref
            or binding.runtime_file_ref != requirement.runtime_file_ref
            or binding.target_requirement_ref
            != requirement.target_requirement_ref
            or binding.target_stage_requirement_ref
            != requirement.target_stage_requirement_ref
            or binding.command_id in command_ids
            or kind_index < prior_kind_index
        ):
            raise _InvalidTargetStaging
        command_ids.add(binding.command_id)
        if binding.target_stage_requirement_ref not in bound_stage_requirement_refs:
            ordered_stage_requirement_refs.append(
                binding.target_stage_requirement_ref
            )
        bound_stage_requirement_refs.add(binding.target_stage_requirement_ref)
        prior_kind_index = kind_index

    if (
        bound_stage_requirement_refs != stage_requirement_refs
        or tuple(ordered_stage_requirement_refs)
        != tuple(item.target_stage_requirement_ref for item in value.requirements)
        or direct_count != value.direct_target_requirement_count
        or native_count != value.native_not_applicable_count
        or direct_count + native_count != value.requirement_count
        or total_bytes != value.total_staged_bytes
        or (value.unique_target_count == 0 and direct_count != 0)
        or (value.unique_target_count > 0 and direct_count == 0)
    ):
        raise _InvalidTargetStaging

    return {
        "action_target_resolution_receipt_digest": (
            value.action_target_resolution_receipt_digest
        ),
        "bindings": bindings,
        "command_count": value.command_count,
        "direct_target_requirement_count": (
            value.direct_target_requirement_count
        ),
        "expected_target_resolution_receipt_digest": (
            value.expected_target_resolution_receipt_digest
        ),
        "kind": value.kind,
        "measurement_source": value.measurement_source,
        "native_not_applicable_count": value.native_not_applicable_count,
        "post_stage_target_resolution_receipt_digest": (
            value.post_stage_target_resolution_receipt_digest
        ),
        "registration_digest": value.registration_digest,
        "repository_ref": value.repository_ref,
        "requirement_count": value.requirement_count,
        "requirements": requirements,
        "resolution_context_digest": value.resolution_context_digest,
        "resolution_scope": value.resolution_scope,
        "runtime_manifest_receipt_digest": (
            value.runtime_manifest_receipt_digest
        ),
        "schema_version": value.schema_version,
        "shebang_requirements_receipt_digest": (
            value.shebang_requirements_receipt_digest
        ),
        "source_staging_context_digest": value.source_staging_context_digest,
        "staged_files": staged_files,
        "staging_receipt_digest": value.staging_receipt_digest,
        "staging_root_used": value.staging_root_used,
        "staging_scope": value.staging_scope,
        "staging_source": value.staging_source,
        "target_path_context_digest": value.target_path_context_digest,
        "target_staging_context_digest": (
            value.target_staging_context_digest
        ),
        "total_staged_bytes": value.total_staged_bytes,
        "unique_target_count": value.unique_target_count,
        "verification_commands_digest": value.verification_commands_digest,
    }


def _staging_evidence_projection(
    value: RepositoryExecutableShebangTargetStagingReceipt,
) -> dict[str, Any]:
    canonical = _staging_receipt_projection(value)
    return {
        "action_boundary_target_remeasurement_complete": True,
        "action_receipt_issued": False,
        "atomic_snapshot_verified": False,
        "authority_granted": False,
        "authorization_verified": False,
        "billing_eligible": False,
        "capacity_eligible": False,
        "circuit_eligible": False,
        "command_count": value.command_count,
        "controller_write_descriptors_closed": value.staging_root_used,
        "crash_cleanup_verified": False,
        "current_freshness_verified": False,
        "current_lease_activity_verified": False,
        "dependency_environment_coverage_verified": False,
        "direct_target_requirement_count": (
            value.direct_target_requirement_count
        ),
        "dispatch_enabled": False,
        "durable_control_plane_persistence_enabled": False,
        "dynamic_loader_identity_verified": False,
        "effect_class": 1,
        "effective_interpreter_resolution_verified": False,
        "effective_invocability_verified": False,
        "environment_coverage_verified": False,
        "exact_receipt_chain_verified": True,
        "execution_enabled": False,
        "external_hardlink_alias_excluded": False,
        "external_writable_descriptor_absence_verified": False,
        "filesystem_immutability_verified": False,
        "fork_descriptor_inheritance_excluded": False,
        "future_execution_correspondence_verified": False,
        "interpreter_argument_semantics_verified": False,
        "interpreter_authenticity_verified": False,
        "interpreter_compatibility_verified": False,
        "interpreter_identity_verified": False,
        "interpreter_provenance_verified": False,
        "hardlink_alias_exclusion_verified": False,
        "kind": REPOSITORY_EXECUTABLE_SHEBANG_TARGET_STAGING_EVIDENCE_KIND,
        "lease_process_binding_established": True,
        "live_execution_eligible": False,
        "mount_alias_exclusion_verified": False,
        "native_not_applicable_count": value.native_not_applicable_count,
        "post_stage_target_resolution_correspondence_verified": True,
        "proposal_lineage_extended": False,
        "read_only_descriptor_lease_established": value.staging_root_used,
        "receipt_authenticity_verified": False,
        "receipt_digest": _BUILTIN_CANONICAL_DIGEST(canonical),
        "registration_digest": value.registration_digest,
        "repository_ref": value.repository_ref,
        "requirement_count": value.requirement_count,
        "resolution_context_digest": value.resolution_context_digest,
        "resolution_scope": value.resolution_scope,
        "route_eligible": False,
        "same_uid_tamper_exclusion_verified": False,
        "schema_version": value.schema_version,
        "secure_erasure_verified": False,
        "shared_library_identity_verified": False,
        "staged_byte_correspondence_verified": True,
        "staged_readback_complete": value.staging_root_used,
        "staging_root_used": value.staging_root_used,
        "staging_scope": value.staging_scope,
        "staging_source": value.staging_source,
        "subprocess_invocation_performed": False,
        "target_semantics_verified": False,
        "toolchain_completeness_verified": False,
        "total_staged_bytes": value.total_staged_bytes,
        "unique_target_count": value.unique_target_count,
        "validation_mode": "local_staging",
        "worktree_integration_enabled": False,
    }


def _cleanup_receipt_projection(
    value: RepositoryExecutableShebangTargetStageCleanupReceipt,
) -> dict[str, Any]:
    if (
        type(value)
        is not RepositoryExecutableShebangTargetStageCleanupReceipt
        or value.kind
        != REPOSITORY_EXECUTABLE_SHEBANG_TARGET_STAGE_CLEANUP_KIND
        or type(value.schema_version) is not int
        or value.schema_version
        != REPOSITORY_EXECUTABLE_SHEBANG_TARGET_STAGING_SCHEMA_VERSION
        or value.outcome
        not in {"removed", "already_absent_verified", "unverifiable"}
        or (
            value.target_staging_receipt_digest is not None
            and not _is_digest(value.target_staging_receipt_digest)
        )
        or type(value.owned_namespace_absence_verified) is not bool
        or type(value.descriptor_release_complete) is not bool
        or type(value.staging_root_identity_verified) is not bool
        or type(value.staging_root_metadata_restored) is not bool
        or value.staging_root_metadata_restored
        or type(value.secure_erasure_verified) is not bool
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
        raise _InvalidTargetStaging
    return {
        "descriptor_release_complete": value.descriptor_release_complete,
        "kind": value.kind,
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
        "target_staging_receipt_digest": (
            value.target_staging_receipt_digest
        ),
    }


def _store_cleanup_receipt(
    lease: RepositoryExecutableShebangTargetStageLease,
    receipt: RepositoryExecutableShebangTargetStageCleanupReceipt,
) -> None:
    canonical = _cleanup_receipt_projection(receipt)
    lease._cleanup_receipt = receipt
    lease._cleanup_receipt_object_anchor = receipt
    lease._cleanup_receipt_digest_anchor = _BUILTIN_CANONICAL_DIGEST(canonical)


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
        raise _InvalidTargetStaging


def _require_new_lease(
    lease: Any,
) -> RepositoryExecutableShebangTargetStageLease:
    if (
        type(lease) is not RepositoryExecutableShebangTargetStageLease
        or lease._receipt is not None
        or lease._cleanup_receipt is not None
        or lease._receipt_digest_anchor is not None
        or lease._receipt_object_anchor is not None
        or lease._receipt_file_refs_anchor != ()
        or lease._files_object_anchor is not None
        or lease._cleanup_receipt_digest_anchor is not None
        or lease._cleanup_receipt_object_anchor is not None
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
        raise _InvalidTargetStaging
    return lease


class _TargetCaptureSink:
    """Copy bounded bytes through each action measurement's pinned FD."""

    def __init__(self) -> None:
        self.by_identity_ref: dict[str, _CapturedTarget] = {}
        self.total_bytes = 0

    def __call__(
        self,
        descriptor: int,
        metadata: os.stat_result,
        measured: _MeasuredTarget,
    ) -> None:
        if (
            type(measured) is not _MeasuredTarget
            or measured.filesystem_identity_ref in self.by_identity_ref
            or len(self.by_identity_ref) >= _MAX_TARGETS
            or measured.content_bytes != metadata.st_size
            or measured.content_bytes < 0
            or measured.content_bytes > _MAX_TARGET_BYTES
            or self.total_bytes + measured.content_bytes
            > _MAX_TOTAL_TARGET_BYTES
        ):
            raise _InvalidTargetStaging
        try:
            before = os.fstat(descriptor)
            flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
            inheritable = os.get_inheritable(descriptor)
            position = os.lseek(descriptor, 0, os.SEEK_CUR)
        except (OSError, ValueError):
            raise _InvalidTargetStaging from None
        if (
            _metadata_signature(before) != measured.metadata
            or _metadata_signature(metadata) != measured.metadata
            or flags & os.O_ACCMODE != os.O_RDONLY
            or inheritable
        ):
            raise _InvalidTargetStaging

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
                raise _InvalidTargetStaging from None
            if not chunk or len(chunk) > measured.content_bytes - offset:
                raise _InvalidTargetStaging
            chunks.append(chunk)
            digest.update(chunk)
            offset += len(chunk)
        try:
            boundary = os.pread(descriptor, 1, measured.content_bytes)
            after = os.fstat(descriptor)
            after_flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
            after_inheritable = os.get_inheritable(descriptor)
            after_position = os.lseek(descriptor, 0, os.SEEK_CUR)
        except (OSError, ValueError):
            raise _InvalidTargetStaging from None
        content_digest = "sha256:" + digest.hexdigest()
        if (
            boundary != b""
            or _metadata_signature(after) != measured.metadata
            or after_flags != flags
            or after_inheritable != inheritable
            or after_position != position
            or content_digest != measured.content_digest
        ):
            raise _InvalidTargetStaging
        self.by_identity_ref[measured.filesystem_identity_ref] = _CapturedTarget(
            target_path_ref=measured.path_ref,
            source_identity=measured.identity,
            source_filesystem_identity_ref=measured.filesystem_identity_ref,
            source_metadata=measured.metadata,
            source_metadata_digest=measured.metadata_digest,
            content_digest=content_digest,
            content=tuple(chunks),  # type: ignore[arg-type]
        )
        self.total_bytes += measured.content_bytes

    def clear(self) -> None:
        self.by_identity_ref.clear()
        self.total_bytes = 0


@dataclass(frozen=True, slots=True)
class _ProtectedContext:
    registration: RepositoryRegistration = field(repr=False)
    registration_canonical: dict[str, Any] = field(repr=False)
    repository: _PinnedDirectory = field(repr=False)
    searches: tuple[_PinnedDirectory, ...] = field(repr=False)
    source_staging_root: _PinnedDirectory = field(repr=False)
    resolution_context_digest: str = field(repr=False)

    @property
    def all_directories(self) -> tuple[_PinnedDirectory, ...]:
        return (self.repository, *self.searches, self.source_staging_root)


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
    expected_target_resolution: (
        RepositoryExecutableShebangTargetResolutionReceipt
    ),
    expected_requirements: RepositoryExecutableShebangRequirementsReceipt,
    expected_runtime: RepositoryExecutableRuntimeManifestReceipt,
    expected_staging: RepositoryExecutableStagingReceipt,
    executable_lease: RepositoryExecutableStageLease,
) -> _ProtectedContext:
    if (
        type(registration) is not RepositoryRegistration
        or type(registration.schema_version) is not int
        or registration.schema_version != 4
        or type(expected_requirements)
        is not RepositoryExecutableShebangRequirementsReceipt
        or type(expected_runtime)
        is not RepositoryExecutableRuntimeManifestReceipt
        or type(expected_staging) is not RepositoryExecutableStagingReceipt
        or type(executable_lease) is not RepositoryExecutableStageLease
    ):
        raise _InvalidTargetStaging
    refreshed = _BUILTIN_REVALIDATE_REGISTRATION(registration)
    if refreshed.schema_version != 4:
        raise _InvalidTargetStaging
    canonical = _BUILTIN_REGISTRATION_PROJECTION(refreshed)
    registration_digest = _BUILTIN_CANONICAL_DIGEST(canonical)
    commands_digest = _BUILTIN_CANONICAL_DIGEST(
        canonical["verification_commands"]
    )
    if (
        registration_digest != expected_target_resolution.registration_digest
        or registration_digest != expected_requirements.registration_digest
        or registration_digest != expected_runtime.registration_digest
        or registration_digest != expected_staging.registration_digest
        or refreshed.repository.repository_ref
        != expected_target_resolution.repository_ref
        or refreshed.repository.repository_ref != expected_requirements.repository_ref
        or refreshed.repository.repository_ref != expected_runtime.repository_ref
        or refreshed.repository.repository_ref != expected_staging.repository_ref
        or commands_digest
        != expected_target_resolution.verification_commands_digest
        or commands_digest != expected_requirements.verification_commands_digest
        or commands_digest != expected_runtime.verification_commands_digest
        or commands_digest != expected_staging.verification_commands_digest
    ):
        raise _InvalidTargetStaging

    paths = _BUILTIN_VALIDATE_SEARCH_DIRECTORIES(search_directories)
    repository: _PinnedDirectory | None = None
    searches: list[_PinnedDirectory] = []
    source_root: _PinnedDirectory | None = None
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
            raise _InvalidTargetStaging
        for path in paths:
            pinned = _BUILTIN_OPEN_ABSOLUTE_DIRECTORY(path)
            if any(
                existing.metadata[:2] == pinned.metadata[:2]
                for existing in searches
            ):
                try:
                    os.close(pinned.descriptor)
                except OSError:
                    pass
                raise _InvalidTargetStaging
            searches.append(pinned)
        context_digest = _BUILTIN_RESOLUTION_CONTEXT_DIGEST(tuple(searches))
        if (
            context_digest != expected_target_resolution.resolution_context_digest
            or context_digest != expected_requirements.resolution_context_digest
            or context_digest != expected_runtime.resolution_context_digest
            or context_digest != expected_staging.resolution_context_digest
        ):
            raise _InvalidTargetStaging
        source_root = _BUILTIN_OPEN_ABSOLUTE_DIRECTORY(
            executable_lease.staging_root
        )
        source_root_metadata = os.fstat(source_root.descriptor)
        source_staging_context_digest = _BUILTIN_CANONICAL_DIGEST(
            {
                "directory_device": source_root_metadata.st_dev,
                "directory_inode": source_root_metadata.st_ino,
                "directory_mode": stat.S_IMODE(source_root_metadata.st_mode),
                "directory_owner": source_root_metadata.st_uid,
                "kind": "repository_executable_staging_context",
                "schema_version": 1,
                "staging_scope": SOURCE_STAGING_SCOPE,
            }
        )
        if (
            executable_lease._root_metadata is None
            or source_root.metadata[:2]
            != executable_lease._root_metadata[:2]
            or stat.S_IMODE(source_root.metadata[2])
            != stat.S_IMODE(executable_lease._root_metadata[2])
            or source_root.metadata[4:6]
            != executable_lease._root_metadata[4:6]
            or source_staging_context_digest
            != expected_staging.staging_context_digest
            or source_staging_context_digest
            != expected_runtime.staging_context_digest
            or source_staging_context_digest
            != expected_requirements.staging_context_digest
            or source_staging_context_digest
            != expected_target_resolution.staging_context_digest
        ):
            raise _InvalidTargetStaging
        return _ProtectedContext(
            registration=refreshed,
            registration_canonical=canonical,
            repository=repository,
            searches=tuple(searches),
            source_staging_root=source_root,
            resolution_context_digest=context_digest,
        )
    except BaseException:
        if source_root is not None:
            try:
                os.close(source_root.descriptor)
            except OSError:
                pass
        for directory in reversed(searches):
            try:
                os.close(directory.descriptor)
            except OSError:
                pass
        if repository is not None:
            try:
                os.close(repository.descriptor)
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
        raise _InvalidTargetStaging from None


def _same_identity(first: os.stat_result, second: tuple[int, ...]) -> bool:
    return (first.st_dev, first.st_ino) == second[:2]


def _root_path_identity_matches(
    lease: RepositoryExecutableShebangTargetStageLease,
) -> bool:
    if lease._root_metadata is None:
        return False
    reopened: _PinnedDirectory | None = None
    try:
        reopened = _BUILTIN_OPEN_ABSOLUTE_DIRECTORY(lease.staging_root)
        metadata = os.fstat(reopened.descriptor)
        expected = lease._root_metadata
        return bool(
            (metadata.st_dev, metadata.st_ino) == expected[:2]
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


def _target_ancestor_aliases_root(
    paths: tuple[Path, ...],
    *,
    root_metadata: os.stat_result,
) -> bool:
    checked: set[tuple[str, ...]] = set()
    for path in paths:
        components = _absolute_path_parts(path)
        for count in range(len(components)):
            prefix = components[:count]
            if prefix in checked:
                continue
            checked.add(prefix)
            ancestor = Path(os.sep).joinpath(*prefix)
            pinned = _BUILTIN_OPEN_ABSOLUTE_DIRECTORY(ancestor)
            try:
                if _same_identity(root_metadata, pinned.metadata):
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
            "kind": "repository_executable_shebang_target_staging_context",
            "schema_version": 1,
            "staging_root_used": False,
            "staging_scope": STAGING_SCOPE,
        }
    )


def _prepare_target_staging_root(
    lease: RepositoryExecutableShebangTargetStageLease,
    *,
    protected: _ProtectedContext,
    expected_target_paths: tuple[Path, ...],
) -> str:
    if (
        type(lease.staging_root) is not _CONCRETE_PATH_TYPE
        or not lease.staging_root.is_absolute()
        or type(expected_target_paths) is not tuple
    ):
        raise _InvalidTargetStaging
    _absolute_path_parts(lease.staging_root)
    protected_paths = (
        protected.repository.path,
        *(item.path for item in protected.searches),
        protected.source_staging_root.path,
        *expected_target_paths,
    )
    for path in protected_paths:
        _absolute_path_parts(path)
        if _path_components_overlap(lease.staging_root, path):
            raise _InvalidTargetStaging

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
                _same_identity(metadata, item.metadata)
                for item in protected.all_directories
            )
            or _target_ancestor_aliases_root(
                expected_target_paths,
                root_metadata=metadata,
            )
        ):
            raise _InvalidTargetStaging

        # Keep an invalid pre-existing root outside the lease: cleanup owns
        # only roots that passed every non-mutating validation above.
        lease._root_metadata = _metadata_signature(metadata)
        lease._root_descriptor = pinned.descriptor
    except BaseException:
        if pinned is not None and lease._root_descriptor != pinned.descriptor:
            if not _close_descriptor(pinned.descriptor):
                lease._descriptor_release_unverifiable = True
                _mark_cleanup_unverifiable(lease)
                raise _CleanupUncertain from None
            lease._root_metadata = None
        raise
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "directory_device": metadata.st_dev,
            "directory_inode": metadata.st_ino,
            "directory_mode": stat.S_IMODE(metadata.st_mode),
            "directory_owner": metadata.st_uid,
            "kind": "repository_executable_shebang_target_staging_context",
            "schema_version": 1,
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
        raise _InvalidTargetStaging
    return ".ordomata-shebang-target-" + value


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
        raise _InvalidTargetStaging from None


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
            raise _InvalidTargetStaging from None
        if not chunk or len(chunk) > content_bytes - offset:
            raise _InvalidTargetStaging
        digest.update(chunk)
        offset += len(chunk)
    try:
        if os.pread(descriptor, 1, content_bytes) != b"":
            raise _InvalidTargetStaging
    except (BlockingIOError, InterruptedError, OSError):
        raise _InvalidTargetStaging from None
    return "sha256:" + digest.hexdigest()


def _staged_identity_ref(metadata: os.stat_result) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "kind": (
                "repository_executable_shebang_target_staged_file_identity"
            ),
            "schema_version": 1,
        }
    )


def _staged_metadata_digest(
    metadata: os.stat_result,
    *,
    staged_filesystem_identity_ref: str,
) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "change_time_ns": metadata.st_ctime_ns,
            "filesystem_identity_ref": staged_filesystem_identity_ref,
            "group_id": metadata.st_gid,
            "kind": (
                "repository_executable_shebang_target_staged_file_metadata"
            ),
            "link_count": metadata.st_nlink,
            "mode": metadata.st_mode,
            "modified_time_ns": metadata.st_mtime_ns,
            "owner_id": metadata.st_uid,
            "schema_version": 1,
            "size_bytes": metadata.st_size,
        }
    )


def _target_staged_file_ref(
    *,
    captured: _CapturedTarget,
    target_measurement_ref: str,
    staged_filesystem_identity_ref: str,
    staged_metadata_digest: str,
    target_staging_context_digest: str,
) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "content_digest": captured.content_digest,
            "kind": "repository_executable_shebang_target_staged_file_ref",
            "schema_version": 1,
            "source_filesystem_identity_ref": (
                captured.source_filesystem_identity_ref
            ),
            "source_metadata_digest": captured.source_metadata_digest,
            "staged_filesystem_identity_ref": (
                staged_filesystem_identity_ref
            ),
            "staged_metadata_digest": staged_metadata_digest,
            "target_measurement_ref": target_measurement_ref,
            "target_path_ref": captured.target_path_ref,
            "target_staging_context_digest": target_staging_context_digest,
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
    lease: RepositoryExecutableShebangTargetStageLease,
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
        for descriptor in descriptors:
            if not _close_descriptor(descriptor):
                close_failed = True
        lease._pending_name = None
        lease._pending_identity = None
        lease._pending_descriptors = ()
        if close_failed:
            lease._descriptor_release_unverifiable = True
            return None
        return "removed" if removed else "already_absent_verified"
    except (OSError, TypeError, ValueError, _InvalidTargetStaging):
        return None


def _mark_cleanup_unverifiable(
    lease: RepositoryExecutableShebangTargetStageLease,
) -> None:
    lease._state = "cleanup_unverifiable"
    receipt = RepositoryExecutableShebangTargetStageCleanupReceipt(
        kind=REPOSITORY_EXECUTABLE_SHEBANG_TARGET_STAGE_CLEANUP_KIND,
        schema_version=(
            REPOSITORY_EXECUTABLE_SHEBANG_TARGET_STAGING_SCHEMA_VERSION
        ),
        outcome="unverifiable",
        target_staging_receipt_digest=(
            None if lease._receipt is None else lease._receipt_digest_anchor
        ),
        owned_namespace_absence_verified=False,
        descriptor_release_complete=False,
        staging_root_identity_verified=False,
        staging_root_metadata_restored=False,
        secure_erasure_verified=False,
    )
    _store_cleanup_receipt(lease, receipt)


def _recover_pending_handoff(
    lease: RepositoryExecutableShebangTargetStageLease,
    *,
    name: str,
    descriptors: tuple[int, ...],
) -> bool:
    """Adopt exact local handles, then prove their linked-name cleanup."""

    identity = _pending_identity_from_descriptors(descriptors)
    if identity is None:
        lease._descriptor_release_unverifiable = True
        _mark_cleanup_unverifiable(lease)
        return False
    # The lease type is exact.  Bypass an interrupted/instrumented normal
    # assignment so this recovery frame can adopt every locally owned handle
    # as one conservative cleanup record before any local is discarded.
    object.__setattr__(lease, "_pending_name", name)
    object.__setattr__(lease, "_pending_identity", identity)
    object.__setattr__(lease, "_pending_descriptors", descriptors)
    if _attempt_pending_name_cleanup(lease) is None:
        _mark_cleanup_unverifiable(lease)
        return False
    return True


def _open_pending_writer(
    lease: RepositoryExecutableShebangTargetStageLease,
    *,
    root_descriptor: int,
    name: str,
    flags: int,
) -> int | None:
    """Open one exclusive writer and transfer or clean its linked ownership."""

    descriptor: int | None = None
    try:
        try:
            descriptor = os.open(
                name,
                flags,
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
        if descriptor is not None:
            if not _recover_pending_handoff(
                lease,
                name=name,
                descriptors=(descriptor,),
            ):
                raise _CleanupUncertain from None
        raise


def _open_pending_reader(
    lease: RepositoryExecutableShebangTargetStageLease,
    *,
    root_descriptor: int,
    name: str,
    writer: int,
) -> int:
    """Open the reader and transfer both linked handles as one ownership set."""

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


def _stage_captured_target(
    lease: RepositoryExecutableShebangTargetStageLease,
    captured: _CapturedTarget,
    *,
    target_measurement_ref: str,
    target_staging_context_digest: str,
) -> _RetainedStagedTarget:
    root_descriptor = lease._root_descriptor
    if root_descriptor is None:
        raise _InvalidTargetStaging
    writer: int | None = None
    reader: int | None = None
    detached = False
    name: str | None = None
    identity: tuple[int, int] | None = None
    installed_files: tuple[_RetainedStagedTarget, ...] | None = None
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
            name = candidate
            try:
                writer = _open_pending_writer(
                    lease,
                    root_descriptor=root_descriptor,
                    name=name,
                    flags=flags,
                )
            except OSError:
                raise _InvalidTargetStaging from None
            if writer is None:
                name = None
                continue
            break
        if writer is None or name is None:
            raise _InvalidTargetStaging

        try:
            os.fchmod(writer, 0o600)
            writer_metadata = os.fstat(writer)
        except OSError:
            raise _InvalidTargetStaging from None
        identity = (writer_metadata.st_dev, writer_metadata.st_ino)
        lease._pending_identity = identity
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
            raise _InvalidTargetStaging

        entry = _entry_metadata(root_descriptor, name)
        if (
            entry is None
            or stat.S_ISLNK(entry.st_mode)
            or (entry.st_dev, entry.st_ino) != identity
        ):
            raise _InvalidTargetStaging
        try:
            reader = _open_pending_reader(
                lease,
                root_descriptor=root_descriptor,
                name=name,
                writer=writer,
            )
        except BaseException:
            # The helper either proved cleanup or retained every exact handle
            # in the lease's conservative pending record.
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
            raise _InvalidTargetStaging

        current = _entry_metadata(root_descriptor, name)
        if current is None or (current.st_dev, current.st_ino) != identity:
            raise _CleanupUncertain
        try:
            os.unlink(name, dir_fd=root_descriptor)
        except OSError:
            raise _CleanupUncertain from None
        if (
            _entry_metadata(root_descriptor, name) is not None
            or os.fstat(writer).st_nlink != 0
            or os.fstat(reader).st_nlink != 0
        ):
            raise _CleanupUncertain
        try:
            os.fsync(root_descriptor)
        except OSError:
            raise _CleanupUncertain from None
        detached = True
        lease._pending_name = None
        lease._pending_identity = None
        lease._pending_descriptors = ()

        _write_all(writer, captured.content)
        try:
            os.fchmod(writer, _STAGED_FILE_MODE)
            os.fsync(writer)
        except OSError:
            raise _InvalidTargetStaging from None
        content_bytes = sum(len(chunk) for chunk in captured.content)
        if (
            content_bytes > _MAX_TARGET_BYTES
            or _descriptor_digest(reader, content_bytes=content_bytes)
            != captured.content_digest
        ):
            raise _InvalidTargetStaging
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
            raise _InvalidTargetStaging

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
            raise _InvalidTargetStaging
        staged_identity_ref = _staged_identity_ref(final_metadata)
        staged_metadata_digest = _staged_metadata_digest(
            final_metadata,
            staged_filesystem_identity_ref=staged_identity_ref,
        )
        staged_file = RepositoryExecutableShebangTargetStagedFile(
            kind=REPOSITORY_EXECUTABLE_SHEBANG_TARGET_STAGED_FILE_KIND,
            target_path_ref=captured.target_path_ref,
            source_filesystem_identity_ref=(
                captured.source_filesystem_identity_ref
            ),
            source_metadata_digest=captured.source_metadata_digest,
            target_measurement_ref=target_measurement_ref,
            target_staged_file_ref=_target_staged_file_ref(
                captured=captured,
                target_measurement_ref=target_measurement_ref,
                staged_filesystem_identity_ref=staged_identity_ref,
                staged_metadata_digest=staged_metadata_digest,
                target_staging_context_digest=(
                    target_staging_context_digest
                ),
            ),
            staged_filesystem_identity_ref=staged_identity_ref,
            staged_metadata_digest=staged_metadata_digest,
            content_digest=captured.content_digest,
            content_bytes=content_bytes,
        )
        retained = _RetainedStagedTarget(
            staged_file=staged_file,
            descriptor=reader,
            metadata=_metadata_signature(final_metadata),
        )
        installed_files = lease._files + (retained,)
        lease._files = installed_files
        reader = None
        return retained
    except BaseException:
        if installed_files is not None and lease._files is installed_files:
            reader = None
        if not detached:
            local_descriptors = tuple(
                item for item in (writer, reader) if item is not None
            )
            pending_name = lease._pending_name or name
            if local_descriptors and pending_name is not None:
                cleanup_verified = _recover_pending_handoff(
                    lease,
                    name=pending_name,
                    descriptors=local_descriptors,
                )
                writer = None
                reader = None
                if not cleanup_verified:
                    raise _CleanupUncertain from None
            elif lease._pending_name is not None:
                if _attempt_pending_name_cleanup(lease) is None:
                    _mark_cleanup_unverifiable(lease)
                    raise _CleanupUncertain from None
        if detached:
            detached_descriptors = tuple(
                item for item in (writer, reader) if item is not None
            )
            try:
                unexpected_links = any(
                    os.fstat(item).st_nlink != 0
                    for item in detached_descriptors
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


def _verify_retained_target(value: _RetainedStagedTarget) -> None:
    if type(value) is not _RetainedStagedTarget:
        raise _InvalidTargetStaging
    _staged_file_projection(value.staged_file)
    try:
        metadata = os.fstat(value.descriptor)
        flags = fcntl.fcntl(value.descriptor, fcntl.F_GETFL)
        inheritable = os.get_inheritable(value.descriptor)
    except (OSError, ValueError):
        raise _InvalidTargetStaging from None
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
        raise _InvalidTargetStaging


def _build_staging_receipt(
    *,
    expected: RepositoryExecutableShebangTargetResolutionReceipt,
    action: RepositoryExecutableShebangTargetResolutionReceipt,
    post_stage: RepositoryExecutableShebangTargetResolutionReceipt,
    retained_files: tuple[_RetainedStagedTarget, ...],
    target_staging_context_digest: str,
) -> RepositoryExecutableShebangTargetStagingReceipt:
    file_by_measurement_ref = {
        item.staged_file.target_measurement_ref: item.staged_file
        for item in retained_files
    }
    if tuple(file_by_measurement_ref) != tuple(
        item.measurement_ref for item in action.measurements
    ):
        raise _InvalidTargetStaging

    requirements: list[RepositoryExecutableShebangTargetStageRequirement] = []
    for upstream in action.requirements:
        if upstream.disposition == "direct_absolute_target_measured":
            if upstream.target_measurement_ref is None:
                raise _InvalidTargetStaging
            staged = file_by_measurement_ref.get(
                upstream.target_measurement_ref
            )
            if staged is None:
                raise _InvalidTargetStaging
            disposition = "direct_absolute_target_staged"
            target_measurement_ref = upstream.target_measurement_ref
            target_staged_file_ref = staged.target_staged_file_ref
        elif upstream.disposition == "native_not_applicable":
            disposition = "native_not_applicable"
            target_measurement_ref = None
            target_staged_file_ref = None
        else:
            raise _InvalidTargetStaging
        reference = _stage_requirement_ref_projection(
            staged_file_ref=upstream.staged_file_ref,
            runtime_file_ref=upstream.runtime_file_ref,
            requirement_ref=upstream.requirement_ref,
            target_requirement_ref=upstream.target_requirement_ref,
            runtime_classification=upstream.runtime_classification,
            disposition=disposition,
            target_measurement_ref=target_measurement_ref,
            target_staged_file_ref=target_staged_file_ref,
        )
        requirement = RepositoryExecutableShebangTargetStageRequirement(
            kind=(
                REPOSITORY_EXECUTABLE_SHEBANG_TARGET_STAGE_REQUIREMENT_KIND
            ),
            staged_file_ref=upstream.staged_file_ref,
            runtime_file_ref=upstream.runtime_file_ref,
            requirement_ref=upstream.requirement_ref,
            target_requirement_ref=upstream.target_requirement_ref,
            runtime_classification=upstream.runtime_classification,
            disposition=disposition,
            target_measurement_ref=target_measurement_ref,
            target_staged_file_ref=target_staged_file_ref,
            target_stage_requirement_ref=_BUILTIN_CANONICAL_DIGEST(reference),
        )
        _stage_requirement_projection(requirement)
        requirements.append(requirement)

    requirement_by_target_ref = {
        item.target_requirement_ref: item for item in requirements
    }
    bindings: list[RepositoryExecutableShebangTargetStageBinding] = []
    for upstream in action.bindings:
        requirement = requirement_by_target_ref.get(
            upstream.target_requirement_ref
        )
        if requirement is None:
            raise _InvalidTargetStaging
        binding = RepositoryExecutableShebangTargetStageBinding(
            kind=REPOSITORY_EXECUTABLE_SHEBANG_TARGET_STAGE_BINDING_KIND,
            command_kind=upstream.command_kind,
            command_id=upstream.command_id,
            command_digest=upstream.command_digest,
            staged_file_ref=upstream.staged_file_ref,
            runtime_file_ref=upstream.runtime_file_ref,
            requirement_ref=upstream.requirement_ref,
            target_requirement_ref=upstream.target_requirement_ref,
            target_stage_requirement_ref=(
                requirement.target_stage_requirement_ref
            ),
        )
        _stage_binding_projection(binding)
        bindings.append(binding)

    receipt = RepositoryExecutableShebangTargetStagingReceipt(
        kind=REPOSITORY_EXECUTABLE_SHEBANG_TARGET_STAGING_KIND,
        schema_version=(
            REPOSITORY_EXECUTABLE_SHEBANG_TARGET_STAGING_SCHEMA_VERSION
        ),
        measurement_source=action.measurement_source,
        resolution_scope=action.resolution_scope,
        staging_source=STAGING_SOURCE,
        staging_scope=STAGING_SCOPE,
        shebang_requirements_receipt_digest=(
            action.shebang_requirements_receipt_digest
        ),
        runtime_manifest_receipt_digest=(
            action.runtime_manifest_receipt_digest
        ),
        staging_receipt_digest=action.staging_receipt_digest,
        registration_digest=action.registration_digest,
        repository_ref=action.repository_ref,
        verification_commands_digest=action.verification_commands_digest,
        resolution_context_digest=action.resolution_context_digest,
        source_staging_context_digest=action.staging_context_digest,
        target_path_context_digest=action.target_path_context_digest,
        expected_target_resolution_receipt_digest=_BUILTIN_CANONICAL_DIGEST(
            _BUILTIN_TARGET_RESOLUTION_PROJECTION(expected)
        ),
        action_target_resolution_receipt_digest=_BUILTIN_CANONICAL_DIGEST(
            _BUILTIN_TARGET_RESOLUTION_PROJECTION(action)
        ),
        post_stage_target_resolution_receipt_digest=(
            _BUILTIN_CANONICAL_DIGEST(
                _BUILTIN_TARGET_RESOLUTION_PROJECTION(post_stage)
            )
        ),
        target_staging_context_digest=target_staging_context_digest,
        staging_root_used=bool(retained_files),
        staged_files=tuple(item.staged_file for item in retained_files),
        requirements=tuple(requirements),
        bindings=tuple(bindings),
        requirement_count=len(requirements),
        command_count=len(bindings),
        direct_target_requirement_count=(
            action.direct_target_requirement_count
        ),
        native_not_applicable_count=action.native_not_applicable_count,
        unique_target_count=len(retained_files),
        total_staged_bytes=sum(
            item.staged_file.content_bytes for item in retained_files
        ),
    )
    _staging_receipt_projection(receipt)
    return receipt


def _verified_cleanup_receipt(
    lease: RepositoryExecutableShebangTargetStageLease,
    *,
    outcome: Literal["removed", "already_absent_verified"],
    root_identity_verified: bool,
) -> RepositoryExecutableShebangTargetStageCleanupReceipt:
    receipt = RepositoryExecutableShebangTargetStageCleanupReceipt(
        kind=REPOSITORY_EXECUTABLE_SHEBANG_TARGET_STAGE_CLEANUP_KIND,
        schema_version=(
            REPOSITORY_EXECUTABLE_SHEBANG_TARGET_STAGING_SCHEMA_VERSION
        ),
        outcome=outcome,
        target_staging_receipt_digest=(
            None if lease._receipt is None else lease._receipt_digest_anchor
        ),
        owned_namespace_absence_verified=True,
        descriptor_release_complete=True,
        staging_root_identity_verified=root_identity_verified,
        staging_root_metadata_restored=False,
        secure_erasure_verified=False,
    )
    _cleanup_receipt_projection(receipt)
    return receipt


def _release_retained_targets(
    lease: RepositoryExecutableShebangTargetStageLease,
) -> bool:
    remaining: list[_RetainedStagedTarget] = []
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
            lease._descriptor_release_unverifiable = True
            success = False
            continue
        if not namespace_absent:
            success = False
            remaining.append(value)
            continue
        if _close_descriptor(value.descriptor):
            continue
        lease._descriptor_release_unverifiable = True
        success = False
    lease._files = tuple(remaining)
    return success and not lease._descriptor_release_unverifiable


def _close_root_descriptor(
    lease: RepositoryExecutableShebangTargetStageLease,
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


def _abort_staging(
    lease: RepositoryExecutableShebangTargetStageLease,
) -> bool:
    if type(lease) is not RepositoryExecutableShebangTargetStageLease:
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
        except _InvalidTargetStaging:
            root_identity_verified = False
        if not root_identity_verified:
            _mark_cleanup_unverifiable(lease)
            return False
    if not _release_retained_targets(lease):
        _mark_cleanup_unverifiable(lease)
        return False
    lease._files_object_anchor = None
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


def cleanup_repository_executable_shebang_target_stage(
    lease: RepositoryExecutableShebangTargetStageLease,
) -> RepositoryExecutableShebangTargetStageCleanupReceipt:
    """Release a target lease or conservatively retry uncertain cleanup."""

    if type(lease) is not RepositoryExecutableShebangTargetStageLease:
        raise ValidationError(_INVALID_MESSAGE)
    if lease._owner_pid != os.getpid():
        raise ValidationError(_INVALID_MESSAGE)
    if lease._state == "cleaned":
        if lease._cleanup_receipt is None:
            raise ValidationError(_INVALID_MESSAGE)
        try:
            canonical = _cleanup_receipt_projection(lease._cleanup_receipt)
            if (
                lease._cleanup_receipt
                is not lease._cleanup_receipt_object_anchor
                or lease._cleanup_receipt_digest_anchor
                != _BUILTIN_CANONICAL_DIGEST(canonical)
            ):
                raise _InvalidTargetStaging
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
                raise _InvalidTargetStaging
            canonical = _staging_receipt_projection(lease._receipt)
            file_refs = tuple(
                item.target_staged_file_ref
                for item in lease._receipt.staged_files
            )
            retained_refs = tuple(
                item.staged_file.target_staged_file_ref
                for item in lease._files
            )
            if (
                lease._receipt is not lease._receipt_object_anchor
                or lease._receipt_digest_anchor
                != _BUILTIN_CANONICAL_DIGEST(canonical)
                or file_refs != lease._receipt_file_refs_anchor
                or lease._files is not lease._files_object_anchor
                or retained_refs != file_refs
                or len(lease._files) != lease._receipt.unique_target_count
                or any(
                    retained.staged_file is not anchored
                    for retained, anchored in zip(
                        lease._files,
                        lease._receipt.staged_files,
                        strict=True,
                    )
                )
            ):
                raise _InvalidTargetStaging
            for item in lease._files:
                _verify_retained_target(item)
        except (AttributeError, OSError, TypeError, ValueError):
            _mark_cleanup_unverifiable(lease)
            raise ConfigurationError(_CLEANUP_UNCERTAIN_MESSAGE) from None
        if not _release_retained_targets(lease):
            _mark_cleanup_unverifiable(lease)
            raise ConfigurationError(_CLEANUP_UNCERTAIN_MESSAGE) from None
        lease._files_object_anchor = None
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
                    assert lease._cleanup_receipt is not None
                    return lease._cleanup_receipt
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
                    if metadata.st_nlink != 0:
                        remaining.append(descriptor)
                    elif not _close_descriptor(descriptor):
                        lease._descriptor_release_unverifiable = True
                lease._pending_descriptors = tuple(remaining)
                if remaining:
                    _mark_cleanup_unverifiable(lease)
                    assert lease._cleanup_receipt is not None
                    return lease._cleanup_receipt
                lease._pending_identity = None
        if not _release_retained_targets(lease):
            _mark_cleanup_unverifiable(lease)
            assert lease._cleanup_receipt is not None
            return lease._cleanup_receipt
        lease._files_object_anchor = None
        root_identity_verified = False
        if lease._root_descriptor is not None:
            try:
                root_identity_verified = bool(
                    _directory_is_empty(lease._root_descriptor)
                    and _root_path_identity_matches(lease)
                )
            except _InvalidTargetStaging:
                root_identity_verified = False
            if not root_identity_verified or not _close_root_descriptor(lease):
                _mark_cleanup_unverifiable(lease)
                assert lease._cleanup_receipt is not None
                return lease._cleanup_receipt
        if lease._descriptor_release_unverifiable:
            _mark_cleanup_unverifiable(lease)
            assert lease._cleanup_receipt is not None
            return lease._cleanup_receipt
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


def _captures_in_action_order(
    capture: _TargetCaptureSink,
    action: RepositoryExecutableShebangTargetResolutionReceipt,
) -> tuple[_CapturedTarget, ...]:
    if (
        len(capture.by_identity_ref) != action.unique_target_count
        or capture.total_bytes != action.total_measured_bytes
        or tuple(capture.by_identity_ref)
        != tuple(
            item.filesystem_identity_ref for item in action.measurements
        )
    ):
        raise _InvalidTargetStaging
    ordered: list[_CapturedTarget] = []
    for measurement in action.measurements:
        captured = capture.by_identity_ref.get(
            measurement.filesystem_identity_ref
        )
        if (
            captured is None
            or captured.target_path_ref != measurement.path_ref
            or captured.source_filesystem_identity_ref
            != measurement.filesystem_identity_ref
            or captured.source_metadata_digest != measurement.metadata_digest
            or captured.content_digest != measurement.content_digest
            or sum(len(chunk) for chunk in captured.content)
            != measurement.content_bytes
        ):
            raise _InvalidTargetStaging
        ordered.append(captured)
    return tuple(ordered)


def stage_repository_executable_shebang_target_bytes(
    registration: RepositoryRegistration,
    *,
    search_directories: tuple[Path, ...],
    expected_target_resolution: (
        RepositoryExecutableShebangTargetResolutionReceipt
    ),
    expected_requirements: RepositoryExecutableShebangRequirementsReceipt,
    expected_runtime: RepositoryExecutableRuntimeManifestReceipt,
    expected_staging: RepositoryExecutableStagingReceipt,
    executable_lease: RepositoryExecutableStageLease,
    expected_target_paths: tuple[Path, ...],
    lease: RepositoryExecutableShebangTargetStageLease,
) -> RepositoryExecutableShebangTargetStagingReceipt:
    """Freshly reproduce and stage one exact direct-target byte set.

    The caller must already own any required Class 1 authorization.  This
    function is a non-authorizing filesystem primitive and never executes or
    dispatches a target.
    """

    capture = _TargetCaptureSink()
    protected: _ProtectedContext | None = None
    staging_started = False
    lease_validated = False
    try:
        _require_supported_platform()
        lease = _require_new_lease(lease)
        lease_validated = True
        expected_canonical = _BUILTIN_TARGET_RESOLUTION_PROJECTION(
            expected_target_resolution
        )

        # The private inspector calls the sink while each action measurement's
        # source descriptor remains pinned.  It then performs its independent
        # second pass and full upstream lease revalidation before returning.
        action = _BUILTIN_INSPECT_TARGETS(
            expected_requirements,
            expected_runtime=expected_runtime,
            expected_staging=expected_staging,
            lease=executable_lease,
            expected_target_paths=expected_target_paths,
            unique_target_consumer=capture,
        )
        action_canonical = _BUILTIN_TARGET_RESOLUTION_PROJECTION(action)
        if action_canonical != expected_canonical:
            raise _InvalidTargetStaging
        ordered_captures = _captures_in_action_order(capture, action)
        source_files_anchor = executable_lease._files

        # Independently derive the protected-root set from a fresh schema-v4
        # registration and the exact no-follow search context.  These pinned
        # directories remain open across every target-staging mutation.
        protected = _registration_and_search_context(
            registration,
            search_directories=search_directories,
            expected_target_resolution=expected_target_resolution,
            expected_requirements=expected_requirements,
            expected_runtime=expected_runtime,
            expected_staging=expected_staging,
            executable_lease=executable_lease,
        )
        if (
            not _protected_context_still_matches(protected)
            or executable_lease._files is not source_files_anchor
        ):
            raise _InvalidTargetStaging

        if action.unique_target_count == 0:
            if (
                action.direct_target_requirement_count != 0
                or action.total_measured_bytes != 0
                or ordered_captures != ()
            ):
                raise _InvalidTargetStaging
            target_staging_context_digest = _noop_staging_context_digest()
        else:
            target_staging_context_digest = _prepare_target_staging_root(
                lease,
                protected=protected,
                expected_target_paths=expected_target_paths,
            )
            staging_started = True
            for measurement, captured in zip(
                action.measurements,
                ordered_captures,
                strict=True,
            ):
                _stage_captured_target(
                    lease,
                    captured,
                    target_measurement_ref=measurement.measurement_ref,
                    target_staging_context_digest=(
                        target_staging_context_digest
                    ),
                )

        retained = lease._files
        post_stage = _BUILTIN_INSPECT_TARGETS(
            expected_requirements,
            expected_runtime=expected_runtime,
            expected_staging=expected_staging,
            lease=executable_lease,
            expected_target_paths=expected_target_paths,
        )
        post_canonical = _BUILTIN_TARGET_RESOLUTION_PROJECTION(post_stage)
        if (
            post_canonical != expected_canonical
            or post_canonical != action_canonical
            or executable_lease._files is not source_files_anchor
            or not _protected_context_still_matches(protected)
        ):
            raise _InvalidTargetStaging

        if action.unique_target_count:
            root_descriptor = lease._root_descriptor
            if (
                root_descriptor is None
                or not _directory_is_empty(root_descriptor)
                or not _root_path_identity_matches(lease)
            ):
                raise _InvalidTargetStaging
            try:
                os.fsync(root_descriptor)
            except OSError:
                raise _InvalidTargetStaging from None
            for item in retained:
                _verify_retained_target(item)
        elif (
            lease._root_descriptor is not None
            or lease._root_metadata is not None
            or lease._files
            or lease._pending_name is not None
            or lease._pending_descriptors
        ):
            raise _InvalidTargetStaging

        receipt = _build_staging_receipt(
            expected=expected_target_resolution,
            action=action,
            post_stage=post_stage,
            retained_files=tuple(retained),
            target_staging_context_digest=target_staging_context_digest,
        )
        if not _close_root_descriptor(lease):
            raise _CleanupUncertain
        receipt_canonical = _staging_receipt_projection(receipt)
        receipt_digest_anchor = _BUILTIN_CANONICAL_DIGEST(receipt_canonical)
        receipt_file_refs_anchor = tuple(
            item.target_staged_file_ref for item in receipt.staged_files
        )
        lease._receipt = receipt
        lease._receipt_object_anchor = receipt
        lease._receipt_digest_anchor = receipt_digest_anchor
        lease._receipt_file_refs_anchor = receipt_file_refs_anchor
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
            or lease._files
            or lease._receipt is not None
            or lease._receipt_object_anchor is not None
            or lease._receipt_digest_anchor is not None
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
