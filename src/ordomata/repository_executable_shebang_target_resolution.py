"""Measure direct absolute shebang target files without interpreting them.

This Class 0 boundary consumes one exact staged shebang-requirements chain and
measures only the concrete absolute file named by each supported shebang's
first token.  The token is not called an interpreter: launcher, ``env``,
argument, kernel, PATH, dependency, and future execution semantics remain
outside this receipt.  Native ELF and Mach-O files are explicitly not
applicable.  All other runtime or token forms fail the whole call.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
import unicodedata
from typing import Any, Callable

from .authorization import canonical_digest
from .errors import ValidationError
from .repository_executable_resolution import (
    MEASUREMENT_SOURCE as STAGING_MEASUREMENT_SOURCE,
    REPOSITORY_EXECUTABLE_RESOLUTION_SCOPE as STAGING_RESOLUTION_SCOPE,
)
from .repository_executable_runtime_manifest import (
    MANIFEST_SCOPE as RUNTIME_MANIFEST_SCOPE,
    MANIFEST_SOURCE as RUNTIME_MANIFEST_SOURCE,
    REPOSITORY_EXECUTABLE_RUNTIME_BINDING_KIND,
    REPOSITORY_EXECUTABLE_RUNTIME_FILE_KIND,
    REPOSITORY_EXECUTABLE_RUNTIME_MANIFEST_KIND,
    REPOSITORY_EXECUTABLE_RUNTIME_MANIFEST_SCHEMA_VERSION,
    RepositoryExecutableRuntimeBinding,
    RepositoryExecutableRuntimeFile,
    RepositoryExecutableRuntimeManifestReceipt,
    inspect_staged_executable_runtime_manifest,
)
from .repository_executable_shebang_requirements import (
    REQUIREMENTS_SCOPE,
    REQUIREMENTS_SOURCE,
    REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENT_BINDING_KIND,
    REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENT_KIND,
    REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENTS_KIND,
    REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENTS_SCHEMA_VERSION,
    RepositoryExecutableShebangRequirement,
    RepositoryExecutableShebangRequirementBinding,
    RepositoryExecutableShebangRequirementsReceipt,
    _independent_runtime_manifest_projection as _runtime_projection_v1,
    _independent_staging_receipt_projection as _staging_projection_v1,
    inspect_staged_executable_shebang_requirements,
)
from .repository_executable_staging import (
    REPOSITORY_EXECUTABLE_STAGE_BINDING_KIND,
    REPOSITORY_EXECUTABLE_STAGED_FILE_KIND,
    REPOSITORY_EXECUTABLE_STAGING_KIND,
    REPOSITORY_EXECUTABLE_STAGING_SCHEMA_VERSION,
    STAGING_SCOPE,
    STAGING_SOURCE,
    RepositoryExecutableStageBinding,
    RepositoryExecutableStageLease,
    RepositoryExecutableStagedFile,
    RepositoryExecutableStagingReceipt,
    _RetainedStagedFile,
)


REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RESOLUTION_SCHEMA_VERSION = 1
REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RESOLUTION_KIND = (
    "repository_executable_shebang_target_resolution"
)
REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RESOLUTION_EVIDENCE_KIND = (
    "repository_executable_shebang_target_resolution_validation"
)
REPOSITORY_EXECUTABLE_SHEBANG_TARGET_MEASUREMENT_KIND = (
    "repository_executable_shebang_target_measurement"
)
REPOSITORY_EXECUTABLE_SHEBANG_TARGET_REQUIREMENT_KIND = (
    "repository_executable_shebang_target_requirement"
)
REPOSITORY_EXECUTABLE_SHEBANG_TARGET_BINDING_KIND = (
    "repository_executable_shebang_target_binding"
)
MEASUREMENT_SOURCE = "controller_measured"
RESOLUTION_SCOPE = "posix_absolute_shebang_target_nofollow_v1"

_INVALID_MESSAGE = "repository executable shebang target resolution is invalid"
_COMMAND_KINDS = ("format", "lint", "type_check", "test", "build")
_RUNTIME_CLASSIFICATIONS = (
    "elf",
    "mach_o",
    "posix_shebang",
    "unsupported_shebang",
    "unknown",
)
_TARGET_DISPOSITIONS = (
    "direct_absolute_target_measured",
    "native_not_applicable",
)
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER_PATTERN = re.compile(r"[a-z][a-z0-9_.-]{0,119}\Z")
_CONCRETE_PATH_TYPE = type(Path())
_MAX_FILES = 80
_MAX_COMMANDS = 80
_MAX_TARGET_PATHS = 80
_MAX_TARGET_PATH_BYTES = 4_096
_MAX_TOTAL_TARGET_PATH_BYTES = 16 * 1024
_MAX_TARGET_PATH_COMPONENTS = 64
_MAX_TARGET_PATH_COMPONENT_BYTES = 255
_MAX_DIRECTORY_ENTRIES = 16_384
_MAX_DIRECTORY_ENTRY_BYTES = 4 * 1024 * 1024
_MAX_TARGET_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_TARGET_BYTES = 256 * 1024 * 1024
_MAX_RUNTIME_FILE_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_RUNTIME_BYTES = 256 * 1024 * 1024
_MAX_HEADER_BYTES = 4_096
_MAX_DIRECTIVE_BYTES = 255
_READ_CHUNK_BYTES = 1024 * 1024
_STAGED_FILE_MODE = 0o400
_MACH_O_MAGICS = frozenset(
    {
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf",
        b"\xbf\xba\xfe\xca",
    }
)
_MACH_O_MINIMUM_BYTES = {
    b"\xfe\xed\xfa\xce": 28,
    b"\xce\xfa\xed\xfe": 28,
    b"\xfe\xed\xfa\xcf": 32,
    b"\xcf\xfa\xed\xfe": 32,
    b"\xca\xfe\xba\xbe": 28,
    b"\xbe\xba\xfe\xca": 28,
    b"\xca\xfe\xba\xbf": 40,
    b"\xbf\xba\xfe\xca": 40,
}

_BUILTIN_CANONICAL_DIGEST = canonical_digest
_BUILTIN_SHA256 = hashlib.sha256
_BUILTIN_PREAD = os.pread
_BUILTIN_GETPID = os.getpid
_BUILTIN_INSPECT_RUNTIME_MANIFEST = inspect_staged_executable_runtime_manifest
_BUILTIN_INSPECT_SHEBANG_REQUIREMENTS = (
    inspect_staged_executable_shebang_requirements
)


class _InvalidShebangTargetResolution(ValueError):
    """Private fail-closed sentinel whose details never cross the boundary."""


@dataclass(frozen=True, slots=True)
class RepositoryExecutableShebangTargetMeasurement:
    """One exact direct target path and its point-in-time file measurement."""

    kind: str
    path_ref: str = field(repr=False)
    filesystem_identity_ref: str = field(repr=False)
    metadata_digest: str = field(repr=False)
    content_digest: str = field(repr=False)
    content_bytes: int
    measurement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _measurement_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableShebangTargetRequirement:
    """One upstream requirement's direct-target or native disposition."""

    kind: str
    staged_file_ref: str = field(repr=False)
    runtime_file_ref: str = field(repr=False)
    requirement_ref: str = field(repr=False)
    runtime_classification: str
    disposition: str
    shebang_directive_ref: str | None = field(repr=False)
    interpreter_token_ref: str | None = field(repr=False)
    argument_tail_ref: str | None = field(repr=False)
    target_measurement_ref: str | None = field(repr=False)
    target_requirement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _target_requirement_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableShebangTargetBinding:
    """One registered command bound to one target requirement."""

    kind: str
    command_kind: str
    command_id: str = field(repr=False)
    command_digest: str = field(repr=False)
    staged_file_ref: str = field(repr=False)
    runtime_file_ref: str = field(repr=False)
    requirement_ref: str = field(repr=False)
    target_requirement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _target_binding_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableShebangTargetResolutionReceipt:
    """Immutable privacy-bounded evidence for sequential direct-target reads."""

    kind: str
    schema_version: int
    measurement_source: str
    resolution_scope: str
    shebang_requirements_receipt_digest: str = field(repr=False)
    runtime_manifest_receipt_digest: str = field(repr=False)
    staging_receipt_digest: str = field(repr=False)
    registration_digest: str = field(repr=False)
    repository_ref: str = field(repr=False)
    verification_commands_digest: str = field(repr=False)
    resolution_context_digest: str = field(repr=False)
    staging_context_digest: str = field(repr=False)
    target_path_context_digest: str = field(repr=False)
    measurements: tuple[
        RepositoryExecutableShebangTargetMeasurement, ...
    ] = field(repr=False)
    requirements: tuple[
        RepositoryExecutableShebangTargetRequirement, ...
    ] = field(repr=False)
    bindings: tuple[RepositoryExecutableShebangTargetBinding, ...] = field(
        repr=False
    )
    requirement_count: int
    command_count: int
    direct_target_requirement_count: int
    native_not_applicable_count: int
    unique_target_count: int
    total_measured_bytes: int

    def to_canonical(self) -> dict[str, Any]:
        return _receipt_projection(self)

    @property
    def receipt_digest(self) -> str:
        return _BUILTIN_CANONICAL_DIGEST(_receipt_projection(self))

    def to_evidence(self) -> dict[str, Any]:
        return _evidence_projection(self)


def _is_digest(value: Any) -> bool:
    return type(value) is str and _DIGEST_PATTERN.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class _DerivedRequirement:
    upstream: RepositoryExecutableShebangRequirement = field(repr=False)
    target_path: Path | None = field(repr=False)


@dataclass(frozen=True, slots=True)
class _MeasuredTarget:
    path: Path = field(repr=False)
    path_ref: str = field(repr=False)
    identity: tuple[int, int] = field(repr=False)
    metadata: tuple[int, ...] = field(repr=False)
    directory_chain: tuple[tuple[int, ...], ...] = field(repr=False)
    filesystem_identity_ref: str = field(repr=False)
    metadata_digest: str = field(repr=False)
    content_digest: str = field(repr=False)
    content_bytes: int


_UniqueTargetConsumer = Callable[
    [int, os.stat_result, _MeasuredTarget],
    None,
]


def _measurement_ref_projection(
    *,
    path_ref: str,
    filesystem_identity_ref: str,
    metadata_digest: str,
    content_digest: str,
    content_bytes: int,
) -> dict[str, Any]:
    return {
        "content_bytes": content_bytes,
        "content_digest": content_digest,
        "filesystem_identity_ref": filesystem_identity_ref,
        "kind": "repository_executable_shebang_target_measurement_ref",
        "measurement_source": MEASUREMENT_SOURCE,
        "metadata_digest": metadata_digest,
        "path_ref": path_ref,
        "resolution_scope": RESOLUTION_SCOPE,
        "schema_version": (
            REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RESOLUTION_SCHEMA_VERSION
        ),
    }


def _measurement_projection(
    value: RepositoryExecutableShebangTargetMeasurement,
) -> dict[str, Any]:
    if (
        type(value) is not RepositoryExecutableShebangTargetMeasurement
        or type(value.kind) is not str
        or value.kind != REPOSITORY_EXECUTABLE_SHEBANG_TARGET_MEASUREMENT_KIND
        or not _is_digest(value.path_ref)
        or not _is_digest(value.filesystem_identity_ref)
        or not _is_digest(value.metadata_digest)
        or not _is_digest(value.content_digest)
        or type(value.content_bytes) is not int
        or not 0 <= value.content_bytes <= _MAX_TARGET_BYTES
        or not _is_digest(value.measurement_ref)
    ):
        raise _InvalidShebangTargetResolution
    reference = _measurement_ref_projection(
        path_ref=value.path_ref,
        filesystem_identity_ref=value.filesystem_identity_ref,
        metadata_digest=value.metadata_digest,
        content_digest=value.content_digest,
        content_bytes=value.content_bytes,
    )
    if value.measurement_ref != _BUILTIN_CANONICAL_DIGEST(reference):
        raise _InvalidShebangTargetResolution
    return {
        "content_bytes": value.content_bytes,
        "content_digest": value.content_digest,
        "filesystem_identity_ref": value.filesystem_identity_ref,
        "kind": value.kind,
        "measurement_ref": value.measurement_ref,
        "metadata_digest": value.metadata_digest,
        "path_ref": value.path_ref,
    }


def _target_requirement_ref_projection(
    *,
    staged_file_ref: str,
    runtime_file_ref: str,
    requirement_ref: str,
    runtime_classification: str,
    disposition: str,
    shebang_directive_ref: str | None,
    interpreter_token_ref: str | None,
    argument_tail_ref: str | None,
    target_measurement_ref: str | None,
) -> dict[str, Any]:
    return {
        "argument_tail_ref": argument_tail_ref,
        "disposition": disposition,
        "interpreter_token_ref": interpreter_token_ref,
        "kind": "repository_executable_shebang_target_requirement_ref",
        "requirement_ref": requirement_ref,
        "resolution_scope": RESOLUTION_SCOPE,
        "runtime_classification": runtime_classification,
        "runtime_file_ref": runtime_file_ref,
        "schema_version": (
            REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RESOLUTION_SCHEMA_VERSION
        ),
        "shebang_directive_ref": shebang_directive_ref,
        "staged_file_ref": staged_file_ref,
        "target_measurement_ref": target_measurement_ref,
    }


def _target_requirement_projection(
    value: RepositoryExecutableShebangTargetRequirement,
) -> dict[str, Any]:
    if (
        type(value) is not RepositoryExecutableShebangTargetRequirement
        or type(value.kind) is not str
        or value.kind != REPOSITORY_EXECUTABLE_SHEBANG_TARGET_REQUIREMENT_KIND
        or not _is_digest(value.staged_file_ref)
        or not _is_digest(value.runtime_file_ref)
        or not _is_digest(value.requirement_ref)
        or type(value.runtime_classification) is not str
        or value.runtime_classification not in _RUNTIME_CLASSIFICATIONS
        or type(value.disposition) is not str
        or value.disposition not in _TARGET_DISPOSITIONS
        or (
            value.shebang_directive_ref is not None
            and not _is_digest(value.shebang_directive_ref)
        )
        or (
            value.interpreter_token_ref is not None
            and not _is_digest(value.interpreter_token_ref)
        )
        or (
            value.argument_tail_ref is not None
            and not _is_digest(value.argument_tail_ref)
        )
        or (
            value.target_measurement_ref is not None
            and not _is_digest(value.target_measurement_ref)
        )
        or not _is_digest(value.target_requirement_ref)
    ):
        raise _InvalidShebangTargetResolution
    if value.disposition == "direct_absolute_target_measured":
        if (
            value.runtime_classification != "posix_shebang"
            or value.shebang_directive_ref is None
            or value.interpreter_token_ref is None
            or value.target_measurement_ref is None
        ):
            raise _InvalidShebangTargetResolution
    elif (
        value.runtime_classification not in {"elf", "mach_o"}
        or value.shebang_directive_ref is not None
        or value.interpreter_token_ref is not None
        or value.argument_tail_ref is not None
        or value.target_measurement_ref is not None
    ):
        raise _InvalidShebangTargetResolution
    reference = _target_requirement_ref_projection(
        staged_file_ref=value.staged_file_ref,
        runtime_file_ref=value.runtime_file_ref,
        requirement_ref=value.requirement_ref,
        runtime_classification=value.runtime_classification,
        disposition=value.disposition,
        shebang_directive_ref=value.shebang_directive_ref,
        interpreter_token_ref=value.interpreter_token_ref,
        argument_tail_ref=value.argument_tail_ref,
        target_measurement_ref=value.target_measurement_ref,
    )
    if value.target_requirement_ref != _BUILTIN_CANONICAL_DIGEST(reference):
        raise _InvalidShebangTargetResolution
    return {
        "argument_tail_ref": value.argument_tail_ref,
        "disposition": value.disposition,
        "interpreter_token_ref": value.interpreter_token_ref,
        "kind": value.kind,
        "requirement_ref": value.requirement_ref,
        "runtime_classification": value.runtime_classification,
        "runtime_file_ref": value.runtime_file_ref,
        "shebang_directive_ref": value.shebang_directive_ref,
        "staged_file_ref": value.staged_file_ref,
        "target_measurement_ref": value.target_measurement_ref,
        "target_requirement_ref": value.target_requirement_ref,
    }


def _target_binding_projection(
    value: RepositoryExecutableShebangTargetBinding,
) -> dict[str, Any]:
    if (
        type(value) is not RepositoryExecutableShebangTargetBinding
        or type(value.kind) is not str
        or value.kind != REPOSITORY_EXECUTABLE_SHEBANG_TARGET_BINDING_KIND
        or type(value.command_kind) is not str
        or value.command_kind not in _COMMAND_KINDS
        or type(value.command_id) is not str
        or _IDENTIFIER_PATTERN.fullmatch(value.command_id) is None
        or not _is_digest(value.command_digest)
        or not _is_digest(value.staged_file_ref)
        or not _is_digest(value.runtime_file_ref)
        or not _is_digest(value.requirement_ref)
        or not _is_digest(value.target_requirement_ref)
    ):
        raise _InvalidShebangTargetResolution
    return {
        "command_digest": value.command_digest,
        "command_id": value.command_id,
        "command_kind": value.command_kind,
        "kind": value.kind,
        "requirement_ref": value.requirement_ref,
        "runtime_file_ref": value.runtime_file_ref,
        "staged_file_ref": value.staged_file_ref,
        "target_requirement_ref": value.target_requirement_ref,
    }


def _receipt_projection(
    value: RepositoryExecutableShebangTargetResolutionReceipt,
) -> dict[str, Any]:
    digest_fields = (
        value.shebang_requirements_receipt_digest,
        value.runtime_manifest_receipt_digest,
        value.staging_receipt_digest,
        value.registration_digest,
        value.repository_ref,
        value.verification_commands_digest,
        value.resolution_context_digest,
        value.staging_context_digest,
        value.target_path_context_digest,
    )
    if (
        type(value) is not RepositoryExecutableShebangTargetResolutionReceipt
        or type(value.kind) is not str
        or value.kind != REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RESOLUTION_KIND
        or type(value.schema_version) is not int
        or value.schema_version
        != REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RESOLUTION_SCHEMA_VERSION
        or type(value.measurement_source) is not str
        or value.measurement_source != MEASUREMENT_SOURCE
        or type(value.resolution_scope) is not str
        or value.resolution_scope != RESOLUTION_SCOPE
        or not all(_is_digest(item) for item in digest_fields)
        or type(value.measurements) is not tuple
        or not 0 <= len(value.measurements) <= _MAX_TARGET_PATHS
        or type(value.requirements) is not tuple
        or not 1 <= len(value.requirements) <= _MAX_FILES
        or type(value.bindings) is not tuple
        or not 1 <= len(value.bindings) <= _MAX_COMMANDS
        or type(value.requirement_count) is not int
        or value.requirement_count != len(value.requirements)
        or type(value.command_count) is not int
        or value.command_count != len(value.bindings)
        or type(value.direct_target_requirement_count) is not int
        or type(value.native_not_applicable_count) is not int
        or type(value.unique_target_count) is not int
        or value.unique_target_count != len(value.measurements)
        or type(value.total_measured_bytes) is not int
        or not 0 <= value.total_measured_bytes <= _MAX_TOTAL_TARGET_BYTES
    ):
        raise _InvalidShebangTargetResolution

    measurements = [_measurement_projection(item) for item in value.measurements]
    requirements = [
        _target_requirement_projection(item) for item in value.requirements
    ]
    bindings = [_target_binding_projection(item) for item in value.bindings]
    measurement_refs: set[str] = set()
    path_refs: set[str] = set()
    identity_refs: set[str] = set()
    total_bytes = 0
    for measurement in value.measurements:
        if (
            measurement.measurement_ref in measurement_refs
            or measurement.path_ref in path_refs
            or measurement.filesystem_identity_ref in identity_refs
        ):
            raise _InvalidShebangTargetResolution
        measurement_refs.add(measurement.measurement_ref)
        path_refs.add(measurement.path_ref)
        identity_refs.add(measurement.filesystem_identity_ref)
        total_bytes += measurement.content_bytes

    by_requirement_ref: dict[
        str, RepositoryExecutableShebangTargetRequirement
    ] = {}
    target_requirement_refs: set[str] = set()
    used_measurement_refs: list[str] = []
    for requirement in value.requirements:
        if (
            requirement.requirement_ref in by_requirement_ref
            or requirement.target_requirement_ref in target_requirement_refs
        ):
            raise _InvalidShebangTargetResolution
        by_requirement_ref[requirement.requirement_ref] = requirement
        target_requirement_refs.add(requirement.target_requirement_ref)
        if (
            requirement.target_measurement_ref is not None
            and requirement.target_measurement_ref not in used_measurement_refs
        ):
            used_measurement_refs.append(requirement.target_measurement_ref)
    if (
        set(used_measurement_refs) != measurement_refs
        or tuple(used_measurement_refs)
        != tuple(item.measurement_ref for item in value.measurements)
    ):
        raise _InvalidShebangTargetResolution

    command_ids: set[str] = set()
    bound_target_refs: set[str] = set()
    ordered_target_refs: list[str] = []
    prior_kind_index = -1
    for binding in value.bindings:
        requirement = by_requirement_ref.get(binding.requirement_ref)
        kind_index = _COMMAND_KINDS.index(binding.command_kind)
        if (
            requirement is None
            or binding.staged_file_ref != requirement.staged_file_ref
            or binding.runtime_file_ref != requirement.runtime_file_ref
            or binding.target_requirement_ref
            != requirement.target_requirement_ref
            or binding.command_id in command_ids
            or kind_index < prior_kind_index
        ):
            raise _InvalidShebangTargetResolution
        command_ids.add(binding.command_id)
        if binding.target_requirement_ref not in bound_target_refs:
            ordered_target_refs.append(binding.target_requirement_ref)
        bound_target_refs.add(binding.target_requirement_ref)
        prior_kind_index = kind_index
    direct_count = sum(
        item.disposition == "direct_absolute_target_measured"
        for item in value.requirements
    )
    native_count = sum(
        item.disposition == "native_not_applicable"
        for item in value.requirements
    )
    if (
        bound_target_refs != target_requirement_refs
        or tuple(ordered_target_refs)
        != tuple(item.target_requirement_ref for item in value.requirements)
        or direct_count != value.direct_target_requirement_count
        or native_count != value.native_not_applicable_count
        or direct_count + native_count != value.requirement_count
        or total_bytes != value.total_measured_bytes
    ):
        raise _InvalidShebangTargetResolution
    return {
        "bindings": bindings,
        "command_count": value.command_count,
        "direct_target_requirement_count": (
            value.direct_target_requirement_count
        ),
        "kind": value.kind,
        "measurement_source": value.measurement_source,
        "measurements": measurements,
        "native_not_applicable_count": value.native_not_applicable_count,
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
        "staging_context_digest": value.staging_context_digest,
        "staging_receipt_digest": value.staging_receipt_digest,
        "target_path_context_digest": value.target_path_context_digest,
        "total_measured_bytes": value.total_measured_bytes,
        "unique_target_count": value.unique_target_count,
        "verification_commands_digest": value.verification_commands_digest,
    }


def _evidence_projection(
    value: RepositoryExecutableShebangTargetResolutionReceipt,
) -> dict[str, Any]:
    canonical = _receipt_projection(value)
    return {
        "action_receipt_issued": False,
        "active_lease_verified_at_measurement": True,
        "ambient_path_search_performed": False,
        "atomic_snapshot_verified": False,
        "authority_granted": False,
        "authorization_verified": False,
        "billing_eligible": False,
        "capacity_eligible": False,
        "circuit_eligible": False,
        "command_count": value.command_count,
        "current_freshness_verified": False,
        "current_lease_activity_verified": False,
        "current_source_freshness_verified": False,
        "dependency_environment_coverage_verified": False,
        "direct_shebang_target_measurement_complete": True,
        "direct_target_requirement_count": (
            value.direct_target_requirement_count
        ),
        "dispatch_enabled": False,
        "durable_control_plane_persistence_enabled": False,
        "dynamic_loader_identity_verified": False,
        "effect_class": 0,
        "effective_interpreter_resolution_verified": False,
        "effective_invocability_verified": False,
        "environment_coverage_verified": False,
        "exact_receipt_chain_verified": True,
        "exact_target_path_lookup_performed": bool(
            value.direct_target_requirement_count
        ),
        "exact_target_path_set_verified": True,
        "execution_enabled": False,
        "external_writable_descriptor_absence_verified": False,
        "external_hardlink_alias_excluded": False,
        "external_mount_alias_excluded": False,
        "external_writable_descriptor_excluded": False,
        "future_execution_correspondence_verified": False,
        "filesystem_immutability_verified": False,
        "hardlink_alias_exclusion_verified": False,
        "interpreter_argument_semantics_verified": False,
        "interpreter_authenticity_verified": False,
        "interpreter_compatibility_verified": False,
        "interpreter_identity_verified": False,
        "interpreter_provenance_verified": False,
        "interpreter_resolution_verified": False,
        "kind": (
            REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RESOLUTION_EVIDENCE_KIND
        ),
        "launcher_semantics_verified": False,
        "lease_cleanup_performed": False,
        "lease_mutated": False,
        "live_execution_eligible": False,
        "measurement_source": value.measurement_source,
        "mount_alias_exclusion_verified": False,
        "namespace_reopen_verified_at_measurement": bool(
            value.direct_target_requirement_count
        ),
        "native_not_applicable_count": value.native_not_applicable_count,
        "path_lookup_performed": bool(value.direct_target_requirement_count),
        "proposal_lineage_extended": False,
        "receipt_authenticity_verified": False,
        "receipt_digest": _BUILTIN_CANONICAL_DIGEST(canonical),
        "registration_digest": value.registration_digest,
        "repository_ref": value.repository_ref,
        "requirement_count": value.requirement_count,
        "resolution_context_digest": value.resolution_context_digest,
        "resolution_scope": value.resolution_scope,
        "route_eligible": False,
        "same_uid_tamper_exclusion_verified": False,
        "same_uid_mutation_excluded": False,
        "selected_target_content_measured": bool(
            value.direct_target_requirement_count
        ),
        "selected_target_namespace_reopen_verified": bool(
            value.direct_target_requirement_count
        ),
        "sequential_direct_target_measurement_complete": True,
        "shared_library_identity_verified": False,
        "staged_byte_correspondence_verified": True,
        "subprocess_invocation_performed": False,
        "target_path_context_digest": value.target_path_context_digest,
        "toolchain_completeness_verified": False,
        "total_measured_bytes": value.total_measured_bytes,
        "two_pass_target_measurement_verified": True,
        "unique_target_count": value.unique_target_count,
        "validation_mode": "read_only",
        "worktree_integration_enabled": False,
    }


def _require_supported_platform() -> None:
    required_flags = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")
    if (
        os.name != "posix"
        or any(not hasattr(os, name) for name in required_flags)
        or os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.stat not in os.supports_follow_symlinks
    ):
        raise _InvalidShebangTargetResolution


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


def _directory_signature(metadata: os.stat_result) -> tuple[int, ...]:
    """Bind a directory without treating unrelated child churn as path drift."""

    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


def _staged_identity_ref(metadata: os.stat_result) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
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
    identity_ref: str,
) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "change_time_ns": metadata.st_ctime_ns,
            "filesystem_identity_ref": identity_ref,
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


def _staged_file_ref(
    value: RepositoryExecutableStagedFile,
    *,
    staging_context_digest: str,
) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "content_bytes": value.content_bytes,
            "content_digest": value.content_digest,
            "kind": "repository_executable_staged_file_ref",
            "schema_version": 1,
            "source_filesystem_identity_ref": (
                value.source_filesystem_identity_ref
            ),
            "source_metadata_digest": value.source_metadata_digest,
            "staged_filesystem_identity_ref": (
                value.staged_filesystem_identity_ref
            ),
            "staged_metadata_digest": value.staged_metadata_digest,
            "staging_context_digest": staging_context_digest,
        }
    )


def _runtime_file_ref_projection(
    *,
    staged_file_ref: str,
    staged_filesystem_identity_ref: str,
    content_digest: str,
    content_bytes: int,
    header_digest: str,
    header_bytes: int,
    classification: str,
    shebang_directive_ref: str | None,
) -> dict[str, Any]:
    return {
        "classification": classification,
        "content_bytes": content_bytes,
        "content_digest": content_digest,
        "header_bytes": header_bytes,
        "header_digest": header_digest,
        "kind": "repository_executable_runtime_file_ref",
        "manifest_scope": RUNTIME_MANIFEST_SCOPE,
        "schema_version": REPOSITORY_EXECUTABLE_RUNTIME_MANIFEST_SCHEMA_VERSION,
        "shebang_directive_ref": shebang_directive_ref,
        "staged_file_ref": staged_file_ref,
        "staged_filesystem_identity_ref": staged_filesystem_identity_ref,
    }


def _header_digest(staged_file_ref: str, header: bytes) -> str:
    return "sha256:" + _BUILTIN_SHA256(
        staged_file_ref.encode("ascii") + b"\x00" + header
    ).hexdigest()


def _bounded_shebang_directive(header: bytes) -> bytes | None:
    if not header.startswith(b"#!"):
        return None
    newline = header.find(b"\n", 2)
    if newline < 0:
        return None
    directive = header[2:newline]
    if (
        not 1 <= len(directive) <= _MAX_DIRECTIVE_BYTES
        or directive[:1] in {b" ", b"\t"}
        or directive[-1:] in {b" ", b"\t"}
        or not any(value not in {0x20, 0x09} for value in directive)
        or any(
            value != 0x09 and not 0x20 <= value <= 0x7E
            for value in directive
        )
    ):
        return None
    return directive


def _classify_header(
    staged_file_ref: str,
    header: bytes,
) -> tuple[str, str | None, bytes | None]:
    if header.startswith(b"#!"):
        directive = _bounded_shebang_directive(header)
        if directive is None:
            return "unsupported_shebang", None, None
        directive_ref = _BUILTIN_CANONICAL_DIGEST(
            {
                "directive_hex": directive.hex(),
                "kind": "repository_executable_shebang_directive_ref",
                "schema_version": (
                    REPOSITORY_EXECUTABLE_RUNTIME_MANIFEST_SCHEMA_VERSION
                ),
                "staged_file_ref": staged_file_ref,
            }
        )
        return "posix_shebang", directive_ref, directive
    if header.startswith(b"\x7fELF"):
        if (
            len(header) >= 16
            and header[4] in {1, 2}
            and header[5] in {1, 2}
            and header[6] == 1
        ):
            return "elf", None, None
        return "unknown", None, None
    magic = header[:4]
    if (
        magic in _MACH_O_MAGICS
        and len(header) >= _MACH_O_MINIMUM_BYTES[magic]
    ):
        return "mach_o", None, None
    return "unknown", None, None


def _split_directive(directive: bytes) -> tuple[bytes, str | None, bytes | None]:
    boundary = next(
        (
            index
            for index, value in enumerate(directive)
            if value in {0x20, 0x09}
        ),
        None,
    )
    if boundary is None:
        return directive, None, None
    token = directive[:boundary]
    tail_start = boundary + 1
    while (
        tail_start < len(directive)
        and directive[tail_start] in {0x20, 0x09}
    ):
        tail_start += 1
    tail = directive[tail_start:]
    if not token or not tail:
        raise _InvalidShebangTargetResolution
    separator = "space" if directive[boundary] == 0x20 else "horizontal_tab"
    return token, separator, tail


def _token_ref(
    *,
    runtime_file_ref: str,
    shebang_directive_ref: str,
    token: bytes,
) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "interpreter_token_hex": token.hex(),
            "kind": "repository_executable_shebang_interpreter_token_ref",
            "runtime_file_ref": runtime_file_ref,
            "schema_version": (
                REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENTS_SCHEMA_VERSION
            ),
            "shebang_directive_ref": shebang_directive_ref,
        }
    )


def _tail_ref(
    *,
    runtime_file_ref: str,
    shebang_directive_ref: str,
    interpreter_token_ref: str,
    separator_kind: str,
    tail: bytes,
) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "argument_separator_kind": separator_kind,
            "argument_tail_hex": tail.hex(),
            "interpreter_token_ref": interpreter_token_ref,
            "kind": "repository_executable_shebang_argument_tail_ref",
            "runtime_file_ref": runtime_file_ref,
            "schema_version": (
                REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENTS_SCHEMA_VERSION
            ),
            "shebang_directive_ref": shebang_directive_ref,
        }
    )


def _upstream_requirement_ref_projection(
    *,
    staged_file_ref: str,
    runtime_file_ref: str,
    runtime_classification: str,
    disposition: str,
    shebang_directive_ref: str | None,
    interpreter_token_ref: str | None,
    interpreter_token_bytes: int,
    argument_separator_kind: str | None,
    argument_tail_ref: str | None,
    argument_tail_bytes: int,
) -> dict[str, Any]:
    return {
        "argument_separator_kind": argument_separator_kind,
        "argument_tail_bytes": argument_tail_bytes,
        "argument_tail_ref": argument_tail_ref,
        "disposition": disposition,
        "interpreter_token_bytes": interpreter_token_bytes,
        "interpreter_token_ref": interpreter_token_ref,
        "kind": "repository_executable_shebang_requirement_ref",
        "requirements_scope": REQUIREMENTS_SCOPE,
        "runtime_classification": runtime_classification,
        "runtime_file_ref": runtime_file_ref,
        "schema_version": (
            REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENTS_SCHEMA_VERSION
        ),
        "shebang_directive_ref": shebang_directive_ref,
        "staged_file_ref": staged_file_ref,
    }


def _local_upstream_requirement_projection(
    value: RepositoryExecutableShebangRequirement,
) -> dict[str, Any]:
    if (
        type(value) is not RepositoryExecutableShebangRequirement
        or type(value.kind) is not str
        or value.kind != REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENT_KIND
        or not _is_digest(value.staged_file_ref)
        or not _is_digest(value.runtime_file_ref)
        or type(value.runtime_classification) is not str
        or value.runtime_classification not in _RUNTIME_CLASSIFICATIONS
        or type(value.disposition) is not str
        or value.disposition
        not in {
            "native_binary_no_shebang",
            "absolute_interpreter_token",
            "non_absolute_interpreter_token",
            "unsupported_shebang",
            "unknown_runtime_format",
        }
        or type(value.interpreter_token_bytes) is not int
        or not 0 <= value.interpreter_token_bytes <= _MAX_DIRECTIVE_BYTES
        or type(value.argument_tail_bytes) is not int
        or not 0 <= value.argument_tail_bytes <= _MAX_DIRECTIVE_BYTES
        or not _is_digest(value.requirement_ref)
    ):
        raise _InvalidShebangTargetResolution
    expected_dispositions = {
        "elf": {"native_binary_no_shebang"},
        "mach_o": {"native_binary_no_shebang"},
        "posix_shebang": {
            "absolute_interpreter_token",
            "non_absolute_interpreter_token",
        },
        "unsupported_shebang": {"unsupported_shebang"},
        "unknown": {"unknown_runtime_format"},
    }
    if value.disposition not in expected_dispositions[value.runtime_classification]:
        raise _InvalidShebangTargetResolution
    is_posix = value.runtime_classification == "posix_shebang"
    has_tail = value.argument_tail_bytes > 0
    if is_posix:
        if (
            not _is_digest(value.shebang_directive_ref)
            or not _is_digest(value.interpreter_token_ref)
            or not 1 <= value.interpreter_token_bytes <= _MAX_DIRECTIVE_BYTES
            or (
                has_tail
                and (
                    type(value.argument_separator_kind) is not str
                    or value.argument_separator_kind
                    not in {"space", "horizontal_tab"}
                    or not _is_digest(value.argument_tail_ref)
                    or value.interpreter_token_bytes
                    + 1
                    + value.argument_tail_bytes
                    > _MAX_DIRECTIVE_BYTES
                )
            )
            or (
                not has_tail
                and (
                    value.argument_separator_kind is not None
                    or value.argument_tail_ref is not None
                )
            )
        ):
            raise _InvalidShebangTargetResolution
    elif (
        value.shebang_directive_ref is not None
        or value.interpreter_token_ref is not None
        or value.interpreter_token_bytes != 0
        or value.argument_separator_kind is not None
        or value.argument_tail_ref is not None
        or value.argument_tail_bytes != 0
    ):
        raise _InvalidShebangTargetResolution
    reference = _upstream_requirement_ref_projection(
        staged_file_ref=value.staged_file_ref,
        runtime_file_ref=value.runtime_file_ref,
        runtime_classification=value.runtime_classification,
        disposition=value.disposition,
        shebang_directive_ref=value.shebang_directive_ref,
        interpreter_token_ref=value.interpreter_token_ref,
        interpreter_token_bytes=value.interpreter_token_bytes,
        argument_separator_kind=value.argument_separator_kind,
        argument_tail_ref=value.argument_tail_ref,
        argument_tail_bytes=value.argument_tail_bytes,
    )
    if value.requirement_ref != _BUILTIN_CANONICAL_DIGEST(reference):
        raise _InvalidShebangTargetResolution
    return {
        "argument_separator_kind": value.argument_separator_kind,
        "argument_tail_bytes": value.argument_tail_bytes,
        "argument_tail_ref": value.argument_tail_ref,
        "disposition": value.disposition,
        "interpreter_token_bytes": value.interpreter_token_bytes,
        "interpreter_token_ref": value.interpreter_token_ref,
        "kind": value.kind,
        "requirement_ref": value.requirement_ref,
        "runtime_classification": value.runtime_classification,
        "runtime_file_ref": value.runtime_file_ref,
        "shebang_directive_ref": value.shebang_directive_ref,
        "staged_file_ref": value.staged_file_ref,
    }


def _local_upstream_binding_projection(
    value: RepositoryExecutableShebangRequirementBinding,
) -> dict[str, Any]:
    if (
        type(value) is not RepositoryExecutableShebangRequirementBinding
        or type(value.kind) is not str
        or value.kind
        != REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENT_BINDING_KIND
        or type(value.command_kind) is not str
        or value.command_kind not in _COMMAND_KINDS
        or type(value.command_id) is not str
        or _IDENTIFIER_PATTERN.fullmatch(value.command_id) is None
        or not _is_digest(value.command_digest)
        or not _is_digest(value.staged_file_ref)
        or not _is_digest(value.runtime_file_ref)
        or not _is_digest(value.requirement_ref)
    ):
        raise _InvalidShebangTargetResolution
    return {
        "command_digest": value.command_digest,
        "command_id": value.command_id,
        "command_kind": value.command_kind,
        "kind": value.kind,
        "requirement_ref": value.requirement_ref,
        "runtime_file_ref": value.runtime_file_ref,
        "staged_file_ref": value.staged_file_ref,
    }


def _local_requirements_projection(
    value: RepositoryExecutableShebangRequirementsReceipt,
) -> dict[str, Any]:
    digest_fields = (
        value.runtime_manifest_receipt_digest,
        value.staging_receipt_digest,
        value.registration_digest,
        value.repository_ref,
        value.verification_commands_digest,
        value.resolution_context_digest,
        value.staging_context_digest,
    )
    if (
        type(value) is not RepositoryExecutableShebangRequirementsReceipt
        or type(value.kind) is not str
        or value.kind != REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENTS_KIND
        or type(value.schema_version) is not int
        or value.schema_version
        != REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENTS_SCHEMA_VERSION
        or type(value.requirements_source) is not str
        or value.requirements_source != REQUIREMENTS_SOURCE
        or type(value.requirements_scope) is not str
        or value.requirements_scope != REQUIREMENTS_SCOPE
        or not all(_is_digest(item) for item in digest_fields)
        or type(value.requirements) is not tuple
        or not 1 <= len(value.requirements) <= _MAX_FILES
        or type(value.bindings) is not tuple
        or not 1 <= len(value.bindings) <= _MAX_COMMANDS
        or type(value.requirement_count) is not int
        or value.requirement_count != len(value.requirements)
        or type(value.command_count) is not int
        or value.command_count != len(value.bindings)
        or type(value.posix_shebang_requirement_count) is not int
        or type(value.argument_tail_requirement_count) is not int
        or type(value.total_interpreter_token_bytes) is not int
        or not 0
        <= value.total_interpreter_token_bytes
        <= _MAX_FILES * _MAX_DIRECTIVE_BYTES
        or type(value.total_argument_tail_bytes) is not int
        or not 0
        <= value.total_argument_tail_bytes
        <= _MAX_FILES * _MAX_DIRECTIVE_BYTES
    ):
        raise _InvalidShebangTargetResolution
    requirements = [
        _local_upstream_requirement_projection(item)
        for item in value.requirements
    ]
    bindings = [
        _local_upstream_binding_projection(item) for item in value.bindings
    ]
    by_runtime_ref: dict[str, RepositoryExecutableShebangRequirement] = {}
    staged_refs: set[str] = set()
    requirement_refs: set[str] = set()
    for requirement in value.requirements:
        if (
            requirement.runtime_file_ref in by_runtime_ref
            or requirement.staged_file_ref in staged_refs
            or requirement.requirement_ref in requirement_refs
        ):
            raise _InvalidShebangTargetResolution
        by_runtime_ref[requirement.runtime_file_ref] = requirement
        staged_refs.add(requirement.staged_file_ref)
        requirement_refs.add(requirement.requirement_ref)
    command_ids: set[str] = set()
    bound_refs: set[str] = set()
    ordered_refs: list[str] = []
    prior_kind_index = -1
    for binding in value.bindings:
        requirement = by_runtime_ref.get(binding.runtime_file_ref)
        kind_index = _COMMAND_KINDS.index(binding.command_kind)
        if (
            requirement is None
            or binding.staged_file_ref != requirement.staged_file_ref
            or binding.requirement_ref != requirement.requirement_ref
            or binding.command_id in command_ids
            or kind_index < prior_kind_index
        ):
            raise _InvalidShebangTargetResolution
        command_ids.add(binding.command_id)
        if binding.requirement_ref not in bound_refs:
            ordered_refs.append(binding.requirement_ref)
        bound_refs.add(binding.requirement_ref)
        prior_kind_index = kind_index
    posix_count = sum(
        item.runtime_classification == "posix_shebang"
        for item in value.requirements
    )
    tail_count = sum(
        item.argument_tail_ref is not None for item in value.requirements
    )
    token_bytes = sum(
        item.interpreter_token_bytes for item in value.requirements
    )
    tail_bytes = sum(item.argument_tail_bytes for item in value.requirements)
    if (
        bound_refs != requirement_refs
        or tuple(ordered_refs)
        != tuple(item.requirement_ref for item in value.requirements)
        or value.posix_shebang_requirement_count != posix_count
        or value.argument_tail_requirement_count != tail_count
        or value.total_interpreter_token_bytes != token_bytes
        or value.total_argument_tail_bytes != tail_bytes
    ):
        raise _InvalidShebangTargetResolution
    return {
        "argument_tail_requirement_count": (
            value.argument_tail_requirement_count
        ),
        "bindings": bindings,
        "command_count": value.command_count,
        "kind": value.kind,
        "posix_shebang_requirement_count": (
            value.posix_shebang_requirement_count
        ),
        "registration_digest": value.registration_digest,
        "repository_ref": value.repository_ref,
        "requirement_count": value.requirement_count,
        "requirements": requirements,
        "requirements_scope": value.requirements_scope,
        "requirements_source": value.requirements_source,
        "resolution_context_digest": value.resolution_context_digest,
        "runtime_manifest_receipt_digest": (
            value.runtime_manifest_receipt_digest
        ),
        "schema_version": value.schema_version,
        "staging_context_digest": value.staging_context_digest,
        "staging_receipt_digest": value.staging_receipt_digest,
        "total_argument_tail_bytes": value.total_argument_tail_bytes,
        "total_interpreter_token_bytes": value.total_interpreter_token_bytes,
        "verification_commands_digest": value.verification_commands_digest,
    }


def _canonical_target_path_from_token(token: bytes) -> Path:
    try:
        spelling = token.decode("ascii")
    except UnicodeDecodeError:
        raise _InvalidShebangTargetResolution from None
    if (
        not spelling.startswith("/")
        or spelling == "/"
        or spelling.endswith("/")
        or "//" in spelling
        or len(token) > _MAX_TARGET_PATH_BYTES
    ):
        raise _InvalidShebangTargetResolution
    components = spelling[1:].split("/")
    if (
        not 1 <= len(components) <= _MAX_TARGET_PATH_COMPONENTS
        or any(
            not component
            or component in {".", ".."}
            or len(component.encode("ascii"))
            > _MAX_TARGET_PATH_COMPONENT_BYTES
            for component in components
        )
    ):
        raise _InvalidShebangTargetResolution
    for component in components:
        _validate_component(component)
    path = Path(spelling)
    if (
        type(path) is not _CONCRETE_PATH_TYPE
        or not path.is_absolute()
        or os.fspath(path) != spelling
    ):
        raise _InvalidShebangTargetResolution
    return path


def _measure_retained_header(
    retained: _RetainedStagedFile,
    staged_file: RepositoryExecutableStagedFile,
) -> bytes:
    if (
        type(retained) is not _RetainedStagedFile
        or type(retained.staged_file) is not RepositoryExecutableStagedFile
        or retained.staged_file != staged_file
        or type(retained.descriptor) is not int
        or retained.descriptor < 0
        or type(retained.metadata) is not tuple
        or len(retained.metadata) != 9
        or any(type(part) is not int for part in retained.metadata)
    ):
        raise _InvalidShebangTargetResolution
    try:
        before = os.fstat(retained.descriptor)
        flags = fcntl.fcntl(retained.descriptor, fcntl.F_GETFL)
        inheritable = os.get_inheritable(retained.descriptor)
    except (OSError, ValueError):
        raise _InvalidShebangTargetResolution from None
    before_signature = _metadata_signature(before)
    identity_ref = _staged_identity_ref(before)
    if (
        before_signature != retained.metadata
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) != _STAGED_FILE_MODE
        or before.st_nlink != 0
        or before.st_size != staged_file.content_bytes
        or flags & os.O_ACCMODE != os.O_RDONLY
        or inheritable
        or identity_ref != staged_file.staged_filesystem_identity_ref
        or _staged_metadata_digest(before, identity_ref=identity_ref)
        != staged_file.staged_metadata_digest
    ):
        raise _InvalidShebangTargetResolution
    digest = _BUILTIN_SHA256()
    header_parts: list[bytes] = []
    header_remaining = min(staged_file.content_bytes, _MAX_HEADER_BYTES)
    offset = 0
    while offset < staged_file.content_bytes:
        requested = min(
            _READ_CHUNK_BYTES,
            staged_file.content_bytes - offset,
        )
        try:
            chunk = _BUILTIN_PREAD(retained.descriptor, requested, offset)
        except (BlockingIOError, InterruptedError, OSError):
            raise _InvalidShebangTargetResolution from None
        if not chunk or len(chunk) > requested:
            raise _InvalidShebangTargetResolution
        digest.update(chunk)
        if header_remaining:
            captured = chunk[:header_remaining]
            header_parts.append(captured)
            header_remaining -= len(captured)
        offset += len(chunk)
    try:
        boundary = _BUILTIN_PREAD(
            retained.descriptor,
            1,
            staged_file.content_bytes,
        )
        after = os.fstat(retained.descriptor)
        after_flags = fcntl.fcntl(retained.descriptor, fcntl.F_GETFL)
        after_inheritable = os.get_inheritable(retained.descriptor)
    except (BlockingIOError, InterruptedError, OSError, ValueError):
        raise _InvalidShebangTargetResolution from None
    header = b"".join(header_parts)
    if (
        boundary != b""
        or _metadata_signature(after) != before_signature
        or after_flags != flags
        or after_inheritable != inheritable
        or header_remaining != 0
        or len(header) != min(staged_file.content_bytes, _MAX_HEADER_BYTES)
        or "sha256:" + digest.hexdigest() != staged_file.content_digest
    ):
        raise _InvalidShebangTargetResolution
    return header


def _derive_requirements(
    expected_requirements: RepositoryExecutableShebangRequirementsReceipt,
    expected_runtime: RepositoryExecutableRuntimeManifestReceipt,
    expected_staging: RepositoryExecutableStagingReceipt,
    retained_files: tuple[_RetainedStagedFile, ...],
) -> tuple[_DerivedRequirement, ...]:
    if not (
        len(retained_files)
        == len(expected_staging.staged_files)
        == len(expected_runtime.files)
        == len(expected_requirements.requirements)
    ):
        raise _InvalidShebangTargetResolution
    derived: list[_DerivedRequirement] = []
    for retained, staged_file, runtime_file, requirement in zip(
        retained_files,
        expected_staging.staged_files,
        expected_runtime.files,
        expected_requirements.requirements,
        strict=True,
    ):
        if (
            type(staged_file) is not RepositoryExecutableStagedFile
            or type(runtime_file) is not RepositoryExecutableRuntimeFile
            or type(requirement) is not RepositoryExecutableShebangRequirement
            or runtime_file.staged_file_ref != staged_file.staged_file_ref
            or runtime_file.staged_filesystem_identity_ref
            != staged_file.staged_filesystem_identity_ref
            or runtime_file.content_digest != staged_file.content_digest
            or runtime_file.content_bytes != staged_file.content_bytes
            or requirement.staged_file_ref != staged_file.staged_file_ref
            or requirement.runtime_file_ref != runtime_file.runtime_file_ref
            or staged_file.staged_file_ref
            != _staged_file_ref(
                staged_file,
                staging_context_digest=expected_staging.staging_context_digest,
            )
        ):
            raise _InvalidShebangTargetResolution
        header = _measure_retained_header(retained, staged_file)
        classification, directive_ref, directive = _classify_header(
            staged_file.staged_file_ref,
            header,
        )
        header_digest = _header_digest(staged_file.staged_file_ref, header)
        runtime_reference = _runtime_file_ref_projection(
            staged_file_ref=staged_file.staged_file_ref,
            staged_filesystem_identity_ref=(
                staged_file.staged_filesystem_identity_ref
            ),
            content_digest=staged_file.content_digest,
            content_bytes=staged_file.content_bytes,
            header_digest=header_digest,
            header_bytes=len(header),
            classification=classification,
            shebang_directive_ref=directive_ref,
        )
        if (
            runtime_file.kind != REPOSITORY_EXECUTABLE_RUNTIME_FILE_KIND
            or runtime_file.header_digest != header_digest
            or runtime_file.header_bytes != len(header)
            or runtime_file.classification != classification
            or runtime_file.shebang_directive_ref != directive_ref
            or runtime_file.runtime_file_ref
            != _BUILTIN_CANONICAL_DIGEST(runtime_reference)
            or requirement.kind
            != REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENT_KIND
            or requirement.runtime_classification != classification
            or requirement.shebang_directive_ref != directive_ref
        ):
            raise _InvalidShebangTargetResolution

        target_path: Path | None = None
        if classification in {"elf", "mach_o"}:
            if (
                requirement.disposition != "native_binary_no_shebang"
                or requirement.interpreter_token_ref is not None
                or requirement.interpreter_token_bytes != 0
                or requirement.argument_separator_kind is not None
                or requirement.argument_tail_ref is not None
                or requirement.argument_tail_bytes != 0
            ):
                raise _InvalidShebangTargetResolution
        elif classification == "posix_shebang":
            if directive is None or directive_ref is None:
                raise _InvalidShebangTargetResolution
            token, separator_kind, tail = _split_directive(directive)
            token_ref = _token_ref(
                runtime_file_ref=runtime_file.runtime_file_ref,
                shebang_directive_ref=directive_ref,
                token=token,
            )
            tail_ref: str | None = None
            if tail is not None:
                if separator_kind is None:
                    raise _InvalidShebangTargetResolution
                tail_ref = _tail_ref(
                    runtime_file_ref=runtime_file.runtime_file_ref,
                    shebang_directive_ref=directive_ref,
                    interpreter_token_ref=token_ref,
                    separator_kind=separator_kind,
                    tail=tail,
                )
            if (
                requirement.disposition != "absolute_interpreter_token"
                or requirement.interpreter_token_ref != token_ref
                or requirement.interpreter_token_bytes != len(token)
                or requirement.argument_separator_kind != separator_kind
                or requirement.argument_tail_ref != tail_ref
                or requirement.argument_tail_bytes
                != (0 if tail is None else len(tail))
            ):
                raise _InvalidShebangTargetResolution
            target_path = _canonical_target_path_from_token(token)
        else:
            # Unsupported shebangs and unknown runtime formats are not partial
            # success states at this boundary.
            raise _InvalidShebangTargetResolution
        requirement_reference = _upstream_requirement_ref_projection(
            staged_file_ref=requirement.staged_file_ref,
            runtime_file_ref=requirement.runtime_file_ref,
            runtime_classification=requirement.runtime_classification,
            disposition=requirement.disposition,
            shebang_directive_ref=requirement.shebang_directive_ref,
            interpreter_token_ref=requirement.interpreter_token_ref,
            interpreter_token_bytes=requirement.interpreter_token_bytes,
            argument_separator_kind=requirement.argument_separator_kind,
            argument_tail_ref=requirement.argument_tail_ref,
            argument_tail_bytes=requirement.argument_tail_bytes,
        )
        if requirement.requirement_ref != _BUILTIN_CANONICAL_DIGEST(
            requirement_reference
        ):
            raise _InvalidShebangTargetResolution
        derived.append(
            _DerivedRequirement(
                upstream=requirement,
                target_path=target_path,
            )
        )
    return tuple(derived)


def _verify_binding_chain(
    expected_requirements: RepositoryExecutableShebangRequirementsReceipt,
    expected_runtime: RepositoryExecutableRuntimeManifestReceipt,
    expected_staging: RepositoryExecutableStagingReceipt,
) -> None:
    if not (
        len(expected_requirements.bindings)
        == len(expected_runtime.bindings)
        == len(expected_staging.bindings)
    ):
        raise _InvalidShebangTargetResolution
    for requirement_binding, runtime_binding, staging_binding in zip(
        expected_requirements.bindings,
        expected_runtime.bindings,
        expected_staging.bindings,
        strict=True,
    ):
        if (
            type(requirement_binding)
            is not RepositoryExecutableShebangRequirementBinding
            or requirement_binding.kind
            != REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENT_BINDING_KIND
            or type(runtime_binding) is not RepositoryExecutableRuntimeBinding
            or runtime_binding.kind
            != REPOSITORY_EXECUTABLE_RUNTIME_BINDING_KIND
            or type(staging_binding) is not RepositoryExecutableStageBinding
            or staging_binding.kind != REPOSITORY_EXECUTABLE_STAGE_BINDING_KIND
            or requirement_binding.command_kind != runtime_binding.command_kind
            or requirement_binding.command_kind != staging_binding.command_kind
            or requirement_binding.command_id != runtime_binding.command_id
            or requirement_binding.command_id != staging_binding.command_id
            or requirement_binding.command_digest
            != runtime_binding.command_digest
            or requirement_binding.command_digest
            != staging_binding.command_digest
            or requirement_binding.staged_file_ref
            != runtime_binding.staged_file_ref
            or requirement_binding.staged_file_ref
            != staging_binding.staged_file_ref
            or requirement_binding.runtime_file_ref
            != runtime_binding.runtime_file_ref
        ):
            raise _InvalidShebangTargetResolution


def _validated_chain_snapshot(
    expected_requirements: RepositoryExecutableShebangRequirementsReceipt,
    expected_runtime: RepositoryExecutableRuntimeManifestReceipt,
    expected_staging: RepositoryExecutableStagingReceipt,
    lease: RepositoryExecutableStageLease,
) -> tuple[
    tuple[_DerivedRequirement, ...],
    str,
    str,
    str,
    tuple[_RetainedStagedFile, ...],
]:
    if (
        type(expected_requirements)
        is not RepositoryExecutableShebangRequirementsReceipt
        or type(expected_runtime)
        is not RepositoryExecutableRuntimeManifestReceipt
        or type(expected_staging)
        is not RepositoryExecutableStagingReceipt
        or type(lease) is not RepositoryExecutableStageLease
    ):
        raise _InvalidShebangTargetResolution
    staging_canonical = _staging_projection_v1(expected_staging)
    runtime_canonical = _runtime_projection_v1(expected_runtime)
    requirements_canonical = _local_requirements_projection(
        expected_requirements
    )
    staging_digest = _BUILTIN_CANONICAL_DIGEST(staging_canonical)
    runtime_digest = _BUILTIN_CANONICAL_DIGEST(runtime_canonical)
    requirements_digest = _BUILTIN_CANONICAL_DIGEST(requirements_canonical)
    if (
        expected_runtime.staging_receipt_digest != staging_digest
        or expected_requirements.staging_receipt_digest != staging_digest
        or expected_requirements.runtime_manifest_receipt_digest
        != runtime_digest
        or expected_runtime.registration_digest
        != expected_staging.registration_digest
        or expected_requirements.registration_digest
        != expected_staging.registration_digest
        or expected_runtime.repository_ref != expected_staging.repository_ref
        or expected_requirements.repository_ref
        != expected_staging.repository_ref
        or expected_runtime.verification_commands_digest
        != expected_staging.verification_commands_digest
        or expected_requirements.verification_commands_digest
        != expected_staging.verification_commands_digest
        or expected_runtime.resolution_context_digest
        != expected_staging.resolution_context_digest
        or expected_requirements.resolution_context_digest
        != expected_staging.resolution_context_digest
        or expected_runtime.staging_context_digest
        != expected_staging.staging_context_digest
        or expected_requirements.staging_context_digest
        != expected_staging.staging_context_digest
    ):
        raise _InvalidShebangTargetResolution

    if (
        type(lease._owner_pid) is not int
        or lease._owner_pid != _BUILTIN_GETPID()
        or type(lease._state) is not str
        or lease._state != "active"
        or type(lease._receipt) is not RepositoryExecutableStagingReceipt
        or lease._cleanup_receipt is not None
        or lease._cleanup_receipt_digest_anchor is not None
        or type(lease._receipt_digest_anchor) is not str
        or lease._receipt_digest_anchor != staging_digest
        or type(lease._receipt_staged_file_refs_anchor) is not tuple
        or any(
            not _is_digest(item)
            for item in lease._receipt_staged_file_refs_anchor
        )
        or lease._receipt_staged_file_refs_anchor
        != tuple(item.staged_file_ref for item in expected_staging.staged_files)
        or lease._root_descriptor is not None
        or lease._pending_name is not None
        or lease._pending_identity is not None
        or type(lease._pending_descriptors) is not tuple
        or lease._pending_descriptors != ()
        or lease._descriptor_release_unverifiable is not False
        or type(lease._files) is not tuple
        or len(lease._files) != expected_staging.unique_file_count
        or any(
            type(item) is not _RetainedStagedFile
            for item in lease._files
        )
        or any(
            retained.staged_file is not anchored
            for retained, anchored in zip(
                lease._files,
                expected_staging.staged_files,
                strict=True,
            )
        )
        or _staging_projection_v1(lease._receipt) != staging_canonical
    ):
        raise _InvalidShebangTargetResolution
    _verify_binding_chain(
        expected_requirements,
        expected_runtime,
        expected_staging,
    )

    fresh_runtime = _BUILTIN_INSPECT_RUNTIME_MANIFEST(
        expected_staging,
        lease=lease,
    )
    if _runtime_projection_v1(fresh_runtime) != runtime_canonical:
        raise _InvalidShebangTargetResolution
    fresh_requirements = _BUILTIN_INSPECT_SHEBANG_REQUIREMENTS(
        expected_runtime,
        expected_staging=expected_staging,
        lease=lease,
    )
    if _local_requirements_projection(
        fresh_requirements
    ) != requirements_canonical:
        raise _InvalidShebangTargetResolution
    derived = _derive_requirements(
        expected_requirements,
        expected_runtime,
        expected_staging,
        lease._files,
    )
    return (
        derived,
        requirements_digest,
        runtime_digest,
        staging_digest,
        lease._files,
    )


def _validate_expected_target_paths(
    derived: tuple[_DerivedRequirement, ...],
    expected_target_paths: Any,
) -> tuple[Path, ...]:
    if type(expected_target_paths) is not tuple:
        raise _InvalidShebangTargetResolution
    used: list[Path] = []
    used_spellings: set[str] = set()
    for requirement in derived:
        path = requirement.target_path
        if path is None:
            continue
        spelling = os.fspath(path)
        if spelling not in used_spellings:
            used.append(path)
            used_spellings.add(spelling)
    if len(expected_target_paths) > _MAX_TARGET_PATHS:
        raise _InvalidShebangTargetResolution
    validated: list[Path] = []
    total_bytes = 0
    for path in expected_target_paths:
        if type(path) is not _CONCRETE_PATH_TYPE:
            raise _InvalidShebangTargetResolution
        try:
            encoded = os.fspath(path).encode("ascii")
        except (UnicodeEncodeError, AttributeError, TypeError):
            raise _InvalidShebangTargetResolution from None
        canonical = _canonical_target_path_from_token(encoded)
        if canonical != path:
            raise _InvalidShebangTargetResolution
        total_bytes += len(encoded)
        if total_bytes > _MAX_TOTAL_TARGET_PATH_BYTES:
            raise _InvalidShebangTargetResolution
        validated.append(path)
    paths = tuple(validated)
    if paths != tuple(used):
        raise _InvalidShebangTargetResolution
    return paths


def _path_ref(path: Path) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "kind": "repository_executable_shebang_target_path_ref",
            "resolution_scope": RESOLUTION_SCOPE,
            "schema_version": (
                REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RESOLUTION_SCHEMA_VERSION
            ),
            "target_path_ascii": os.fspath(path),
        }
    )


def _target_path_context_digest(paths: tuple[Path, ...]) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "kind": "repository_executable_shebang_target_path_context",
            "ordered_target_path_refs": [_path_ref(path) for path in paths],
            "resolution_scope": RESOLUTION_SCOPE,
            "schema_version": (
                REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RESOLUTION_SCHEMA_VERSION
            ),
        }
    )


def _validate_component(component: str) -> None:
    try:
        encoded = component.encode("ascii")
    except UnicodeEncodeError:
        raise _InvalidShebangTargetResolution from None
    if (
        not component
        or component in {".", ".."}
        or "/" in component
        or "\x00" in component
        or len(encoded) > _MAX_TARGET_PATH_COMPONENT_BYTES
        or unicodedata.normalize("NFC", component) != component
        or any(
            unicodedata.category(character).startswith("C")
            for character in component
        )
    ):
        raise _InvalidShebangTargetResolution


def _entry_spelling_state(directory_descriptor: int, name: str) -> str:
    _validate_component(name)
    target = unicodedata.normalize("NFC", name).casefold()
    exact_matches = 0
    folded_matches = 0
    count = 0
    encoded_bytes = 0
    try:
        with os.scandir(directory_descriptor) as entries:
            for entry in entries:
                count += 1
                if count > _MAX_DIRECTORY_ENTRIES:
                    raise _InvalidShebangTargetResolution
                try:
                    encoded_bytes += len(entry.name.encode("utf-8"))
                except UnicodeError:
                    raise _InvalidShebangTargetResolution from None
                if encoded_bytes > _MAX_DIRECTORY_ENTRY_BYTES:
                    raise _InvalidShebangTargetResolution
                folded = unicodedata.normalize("NFC", entry.name).casefold()
                if folded == target:
                    folded_matches += 1
                    if entry.name == name:
                        exact_matches += 1
    except OSError:
        raise _InvalidShebangTargetResolution from None
    if exact_matches == 1 and folded_matches == 1:
        return "exact"
    if folded_matches == 0:
        return "absent"
    raise _InvalidShebangTargetResolution


def _directory_open_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _replace_directory_descriptor(current: int, child: int) -> int:
    try:
        os.close(current)
    except BaseException:
        try:
            os.close(child)
        except OSError:
            pass
        try:
            os.close(current)
        except OSError:
            pass
        raise
    return child


def _open_directory_component(
    parent_descriptor: int,
    component: str,
) -> tuple[int, tuple[int, ...]]:
    if _entry_spelling_state(parent_descriptor, component) != "exact":
        raise _InvalidShebangTargetResolution
    try:
        descriptor = os.open(
            component,
            _directory_open_flags(),
            dir_fd=parent_descriptor,
        )
    except OSError:
        raise _InvalidShebangTargetResolution from None
    try:
        metadata = os.fstat(descriptor)
        namespace_metadata = os.stat(
            component,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        signature = _directory_signature(metadata)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(namespace_metadata.st_mode)
            or _directory_signature(namespace_metadata) != signature
        ):
            raise _InvalidShebangTargetResolution
        return descriptor, signature
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _open_target_at(
    directory_descriptor: int,
    name: str,
) -> tuple[int, os.stat_result]:
    if _entry_spelling_state(directory_descriptor, name) != "exact":
        raise _InvalidShebangTargetResolution
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open(name, flags, dir_fd=directory_descriptor)
    except OSError:
        raise _InvalidShebangTargetResolution from None
    try:
        metadata = os.fstat(descriptor)
        namespace_metadata = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_mode & 0o111 == 0
            or metadata.st_nlink <= 0
            or stat.S_ISLNK(namespace_metadata.st_mode)
            or _metadata_signature(namespace_metadata)
            != _metadata_signature(metadata)
        ):
            raise _InvalidShebangTargetResolution
        return descriptor, metadata
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _file_is_sparse(metadata: os.stat_result) -> bool:
    blocks = getattr(metadata, "st_blocks", None)
    if type(blocks) is not int or blocks < 0:
        raise _InvalidShebangTargetResolution
    return metadata.st_size > 0 and blocks * 512 < metadata.st_size


def _target_identity_ref(metadata: os.stat_result) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "kind": "repository_executable_shebang_target_file_identity",
            "schema_version": 1,
        }
    )


def _target_metadata_digest(
    metadata: os.stat_result,
    *,
    identity_ref: str,
) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "change_time_ns": metadata.st_ctime_ns,
            "filesystem_identity_ref": identity_ref,
            "group_id": metadata.st_gid,
            "kind": "repository_executable_shebang_target_file_metadata",
            "link_count": metadata.st_nlink,
            "mode": metadata.st_mode,
            "modified_time_ns": metadata.st_mtime_ns,
            "owner_id": metadata.st_uid,
            "schema_version": 1,
            "size_bytes": metadata.st_size,
        }
    )


def _consume_measured_target(
    descriptor: int,
    metadata: os.stat_result,
    measured: _MeasuredTarget,
    consumer: _UniqueTargetConsumer,
) -> None:
    """Invoke one private consumer without surrendering the pinned FD state."""

    try:
        before_metadata = os.fstat(descriptor)
        before_status_flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        before_descriptor_flags = fcntl.fcntl(descriptor, fcntl.F_GETFD)
        before_offset = os.lseek(descriptor, 0, os.SEEK_CUR)
        before_inheritable = os.get_inheritable(descriptor)
    except (OSError, ValueError):
        raise _InvalidShebangTargetResolution from None
    if (
        _metadata_signature(metadata) != measured.metadata
        or _metadata_signature(before_metadata) != measured.metadata
        or (before_metadata.st_dev, before_metadata.st_ino)
        != measured.identity
        or before_status_flags & os.O_ACCMODE != os.O_RDONLY
        or before_offset != measured.content_bytes
        or before_inheritable
    ):
        raise _InvalidShebangTargetResolution
    try:
        consumer(descriptor, metadata, measured)
    except Exception:
        raise _InvalidShebangTargetResolution from None
    try:
        after_metadata = os.fstat(descriptor)
        after_status_flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        after_descriptor_flags = fcntl.fcntl(descriptor, fcntl.F_GETFD)
        after_offset = os.lseek(descriptor, 0, os.SEEK_CUR)
        after_inheritable = os.get_inheritable(descriptor)
    except (OSError, ValueError):
        raise _InvalidShebangTargetResolution from None
    if (
        _metadata_signature(after_metadata) != measured.metadata
        or (after_metadata.st_dev, after_metadata.st_ino)
        != measured.identity
        or after_status_flags != before_status_flags
        or after_descriptor_flags != before_descriptor_flags
        or after_offset != before_offset
        or after_inheritable != before_inheritable
    ):
        raise _InvalidShebangTargetResolution


def _measure_target_path(
    path: Path,
    *,
    total_measured_bytes: int,
    unique_target_consumer: _UniqueTargetConsumer | None = None,
) -> _MeasuredTarget:
    spelling = os.fspath(path)
    components = tuple(spelling[1:].split("/"))
    descriptor: int | None = None
    file_descriptor: int | None = None
    directory_chain: list[tuple[int, ...]] = []
    try:
        try:
            descriptor = os.open(os.sep, _directory_open_flags())
            root_metadata = os.fstat(descriptor)
        except OSError:
            raise _InvalidShebangTargetResolution from None
        if not stat.S_ISDIR(root_metadata.st_mode):
            raise _InvalidShebangTargetResolution
        directory_chain.append(_directory_signature(root_metadata))
        for component in components[:-1]:
            child, signature = _open_directory_component(
                descriptor,
                component,
            )
            descriptor = _replace_directory_descriptor(descriptor, child)
            directory_chain.append(signature)
        parent_signature = _directory_signature(os.fstat(descriptor))
        file_descriptor, before = _open_target_at(
            descriptor,
            components[-1],
        )
        try:
            file_flags = fcntl.fcntl(file_descriptor, fcntl.F_GETFL)
            file_inheritable = os.get_inheritable(file_descriptor)
        except (OSError, ValueError):
            raise _InvalidShebangTargetResolution from None
        if (
            before.st_size < 0
            or before.st_size > _MAX_TARGET_BYTES
            or total_measured_bytes + before.st_size
            > _MAX_TOTAL_TARGET_BYTES
            or _file_is_sparse(before)
            or file_flags & os.O_ACCMODE != os.O_RDONLY
            or file_inheritable
        ):
            raise _InvalidShebangTargetResolution
        digest = _BUILTIN_SHA256()
        remaining = before.st_size
        while remaining:
            try:
                chunk = os.read(
                    file_descriptor,
                    min(_READ_CHUNK_BYTES, remaining),
                )
            except (BlockingIOError, InterruptedError, OSError):
                raise _InvalidShebangTargetResolution from None
            if not chunk or len(chunk) > remaining:
                raise _InvalidShebangTargetResolution
            digest.update(chunk)
            remaining -= len(chunk)
        try:
            boundary = os.read(file_descriptor, 1)
            after = os.fstat(file_descriptor)
            after_flags = fcntl.fcntl(file_descriptor, fcntl.F_GETFL)
            after_inheritable = os.get_inheritable(file_descriptor)
        except (OSError, ValueError):
            raise _InvalidShebangTargetResolution from None
        if (
            boundary != b""
            or _metadata_signature(after) != _metadata_signature(before)
            or after_flags != file_flags
            or after_inheritable != file_inheritable
            or _directory_signature(os.fstat(descriptor)) != parent_signature
        ):
            raise _InvalidShebangTargetResolution

        identity_ref = _target_identity_ref(before)
        measured = _MeasuredTarget(
            path=path,
            path_ref=_path_ref(path),
            identity=(before.st_dev, before.st_ino),
            metadata=_metadata_signature(before),
            directory_chain=tuple(directory_chain),
            filesystem_identity_ref=identity_ref,
            metadata_digest=_target_metadata_digest(
                before,
                identity_ref=identity_ref,
            ),
            content_digest="sha256:" + digest.hexdigest(),
            content_bytes=before.st_size,
        )
        if unique_target_consumer is not None:
            _consume_measured_target(
                file_descriptor,
                before,
                measured,
                unique_target_consumer,
            )

        reopened_descriptor: int | None = None
        try:
            reopened_descriptor, reopened = _open_target_at(
                descriptor,
                components[-1],
            )
            if _metadata_signature(reopened) != _metadata_signature(before):
                raise _InvalidShebangTargetResolution
        finally:
            if reopened_descriptor is not None:
                try:
                    os.close(reopened_descriptor)
                except OSError:
                    pass
        try:
            namespace_after_reopen = os.stat(
                components[-1],
                dir_fd=descriptor,
                follow_symlinks=False,
            )
            parent_after_reopen = _directory_signature(os.fstat(descriptor))
        except OSError:
            raise _InvalidShebangTargetResolution from None
        if (
            _metadata_signature(namespace_after_reopen)
            != _metadata_signature(before)
            or parent_after_reopen != parent_signature
        ):
            raise _InvalidShebangTargetResolution
        return measured
    finally:
        if file_descriptor is not None:
            try:
                os.close(file_descriptor)
            except OSError:
                pass
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _target_namespace_snapshot(
    path: Path,
) -> tuple[tuple[tuple[int, ...], ...], tuple[int, ...]]:
    """Independently rewalk one exact path and bind its current namespace."""

    components = tuple(os.fspath(path)[1:].split("/"))
    directory_descriptors: list[int] = []
    target_descriptor: int | None = None
    directory_chain: list[tuple[int, ...]] = []
    try:
        try:
            root_descriptor = os.open(os.sep, _directory_open_flags())
            directory_descriptors.append(root_descriptor)
            root_metadata = os.fstat(root_descriptor)
        except OSError:
            raise _InvalidShebangTargetResolution from None
        if not stat.S_ISDIR(root_metadata.st_mode):
            raise _InvalidShebangTargetResolution
        directory_chain.append(_directory_signature(root_metadata))
        for component in components[:-1]:
            child, signature = _open_directory_component(
                directory_descriptors[-1],
                component,
            )
            directory_descriptors.append(child)
            directory_chain.append(signature)
        parent_descriptor = directory_descriptors[-1]
        parent_before = _directory_signature(os.fstat(parent_descriptor))
        target_descriptor, metadata = _open_target_at(
            parent_descriptor,
            components[-1],
        )
        target_signature = _metadata_signature(metadata)
        try:
            namespace_after = os.stat(
                components[-1],
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            parent_after = _directory_signature(os.fstat(parent_descriptor))
        except OSError:
            raise _InvalidShebangTargetResolution from None
        if (
            _metadata_signature(namespace_after) != target_signature
            or parent_after != parent_before
        ):
            raise _InvalidShebangTargetResolution
        # Retaining every directory descriptor lets this final edge-by-edge
        # namespace check detect an ancestor rename that happens after the leaf
        # is opened.  A metadata-only check of the pinned descendants would not
        # detect that the canonical path now selects a replacement subtree.
        for index, component in enumerate(components[:-1]):
            try:
                if (
                    _entry_spelling_state(
                        directory_descriptors[index],
                        component,
                    )
                    != "exact"
                ):
                    raise _InvalidShebangTargetResolution
                descriptor_metadata = os.fstat(
                    directory_descriptors[index + 1]
                )
                namespace_metadata = os.stat(
                    component,
                    dir_fd=directory_descriptors[index],
                    follow_symlinks=False,
                )
            except OSError:
                raise _InvalidShebangTargetResolution from None
            expected_signature = directory_chain[index + 1]
            if (
                _directory_signature(descriptor_metadata)
                != expected_signature
                or _directory_signature(namespace_metadata)
                != expected_signature
                or stat.S_ISLNK(namespace_metadata.st_mode)
            ):
                raise _InvalidShebangTargetResolution
        try:
            if (
                _entry_spelling_state(
                    parent_descriptor,
                    components[-1],
                )
                != "exact"
            ):
                raise _InvalidShebangTargetResolution
            final_namespace_metadata = os.stat(
                components[-1],
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            final_parent_metadata = os.fstat(parent_descriptor)
        except OSError:
            raise _InvalidShebangTargetResolution from None
        if (
            _metadata_signature(final_namespace_metadata)
            != target_signature
            or _directory_signature(final_parent_metadata)
            != parent_before
        ):
            raise _InvalidShebangTargetResolution
        return tuple(directory_chain), target_signature
    finally:
        if target_descriptor is not None:
            try:
                os.close(target_descriptor)
            except OSError:
                pass
        for descriptor in reversed(directory_descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _target_namespace_matches(measured: _MeasuredTarget) -> bool:
    try:
        directory_chain, target_metadata = _target_namespace_snapshot(
            measured.path
        )
        return (
            directory_chain == measured.directory_chain
            and target_metadata == measured.metadata
        )
    except (OSError, TypeError, ValueError):
        return False


def _measure_target_set(paths: tuple[Path, ...]) -> tuple[_MeasuredTarget, ...]:
    measured: list[_MeasuredTarget] = []
    identities: set[tuple[int, int]] = set()
    total_bytes = 0
    for path in paths:
        target = _measure_target_path(path, total_measured_bytes=total_bytes)
        if (
            target.identity in identities
            or not _target_namespace_matches(target)
        ):
            raise _InvalidShebangTargetResolution
        identities.add(target.identity)
        measured.append(target)
        total_bytes += target.content_bytes
    return tuple(measured)


def _measure_target_set_with_consumer(
    paths: tuple[Path, ...],
    consumer: _UniqueTargetConsumer,
) -> tuple[_MeasuredTarget, ...]:
    """Measure once while handing each still-pinned unique target to a sink."""

    measured: list[_MeasuredTarget] = []
    identities: set[tuple[int, int]] = set()
    total_bytes = 0

    def consume_unique_target(
        descriptor: int,
        metadata: os.stat_result,
        target: _MeasuredTarget,
    ) -> None:
        if target.identity in identities:
            raise _InvalidShebangTargetResolution
        consumer(descriptor, metadata, target)

    for path in paths:
        target = _measure_target_path(
            path,
            total_measured_bytes=total_bytes,
            unique_target_consumer=consume_unique_target,
        )
        if (
            target.identity in identities
            or not _target_namespace_matches(target)
        ):
            raise _InvalidShebangTargetResolution
        identities.add(target.identity)
        measured.append(target)
        total_bytes += target.content_bytes
    return tuple(measured)


def _public_measurement(
    measured: _MeasuredTarget,
) -> RepositoryExecutableShebangTargetMeasurement:
    reference = _measurement_ref_projection(
        path_ref=measured.path_ref,
        filesystem_identity_ref=measured.filesystem_identity_ref,
        metadata_digest=measured.metadata_digest,
        content_digest=measured.content_digest,
        content_bytes=measured.content_bytes,
    )
    value = RepositoryExecutableShebangTargetMeasurement(
        kind=REPOSITORY_EXECUTABLE_SHEBANG_TARGET_MEASUREMENT_KIND,
        path_ref=measured.path_ref,
        filesystem_identity_ref=measured.filesystem_identity_ref,
        metadata_digest=measured.metadata_digest,
        content_digest=measured.content_digest,
        content_bytes=measured.content_bytes,
        measurement_ref=_BUILTIN_CANONICAL_DIGEST(reference),
    )
    _measurement_projection(value)
    return value


def _public_target_requirement(
    derived: _DerivedRequirement,
    *,
    measurement_by_path: dict[
        Path, RepositoryExecutableShebangTargetMeasurement
    ],
) -> RepositoryExecutableShebangTargetRequirement:
    upstream = derived.upstream
    if derived.target_path is None:
        disposition = "native_not_applicable"
        target_measurement_ref = None
    else:
        measurement = measurement_by_path.get(derived.target_path)
        if measurement is None:
            raise _InvalidShebangTargetResolution
        disposition = "direct_absolute_target_measured"
        target_measurement_ref = measurement.measurement_ref
    reference = _target_requirement_ref_projection(
        staged_file_ref=upstream.staged_file_ref,
        runtime_file_ref=upstream.runtime_file_ref,
        requirement_ref=upstream.requirement_ref,
        runtime_classification=upstream.runtime_classification,
        disposition=disposition,
        shebang_directive_ref=upstream.shebang_directive_ref,
        interpreter_token_ref=upstream.interpreter_token_ref,
        argument_tail_ref=upstream.argument_tail_ref,
        target_measurement_ref=target_measurement_ref,
    )
    value = RepositoryExecutableShebangTargetRequirement(
        kind=REPOSITORY_EXECUTABLE_SHEBANG_TARGET_REQUIREMENT_KIND,
        staged_file_ref=upstream.staged_file_ref,
        runtime_file_ref=upstream.runtime_file_ref,
        requirement_ref=upstream.requirement_ref,
        runtime_classification=upstream.runtime_classification,
        disposition=disposition,
        shebang_directive_ref=upstream.shebang_directive_ref,
        interpreter_token_ref=upstream.interpreter_token_ref,
        argument_tail_ref=upstream.argument_tail_ref,
        target_measurement_ref=target_measurement_ref,
        target_requirement_ref=_BUILTIN_CANONICAL_DIGEST(reference),
    )
    _target_requirement_projection(value)
    return value


def _inspect_staged_executable_shebang_targets(
    expected_requirements: RepositoryExecutableShebangRequirementsReceipt,
    *,
    expected_runtime: RepositoryExecutableRuntimeManifestReceipt,
    expected_staging: RepositoryExecutableStagingReceipt,
    lease: RepositoryExecutableStageLease,
    expected_target_paths: tuple[Path, ...],
    unique_target_consumer: _UniqueTargetConsumer | None = None,
) -> RepositoryExecutableShebangTargetResolutionReceipt:
    """Internal inspector with an optional same-descriptor action consumer."""

    try:
        _require_supported_platform()
        (
            derived,
            requirements_digest,
            runtime_digest,
            staging_digest,
            retained_files,
        ) = _validated_chain_snapshot(
            expected_requirements,
            expected_runtime,
            expected_staging,
            lease,
        )
        paths = _validate_expected_target_paths(
            derived,
            expected_target_paths,
        )
        if unique_target_consumer is None:
            first_measurement = _measure_target_set(paths)
        else:
            first_measurement = _measure_target_set_with_consumer(
                paths,
                unique_target_consumer,
            )

        (
            middle_derived,
            middle_requirements_digest,
            middle_runtime_digest,
            middle_staging_digest,
            middle_retained_files,
        ) = _validated_chain_snapshot(
            expected_requirements,
            expected_runtime,
            expected_staging,
            lease,
        )
        if (
            middle_derived != derived
            or middle_requirements_digest != requirements_digest
            or middle_runtime_digest != runtime_digest
            or middle_staging_digest != staging_digest
            or middle_retained_files is not retained_files
            or _validate_expected_target_paths(
                middle_derived,
                expected_target_paths,
            )
            != paths
        ):
            raise _InvalidShebangTargetResolution
        second_measurement = _measure_target_set(paths)
        if second_measurement != first_measurement:
            raise _InvalidShebangTargetResolution

        (
            final_derived,
            final_requirements_digest,
            final_runtime_digest,
            final_staging_digest,
            final_retained_files,
        ) = _validated_chain_snapshot(
            expected_requirements,
            expected_runtime,
            expected_staging,
            lease,
        )
        if (
            final_derived != derived
            or final_requirements_digest != requirements_digest
            or final_runtime_digest != runtime_digest
            or final_staging_digest != staging_digest
            or final_retained_files is not retained_files
            or _validate_expected_target_paths(
                final_derived,
                expected_target_paths,
            )
            != paths
        ):
            raise _InvalidShebangTargetResolution
        if any(
            not _target_namespace_matches(item)
            for item in first_measurement
        ):
            raise _InvalidShebangTargetResolution

        measurements = tuple(
            _public_measurement(item) for item in first_measurement
        )
        measurement_by_path = {
            measured.path: public
            for measured, public in zip(
                first_measurement,
                measurements,
                strict=True,
            )
        }
        requirements = tuple(
            _public_target_requirement(
                item,
                measurement_by_path=measurement_by_path,
            )
            for item in derived
        )
        by_requirement_ref = {
            item.requirement_ref: item for item in requirements
        }
        bindings: list[RepositoryExecutableShebangTargetBinding] = []
        for upstream in expected_requirements.bindings:
            target_requirement = by_requirement_ref.get(
                upstream.requirement_ref
            )
            if target_requirement is None:
                raise _InvalidShebangTargetResolution
            binding = RepositoryExecutableShebangTargetBinding(
                kind=REPOSITORY_EXECUTABLE_SHEBANG_TARGET_BINDING_KIND,
                command_kind=upstream.command_kind,
                command_id=upstream.command_id,
                command_digest=upstream.command_digest,
                staged_file_ref=upstream.staged_file_ref,
                runtime_file_ref=upstream.runtime_file_ref,
                requirement_ref=upstream.requirement_ref,
                target_requirement_ref=(
                    target_requirement.target_requirement_ref
                ),
            )
            _target_binding_projection(binding)
            bindings.append(binding)

        receipt = RepositoryExecutableShebangTargetResolutionReceipt(
            kind=REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RESOLUTION_KIND,
            schema_version=(
                REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RESOLUTION_SCHEMA_VERSION
            ),
            measurement_source=MEASUREMENT_SOURCE,
            resolution_scope=RESOLUTION_SCOPE,
            shebang_requirements_receipt_digest=requirements_digest,
            runtime_manifest_receipt_digest=runtime_digest,
            staging_receipt_digest=staging_digest,
            registration_digest=expected_requirements.registration_digest,
            repository_ref=expected_requirements.repository_ref,
            verification_commands_digest=(
                expected_requirements.verification_commands_digest
            ),
            resolution_context_digest=(
                expected_requirements.resolution_context_digest
            ),
            staging_context_digest=(
                expected_requirements.staging_context_digest
            ),
            target_path_context_digest=_target_path_context_digest(paths),
            measurements=measurements,
            requirements=requirements,
            bindings=tuple(bindings),
            requirement_count=len(requirements),
            command_count=len(bindings),
            direct_target_requirement_count=sum(
                item.disposition == "direct_absolute_target_measured"
                for item in requirements
            ),
            native_not_applicable_count=sum(
                item.disposition == "native_not_applicable"
                for item in requirements
            ),
            unique_target_count=len(measurements),
            total_measured_bytes=sum(
                item.content_bytes for item in measurements
            ),
        )
        _receipt_projection(receipt)
        return receipt
    except (
        AttributeError,
        OSError,
        OverflowError,
        NotImplementedError,
        TypeError,
        ValueError,
        ValidationError,
    ):
        raise ValidationError(_INVALID_MESSAGE) from None


def inspect_staged_executable_shebang_targets(
    expected_requirements: RepositoryExecutableShebangRequirementsReceipt,
    *,
    expected_runtime: RepositoryExecutableRuntimeManifestReceipt,
    expected_staging: RepositoryExecutableStagingReceipt,
    lease: RepositoryExecutableStageLease,
    expected_target_paths: tuple[Path, ...],
) -> RepositoryExecutableShebangTargetResolutionReceipt:
    """Measure the exact direct canonical target set from one active lease."""

    return _inspect_staged_executable_shebang_targets(
        expected_requirements,
        expected_runtime=expected_runtime,
        expected_staging=expected_staging,
        lease=lease,
        expected_target_paths=expected_target_paths,
    )
