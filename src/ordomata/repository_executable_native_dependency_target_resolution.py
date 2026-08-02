"""Measure only exact canonical-absolute native dependency targets.

This Class 0 boundary consumes one exact native-dependency requirements
receipt, runtime manifest, staging receipt, and active process-local lease.
Only dependency declarations already classified as absolute are matched to an
exact caller-supplied canonical path and measured with no-follow traversal.
Bare, relative, and Mach-O tokenized declarations remain explicitly
unresolved. No loader search semantics, staging, or execution is performed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import re
from typing import Any

from .authorization import canonical_json
from .errors import ValidationError
from .repository_executable_native_dependency_requirements import (
    RepositoryExecutableNativeDependencyDeclaration,
    RepositoryExecutableNativeDependencyRequirement,
    RepositoryExecutableNativeDependencyRequirementBinding,
    RepositoryExecutableNativeDependencyRequirementsReceipt,
    _dependency_name_ref as _dependency_name_ref,
    _receipt_projection as _dependency_receipt_projection,
    inspect_staged_executable_native_dependency_requirements,
)
from .repository_executable_native_loader_requirements import (
    inspect_staged_executable_native_loader_requirements,
)
from .repository_executable_native_loader_target_resolution import (
    _MeasuredTarget,
    _canonical_target_path as _canonical_target_path,
    _measure_target_set as _measure_target_set,
    _require_supported_platform as _require_supported_platform,
    _target_namespace_matches as _target_namespace_matches,
)
from .repository_executable_runtime_manifest import (
    RepositoryExecutableRuntimeManifestReceipt,
    _active_stage_snapshot,
    _runtime_manifest_projection,
)
from .repository_executable_staging import (
    RepositoryExecutableStageLease,
    RepositoryExecutableStagingReceipt,
    _staging_receipt_projection,
)


REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_TARGET_RESOLUTION_SCHEMA_VERSION = 1
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_TARGET_RESOLUTION_KIND = (
    "repository_executable_native_dependency_target_resolution"
)
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_TARGET_RESOLUTION_EVIDENCE_KIND = (
    "repository_executable_native_dependency_target_resolution_validation"
)
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_TARGET_MEASUREMENT_KIND = (
    "repository_executable_native_dependency_target_measurement"
)
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_TARGET_DECLARATION_KIND = (
    "repository_executable_native_dependency_target_declaration"
)
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_TARGET_REQUIREMENT_KIND = (
    "repository_executable_native_dependency_target_requirement"
)
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_TARGET_BINDING_KIND = (
    "repository_executable_native_dependency_target_binding"
)
MEASUREMENT_SOURCE = "controller_measured"
RESOLUTION_SCOPE = "canonical_absolute_native_dependency_target_nofollow_v1"

_FIXED_SCHEMA_VERSION = (
    REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_TARGET_RESOLUTION_SCHEMA_VERSION
)
_FIXED_RECEIPT_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_TARGET_RESOLUTION_KIND
)
_FIXED_EVIDENCE_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_TARGET_RESOLUTION_EVIDENCE_KIND
)
_FIXED_MEASUREMENT_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_TARGET_MEASUREMENT_KIND
)
_FIXED_DECLARATION_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_TARGET_DECLARATION_KIND
)
_FIXED_REQUIREMENT_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_TARGET_REQUIREMENT_KIND
)
_FIXED_BINDING_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_TARGET_BINDING_KIND
)
_FIXED_MEASUREMENT_SOURCE = MEASUREMENT_SOURCE
_FIXED_RESOLUTION_SCOPE = RESOLUTION_SCOPE

_INVALID_MESSAGE = (
    "repository executable native dependency target resolution is invalid"
)
_DIGEST_PREFIX = "sha256:"
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER_PATTERN = re.compile(r"[a-z][a-z0-9_.-]{0,119}\Z")
_COMMAND_KINDS = ("format", "lint", "type_check", "test", "build")
_RUNTIME_CLASSIFICATIONS = (
    "elf",
    "mach_o",
    "posix_shebang",
    "unsupported_shebang",
    "unknown",
)
_FORMAT_CLASSES = (
    "elf32",
    "elf64",
    "mach_o32",
    "mach_o64",
    "mach_o_fat32",
    "mach_o_fat64",
)
_UPSTREAM_DISPOSITIONS = (
    "elf_dependencies_declared",
    "elf_dependencies_absent",
    "mach_o_dependencies_declared",
    "mach_o_dependencies_absent",
    "unsupported_native_layout",
    "non_native_not_applicable",
)
_PATH_STYLES = (
    "absolute",
    "bare",
    "relative",
    "at_rpath",
    "at_loader_path",
    "at_executable_path",
)
_TARGET_DISPOSITIONS = (
    "absolute_dependency_target_measured",
    "non_absolute_dependency_unresolved",
)
_MAX_FILES = 80
_MAX_COMMANDS = 80
_MAX_DECLARATIONS_PER_FILE = 512
_MAX_DECLARATIONS = _MAX_FILES * _MAX_DECLARATIONS_PER_FILE
_MAX_TARGET_PATHS = 80
_MAX_TARGET_PATH_BYTES = 4_095
_MAX_TOTAL_TARGET_PATH_BYTES = 16 * 1024
_MAX_TARGET_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_TARGET_BYTES = 256 * 1024 * 1024
_CONCRETE_PATH_TYPE = type(Path())

_BUILTIN_SHA256 = hashlib.sha256
_BUILTIN_CANONICAL_JSON = canonical_json


def _captured_canonical_digest(value: Any) -> str:
    encoded = _BUILTIN_CANONICAL_JSON(value).encode("utf-8")
    return _DIGEST_PREFIX + _BUILTIN_SHA256(encoded).hexdigest()


_BUILTIN_CANONICAL_DIGEST = _captured_canonical_digest
_BUILTIN_DEPENDENCY_RECEIPT_PROJECTION = _dependency_receipt_projection
_BUILTIN_RUNTIME_PROJECTION = _runtime_manifest_projection
_BUILTIN_STAGING_PROJECTION = _staging_receipt_projection
_BUILTIN_INSPECT_NATIVE_LOADER = (
    inspect_staged_executable_native_loader_requirements
)
_BUILTIN_INSPECT_DEPENDENCY_REQUIREMENTS = (
    inspect_staged_executable_native_dependency_requirements
)
_BUILTIN_DEPENDENCY_NAME_REF = _dependency_name_ref
_BUILTIN_ACTIVE_STAGE_SNAPSHOT = _active_stage_snapshot
_BUILTIN_REQUIRE_SUPPORTED_PLATFORM = _require_supported_platform
_BUILTIN_CANONICAL_TARGET_PATH = _canonical_target_path
_BUILTIN_MEASURE_TARGET_SET = _measure_target_set
_BUILTIN_TARGET_NAMESPACE_MATCHES = _target_namespace_matches
_FIXED_DEPENDENCY_RECEIPT_TYPE = (
    RepositoryExecutableNativeDependencyRequirementsReceipt
)
_FIXED_UPSTREAM_REQUIREMENT_TYPE = (
    RepositoryExecutableNativeDependencyRequirement
)
_FIXED_UPSTREAM_DECLARATION_TYPE = (
    RepositoryExecutableNativeDependencyDeclaration
)
_FIXED_UPSTREAM_BINDING_TYPE = (
    RepositoryExecutableNativeDependencyRequirementBinding
)
_FIXED_RUNTIME_TYPE = RepositoryExecutableRuntimeManifestReceipt
_FIXED_STAGING_TYPE = RepositoryExecutableStagingReceipt
_FIXED_LEASE_TYPE = RepositoryExecutableStageLease
_FIXED_MEASURED_TARGET_TYPE = _MeasuredTarget
_FIXED_VALIDATION_ERROR = ValidationError


class _InvalidNativeDependencyTargetResolution(ValueError):
    """Private fail-closed sentinel whose details never cross the API."""


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeDependencyTargetMeasurement:
    """One exact absolute dependency target's point-in-time measurement."""

    kind: str
    path_ref: str = field(repr=False)
    filesystem_identity_ref: str = field(repr=False)
    metadata_digest: str = field(repr=False)
    content_digest: str = field(repr=False)
    content_bytes: int
    measurement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_MEASUREMENT_PROJECTION(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeDependencyTargetDeclaration:
    """One dependency declaration's measured or unresolved target outcome."""

    kind: str
    runtime_file_ref: str = field(repr=False)
    dependency_declaration_ref: str = field(repr=False)
    dependency_name_ref: str = field(repr=False)
    format_class: str
    ordinal: int
    path_style: str
    target_disposition: str
    target_measurement_ref: str | None = field(repr=False)
    target_declaration_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_DECLARATION_PROJECTION(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeDependencyTargetRequirement:
    """One direct runtime file's dependency-target outcomes."""

    kind: str
    staged_file_ref: str = field(repr=False)
    runtime_file_ref: str = field(repr=False)
    native_dependency_requirement_ref: str = field(repr=False)
    runtime_classification: str
    dependency_disposition: str
    target_declarations: tuple[
        RepositoryExecutableNativeDependencyTargetDeclaration, ...
    ] = field(repr=False)
    dependency_declaration_count: int
    absolute_dependency_count: int
    unresolved_dependency_count: int
    target_requirement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_REQUIREMENT_PROJECTION(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeDependencyTargetBinding:
    """One registered command bound to one target requirement."""

    kind: str
    command_kind: str
    command_id: str = field(repr=False)
    command_digest: str = field(repr=False)
    staged_file_ref: str = field(repr=False)
    runtime_file_ref: str = field(repr=False)
    native_dependency_requirement_ref: str = field(repr=False)
    target_requirement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_BINDING_PROJECTION(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeDependencyTargetResolutionReceipt:
    """Privacy-bounded historical evidence for exact absolute-target reads."""

    kind: str
    schema_version: int
    measurement_source: str
    resolution_scope: str
    native_dependency_requirements_receipt_digest: str = field(repr=False)
    runtime_manifest_receipt_digest: str = field(repr=False)
    staging_receipt_digest: str = field(repr=False)
    registration_digest: str = field(repr=False)
    repository_ref: str = field(repr=False)
    verification_commands_digest: str = field(repr=False)
    resolution_context_digest: str = field(repr=False)
    staging_context_digest: str = field(repr=False)
    dependency_path_context_digest: str = field(repr=False)
    measurements: tuple[
        RepositoryExecutableNativeDependencyTargetMeasurement, ...
    ] = field(repr=False)
    requirements: tuple[
        RepositoryExecutableNativeDependencyTargetRequirement, ...
    ] = field(repr=False)
    bindings: tuple[
        RepositoryExecutableNativeDependencyTargetBinding, ...
    ] = field(repr=False)
    requirement_count: int
    command_count: int
    dependency_declaration_count: int
    absolute_dependency_declaration_count: int
    unresolved_dependency_declaration_count: int
    unique_target_count: int
    total_measured_bytes: int

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_RECEIPT_PROJECTION(self)

    @property
    def receipt_digest(self) -> str:
        return _BUILTIN_CANONICAL_DIGEST(
            _BUILTIN_RECEIPT_PROJECTION(self)
        )

    def to_evidence(self) -> dict[str, Any]:
        return _BUILTIN_EVIDENCE_PROJECTION(self)


_FIXED_MEASUREMENT_TYPE = RepositoryExecutableNativeDependencyTargetMeasurement
_FIXED_DECLARATION_TYPE = RepositoryExecutableNativeDependencyTargetDeclaration
_FIXED_REQUIREMENT_TYPE = RepositoryExecutableNativeDependencyTargetRequirement
_FIXED_BINDING_TYPE = RepositoryExecutableNativeDependencyTargetBinding
_FIXED_RECEIPT_TYPE = (
    RepositoryExecutableNativeDependencyTargetResolutionReceipt
)


def _is_digest(value: Any) -> bool:
    return type(value) is str and _DIGEST_PATTERN.fullmatch(value) is not None


_BUILTIN_IS_DIGEST = _is_digest


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
        "kind": "repository_executable_native_dependency_target_measurement_ref",
        "measurement_source": _FIXED_MEASUREMENT_SOURCE,
        "metadata_digest": metadata_digest,
        "path_ref": path_ref,
        "resolution_scope": _FIXED_RESOLUTION_SCOPE,
        "schema_version": _FIXED_SCHEMA_VERSION,
    }


_BUILTIN_MEASUREMENT_REF_PROJECTION = _measurement_ref_projection


def _measurement_projection(
    value: RepositoryExecutableNativeDependencyTargetMeasurement,
) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_MEASUREMENT_TYPE
        or value.kind != _FIXED_MEASUREMENT_KIND
        or not all(
            _BUILTIN_IS_DIGEST(item)
            for item in (
                value.path_ref,
                value.filesystem_identity_ref,
                value.metadata_digest,
                value.content_digest,
                value.measurement_ref,
            )
        )
        or type(value.content_bytes) is not int
        or not 0 <= value.content_bytes <= _MAX_TARGET_BYTES
    ):
        raise _InvalidNativeDependencyTargetResolution
    reference = _BUILTIN_MEASUREMENT_REF_PROJECTION(
        path_ref=value.path_ref,
        filesystem_identity_ref=value.filesystem_identity_ref,
        metadata_digest=value.metadata_digest,
        content_digest=value.content_digest,
        content_bytes=value.content_bytes,
    )
    if value.measurement_ref != _BUILTIN_CANONICAL_DIGEST(reference):
        raise _InvalidNativeDependencyTargetResolution
    return {**reference, "kind": value.kind, "measurement_ref": value.measurement_ref}


_BUILTIN_MEASUREMENT_PROJECTION = _measurement_projection


def _target_declaration_ref_projection(
    *,
    runtime_file_ref: str,
    dependency_declaration_ref: str,
    dependency_name_ref: str,
    format_class: str,
    ordinal: int,
    path_style: str,
    target_disposition: str,
    target_measurement_ref: str | None,
) -> dict[str, Any]:
    return {
        "dependency_declaration_ref": dependency_declaration_ref,
        "dependency_name_ref": dependency_name_ref,
        "format_class": format_class,
        "kind": "repository_executable_native_dependency_target_declaration_ref",
        "ordinal": ordinal,
        "path_style": path_style,
        "resolution_scope": _FIXED_RESOLUTION_SCOPE,
        "runtime_file_ref": runtime_file_ref,
        "schema_version": _FIXED_SCHEMA_VERSION,
        "target_disposition": target_disposition,
        "target_measurement_ref": target_measurement_ref,
    }


_BUILTIN_TARGET_DECLARATION_REF_PROJECTION = (
    _target_declaration_ref_projection
)


def _declaration_projection(
    value: RepositoryExecutableNativeDependencyTargetDeclaration,
) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_DECLARATION_TYPE
        or value.kind != _FIXED_DECLARATION_KIND
        or not all(
            _BUILTIN_IS_DIGEST(item)
            for item in (
                value.runtime_file_ref,
                value.dependency_declaration_ref,
                value.dependency_name_ref,
                value.target_declaration_ref,
            )
        )
        or value.format_class not in _FORMAT_CLASSES
        or type(value.ordinal) is not int
        or not 0 <= value.ordinal < _MAX_DECLARATIONS_PER_FILE
        or value.path_style not in _PATH_STYLES
        or value.target_disposition not in _TARGET_DISPOSITIONS
        or (
            value.target_measurement_ref is not None
            and not _BUILTIN_IS_DIGEST(value.target_measurement_ref)
        )
    ):
        raise _InvalidNativeDependencyTargetResolution
    measured = (
        value.target_disposition == "absolute_dependency_target_measured"
    )
    if (
        measured != (value.path_style == "absolute")
        or measured != (value.target_measurement_ref is not None)
    ):
        raise _InvalidNativeDependencyTargetResolution
    reference = _BUILTIN_TARGET_DECLARATION_REF_PROJECTION(
        runtime_file_ref=value.runtime_file_ref,
        dependency_declaration_ref=value.dependency_declaration_ref,
        dependency_name_ref=value.dependency_name_ref,
        format_class=value.format_class,
        ordinal=value.ordinal,
        path_style=value.path_style,
        target_disposition=value.target_disposition,
        target_measurement_ref=value.target_measurement_ref,
    )
    if value.target_declaration_ref != _BUILTIN_CANONICAL_DIGEST(reference):
        raise _InvalidNativeDependencyTargetResolution
    return {
        **reference,
        "kind": value.kind,
        "target_declaration_ref": value.target_declaration_ref,
    }


_BUILTIN_DECLARATION_PROJECTION = _declaration_projection


def _dependency_disposition_matches_classification(
    dependency_disposition: str,
    runtime_classification: str,
) -> bool:
    if dependency_disposition.startswith("elf_"):
        return runtime_classification == "elf"
    if dependency_disposition.startswith("mach_o_"):
        return runtime_classification == "mach_o"
    if dependency_disposition == "unsupported_native_layout":
        return runtime_classification in {"elf", "mach_o"}
    if dependency_disposition == "non_native_not_applicable":
        return runtime_classification not in {"elf", "mach_o"}
    return False


_BUILTIN_DEPENDENCY_DISPOSITION_MATCHES_CLASSIFICATION = (
    _dependency_disposition_matches_classification
)


def _target_requirement_ref_projection(
    *,
    staged_file_ref: str,
    runtime_file_ref: str,
    native_dependency_requirement_ref: str,
    runtime_classification: str,
    dependency_disposition: str,
    target_declarations: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "dependency_disposition": dependency_disposition,
        "kind": "repository_executable_native_dependency_target_requirement_ref",
        "native_dependency_requirement_ref": native_dependency_requirement_ref,
        "resolution_scope": _FIXED_RESOLUTION_SCOPE,
        "runtime_classification": runtime_classification,
        "runtime_file_ref": runtime_file_ref,
        "schema_version": _FIXED_SCHEMA_VERSION,
        "staged_file_ref": staged_file_ref,
        "target_declarations": target_declarations,
    }


_BUILTIN_TARGET_REQUIREMENT_REF_PROJECTION = (
    _target_requirement_ref_projection
)


def _requirement_projection(
    value: RepositoryExecutableNativeDependencyTargetRequirement,
) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_REQUIREMENT_TYPE
        or value.kind != _FIXED_REQUIREMENT_KIND
        or not all(
            _BUILTIN_IS_DIGEST(item)
            for item in (
                value.staged_file_ref,
                value.runtime_file_ref,
                value.native_dependency_requirement_ref,
                value.target_requirement_ref,
            )
        )
        or value.runtime_classification not in _RUNTIME_CLASSIFICATIONS
        or value.dependency_disposition not in _UPSTREAM_DISPOSITIONS
        or not _BUILTIN_DEPENDENCY_DISPOSITION_MATCHES_CLASSIFICATION(
            value.dependency_disposition,
            value.runtime_classification,
        )
        or type(value.target_declarations) is not tuple
        or len(value.target_declarations) > _MAX_DECLARATIONS_PER_FILE
        or type(value.dependency_declaration_count) is not int
        or value.dependency_declaration_count != len(value.target_declarations)
        or any(
            type(item) is not int or item < 0
            for item in (
                value.absolute_dependency_count,
                value.unresolved_dependency_count,
            )
        )
    ):
        raise _InvalidNativeDependencyTargetResolution
    declarations = [
        _BUILTIN_DECLARATION_PROJECTION(item)
        for item in value.target_declarations
    ]
    if any(
        item.runtime_file_ref != value.runtime_file_ref
        or item.ordinal != index
        for index, item in enumerate(value.target_declarations)
    ):
        raise _InvalidNativeDependencyTargetResolution
    declared = value.dependency_disposition in {
        "elf_dependencies_declared",
        "mach_o_dependencies_declared",
    }
    if declared != bool(value.target_declarations):
        raise _InvalidNativeDependencyTargetResolution
    absolute_count = sum(
        item.target_disposition == "absolute_dependency_target_measured"
        for item in value.target_declarations
    )
    if (
        absolute_count != value.absolute_dependency_count
        or len(value.target_declarations) - absolute_count
        != value.unresolved_dependency_count
    ):
        raise _InvalidNativeDependencyTargetResolution
    reference = _BUILTIN_TARGET_REQUIREMENT_REF_PROJECTION(
        staged_file_ref=value.staged_file_ref,
        runtime_file_ref=value.runtime_file_ref,
        native_dependency_requirement_ref=(
            value.native_dependency_requirement_ref
        ),
        runtime_classification=value.runtime_classification,
        dependency_disposition=value.dependency_disposition,
        target_declarations=declarations,
    )
    if value.target_requirement_ref != _BUILTIN_CANONICAL_DIGEST(reference):
        raise _InvalidNativeDependencyTargetResolution
    return {
        **reference,
        "absolute_dependency_count": value.absolute_dependency_count,
        "dependency_declaration_count": value.dependency_declaration_count,
        "kind": value.kind,
        "target_requirement_ref": value.target_requirement_ref,
        "unresolved_dependency_count": value.unresolved_dependency_count,
    }


_BUILTIN_REQUIREMENT_PROJECTION = _requirement_projection


def _binding_projection(
    value: RepositoryExecutableNativeDependencyTargetBinding,
) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_BINDING_TYPE
        or value.kind != _FIXED_BINDING_KIND
        or value.command_kind not in _COMMAND_KINDS
        or type(value.command_id) is not str
        or _IDENTIFIER_PATTERN.fullmatch(value.command_id) is None
        or not all(
            _BUILTIN_IS_DIGEST(item)
            for item in (
                value.command_digest,
                value.staged_file_ref,
                value.runtime_file_ref,
                value.native_dependency_requirement_ref,
                value.target_requirement_ref,
            )
        )
    ):
        raise _InvalidNativeDependencyTargetResolution
    return {
        "command_digest": value.command_digest,
        "command_id": value.command_id,
        "command_kind": value.command_kind,
        "kind": value.kind,
        "native_dependency_requirement_ref": (
            value.native_dependency_requirement_ref
        ),
        "runtime_file_ref": value.runtime_file_ref,
        "staged_file_ref": value.staged_file_ref,
        "target_requirement_ref": value.target_requirement_ref,
    }


_BUILTIN_BINDING_PROJECTION = _binding_projection


def _receipt_projection(
    value: RepositoryExecutableNativeDependencyTargetResolutionReceipt,
) -> dict[str, Any]:
    digest_fields = (
        value.native_dependency_requirements_receipt_digest,
        value.runtime_manifest_receipt_digest,
        value.staging_receipt_digest,
        value.registration_digest,
        value.repository_ref,
        value.verification_commands_digest,
        value.resolution_context_digest,
        value.staging_context_digest,
        value.dependency_path_context_digest,
    )
    count_fields = (
        value.dependency_declaration_count,
        value.absolute_dependency_declaration_count,
        value.unresolved_dependency_declaration_count,
        value.unique_target_count,
        value.total_measured_bytes,
    )
    if (
        type(value) is not _FIXED_RECEIPT_TYPE
        or value.kind != _FIXED_RECEIPT_KIND
        or type(value.schema_version) is not int
        or value.schema_version != _FIXED_SCHEMA_VERSION
        or value.measurement_source != _FIXED_MEASUREMENT_SOURCE
        or value.resolution_scope != _FIXED_RESOLUTION_SCOPE
        or not all(_BUILTIN_IS_DIGEST(item) for item in digest_fields)
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
        or any(type(item) is not int or item < 0 for item in count_fields)
        or value.dependency_declaration_count > _MAX_DECLARATIONS
        or value.unique_target_count != len(value.measurements)
        or value.total_measured_bytes > _MAX_TOTAL_TARGET_BYTES
    ):
        raise _InvalidNativeDependencyTargetResolution
    measurements = [
        _BUILTIN_MEASUREMENT_PROJECTION(item) for item in value.measurements
    ]
    requirements = [
        _BUILTIN_REQUIREMENT_PROJECTION(item) for item in value.requirements
    ]
    bindings = [
        _BUILTIN_BINDING_PROJECTION(item) for item in value.bindings
    ]
    measurement_by_ref: dict[
        str, RepositoryExecutableNativeDependencyTargetMeasurement
    ] = {}
    path_refs: set[str] = set()
    identity_refs: set[str] = set()
    total_bytes = 0
    for item in value.measurements:
        if (
            item.measurement_ref in measurement_by_ref
            or item.path_ref in path_refs
            or item.filesystem_identity_ref in identity_refs
        ):
            raise _InvalidNativeDependencyTargetResolution
        measurement_by_ref[item.measurement_ref] = item
        path_refs.add(item.path_ref)
        identity_refs.add(item.filesystem_identity_ref)
        total_bytes += item.content_bytes

    requirement_by_upstream_ref: dict[
        str, RepositoryExecutableNativeDependencyTargetRequirement
    ] = {}
    target_requirement_refs: set[str] = set()
    staged_refs: set[str] = set()
    runtime_refs: set[str] = set()
    upstream_declaration_refs: set[str] = set()
    target_declaration_refs: set[str] = set()
    used_measurement_refs: set[str] = set()
    ordered_measurement_refs: list[str] = []
    for requirement in value.requirements:
        if (
            requirement.native_dependency_requirement_ref
            in requirement_by_upstream_ref
            or requirement.target_requirement_ref in target_requirement_refs
            or requirement.staged_file_ref in staged_refs
            or requirement.runtime_file_ref in runtime_refs
        ):
            raise _InvalidNativeDependencyTargetResolution
        requirement_by_upstream_ref[
            requirement.native_dependency_requirement_ref
        ] = requirement
        target_requirement_refs.add(requirement.target_requirement_ref)
        staged_refs.add(requirement.staged_file_ref)
        runtime_refs.add(requirement.runtime_file_ref)
        for declaration in requirement.target_declarations:
            measurement_ref = declaration.target_measurement_ref
            if (
                declaration.dependency_declaration_ref
                in upstream_declaration_refs
                or declaration.target_declaration_ref
                in target_declaration_refs
                or (
                    measurement_ref is not None
                    and measurement_ref not in measurement_by_ref
                )
            ):
                raise _InvalidNativeDependencyTargetResolution
            upstream_declaration_refs.add(
                declaration.dependency_declaration_ref
            )
            target_declaration_refs.add(declaration.target_declaration_ref)
            if (
                measurement_ref is not None
                and measurement_ref not in used_measurement_refs
            ):
                ordered_measurement_refs.append(measurement_ref)
                used_measurement_refs.add(measurement_ref)

    command_ids: set[str] = set()
    bound_refs: set[str] = set()
    ordered_bound_refs: list[str] = []
    prior_kind_index = -1
    for binding in value.bindings:
        requirement = requirement_by_upstream_ref.get(
            binding.native_dependency_requirement_ref
        )
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
            raise _InvalidNativeDependencyTargetResolution
        command_ids.add(binding.command_id)
        if binding.target_requirement_ref not in bound_refs:
            ordered_bound_refs.append(binding.target_requirement_ref)
        bound_refs.add(binding.target_requirement_ref)
        prior_kind_index = kind_index

    declaration_count = sum(
        item.dependency_declaration_count for item in value.requirements
    )
    absolute_count = sum(
        item.absolute_dependency_count for item in value.requirements
    )
    unresolved_count = sum(
        item.unresolved_dependency_count for item in value.requirements
    )
    if (
        used_measurement_refs != set(measurement_by_ref)
        or tuple(ordered_measurement_refs)
        != tuple(item.measurement_ref for item in value.measurements)
        or bound_refs != target_requirement_refs
        or tuple(ordered_bound_refs)
        != tuple(item.target_requirement_ref for item in value.requirements)
        or declaration_count != value.dependency_declaration_count
        or absolute_count != value.absolute_dependency_declaration_count
        or unresolved_count != value.unresolved_dependency_declaration_count
        or absolute_count + unresolved_count != declaration_count
        or total_bytes != value.total_measured_bytes
        or value.dependency_path_context_digest
        != _BUILTIN_CANONICAL_DIGEST(
            {
                "kind": (
                    "repository_executable_native_dependency_target_path_context"
                ),
                "ordered_target_path_refs": [
                    item.path_ref for item in value.measurements
                ],
                "resolution_scope": _FIXED_RESOLUTION_SCOPE,
                "schema_version": _FIXED_SCHEMA_VERSION,
            }
        )
    ):
        raise _InvalidNativeDependencyTargetResolution
    return {
        "absolute_dependency_declaration_count": (
            value.absolute_dependency_declaration_count
        ),
        "bindings": bindings,
        "command_count": value.command_count,
        "dependency_declaration_count": value.dependency_declaration_count,
        "dependency_path_context_digest": (
            value.dependency_path_context_digest
        ),
        "kind": value.kind,
        "measurement_source": value.measurement_source,
        "measurements": measurements,
        "native_dependency_requirements_receipt_digest": (
            value.native_dependency_requirements_receipt_digest
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
        "staging_context_digest": value.staging_context_digest,
        "staging_receipt_digest": value.staging_receipt_digest,
        "total_measured_bytes": value.total_measured_bytes,
        "unique_target_count": value.unique_target_count,
        "unresolved_dependency_declaration_count": (
            value.unresolved_dependency_declaration_count
        ),
        "verification_commands_digest": value.verification_commands_digest,
    }


_BUILTIN_RECEIPT_PROJECTION = _receipt_projection


def _evidence_projection(
    value: RepositoryExecutableNativeDependencyTargetResolutionReceipt,
) -> dict[str, Any]:
    canonical = _BUILTIN_RECEIPT_PROJECTION(value)
    return {
        "absolute_dependency_declaration_count": (
            value.absolute_dependency_declaration_count
        ),
        "absolute_dependency_target_measurement_complete": True,
        "action_receipt_issued": False,
        "active_lease_verified_at_measurement": True,
        "authority_granted": False,
        "authorization_verified": False,
        "billing_eligible": False,
        "capacity_eligible": False,
        "circuit_eligible": False,
        "command_count": value.command_count,
        "current_lease_activity_verified": False,
        "current_source_freshness_verified": False,
        "dependency_closure_verified": False,
        "dependency_declaration_count": value.dependency_declaration_count,
        "dependency_path_raw_bytes_exposed": False,
        "dependency_search_semantics_applied": False,
        "dispatch_enabled": False,
        "durable_control_plane_persistence_enabled": False,
        "effect_class": 0,
        "environment_coverage_verified": False,
        "exact_absolute_dependency_path_expectation_verified": True,
        "execution_enabled": False,
        "fat_mach_o_architecture_selection_performed": False,
        "future_execution_correspondence_verified": False,
        "harness_invocation_performed": False,
        "kind": _FIXED_EVIDENCE_KIND,
        "lease_cleanup_performed": False,
        "lease_mutated": False,
        "live_execution_eligible": False,
        "loader_invocation_performed": False,
        "model_invocation_performed": False,
        "network_access_performed": False,
        "non_absolute_dependency_resolution_verified": False,
        "path_lookup_performed": bool(value.measurements),
        "proposal_lineage_extended": False,
        "receipt_authenticity_verified": False,
        "receipt_digest": _BUILTIN_CANONICAL_DIGEST(canonical),
        "recursive_dependency_resolution_verified": False,
        "registration_digest": value.registration_digest,
        "repository_ref": value.repository_ref,
        "requirement_count": value.requirement_count,
        "resolution_scope": value.resolution_scope,
        "route_eligible": False,
        "shared_library_closure_verified": False,
        "source_path_reopen_performed": False,
        "subprocess_invocation_performed": False,
        "target_nofollow_measurement_complete": True,
        "toolchain_completeness_verified": False,
        "total_measured_bytes": value.total_measured_bytes,
        "unique_target_count": value.unique_target_count,
        "unresolved_dependency_declaration_count": (
            value.unresolved_dependency_declaration_count
        ),
        "validation_mode": "read_only",
        "worker_authorized": False,
        "worktree_integration_enabled": False,
    }


_BUILTIN_EVIDENCE_PROJECTION = _evidence_projection


@dataclass(frozen=True, slots=True)
class _DerivedTargetRequirement:
    upstream: RepositoryExecutableNativeDependencyRequirement = field(
        repr=False
    )
    declarations: tuple[
        tuple[RepositoryExecutableNativeDependencyDeclaration, Path | None],
        ...,
    ] = field(repr=False)


_FIXED_DERIVED_TYPE = _DerivedTargetRequirement


def _validated_path(path: Any) -> tuple[Path, bytes]:
    if type(path) is not _CONCRETE_PATH_TYPE:
        raise _InvalidNativeDependencyTargetResolution
    try:
        encoded = os.fspath(path).encode("ascii")
    except (AttributeError, TypeError, UnicodeEncodeError):
        raise _InvalidNativeDependencyTargetResolution from None
    if (
        not 1 <= len(encoded) <= _MAX_TARGET_PATH_BYTES
        or _BUILTIN_CANONICAL_TARGET_PATH(encoded) != path
    ):
        raise _InvalidNativeDependencyTargetResolution
    return path, encoded


_BUILTIN_VALIDATED_PATH = _validated_path


def _path_ref(path: Path) -> str:
    _, encoded = _BUILTIN_VALIDATED_PATH(path)
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "kind": "repository_executable_native_dependency_target_path_ref",
            "resolution_scope": _FIXED_RESOLUTION_SCOPE,
            "schema_version": _FIXED_SCHEMA_VERSION,
            "target_path_ascii": encoded.decode("ascii"),
        }
    )


_BUILTIN_PATH_REF = _path_ref


def _dependency_path_context_digest(paths: tuple[Path, ...]) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "kind": (
                "repository_executable_native_dependency_target_path_context"
            ),
            "ordered_target_path_refs": [
                _BUILTIN_PATH_REF(path) for path in paths
            ],
            "resolution_scope": _FIXED_RESOLUTION_SCOPE,
            "schema_version": _FIXED_SCHEMA_VERSION,
        }
    )


_BUILTIN_DEPENDENCY_PATH_CONTEXT_DIGEST = _dependency_path_context_digest


def _expected_dependency_name_ref(
    declaration: RepositoryExecutableNativeDependencyDeclaration,
    *,
    encoded: bytes,
) -> str:
    if (
        type(declaration) is not _FIXED_UPSTREAM_DECLARATION_TYPE
        or declaration.format_class not in _FORMAT_CLASSES
    ):
        raise _InvalidNativeDependencyTargetResolution
    return _BUILTIN_DEPENDENCY_NAME_REF(
        runtime_file_ref=declaration.runtime_file_ref,
        format_class=declaration.format_class,
        dependency_name=encoded,
    )


_BUILTIN_EXPECTED_DEPENDENCY_NAME_REF = _expected_dependency_name_ref


def _validate_expected_dependency_paths(
    expected_requirements: RepositoryExecutableNativeDependencyRequirementsReceipt,
    expected_absolute_dependency_paths: Any,
) -> tuple[tuple[_DerivedTargetRequirement, ...], tuple[Path, ...]]:
    if (
        type(expected_absolute_dependency_paths) is not tuple
        or len(expected_absolute_dependency_paths) > _MAX_TARGET_PATHS
    ):
        raise _InvalidNativeDependencyTargetResolution
    validated: list[tuple[Path, bytes]] = []
    spellings: set[str] = set()
    total_bytes = 0
    for candidate in expected_absolute_dependency_paths:
        path, encoded = _BUILTIN_VALIDATED_PATH(candidate)
        spelling = os.fspath(path)
        if spelling in spellings:
            raise _InvalidNativeDependencyTargetResolution
        spellings.add(spelling)
        total_bytes += len(encoded)
        if total_bytes > _MAX_TOTAL_TARGET_PATH_BYTES:
            raise _InvalidNativeDependencyTargetResolution
        validated.append((path, encoded))

    derived: list[_DerivedTargetRequirement] = []
    used_paths: list[Path] = []
    used_spellings: set[str] = set()
    for requirement in expected_requirements.requirements:
        if type(requirement) is not _FIXED_UPSTREAM_REQUIREMENT_TYPE:
            raise _InvalidNativeDependencyTargetResolution
        derived_declarations: list[
            tuple[RepositoryExecutableNativeDependencyDeclaration, Path | None]
        ] = []
        for declaration in requirement.declarations:
            if type(declaration) is not _FIXED_UPSTREAM_DECLARATION_TYPE:
                raise _InvalidNativeDependencyTargetResolution
            target_path: Path | None = None
            if declaration.path_style == "absolute":
                matches = [
                    path
                    for path, encoded in validated
                    if len(encoded) == declaration.dependency_name_bytes
                    and _BUILTIN_EXPECTED_DEPENDENCY_NAME_REF(
                        declaration,
                        encoded=encoded,
                    )
                    == declaration.dependency_name_ref
                ]
                if len(matches) != 1:
                    raise _InvalidNativeDependencyTargetResolution
                target_path = matches[0]
                spelling = os.fspath(target_path)
                if spelling not in used_spellings:
                    used_paths.append(target_path)
                    used_spellings.add(spelling)
            derived_declarations.append((declaration, target_path))
        derived.append(
            _FIXED_DERIVED_TYPE(
                upstream=requirement,
                declarations=tuple(derived_declarations),
            )
        )
    paths = tuple(path for path, _encoded in validated)
    if tuple(used_paths) != paths:
        raise _InvalidNativeDependencyTargetResolution
    return tuple(derived), paths


_BUILTIN_VALIDATE_EXPECTED_DEPENDENCY_PATHS = (
    _validate_expected_dependency_paths
)


def _validated_chain_snapshot(
    expected_requirements: RepositoryExecutableNativeDependencyRequirementsReceipt,
    expected_runtime: RepositoryExecutableRuntimeManifestReceipt,
    expected_staging: RepositoryExecutableStagingReceipt,
    lease: RepositoryExecutableStageLease,
    expected_absolute_dependency_paths: Any,
) -> tuple[
    tuple[_DerivedTargetRequirement, ...],
    tuple[Path, ...],
    str,
    str,
    str,
]:
    if (
        type(expected_requirements) is not _FIXED_DEPENDENCY_RECEIPT_TYPE
        or type(expected_runtime) is not _FIXED_RUNTIME_TYPE
        or type(expected_staging) is not _FIXED_STAGING_TYPE
        or type(lease) is not _FIXED_LEASE_TYPE
    ):
        raise _InvalidNativeDependencyTargetResolution
    requirements_canonical = _BUILTIN_DEPENDENCY_RECEIPT_PROJECTION(
        expected_requirements
    )
    runtime_canonical = _BUILTIN_RUNTIME_PROJECTION(expected_runtime)
    staging_canonical = _BUILTIN_STAGING_PROJECTION(expected_staging)
    requirements_digest = _BUILTIN_CANONICAL_DIGEST(
        requirements_canonical
    )
    runtime_digest = _BUILTIN_CANONICAL_DIGEST(runtime_canonical)
    staging_digest = _BUILTIN_CANONICAL_DIGEST(staging_canonical)
    if (
        expected_requirements.runtime_manifest_receipt_digest
        != runtime_digest
        or expected_requirements.staging_receipt_digest != staging_digest
        or expected_runtime.staging_receipt_digest != staging_digest
        or expected_requirements.registration_digest
        != expected_runtime.registration_digest
        or expected_requirements.registration_digest
        != expected_staging.registration_digest
        or expected_requirements.repository_ref != expected_runtime.repository_ref
        or expected_requirements.repository_ref != expected_staging.repository_ref
        or expected_requirements.verification_commands_digest
        != expected_runtime.verification_commands_digest
        or expected_requirements.verification_commands_digest
        != expected_staging.verification_commands_digest
        or expected_requirements.resolution_context_digest
        != expected_runtime.resolution_context_digest
        or expected_requirements.resolution_context_digest
        != expected_staging.resolution_context_digest
        or expected_requirements.staging_context_digest
        != expected_runtime.staging_context_digest
        or expected_requirements.staging_context_digest
        != expected_staging.staging_context_digest
    ):
        raise _InvalidNativeDependencyTargetResolution
    fresh_loader = _BUILTIN_INSPECT_NATIVE_LOADER(
        expected_runtime,
        expected_staging=expected_staging,
        lease=lease,
    )
    fresh_requirements = _BUILTIN_INSPECT_DEPENDENCY_REQUIREMENTS(
        fresh_loader,
        expected_runtime=expected_runtime,
        expected_staging=expected_staging,
        lease=lease,
    )
    if (
        _BUILTIN_DEPENDENCY_RECEIPT_PROJECTION(fresh_requirements)
        != requirements_canonical
    ):
        raise _InvalidNativeDependencyTargetResolution
    active_staging_canonical, _retained_files = (
        _BUILTIN_ACTIVE_STAGE_SNAPSHOT(expected_staging, lease)
    )
    if active_staging_canonical != staging_canonical:
        raise _InvalidNativeDependencyTargetResolution
    derived, paths = _BUILTIN_VALIDATE_EXPECTED_DEPENDENCY_PATHS(
        expected_requirements,
        expected_absolute_dependency_paths,
    )
    return (
        derived,
        paths,
        requirements_digest,
        runtime_digest,
        staging_digest,
    )


_BUILTIN_VALIDATED_CHAIN_SNAPSHOT = _validated_chain_snapshot


def _measurement_identity_ref(measured: _MeasuredTarget) -> str:
    if (
        type(measured) is not _FIXED_MEASURED_TARGET_TYPE
        or type(measured.identity) is not tuple
        or len(measured.identity) != 2
        or any(type(item) is not int for item in measured.identity)
    ):
        raise _InvalidNativeDependencyTargetResolution
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "device": measured.identity[0],
            "inode": measured.identity[1],
            "kind": (
                "repository_executable_native_dependency_target_file_identity"
            ),
            "schema_version": _FIXED_SCHEMA_VERSION,
        }
    )


_BUILTIN_MEASUREMENT_IDENTITY_REF = _measurement_identity_ref


def _measurement_metadata_digest(
    measured: _MeasuredTarget,
    *,
    identity_ref: str,
) -> str:
    metadata = measured.metadata
    if (
        type(metadata) is not tuple
        or len(metadata) != 9
        or any(type(item) is not int for item in metadata)
        or not _BUILTIN_IS_DIGEST(identity_ref)
        or metadata[0:2] != measured.identity
        or metadata[6] != measured.content_bytes
    ):
        raise _InvalidNativeDependencyTargetResolution
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "change_time_ns": metadata[8],
            "filesystem_identity_ref": identity_ref,
            "group_id": metadata[5],
            "kind": (
                "repository_executable_native_dependency_target_file_metadata"
            ),
            "link_count": metadata[3],
            "mode": metadata[2],
            "modified_time_ns": metadata[7],
            "owner_id": metadata[4],
            "schema_version": _FIXED_SCHEMA_VERSION,
            "size_bytes": metadata[6],
        }
    )


_BUILTIN_MEASUREMENT_METADATA_DIGEST = _measurement_metadata_digest


def _public_measurement(
    measured: _MeasuredTarget,
) -> RepositoryExecutableNativeDependencyTargetMeasurement:
    if (
        type(measured) is not _FIXED_MEASURED_TARGET_TYPE
        or type(measured.path) is not _CONCRETE_PATH_TYPE
        or not _BUILTIN_IS_DIGEST(measured.content_digest)
        or type(measured.content_bytes) is not int
        or not 0 <= measured.content_bytes <= _MAX_TARGET_BYTES
    ):
        raise _InvalidNativeDependencyTargetResolution
    path_ref = _BUILTIN_PATH_REF(measured.path)
    identity_ref = _BUILTIN_MEASUREMENT_IDENTITY_REF(measured)
    metadata_digest = _BUILTIN_MEASUREMENT_METADATA_DIGEST(
        measured,
        identity_ref=identity_ref,
    )
    reference = _BUILTIN_MEASUREMENT_REF_PROJECTION(
        path_ref=path_ref,
        filesystem_identity_ref=identity_ref,
        metadata_digest=metadata_digest,
        content_digest=measured.content_digest,
        content_bytes=measured.content_bytes,
    )
    value = _FIXED_MEASUREMENT_TYPE(
        kind=_FIXED_MEASUREMENT_KIND,
        path_ref=path_ref,
        filesystem_identity_ref=identity_ref,
        metadata_digest=metadata_digest,
        content_digest=measured.content_digest,
        content_bytes=measured.content_bytes,
        measurement_ref=_BUILTIN_CANONICAL_DIGEST(reference),
    )
    _BUILTIN_MEASUREMENT_PROJECTION(value)
    return value


_BUILTIN_PUBLIC_MEASUREMENT = _public_measurement


def _public_target_declaration(
    upstream: RepositoryExecutableNativeDependencyDeclaration,
    *,
    target_path: Path | None,
    measurement_by_path: dict[
        Path, RepositoryExecutableNativeDependencyTargetMeasurement
    ],
) -> RepositoryExecutableNativeDependencyTargetDeclaration:
    if type(upstream) is not _FIXED_UPSTREAM_DECLARATION_TYPE:
        raise _InvalidNativeDependencyTargetResolution
    target_measurement_ref: str | None = None
    if target_path is not None:
        measurement = measurement_by_path.get(target_path)
        if measurement is None or upstream.path_style != "absolute":
            raise _InvalidNativeDependencyTargetResolution
        target_measurement_ref = measurement.measurement_ref
        disposition = "absolute_dependency_target_measured"
    else:
        if upstream.path_style == "absolute":
            raise _InvalidNativeDependencyTargetResolution
        disposition = "non_absolute_dependency_unresolved"
    reference = _BUILTIN_TARGET_DECLARATION_REF_PROJECTION(
        runtime_file_ref=upstream.runtime_file_ref,
        dependency_declaration_ref=upstream.declaration_ref,
        dependency_name_ref=upstream.dependency_name_ref,
        format_class=upstream.format_class,
        ordinal=upstream.ordinal,
        path_style=upstream.path_style,
        target_disposition=disposition,
        target_measurement_ref=target_measurement_ref,
    )
    value = _FIXED_DECLARATION_TYPE(
        kind=_FIXED_DECLARATION_KIND,
        runtime_file_ref=upstream.runtime_file_ref,
        dependency_declaration_ref=upstream.declaration_ref,
        dependency_name_ref=upstream.dependency_name_ref,
        format_class=upstream.format_class,
        ordinal=upstream.ordinal,
        path_style=upstream.path_style,
        target_disposition=disposition,
        target_measurement_ref=target_measurement_ref,
        target_declaration_ref=_BUILTIN_CANONICAL_DIGEST(reference),
    )
    _BUILTIN_DECLARATION_PROJECTION(value)
    return value


_BUILTIN_PUBLIC_TARGET_DECLARATION = _public_target_declaration


def _public_requirement(
    derived: _DerivedTargetRequirement,
    *,
    measurement_by_path: dict[
        Path, RepositoryExecutableNativeDependencyTargetMeasurement
    ],
) -> RepositoryExecutableNativeDependencyTargetRequirement:
    if (
        type(derived) is not _FIXED_DERIVED_TYPE
        or type(derived.upstream) is not _FIXED_UPSTREAM_REQUIREMENT_TYPE
    ):
        raise _InvalidNativeDependencyTargetResolution
    upstream = derived.upstream
    declarations = tuple(
        _BUILTIN_PUBLIC_TARGET_DECLARATION(
            declaration,
            target_path=target_path,
            measurement_by_path=measurement_by_path,
        )
        for declaration, target_path in derived.declarations
    )
    reference = _BUILTIN_TARGET_REQUIREMENT_REF_PROJECTION(
        staged_file_ref=upstream.staged_file_ref,
        runtime_file_ref=upstream.runtime_file_ref,
        native_dependency_requirement_ref=upstream.requirement_ref,
        runtime_classification=upstream.runtime_classification,
        dependency_disposition=upstream.disposition,
        target_declarations=[
            _BUILTIN_DECLARATION_PROJECTION(item) for item in declarations
        ],
    )
    absolute_count = sum(
        item.target_disposition == "absolute_dependency_target_measured"
        for item in declarations
    )
    value = _FIXED_REQUIREMENT_TYPE(
        kind=_FIXED_REQUIREMENT_KIND,
        staged_file_ref=upstream.staged_file_ref,
        runtime_file_ref=upstream.runtime_file_ref,
        native_dependency_requirement_ref=upstream.requirement_ref,
        runtime_classification=upstream.runtime_classification,
        dependency_disposition=upstream.disposition,
        target_declarations=declarations,
        dependency_declaration_count=len(declarations),
        absolute_dependency_count=absolute_count,
        unresolved_dependency_count=len(declarations) - absolute_count,
        target_requirement_ref=_BUILTIN_CANONICAL_DIGEST(reference),
    )
    _BUILTIN_REQUIREMENT_PROJECTION(value)
    return value


_BUILTIN_PUBLIC_REQUIREMENT = _public_requirement


def inspect_staged_executable_native_dependency_targets(
    expected_requirements: RepositoryExecutableNativeDependencyRequirementsReceipt,
    *,
    expected_runtime: RepositoryExecutableRuntimeManifestReceipt,
    expected_staging: RepositoryExecutableStagingReceipt,
    lease: RepositoryExecutableStageLease,
    expected_absolute_dependency_paths: tuple[Path, ...],
) -> RepositoryExecutableNativeDependencyTargetResolutionReceipt:
    """Measure the exact canonical-absolute dependency target set."""

    try:
        _BUILTIN_REQUIRE_SUPPORTED_PLATFORM()
        (
            derived,
            paths,
            requirements_digest,
            runtime_digest,
            staging_digest,
        ) = _BUILTIN_VALIDATED_CHAIN_SNAPSHOT(
            expected_requirements,
            expected_runtime,
            expected_staging,
            lease,
            expected_absolute_dependency_paths,
        )
        first_measurement = _BUILTIN_MEASURE_TARGET_SET(paths)

        middle = _BUILTIN_VALIDATED_CHAIN_SNAPSHOT(
            expected_requirements,
            expected_runtime,
            expected_staging,
            lease,
            expected_absolute_dependency_paths,
        )
        if middle != (
            derived,
            paths,
            requirements_digest,
            runtime_digest,
            staging_digest,
        ):
            raise _InvalidNativeDependencyTargetResolution
        second_measurement = _BUILTIN_MEASURE_TARGET_SET(paths)
        if second_measurement != first_measurement:
            raise _InvalidNativeDependencyTargetResolution

        final = _BUILTIN_VALIDATED_CHAIN_SNAPSHOT(
            expected_requirements,
            expected_runtime,
            expected_staging,
            lease,
            expected_absolute_dependency_paths,
        )
        if (
            final
            != (
                derived,
                paths,
                requirements_digest,
                runtime_digest,
                staging_digest,
            )
            or any(
                not _BUILTIN_TARGET_NAMESPACE_MATCHES(item)
                for item in first_measurement
            )
        ):
            raise _InvalidNativeDependencyTargetResolution
        closing_staging_canonical, _closing_retained_files = (
            _BUILTIN_ACTIVE_STAGE_SNAPSHOT(expected_staging, lease)
        )
        if (
            _BUILTIN_CANONICAL_DIGEST(closing_staging_canonical)
            != staging_digest
        ):
            raise _InvalidNativeDependencyTargetResolution

        measurements = tuple(
            _BUILTIN_PUBLIC_MEASUREMENT(item)
            for item in first_measurement
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
            _BUILTIN_PUBLIC_REQUIREMENT(
                item,
                measurement_by_path=measurement_by_path,
            )
            for item in derived
        )
        requirement_by_upstream_ref = {
            item.native_dependency_requirement_ref: item
            for item in requirements
        }
        bindings: list[RepositoryExecutableNativeDependencyTargetBinding] = []
        for upstream in expected_requirements.bindings:
            if type(upstream) is not _FIXED_UPSTREAM_BINDING_TYPE:
                raise _InvalidNativeDependencyTargetResolution
            requirement = requirement_by_upstream_ref.get(
                upstream.dependency_requirement_ref
            )
            if (
                requirement is None
                or upstream.staged_file_ref != requirement.staged_file_ref
                or upstream.runtime_file_ref != requirement.runtime_file_ref
            ):
                raise _InvalidNativeDependencyTargetResolution
            binding = _FIXED_BINDING_TYPE(
                kind=_FIXED_BINDING_KIND,
                command_kind=upstream.command_kind,
                command_id=upstream.command_id,
                command_digest=upstream.command_digest,
                staged_file_ref=upstream.staged_file_ref,
                runtime_file_ref=upstream.runtime_file_ref,
                native_dependency_requirement_ref=(
                    upstream.dependency_requirement_ref
                ),
                target_requirement_ref=requirement.target_requirement_ref,
            )
            _BUILTIN_BINDING_PROJECTION(binding)
            bindings.append(binding)

        receipt = _FIXED_RECEIPT_TYPE(
            kind=_FIXED_RECEIPT_KIND,
            schema_version=_FIXED_SCHEMA_VERSION,
            measurement_source=_FIXED_MEASUREMENT_SOURCE,
            resolution_scope=_FIXED_RESOLUTION_SCOPE,
            native_dependency_requirements_receipt_digest=(
                requirements_digest
            ),
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
            dependency_path_context_digest=(
                _BUILTIN_DEPENDENCY_PATH_CONTEXT_DIGEST(paths)
            ),
            measurements=measurements,
            requirements=requirements,
            bindings=tuple(bindings),
            requirement_count=len(requirements),
            command_count=len(bindings),
            dependency_declaration_count=sum(
                item.dependency_declaration_count for item in requirements
            ),
            absolute_dependency_declaration_count=sum(
                item.absolute_dependency_count for item in requirements
            ),
            unresolved_dependency_declaration_count=sum(
                item.unresolved_dependency_count for item in requirements
            ),
            unique_target_count=len(measurements),
            total_measured_bytes=sum(
                item.content_bytes for item in measurements
            ),
        )
        _BUILTIN_RECEIPT_PROJECTION(receipt)
        return receipt
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise _FIXED_VALIDATION_ERROR(_INVALID_MESSAGE) from None


__all__ = [
    "MEASUREMENT_SOURCE",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_TARGET_BINDING_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_TARGET_DECLARATION_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_TARGET_MEASUREMENT_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_TARGET_REQUIREMENT_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_TARGET_RESOLUTION_EVIDENCE_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_TARGET_RESOLUTION_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_TARGET_RESOLUTION_SCHEMA_VERSION",
    "RESOLUTION_SCOPE",
    "RepositoryExecutableNativeDependencyTargetBinding",
    "RepositoryExecutableNativeDependencyTargetDeclaration",
    "RepositoryExecutableNativeDependencyTargetMeasurement",
    "RepositoryExecutableNativeDependencyTargetRequirement",
    "RepositoryExecutableNativeDependencyTargetResolutionReceipt",
    "inspect_staged_executable_native_dependency_targets",
]
