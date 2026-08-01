"""Measure one bounded nested native-loader target hop.

This Class 0 boundary consumes the exact loader-of-loader syntax chain and an
exact ordered set of canonical absolute paths.  Each declared nested path must
reproduce its digest-only declaration before guarded no-follow measurement.
Resolution stops after that measurement: bytes are not parsed or staged and no
loader, process, network, or model is invoked.
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
from .repository_executable_native_loader_target_loader_requirements import (
    RepositoryExecutableNativeLoaderTargetLoaderRequirementsReceipt,
    _receipt_projection as _loader_requirements_projection,
    inspect_staged_executable_native_loader_target_loader_requirements,
)
from .repository_executable_native_loader_target_resolution import (
    RepositoryExecutableNativeLoaderTargetResolutionReceipt,
    _loader_path_context_digest as _first_loader_path_context_digest,
    _path_ref as _first_loader_path_ref,
    _receipt_projection as _first_target_resolution_projection,
    _validated_path as _validate_absolute_path,
)
from .repository_executable_native_loader_target_runtime_manifest import (
    RepositoryExecutableNativeLoaderTargetRuntimeManifestReceipt,
    _active_target_stage_snapshot,
    _runtime_manifest_projection as _target_runtime_projection,
)
from .repository_executable_native_loader_target_staging import (
    RepositoryExecutableNativeLoaderTargetStageLease,
    RepositoryExecutableNativeLoaderTargetStagingReceipt,
    _staging_receipt_projection as _target_staging_projection,
)
from .repository_executable_shebang_nested_target_resolution import (
    _MeasuredNestedTarget,
    _NestedTargetGuardContext,
    _measure_guarded_target_set,
    _require_supported_platform,
)


REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RESOLUTION_SCHEMA_VERSION = 1
REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RESOLUTION_KIND = (
    "repository_executable_native_loader_nested_target_resolution"
)
REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RESOLUTION_EVIDENCE_KIND = (
    "repository_executable_native_loader_nested_target_resolution_validation"
)
REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_MEASUREMENT_KIND = (
    "repository_executable_native_loader_nested_target_measurement"
)
REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_REQUIREMENT_KIND = (
    "repository_executable_native_loader_nested_target_requirement"
)
REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_LINEAGE_KIND = (
    "repository_executable_native_loader_nested_target_lineage"
)
REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_BINDING_KIND = (
    "repository_executable_native_loader_nested_target_binding"
)
MEASUREMENT_SOURCE = "controller_measured"
RESOLUTION_SCOPE = "native_loader_nested_declared_absolute_target_nofollow_v1"
RESOLUTION_DEPTH = 2
MAXIMUM_RESOLUTION_DEPTH = 2
CYCLE_SCOPE = "immediate_native_loader_target_reentry_v1"

_FIXED_SCHEMA_VERSION = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RESOLUTION_SCHEMA_VERSION
)
_FIXED_RECEIPT_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RESOLUTION_KIND
)
_FIXED_EVIDENCE_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RESOLUTION_EVIDENCE_KIND
)
_FIXED_MEASUREMENT_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_MEASUREMENT_KIND
)
_FIXED_REQUIREMENT_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_REQUIREMENT_KIND
)
_FIXED_LINEAGE_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_LINEAGE_KIND
)
_FIXED_BINDING_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_BINDING_KIND
)
_FIXED_MEASUREMENT_SOURCE = MEASUREMENT_SOURCE
_FIXED_RESOLUTION_SCOPE = RESOLUTION_SCOPE
_FIXED_RESOLUTION_DEPTH = RESOLUTION_DEPTH
_FIXED_MAXIMUM_RESOLUTION_DEPTH = MAXIMUM_RESOLUTION_DEPTH
_FIXED_CYCLE_SCOPE = CYCLE_SCOPE

_INVALID_MESSAGE = (
    "repository executable native loader nested target resolution is invalid"
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
_LOADER_DISPOSITIONS = (
    "elf_interpreter_declared",
    "elf_interpreter_absent",
    "mach_o_dylinker_declared",
    "mach_o_dylinker_absent",
    "unsupported_native_layout",
    "non_native_not_applicable",
)
_NESTED_TARGET_DISPOSITIONS = (
    "declared_nested_loader_target_measured",
    "loader_declaration_absent",
    "unsupported_native_layout",
    "non_native_not_applicable",
)
_UPSTREAM_LINEAGE_DISPOSITIONS = (
    "target_loader_requirements_inspected",
    "loader_declaration_absent",
    "unsupported_native_layout",
    "non_native_not_applicable",
)
_LINEAGE_DISPOSITIONS = (
    "nested_loader_requirement_bound",
    "loader_declaration_absent",
    "unsupported_native_layout",
    "non_native_not_applicable",
)
_FORMAT_CLASSES = (
    "elf32",
    "elf64",
    "mach_o32",
    "mach_o64",
    "mach_o_fat32",
    "mach_o_fat64",
)
_MAX_REQUIREMENTS = 80
_MAX_LINEAGES = 80
_MAX_COMMANDS = 80
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
_BUILTIN_LOADER_REQUIREMENTS_PROJECTION = _loader_requirements_projection
_BUILTIN_FIRST_TARGET_RESOLUTION_PROJECTION = (
    _first_target_resolution_projection
)
_BUILTIN_TARGET_RUNTIME_PROJECTION = _target_runtime_projection
_BUILTIN_TARGET_STAGING_PROJECTION = _target_staging_projection
_BUILTIN_INSPECT_LOADER_REQUIREMENTS = (
    inspect_staged_executable_native_loader_target_loader_requirements
)
_BUILTIN_ACTIVE_TARGET_STAGE_SNAPSHOT = _active_target_stage_snapshot
_BUILTIN_VALIDATE_ABSOLUTE_PATH = _validate_absolute_path
_BUILTIN_FIRST_LOADER_PATH_REF = _first_loader_path_ref
_BUILTIN_FIRST_LOADER_PATH_CONTEXT_DIGEST = (
    _first_loader_path_context_digest
)
_BUILTIN_REQUIRE_SUPPORTED_PLATFORM = _require_supported_platform
_BUILTIN_MEASURE_GUARDED_TARGET_SET = _measure_guarded_target_set
_FIXED_LOADER_REQUIREMENTS_TYPE = (
    RepositoryExecutableNativeLoaderTargetLoaderRequirementsReceipt
)
_FIXED_FIRST_TARGET_RESOLUTION_TYPE = (
    RepositoryExecutableNativeLoaderTargetResolutionReceipt
)
_FIXED_TARGET_RUNTIME_TYPE = (
    RepositoryExecutableNativeLoaderTargetRuntimeManifestReceipt
)
_FIXED_TARGET_STAGING_TYPE = (
    RepositoryExecutableNativeLoaderTargetStagingReceipt
)
_FIXED_TARGET_STAGE_LEASE_TYPE = (
    RepositoryExecutableNativeLoaderTargetStageLease
)
_FIXED_MEASURED_TARGET_TYPE = _MeasuredNestedTarget
_FIXED_GUARD_CONTEXT_TYPE = _NestedTargetGuardContext
_FIXED_VALIDATION_ERROR = ValidationError


class _InvalidNestedNativeLoaderResolution(ValueError):
    """Private fixed-redaction sentinel."""


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeLoaderNestedTargetMeasurement:
    """One exact nested loader target's point-in-time file measurement."""

    kind: str
    path_ref: str = field(repr=False)
    filesystem_identity_ref: str = field(repr=False)
    metadata_digest: str = field(repr=False)
    content_digest: str = field(repr=False)
    content_bytes: int
    nested_target_measurement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_MEASUREMENT_PROJECTION(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeLoaderNestedTargetRequirement:
    """One unique loader target's nested-target outcome."""

    kind: str
    target_staged_file_ref: str = field(repr=False)
    target_runtime_file_ref: str = field(repr=False)
    target_loader_requirement_ref: str = field(repr=False)
    runtime_classification: str
    loader_disposition: str
    nested_target_disposition: str
    loader_path_ref: str | None = field(repr=False)
    nested_target_measurement_ref: str | None = field(repr=False)
    nested_target_requirement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_REQUIREMENT_PROJECTION(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeLoaderNestedTargetLineage:
    """One upstream source lineage bound through nested-loader evidence."""

    kind: str
    staged_file_ref: str = field(repr=False)
    runtime_file_ref: str = field(repr=False)
    requirement_ref: str = field(repr=False)
    target_requirement_ref: str = field(repr=False)
    target_stage_requirement_ref: str = field(repr=False)
    target_runtime_requirement_ref: str = field(repr=False)
    target_runtime_file_ref: str | None = field(repr=False)
    target_loader_requirement_ref: str | None = field(repr=False)
    target_loader_lineage_ref: str = field(repr=False)
    source_runtime_classification: str
    disposition: str
    nested_target_requirement_ref: str | None = field(repr=False)
    nested_target_lineage_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_LINEAGE_PROJECTION(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeLoaderNestedTargetBinding:
    """One registered command bound through the nested target lineage."""

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
    target_loader_lineage_ref: str = field(repr=False)
    nested_target_lineage_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_BINDING_PROJECTION(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeLoaderNestedTargetResolutionReceipt:
    """Privacy-bounded historical evidence for one nested loader hop."""

    kind: str
    schema_version: int
    measurement_source: str
    resolution_scope: str
    resolution_depth: int
    maximum_resolution_depth: int
    cycle_scope: str
    target_loader_requirements_receipt_digest: str = field(repr=False)
    target_runtime_manifest_receipt_digest: str = field(repr=False)
    target_staging_receipt_digest: str = field(repr=False)
    target_resolution_receipt_digest: str = field(repr=False)
    native_loader_requirements_receipt_digest: str = field(repr=False)
    runtime_manifest_receipt_digest: str = field(repr=False)
    staging_receipt_digest: str = field(repr=False)
    registration_digest: str = field(repr=False)
    repository_ref: str = field(repr=False)
    verification_commands_digest: str = field(repr=False)
    resolution_context_digest: str = field(repr=False)
    source_staging_context_digest: str = field(repr=False)
    first_loader_path_context_digest: str = field(repr=False)
    target_staging_context_digest: str = field(repr=False)
    nested_loader_path_context_digest: str = field(repr=False)
    guard_context_digest: str = field(repr=False)
    measurements: tuple[
        RepositoryExecutableNativeLoaderNestedTargetMeasurement, ...
    ] = field(repr=False)
    requirements: tuple[
        RepositoryExecutableNativeLoaderNestedTargetRequirement, ...
    ] = field(repr=False)
    lineages: tuple[
        RepositoryExecutableNativeLoaderNestedTargetLineage, ...
    ] = field(repr=False)
    bindings: tuple[
        RepositoryExecutableNativeLoaderNestedTargetBinding, ...
    ] = field(repr=False)
    requirement_count: int
    lineage_count: int
    command_count: int
    declared_nested_target_requirement_count: int
    no_nested_target_requirement_count: int
    target_loader_lineage_count: int
    no_target_lineage_count: int
    unique_nested_target_count: int
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


_FIXED_MEASUREMENT_TYPE = (
    RepositoryExecutableNativeLoaderNestedTargetMeasurement
)
_FIXED_REQUIREMENT_TYPE = (
    RepositoryExecutableNativeLoaderNestedTargetRequirement
)
_FIXED_LINEAGE_TYPE = RepositoryExecutableNativeLoaderNestedTargetLineage
_FIXED_BINDING_TYPE = RepositoryExecutableNativeLoaderNestedTargetBinding
_FIXED_RECEIPT_TYPE = (
    RepositoryExecutableNativeLoaderNestedTargetResolutionReceipt
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
        "kind": (
            "repository_executable_native_loader_nested_target_"
            "measurement_ref"
        ),
        "measurement_source": _FIXED_MEASUREMENT_SOURCE,
        "metadata_digest": metadata_digest,
        "path_ref": path_ref,
        "resolution_depth": _FIXED_RESOLUTION_DEPTH,
        "resolution_scope": _FIXED_RESOLUTION_SCOPE,
        "schema_version": _FIXED_SCHEMA_VERSION,
    }


_BUILTIN_MEASUREMENT_REF_PROJECTION = _measurement_ref_projection


def _measurement_projection(
    value: RepositoryExecutableNativeLoaderNestedTargetMeasurement,
) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_MEASUREMENT_TYPE
        or type(value.kind) is not str
        or value.kind != _FIXED_MEASUREMENT_KIND
        or not all(
            _BUILTIN_IS_DIGEST(item)
            for item in (
                value.path_ref,
                value.filesystem_identity_ref,
                value.metadata_digest,
                value.content_digest,
                value.nested_target_measurement_ref,
            )
        )
        or type(value.content_bytes) is not int
        or not 0 <= value.content_bytes <= _MAX_TARGET_BYTES
    ):
        raise _InvalidNestedNativeLoaderResolution
    reference = _BUILTIN_MEASUREMENT_REF_PROJECTION(
        path_ref=value.path_ref,
        filesystem_identity_ref=value.filesystem_identity_ref,
        metadata_digest=value.metadata_digest,
        content_digest=value.content_digest,
        content_bytes=value.content_bytes,
    )
    if value.nested_target_measurement_ref != _BUILTIN_CANONICAL_DIGEST(
        reference
    ):
        raise _InvalidNestedNativeLoaderResolution
    return {
        **reference,
        "kind": value.kind,
        "nested_target_measurement_ref": value.nested_target_measurement_ref,
    }


_BUILTIN_MEASUREMENT_PROJECTION = _measurement_projection


def _requirement_ref_projection(
    *,
    target_staged_file_ref: str,
    target_runtime_file_ref: str,
    target_loader_requirement_ref: str,
    runtime_classification: str,
    loader_disposition: str,
    nested_target_disposition: str,
    loader_path_ref: str | None,
    nested_target_measurement_ref: str | None,
) -> dict[str, Any]:
    return {
        "kind": (
            "repository_executable_native_loader_nested_target_"
            "requirement_ref"
        ),
        "loader_disposition": loader_disposition,
        "loader_path_ref": loader_path_ref,
        "nested_target_disposition": nested_target_disposition,
        "nested_target_measurement_ref": nested_target_measurement_ref,
        "resolution_depth": _FIXED_RESOLUTION_DEPTH,
        "resolution_scope": _FIXED_RESOLUTION_SCOPE,
        "runtime_classification": runtime_classification,
        "schema_version": _FIXED_SCHEMA_VERSION,
        "target_loader_requirement_ref": target_loader_requirement_ref,
        "target_runtime_file_ref": target_runtime_file_ref,
        "target_staged_file_ref": target_staged_file_ref,
    }


_BUILTIN_REQUIREMENT_REF_PROJECTION = _requirement_ref_projection


def _nested_disposition(loader_disposition: str) -> str:
    if loader_disposition in {
        "elf_interpreter_declared",
        "mach_o_dylinker_declared",
    }:
        return "declared_nested_loader_target_measured"
    if loader_disposition in {
        "elf_interpreter_absent",
        "mach_o_dylinker_absent",
    }:
        return "loader_declaration_absent"
    if loader_disposition == "unsupported_native_layout":
        return "unsupported_native_layout"
    if loader_disposition == "non_native_not_applicable":
        return "non_native_not_applicable"
    raise _InvalidNestedNativeLoaderResolution


_BUILTIN_NESTED_DISPOSITION = _nested_disposition


def _requirement_projection(
    value: RepositoryExecutableNativeLoaderNestedTargetRequirement,
) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_REQUIREMENT_TYPE
        or type(value.kind) is not str
        or value.kind != _FIXED_REQUIREMENT_KIND
        or not all(
            _BUILTIN_IS_DIGEST(item)
            for item in (
                value.target_staged_file_ref,
                value.target_runtime_file_ref,
                value.target_loader_requirement_ref,
                value.nested_target_requirement_ref,
            )
        )
        or type(value.runtime_classification) is not str
        or value.runtime_classification not in _RUNTIME_CLASSIFICATIONS
        or type(value.loader_disposition) is not str
        or value.loader_disposition not in _LOADER_DISPOSITIONS
        or type(value.nested_target_disposition) is not str
        or value.nested_target_disposition not in _NESTED_TARGET_DISPOSITIONS
        or value.nested_target_disposition
        != _BUILTIN_NESTED_DISPOSITION(value.loader_disposition)
        or (
            value.loader_path_ref is not None
            and not _BUILTIN_IS_DIGEST(value.loader_path_ref)
        )
        or (
            value.nested_target_measurement_ref is not None
            and not _BUILTIN_IS_DIGEST(value.nested_target_measurement_ref)
        )
    ):
        raise _InvalidNestedNativeLoaderResolution
    declared = (
        value.nested_target_disposition
        == "declared_nested_loader_target_measured"
    )
    if declared != (
        value.loader_path_ref is not None
        and value.nested_target_measurement_ref is not None
    ) or (not declared and value.loader_path_ref is not None):
        raise _InvalidNestedNativeLoaderResolution
    reference = _BUILTIN_REQUIREMENT_REF_PROJECTION(
        target_staged_file_ref=value.target_staged_file_ref,
        target_runtime_file_ref=value.target_runtime_file_ref,
        target_loader_requirement_ref=value.target_loader_requirement_ref,
        runtime_classification=value.runtime_classification,
        loader_disposition=value.loader_disposition,
        nested_target_disposition=value.nested_target_disposition,
        loader_path_ref=value.loader_path_ref,
        nested_target_measurement_ref=value.nested_target_measurement_ref,
    )
    if value.nested_target_requirement_ref != _BUILTIN_CANONICAL_DIGEST(
        reference
    ):
        raise _InvalidNestedNativeLoaderResolution
    return {
        **reference,
        "kind": value.kind,
        "nested_target_requirement_ref": value.nested_target_requirement_ref,
    }


_BUILTIN_REQUIREMENT_PROJECTION = _requirement_projection


def _lineage_ref_projection(
    *,
    staged_file_ref: str,
    runtime_file_ref: str,
    requirement_ref: str,
    target_requirement_ref: str,
    target_stage_requirement_ref: str,
    target_runtime_requirement_ref: str,
    target_runtime_file_ref: str | None,
    target_loader_requirement_ref: str | None,
    target_loader_lineage_ref: str,
    source_runtime_classification: str,
    disposition: str,
    nested_target_requirement_ref: str | None,
) -> dict[str, Any]:
    return {
        "disposition": disposition,
        "kind": (
            "repository_executable_native_loader_nested_target_lineage_ref"
        ),
        "nested_target_requirement_ref": nested_target_requirement_ref,
        "requirement_ref": requirement_ref,
        "runtime_file_ref": runtime_file_ref,
        "schema_version": _FIXED_SCHEMA_VERSION,
        "source_runtime_classification": source_runtime_classification,
        "staged_file_ref": staged_file_ref,
        "target_loader_lineage_ref": target_loader_lineage_ref,
        "target_loader_requirement_ref": target_loader_requirement_ref,
        "target_requirement_ref": target_requirement_ref,
        "target_runtime_file_ref": target_runtime_file_ref,
        "target_runtime_requirement_ref": target_runtime_requirement_ref,
        "target_stage_requirement_ref": target_stage_requirement_ref,
    }


_BUILTIN_LINEAGE_REF_PROJECTION = _lineage_ref_projection


def _lineage_projection(
    value: RepositoryExecutableNativeLoaderNestedTargetLineage,
) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_LINEAGE_TYPE
        or type(value.kind) is not str
        or value.kind != _FIXED_LINEAGE_KIND
        or not all(
            _BUILTIN_IS_DIGEST(item)
            for item in (
                value.staged_file_ref,
                value.runtime_file_ref,
                value.requirement_ref,
                value.target_requirement_ref,
                value.target_stage_requirement_ref,
                value.target_runtime_requirement_ref,
                value.target_loader_lineage_ref,
                value.nested_target_lineage_ref,
            )
        )
        or (
            value.target_runtime_file_ref is not None
            and not _BUILTIN_IS_DIGEST(value.target_runtime_file_ref)
        )
        or (
            value.target_loader_requirement_ref is not None
            and not _BUILTIN_IS_DIGEST(value.target_loader_requirement_ref)
        )
        or (
            value.nested_target_requirement_ref is not None
            and not _BUILTIN_IS_DIGEST(value.nested_target_requirement_ref)
        )
        or type(value.source_runtime_classification) is not str
        or value.source_runtime_classification not in _RUNTIME_CLASSIFICATIONS
        or type(value.disposition) is not str
        or value.disposition not in _LINEAGE_DISPOSITIONS
    ):
        raise _InvalidNestedNativeLoaderResolution
    bound = value.disposition == "nested_loader_requirement_bound"
    if bound:
        if (
            value.source_runtime_classification not in {"elf", "mach_o"}
            or value.target_runtime_file_ref is None
            or value.target_loader_requirement_ref is None
            or value.nested_target_requirement_ref is None
        ):
            raise _InvalidNestedNativeLoaderResolution
    elif any(
        item is not None
        for item in (
            value.target_runtime_file_ref,
            value.target_loader_requirement_ref,
            value.nested_target_requirement_ref,
        )
    ):
        raise _InvalidNestedNativeLoaderResolution
    if (
        value.disposition
        in {"loader_declaration_absent", "unsupported_native_layout"}
        and value.source_runtime_classification not in {"elf", "mach_o"}
    ) or (
        value.disposition == "non_native_not_applicable"
        and value.source_runtime_classification in {"elf", "mach_o"}
    ):
        raise _InvalidNestedNativeLoaderResolution
    reference = _BUILTIN_LINEAGE_REF_PROJECTION(
        staged_file_ref=value.staged_file_ref,
        runtime_file_ref=value.runtime_file_ref,
        requirement_ref=value.requirement_ref,
        target_requirement_ref=value.target_requirement_ref,
        target_stage_requirement_ref=value.target_stage_requirement_ref,
        target_runtime_requirement_ref=value.target_runtime_requirement_ref,
        target_runtime_file_ref=value.target_runtime_file_ref,
        target_loader_requirement_ref=value.target_loader_requirement_ref,
        target_loader_lineage_ref=value.target_loader_lineage_ref,
        source_runtime_classification=value.source_runtime_classification,
        disposition=value.disposition,
        nested_target_requirement_ref=value.nested_target_requirement_ref,
    )
    if value.nested_target_lineage_ref != _BUILTIN_CANONICAL_DIGEST(reference):
        raise _InvalidNestedNativeLoaderResolution
    return {
        **reference,
        "kind": value.kind,
        "nested_target_lineage_ref": value.nested_target_lineage_ref,
    }


_BUILTIN_LINEAGE_PROJECTION = _lineage_projection


def _binding_projection(
    value: RepositoryExecutableNativeLoaderNestedTargetBinding,
) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_BINDING_TYPE
        or type(value.kind) is not str
        or value.kind != _FIXED_BINDING_KIND
        or type(value.command_kind) is not str
        or value.command_kind not in _COMMAND_KINDS
        or type(value.command_id) is not str
        or _IDENTIFIER_PATTERN.fullmatch(value.command_id) is None
        or not all(
            _BUILTIN_IS_DIGEST(item)
            for item in (
                value.command_digest,
                value.staged_file_ref,
                value.runtime_file_ref,
                value.requirement_ref,
                value.target_requirement_ref,
                value.target_stage_requirement_ref,
                value.target_runtime_requirement_ref,
                value.target_loader_lineage_ref,
                value.nested_target_lineage_ref,
            )
        )
    ):
        raise _InvalidNestedNativeLoaderResolution
    return {
        "command_digest": value.command_digest,
        "command_id": value.command_id,
        "command_kind": value.command_kind,
        "kind": value.kind,
        "nested_target_lineage_ref": value.nested_target_lineage_ref,
        "requirement_ref": value.requirement_ref,
        "runtime_file_ref": value.runtime_file_ref,
        "staged_file_ref": value.staged_file_ref,
        "target_loader_lineage_ref": value.target_loader_lineage_ref,
        "target_requirement_ref": value.target_requirement_ref,
        "target_runtime_requirement_ref": value.target_runtime_requirement_ref,
        "target_stage_requirement_ref": value.target_stage_requirement_ref,
    }


_BUILTIN_BINDING_PROJECTION = _binding_projection


def _receipt_projection(
    value: RepositoryExecutableNativeLoaderNestedTargetResolutionReceipt,
) -> dict[str, Any]:
    digest_fields = (
        value.target_loader_requirements_receipt_digest,
        value.target_runtime_manifest_receipt_digest,
        value.target_staging_receipt_digest,
        value.target_resolution_receipt_digest,
        value.native_loader_requirements_receipt_digest,
        value.runtime_manifest_receipt_digest,
        value.staging_receipt_digest,
        value.registration_digest,
        value.repository_ref,
        value.verification_commands_digest,
        value.resolution_context_digest,
        value.source_staging_context_digest,
        value.first_loader_path_context_digest,
        value.target_staging_context_digest,
        value.nested_loader_path_context_digest,
        value.guard_context_digest,
    )
    count_fields = (
        value.declared_nested_target_requirement_count,
        value.no_nested_target_requirement_count,
        value.target_loader_lineage_count,
        value.no_target_lineage_count,
    )
    if (
        type(value) is not _FIXED_RECEIPT_TYPE
        or type(value.kind) is not str
        or value.kind != _FIXED_RECEIPT_KIND
        or type(value.schema_version) is not int
        or value.schema_version != _FIXED_SCHEMA_VERSION
        or type(value.measurement_source) is not str
        or value.measurement_source != _FIXED_MEASUREMENT_SOURCE
        or type(value.resolution_scope) is not str
        or value.resolution_scope != _FIXED_RESOLUTION_SCOPE
        or type(value.resolution_depth) is not int
        or value.resolution_depth != _FIXED_RESOLUTION_DEPTH
        or type(value.maximum_resolution_depth) is not int
        or value.maximum_resolution_depth != _FIXED_MAXIMUM_RESOLUTION_DEPTH
        or type(value.cycle_scope) is not str
        or value.cycle_scope != _FIXED_CYCLE_SCOPE
        or not all(_BUILTIN_IS_DIGEST(item) for item in digest_fields)
        or type(value.measurements) is not tuple
        or not 0 <= len(value.measurements) <= _MAX_TARGET_PATHS
        or type(value.requirements) is not tuple
        or not 0 <= len(value.requirements) <= _MAX_REQUIREMENTS
        or type(value.lineages) is not tuple
        or not 1 <= len(value.lineages) <= _MAX_LINEAGES
        or type(value.bindings) is not tuple
        or not 1 <= len(value.bindings) <= _MAX_COMMANDS
        or type(value.requirement_count) is not int
        or value.requirement_count != len(value.requirements)
        or type(value.lineage_count) is not int
        or value.lineage_count != len(value.lineages)
        or type(value.command_count) is not int
        or value.command_count != len(value.bindings)
        or any(type(item) is not int or item < 0 for item in count_fields)
        or type(value.unique_nested_target_count) is not int
        or value.unique_nested_target_count != len(value.measurements)
        or type(value.total_measured_bytes) is not int
        or not 0 <= value.total_measured_bytes <= _MAX_TOTAL_TARGET_BYTES
    ):
        raise _InvalidNestedNativeLoaderResolution

    measurements = [
        _BUILTIN_MEASUREMENT_PROJECTION(item) for item in value.measurements
    ]
    requirements = [
        _BUILTIN_REQUIREMENT_PROJECTION(item) for item in value.requirements
    ]
    lineages = [
        _BUILTIN_LINEAGE_PROJECTION(item) for item in value.lineages
    ]
    bindings = [
        _BUILTIN_BINDING_PROJECTION(item) for item in value.bindings
    ]

    measurement_by_ref: dict[
        str, RepositoryExecutableNativeLoaderNestedTargetMeasurement
    ] = {}
    path_refs: set[str] = set()
    identity_refs: set[str] = set()
    total_bytes = 0
    for item in value.measurements:
        if (
            item.nested_target_measurement_ref in measurement_by_ref
            or item.path_ref in path_refs
            or item.filesystem_identity_ref in identity_refs
        ):
            raise _InvalidNestedNativeLoaderResolution
        measurement_by_ref[item.nested_target_measurement_ref] = item
        path_refs.add(item.path_ref)
        identity_refs.add(item.filesystem_identity_ref)
        total_bytes += item.content_bytes

    requirement_by_ref: dict[
        str, RepositoryExecutableNativeLoaderNestedTargetRequirement
    ] = {}
    loader_requirement_refs: set[str] = set()
    used_measurements: list[str] = []
    used_measurement_set: set[str] = set()
    declared_count = 0
    for item in value.requirements:
        if (
            item.nested_target_requirement_ref in requirement_by_ref
            or item.target_loader_requirement_ref in loader_requirement_refs
        ):
            raise _InvalidNestedNativeLoaderResolution
        requirement_by_ref[item.nested_target_requirement_ref] = item
        loader_requirement_refs.add(item.target_loader_requirement_ref)
        measurement_ref = item.nested_target_measurement_ref
        if measurement_ref is not None:
            declared_count += 1
            if measurement_ref not in measurement_by_ref:
                raise _InvalidNestedNativeLoaderResolution
            if measurement_ref not in used_measurement_set:
                used_measurements.append(measurement_ref)
            used_measurement_set.add(measurement_ref)

    lineage_by_ref: dict[
        str, RepositoryExecutableNativeLoaderNestedTargetLineage
    ] = {}
    loader_lineage_refs: set[str] = set()
    used_requirements: list[str] = []
    used_requirement_set: set[str] = set()
    bound_count = 0
    no_target_count = 0
    for item in value.lineages:
        if (
            item.nested_target_lineage_ref in lineage_by_ref
            or item.target_loader_lineage_ref in loader_lineage_refs
        ):
            raise _InvalidNestedNativeLoaderResolution
        lineage_by_ref[item.nested_target_lineage_ref] = item
        loader_lineage_refs.add(item.target_loader_lineage_ref)
        if item.disposition == "nested_loader_requirement_bound":
            bound_count += 1
            requirement_ref = item.nested_target_requirement_ref
            if requirement_ref is None or requirement_ref not in requirement_by_ref:
                raise _InvalidNestedNativeLoaderResolution
            requirement = requirement_by_ref[requirement_ref]
            if (
                item.target_loader_requirement_ref
                != requirement.target_loader_requirement_ref
                or item.target_runtime_file_ref
                != requirement.target_runtime_file_ref
            ):
                raise _InvalidNestedNativeLoaderResolution
            if requirement_ref not in used_requirement_set:
                used_requirements.append(requirement_ref)
            used_requirement_set.add(requirement_ref)
        else:
            no_target_count += 1

    command_ids: set[str] = set()
    bound_lineages: list[str] = []
    bound_lineage_set: set[str] = set()
    prior_kind_index = -1
    for item in value.bindings:
        lineage = lineage_by_ref.get(item.nested_target_lineage_ref)
        kind_index = _COMMAND_KINDS.index(item.command_kind)
        if (
            lineage is None
            or item.staged_file_ref != lineage.staged_file_ref
            or item.runtime_file_ref != lineage.runtime_file_ref
            or item.requirement_ref != lineage.requirement_ref
            or item.target_requirement_ref != lineage.target_requirement_ref
            or item.target_stage_requirement_ref
            != lineage.target_stage_requirement_ref
            or item.target_runtime_requirement_ref
            != lineage.target_runtime_requirement_ref
            or item.target_loader_lineage_ref
            != lineage.target_loader_lineage_ref
            or item.command_id in command_ids
            or kind_index < prior_kind_index
        ):
            raise _InvalidNestedNativeLoaderResolution
        command_ids.add(item.command_id)
        if item.nested_target_lineage_ref not in bound_lineage_set:
            bound_lineages.append(item.nested_target_lineage_ref)
        bound_lineage_set.add(item.nested_target_lineage_ref)
        prior_kind_index = kind_index

    if (
        used_measurement_set != set(measurement_by_ref)
        or tuple(used_measurements)
        != tuple(
            item.nested_target_measurement_ref for item in value.measurements
        )
        or used_requirement_set != set(requirement_by_ref)
        or tuple(used_requirements)
        != tuple(
            item.nested_target_requirement_ref for item in value.requirements
        )
        or bound_lineage_set != set(lineage_by_ref)
        or tuple(bound_lineages)
        != tuple(item.nested_target_lineage_ref for item in value.lineages)
        or declared_count != value.declared_nested_target_requirement_count
        or value.no_nested_target_requirement_count
        != value.requirement_count - declared_count
        or bound_count != value.target_loader_lineage_count
        or no_target_count != value.no_target_lineage_count
        or bound_count + no_target_count != value.lineage_count
        or total_bytes != value.total_measured_bytes
        or (value.requirement_count == 0 and bound_count != 0)
        or (value.requirement_count > 0 and bound_count == 0)
        or value.nested_loader_path_context_digest
        != _BUILTIN_CANONICAL_DIGEST(
            {
                "cycle_scope": _FIXED_CYCLE_SCOPE,
                "kind": (
                    "repository_executable_native_loader_nested_target_"
                    "path_context"
                ),
                "maximum_resolution_depth": _FIXED_MAXIMUM_RESOLUTION_DEPTH,
                "ordered_nested_target_path_refs": [
                    item.path_ref for item in value.measurements
                ],
                "resolution_depth": _FIXED_RESOLUTION_DEPTH,
                "resolution_scope": _FIXED_RESOLUTION_SCOPE,
                "schema_version": _FIXED_SCHEMA_VERSION,
            }
        )
    ):
        raise _InvalidNestedNativeLoaderResolution

    return {
        "bindings": bindings,
        "command_count": value.command_count,
        "cycle_scope": value.cycle_scope,
        "declared_nested_target_requirement_count": (
            value.declared_nested_target_requirement_count
        ),
        "first_loader_path_context_digest": (
            value.first_loader_path_context_digest
        ),
        "guard_context_digest": value.guard_context_digest,
        "kind": value.kind,
        "lineage_count": value.lineage_count,
        "lineages": lineages,
        "maximum_resolution_depth": value.maximum_resolution_depth,
        "measurement_source": value.measurement_source,
        "measurements": measurements,
        "native_loader_requirements_receipt_digest": (
            value.native_loader_requirements_receipt_digest
        ),
        "nested_loader_path_context_digest": (
            value.nested_loader_path_context_digest
        ),
        "no_nested_target_requirement_count": (
            value.no_nested_target_requirement_count
        ),
        "no_target_lineage_count": value.no_target_lineage_count,
        "registration_digest": value.registration_digest,
        "repository_ref": value.repository_ref,
        "requirement_count": value.requirement_count,
        "requirements": requirements,
        "resolution_context_digest": value.resolution_context_digest,
        "resolution_depth": value.resolution_depth,
        "resolution_scope": value.resolution_scope,
        "runtime_manifest_receipt_digest": (
            value.runtime_manifest_receipt_digest
        ),
        "schema_version": value.schema_version,
        "source_staging_context_digest": value.source_staging_context_digest,
        "staging_receipt_digest": value.staging_receipt_digest,
        "target_loader_lineage_count": value.target_loader_lineage_count,
        "target_loader_requirements_receipt_digest": (
            value.target_loader_requirements_receipt_digest
        ),
        "target_resolution_receipt_digest": (
            value.target_resolution_receipt_digest
        ),
        "target_runtime_manifest_receipt_digest": (
            value.target_runtime_manifest_receipt_digest
        ),
        "target_staging_context_digest": value.target_staging_context_digest,
        "target_staging_receipt_digest": value.target_staging_receipt_digest,
        "total_measured_bytes": value.total_measured_bytes,
        "unique_nested_target_count": value.unique_nested_target_count,
        "verification_commands_digest": value.verification_commands_digest,
    }


_BUILTIN_RECEIPT_PROJECTION = _receipt_projection


def _evidence_projection(
    value: RepositoryExecutableNativeLoaderNestedTargetResolutionReceipt,
) -> dict[str, Any]:
    canonical = _BUILTIN_RECEIPT_PROJECTION(value)
    measured = bool(value.unique_nested_target_count)
    return {
        "action_receipt_issued": False,
        "active_target_stage_lease_verified_at_measurement": True,
        "authority_granted": False,
        "authorization_verified": False,
        "billing_eligible": False,
        "capacity_eligible": False,
        "circuit_eligible": False,
        "command_count": value.command_count,
        "current_first_target_freshness_verified": False,
        "current_lease_activity_verified": False,
        "current_nested_target_freshness_verified": False,
        "cycle_scope": value.cycle_scope,
        "declared_nested_target_requirement_count": (
            value.declared_nested_target_requirement_count
        ),
        "dependency_closure_verified": False,
        "dispatch_enabled": False,
        "durable_control_plane_persistence_enabled": False,
        "dynamic_loader_authenticity_verified": False,
        "dynamic_loader_identity_verified": False,
        "effect_class": 0,
        "exact_nested_target_path_lookup_performed": measured,
        "execution_enabled": False,
        "fat_mach_o_architecture_selection_performed": False,
        "future_execution_correspondence_verified": False,
        "harness_invocation_performed": False,
        "immediate_target_identity_reentry_excluded": True,
        "immediate_target_path_reentry_excluded": True,
        "kind": _FIXED_EVIDENCE_KIND,
        "lease_cleanup_performed": False,
        "lease_mutated": False,
        "lineage_count": value.lineage_count,
        "live_execution_eligible": False,
        "loader_invocation_performed": False,
        "maximum_resolution_depth": value.maximum_resolution_depth,
        "measurement_source": value.measurement_source,
        "model_invocation_performed": False,
        "nested_target_namespace_reopen_verified": measured,
        "network_access_performed": False,
        "no_nested_target_requirement_count": (
            value.no_nested_target_requirement_count
        ),
        "no_target_lineage_count": value.no_target_lineage_count,
        "path_lookup_performed": measured,
        "proposal_lineage_extended": False,
        "receipt_authenticity_verified": False,
        "receipt_digest": _BUILTIN_CANONICAL_DIGEST(canonical),
        "recursive_native_loader_resolution_verified": False,
        "registration_digest": value.registration_digest,
        "repository_ref": value.repository_ref,
        "requirement_count": value.requirement_count,
        "resolution_depth": value.resolution_depth,
        "resolution_scope": value.resolution_scope,
        "route_eligible": False,
        "schema_version": value.schema_version,
        "sequential_nested_target_measurement_complete": True,
        "shared_library_closure_verified": False,
        "source_path_reentry_exclusion_verified": False,
        "source_staging_root_reentry_exclusion_verified": False,
        "staged_byte_correspondence_verified": True,
        "subprocess_invocation_performed": False,
        "target_loader_lineage_count": value.target_loader_lineage_count,
        "target_staging_root_reentry_excluded": True,
        "toolchain_completeness_verified": False,
        "total_measured_bytes": value.total_measured_bytes,
        "two_pass_nested_target_measurement_verified": True,
        "unique_nested_target_count": value.unique_nested_target_count,
        "validation_mode": "read_only",
        "worker_authorized": False,
        "worktree_integration_enabled": False,
    }


_BUILTIN_EVIDENCE_PROJECTION = _evidence_projection


@dataclass(frozen=True, slots=True)
class _DerivedNestedRequirement:
    upstream: dict[str, Any] = field(repr=False)
    nested_target_path: Path | None = field(repr=False)


_FIXED_DERIVED_TYPE = _DerivedNestedRequirement


def _validated_paths(values: Any) -> tuple[tuple[Path, bytes], ...]:
    if type(values) is not tuple or len(values) > _MAX_TARGET_PATHS:
        raise _InvalidNestedNativeLoaderResolution
    result: list[tuple[Path, bytes]] = []
    spellings: set[str] = set()
    total_bytes = 0
    for value in values:
        if type(value) is not _CONCRETE_PATH_TYPE:
            raise _InvalidNestedNativeLoaderResolution
        path, encoded = _BUILTIN_VALIDATE_ABSOLUTE_PATH(value)
        spelling = os.fspath(path)
        if spelling in spellings:
            raise _InvalidNestedNativeLoaderResolution
        spellings.add(spelling)
        total_bytes += len(encoded)
        if (
            len(encoded) > _MAX_TARGET_PATH_BYTES
            or total_bytes > _MAX_TOTAL_TARGET_PATH_BYTES
        ):
            raise _InvalidNestedNativeLoaderResolution
        result.append((path, encoded))
    return tuple(result)


_BUILTIN_VALIDATED_PATHS = _validated_paths


def _nested_path_ref(path: Path) -> str:
    validated = _BUILTIN_VALIDATED_PATHS((path,))
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "kind": (
                "repository_executable_native_loader_nested_target_path_ref"
            ),
            "resolution_depth": _FIXED_RESOLUTION_DEPTH,
            "resolution_scope": _FIXED_RESOLUTION_SCOPE,
            "schema_version": _FIXED_SCHEMA_VERSION,
            "target_path_ascii": validated[0][1].decode("ascii"),
        }
    )


_BUILTIN_NESTED_PATH_REF = _nested_path_ref


def _nested_path_context_digest(paths: tuple[Path, ...]) -> str:
    if type(paths) is not tuple:
        raise _InvalidNestedNativeLoaderResolution
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "cycle_scope": _FIXED_CYCLE_SCOPE,
            "kind": (
                "repository_executable_native_loader_nested_target_"
                "path_context"
            ),
            "maximum_resolution_depth": _FIXED_MAXIMUM_RESOLUTION_DEPTH,
            "ordered_nested_target_path_refs": [
                _BUILTIN_NESTED_PATH_REF(path) for path in paths
            ],
            "resolution_depth": _FIXED_RESOLUTION_DEPTH,
            "resolution_scope": _FIXED_RESOLUTION_SCOPE,
            "schema_version": _FIXED_SCHEMA_VERSION,
        }
    )


_BUILTIN_NESTED_PATH_CONTEXT_DIGEST = _nested_path_context_digest


def _declaration_kind(disposition: str) -> str:
    if disposition == "elf_interpreter_declared":
        return "elf_pt_interp"
    if disposition == "mach_o_dylinker_declared":
        return "mach_o_lc_load_dylinker"
    raise _InvalidNestedNativeLoaderResolution


_BUILTIN_DECLARATION_KIND = _declaration_kind


def _expected_loader_path_ref(
    requirement: dict[str, Any],
    *,
    encoded: bytes,
) -> str:
    if (
        type(requirement) is not dict
        or requirement.get("format_class") not in _FORMAT_CLASSES
        or type(encoded) is not bytes
    ):
        raise _InvalidNestedNativeLoaderResolution
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "declaration_kind": _BUILTIN_DECLARATION_KIND(
                requirement["disposition"]
            ),
            "format_class": requirement["format_class"],
            "kind": "repository_executable_native_loader_path_ref",
            "loader_path_hex": encoded.hex(),
            "runtime_file_ref": requirement["target_runtime_file_ref"],
            "schema_version": 1,
        }
    )


_BUILTIN_EXPECTED_LOADER_PATH_REF = _expected_loader_path_ref


def _validate_first_loader_paths(
    resolution_canonical: dict[str, Any],
    staging_canonical: dict[str, Any],
    expected_loader_paths: Any,
) -> tuple[Path, ...]:
    validated = _BUILTIN_VALIDATED_PATHS(expected_loader_paths)
    paths = tuple(path for path, _encoded in validated)
    expected_refs = tuple(
        _BUILTIN_FIRST_LOADER_PATH_REF(path) for path in paths
    )
    resolution_refs = tuple(
        item["path_ref"] for item in resolution_canonical["measurements"]
    )
    staged_refs = tuple(
        item["target_path_ref"] for item in staging_canonical["staged_files"]
    )
    if (
        expected_refs != resolution_refs
        or expected_refs != staged_refs
        or resolution_canonical["loader_path_context_digest"]
        != _BUILTIN_FIRST_LOADER_PATH_CONTEXT_DIGEST(paths)
    ):
        raise _InvalidNestedNativeLoaderResolution
    return paths


_BUILTIN_VALIDATE_FIRST_LOADER_PATHS = _validate_first_loader_paths


def _derive_nested_requirements(
    requirements_canonical: dict[str, Any],
    expected_nested_loader_paths: Any,
    *,
    first_loader_paths: tuple[Path, ...],
) -> tuple[tuple[_DerivedNestedRequirement, ...], tuple[Path, ...]]:
    validated = _BUILTIN_VALIDATED_PATHS(expected_nested_loader_paths)
    first_spellings = {os.fspath(path) for path in first_loader_paths}
    if any(os.fspath(path) in first_spellings for path, _encoded in validated):
        raise _InvalidNestedNativeLoaderResolution
    used_paths: list[Path] = []
    used_spellings: set[str] = set()
    derived: list[_DerivedNestedRequirement] = []
    for requirement in requirements_canonical["requirements"]:
        if type(requirement) is not dict:
            raise _InvalidNestedNativeLoaderResolution
        target_path: Path | None = None
        loader_ref = requirement["loader_path_ref"]
        if loader_ref is not None:
            matches = [
                path
                for path, encoded in validated
                if len(encoded) == requirement["loader_path_bytes"]
                and _BUILTIN_EXPECTED_LOADER_PATH_REF(
                    requirement,
                    encoded=encoded,
                )
                == loader_ref
            ]
            if len(matches) != 1:
                raise _InvalidNestedNativeLoaderResolution
            target_path = matches[0]
            spelling = os.fspath(target_path)
            if spelling not in used_spellings:
                used_paths.append(target_path)
                used_spellings.add(spelling)
        derived.append(
            _FIXED_DERIVED_TYPE(
                upstream=dict(requirement),
                nested_target_path=target_path,
            )
        )
    paths = tuple(path for path, _encoded in validated)
    if tuple(used_paths) != paths:
        raise _InvalidNestedNativeLoaderResolution
    return tuple(derived), paths


_BUILTIN_DERIVE_NESTED_REQUIREMENTS = _derive_nested_requirements


def _guard_context(
    resolution_canonical: dict[str, Any],
    staging_canonical: dict[str, Any],
    lease: RepositoryExecutableNativeLoaderTargetStageLease,
) -> tuple[_NestedTargetGuardContext, tuple[int, int] | None, str]:
    root_identity: tuple[int, int] | None = None
    if staging_canonical["staging_root_used"]:
        metadata = lease._root_metadata
        if (
            type(metadata) is not tuple
            or len(metadata) != 9
            or any(type(item) is not int for item in metadata)
        ):
            raise _InvalidNestedNativeLoaderResolution
        root_identity = (metadata[0], metadata[1])
    elif lease._root_metadata is not None:
        raise _InvalidNestedNativeLoaderResolution
    known_target_refs = frozenset(
        [
            item["filesystem_identity_ref"]
            for item in resolution_canonical["measurements"]
        ]
        + [
            item["staged_filesystem_identity_ref"]
            for item in staging_canonical["staged_files"]
        ]
    )
    expected_ref_count = (
        len(resolution_canonical["measurements"])
        + len(staging_canonical["staged_files"])
    )
    if len(known_target_refs) != expected_ref_count:
        raise _InvalidNestedNativeLoaderResolution
    roots = frozenset(() if root_identity is None else (root_identity,))
    context = _FIXED_GUARD_CONTEXT_TYPE(
        protected_root_identities=roots,
        known_source_identity_refs=frozenset(),
        known_target_identity_refs=known_target_refs,
    )
    digest = _BUILTIN_CANONICAL_DIGEST(
        {
            "kind": (
                "repository_executable_native_loader_nested_target_"
                "guard_context"
            ),
            "known_target_identity_refs": sorted(known_target_refs),
            "protected_root_identity_refs": [
                _BUILTIN_CANONICAL_DIGEST(
                    {
                        "device": identity[0],
                        "inode": identity[1],
                        "kind": (
                            "repository_executable_native_loader_target_"
                            "staging_root_identity"
                        ),
                        "schema_version": 1,
                    }
                )
                for identity in sorted(roots)
            ],
            "schema_version": _FIXED_SCHEMA_VERSION,
        }
    )
    return context, root_identity, digest


_BUILTIN_GUARD_CONTEXT = _guard_context


def _validated_chain_snapshot(
    expected_loader_requirements: (
        RepositoryExecutableNativeLoaderTargetLoaderRequirementsReceipt
    ),
    expected_target_runtime: (
        RepositoryExecutableNativeLoaderTargetRuntimeManifestReceipt
    ),
    expected_target_staging: (
        RepositoryExecutableNativeLoaderTargetStagingReceipt
    ),
    expected_target_resolution: (
        RepositoryExecutableNativeLoaderTargetResolutionReceipt
    ),
    lease: RepositoryExecutableNativeLoaderTargetStageLease,
    expected_loader_paths: Any,
    expected_nested_loader_paths: Any,
) -> tuple[
    tuple[_DerivedNestedRequirement, ...],
    tuple[Path, ...],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    tuple[Any, ...],
    _NestedTargetGuardContext,
    tuple[int, int] | None,
    str,
]:
    if (
        type(expected_loader_requirements)
        is not _FIXED_LOADER_REQUIREMENTS_TYPE
        or type(expected_target_runtime) is not _FIXED_TARGET_RUNTIME_TYPE
        or type(expected_target_staging) is not _FIXED_TARGET_STAGING_TYPE
        or type(expected_target_resolution)
        is not _FIXED_FIRST_TARGET_RESOLUTION_TYPE
        or type(lease) is not _FIXED_TARGET_STAGE_LEASE_TYPE
    ):
        raise _InvalidNestedNativeLoaderResolution
    requirements_canonical = _BUILTIN_LOADER_REQUIREMENTS_PROJECTION(
        expected_loader_requirements
    )
    runtime_canonical = _BUILTIN_TARGET_RUNTIME_PROJECTION(
        expected_target_runtime
    )
    staging_canonical = _BUILTIN_TARGET_STAGING_PROJECTION(
        expected_target_staging
    )
    resolution_canonical = _BUILTIN_FIRST_TARGET_RESOLUTION_PROJECTION(
        expected_target_resolution
    )
    requirements_digest = _BUILTIN_CANONICAL_DIGEST(
        requirements_canonical
    )
    runtime_digest = _BUILTIN_CANONICAL_DIGEST(runtime_canonical)
    staging_digest = _BUILTIN_CANONICAL_DIGEST(staging_canonical)
    resolution_digest = _BUILTIN_CANONICAL_DIGEST(resolution_canonical)
    if (
        requirements_canonical["target_runtime_manifest_receipt_digest"]
        != runtime_digest
        or requirements_canonical["target_staging_receipt_digest"]
        != staging_digest
        or runtime_canonical["target_staging_receipt_digest"]
        != staging_digest
        or requirements_canonical["target_resolution_receipt_digest"]
        != resolution_digest
        or runtime_canonical["target_resolution_receipt_digest"]
        != resolution_digest
        or not (
            staging_canonical[
                "expected_target_resolution_receipt_digest"
            ]
            == staging_canonical[
                "action_target_resolution_receipt_digest"
            ]
            == staging_canonical[
                "post_stage_target_resolution_receipt_digest"
            ]
            == resolution_digest
        )
    ):
        raise _InvalidNestedNativeLoaderResolution
    common_fields = (
        "native_loader_requirements_receipt_digest",
        "runtime_manifest_receipt_digest",
        "staging_receipt_digest",
        "registration_digest",
        "repository_ref",
        "verification_commands_digest",
        "resolution_context_digest",
        "source_staging_context_digest",
        "loader_path_context_digest",
        "target_staging_context_digest",
    )
    if any(
        requirements_canonical[field] != runtime_canonical[field]
        or requirements_canonical[field] != staging_canonical[field]
        for field in common_fields
    ) or any(
        resolution_canonical[field] != staging_canonical[field]
        for field in (
            "native_loader_requirements_receipt_digest",
            "runtime_manifest_receipt_digest",
            "staging_receipt_digest",
            "registration_digest",
            "repository_ref",
            "verification_commands_digest",
            "resolution_context_digest",
        )
    ) or (
        resolution_canonical["staging_context_digest"]
        != staging_canonical["source_staging_context_digest"]
    ) or (
        resolution_canonical["loader_path_context_digest"]
        != staging_canonical["loader_path_context_digest"]
    ):
        raise _InvalidNestedNativeLoaderResolution

    active_canonical, retained_files = (
        _BUILTIN_ACTIVE_TARGET_STAGE_SNAPSHOT(
            expected_target_staging,
            lease,
        )
    )
    if active_canonical != staging_canonical:
        raise _InvalidNestedNativeLoaderResolution
    fresh_requirements = _BUILTIN_INSPECT_LOADER_REQUIREMENTS(
        expected_target_runtime,
        expected_target_staging=expected_target_staging,
        lease=lease,
    )
    if (
        _BUILTIN_LOADER_REQUIREMENTS_PROJECTION(fresh_requirements)
        != requirements_canonical
    ):
        raise _InvalidNestedNativeLoaderResolution
    first_paths = _BUILTIN_VALIDATE_FIRST_LOADER_PATHS(
        resolution_canonical,
        staging_canonical,
        expected_loader_paths,
    )
    derived, nested_paths = _BUILTIN_DERIVE_NESTED_REQUIREMENTS(
        requirements_canonical,
        expected_nested_loader_paths,
        first_loader_paths=first_paths,
    )
    guard_context, root_identity, guard_digest = _BUILTIN_GUARD_CONTEXT(
        resolution_canonical,
        staging_canonical,
        lease,
    )
    if requirements_digest != expected_loader_requirements.receipt_digest:
        raise _InvalidNestedNativeLoaderResolution
    return (
        derived,
        nested_paths,
        requirements_canonical,
        runtime_canonical,
        staging_canonical,
        resolution_canonical,
        retained_files,
        guard_context,
        root_identity,
        guard_digest,
    )


_BUILTIN_VALIDATED_CHAIN_SNAPSHOT = _validated_chain_snapshot


def _public_measurement(
    measured: _MeasuredNestedTarget,
) -> RepositoryExecutableNativeLoaderNestedTargetMeasurement:
    if (
        type(measured) is not _FIXED_MEASURED_TARGET_TYPE
        or type(measured.path) is not str
        or type(measured.identity) is not tuple
        or len(measured.identity) != 2
        or any(type(item) is not int for item in measured.identity)
        or type(measured.metadata) is not tuple
        or len(measured.metadata) != 9
        or any(type(item) is not int for item in measured.metadata)
        or not _BUILTIN_IS_DIGEST(measured.content_digest)
        or type(measured.content_bytes) is not int
        or not 0 <= measured.content_bytes <= _MAX_TARGET_BYTES
    ):
        raise _InvalidNestedNativeLoaderResolution
    path = Path(measured.path)
    path_ref = _BUILTIN_NESTED_PATH_REF(path)
    identity_ref = _BUILTIN_CANONICAL_DIGEST(
        {
            "device": measured.identity[0],
            "inode": measured.identity[1],
            "kind": (
                "repository_executable_native_loader_nested_target_"
                "file_identity"
            ),
            "schema_version": _FIXED_SCHEMA_VERSION,
        }
    )
    metadata_digest = _BUILTIN_CANONICAL_DIGEST(
        {
            "change_time_ns": measured.metadata[8],
            "filesystem_identity_ref": identity_ref,
            "group_id": measured.metadata[5],
            "kind": (
                "repository_executable_native_loader_nested_target_"
                "file_metadata"
            ),
            "link_count": measured.metadata[3],
            "mode": measured.metadata[2],
            "modified_time_ns": measured.metadata[7],
            "owner_id": measured.metadata[4],
            "schema_version": _FIXED_SCHEMA_VERSION,
            "size_bytes": measured.metadata[6],
        }
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
        nested_target_measurement_ref=_BUILTIN_CANONICAL_DIGEST(reference),
    )
    _BUILTIN_MEASUREMENT_PROJECTION(value)
    return value


_BUILTIN_PUBLIC_MEASUREMENT = _public_measurement


def _public_requirement(
    derived: _DerivedNestedRequirement,
    *,
    measurement_by_path: dict[
        Path, RepositoryExecutableNativeLoaderNestedTargetMeasurement
    ],
) -> RepositoryExecutableNativeLoaderNestedTargetRequirement:
    if type(derived) is not _FIXED_DERIVED_TYPE:
        raise _InvalidNestedNativeLoaderResolution
    upstream = derived.upstream
    disposition = _BUILTIN_NESTED_DISPOSITION(upstream["disposition"])
    measurement_ref: str | None = None
    if derived.nested_target_path is not None:
        measurement = measurement_by_path.get(derived.nested_target_path)
        if measurement is None:
            raise _InvalidNestedNativeLoaderResolution
        measurement_ref = measurement.nested_target_measurement_ref
    elif disposition == "declared_nested_loader_target_measured":
        raise _InvalidNestedNativeLoaderResolution
    reference = _BUILTIN_REQUIREMENT_REF_PROJECTION(
        target_staged_file_ref=upstream["target_staged_file_ref"],
        target_runtime_file_ref=upstream["target_runtime_file_ref"],
        target_loader_requirement_ref=upstream[
            "target_loader_requirement_ref"
        ],
        runtime_classification=upstream["runtime_classification"],
        loader_disposition=upstream["disposition"],
        nested_target_disposition=disposition,
        loader_path_ref=upstream["loader_path_ref"],
        nested_target_measurement_ref=measurement_ref,
    )
    value = _FIXED_REQUIREMENT_TYPE(
        kind=_FIXED_REQUIREMENT_KIND,
        target_staged_file_ref=upstream["target_staged_file_ref"],
        target_runtime_file_ref=upstream["target_runtime_file_ref"],
        target_loader_requirement_ref=upstream[
            "target_loader_requirement_ref"
        ],
        runtime_classification=upstream["runtime_classification"],
        loader_disposition=upstream["disposition"],
        nested_target_disposition=disposition,
        loader_path_ref=upstream["loader_path_ref"],
        nested_target_measurement_ref=measurement_ref,
        nested_target_requirement_ref=_BUILTIN_CANONICAL_DIGEST(reference),
    )
    _BUILTIN_REQUIREMENT_PROJECTION(value)
    return value


_BUILTIN_PUBLIC_REQUIREMENT = _public_requirement


def _public_lineage(
    upstream: dict[str, Any],
    *,
    requirement_by_loader_ref: dict[
        str, RepositoryExecutableNativeLoaderNestedTargetRequirement
    ],
) -> RepositoryExecutableNativeLoaderNestedTargetLineage:
    if (
        type(upstream) is not dict
        or upstream.get("disposition") not in _UPSTREAM_LINEAGE_DISPOSITIONS
    ):
        raise _InvalidNestedNativeLoaderResolution
    if upstream["disposition"] == "target_loader_requirements_inspected":
        loader_ref = upstream["target_loader_requirement_ref"]
        requirement = requirement_by_loader_ref.get(loader_ref)
        if requirement is None:
            raise _InvalidNestedNativeLoaderResolution
        disposition = "nested_loader_requirement_bound"
        nested_requirement_ref = requirement.nested_target_requirement_ref
    else:
        disposition = upstream["disposition"]
        nested_requirement_ref = None
    reference = _BUILTIN_LINEAGE_REF_PROJECTION(
        staged_file_ref=upstream["staged_file_ref"],
        runtime_file_ref=upstream["runtime_file_ref"],
        requirement_ref=upstream["requirement_ref"],
        target_requirement_ref=upstream["target_requirement_ref"],
        target_stage_requirement_ref=upstream[
            "target_stage_requirement_ref"
        ],
        target_runtime_requirement_ref=upstream[
            "target_runtime_requirement_ref"
        ],
        target_runtime_file_ref=upstream["target_runtime_file_ref"],
        target_loader_requirement_ref=upstream[
            "target_loader_requirement_ref"
        ],
        target_loader_lineage_ref=upstream["target_loader_lineage_ref"],
        source_runtime_classification=upstream[
            "source_runtime_classification"
        ],
        disposition=disposition,
        nested_target_requirement_ref=nested_requirement_ref,
    )
    value = _FIXED_LINEAGE_TYPE(
        kind=_FIXED_LINEAGE_KIND,
        staged_file_ref=upstream["staged_file_ref"],
        runtime_file_ref=upstream["runtime_file_ref"],
        requirement_ref=upstream["requirement_ref"],
        target_requirement_ref=upstream["target_requirement_ref"],
        target_stage_requirement_ref=upstream[
            "target_stage_requirement_ref"
        ],
        target_runtime_requirement_ref=upstream[
            "target_runtime_requirement_ref"
        ],
        target_runtime_file_ref=upstream["target_runtime_file_ref"],
        target_loader_requirement_ref=upstream[
            "target_loader_requirement_ref"
        ],
        target_loader_lineage_ref=upstream["target_loader_lineage_ref"],
        source_runtime_classification=upstream[
            "source_runtime_classification"
        ],
        disposition=disposition,
        nested_target_requirement_ref=nested_requirement_ref,
        nested_target_lineage_ref=_BUILTIN_CANONICAL_DIGEST(reference),
    )
    _BUILTIN_LINEAGE_PROJECTION(value)
    return value


_BUILTIN_PUBLIC_LINEAGE = _public_lineage


def inspect_staged_executable_native_loader_nested_targets(
    expected_loader_requirements: (
        RepositoryExecutableNativeLoaderTargetLoaderRequirementsReceipt
    ),
    *,
    expected_target_runtime: (
        RepositoryExecutableNativeLoaderTargetRuntimeManifestReceipt
    ),
    expected_target_staging: (
        RepositoryExecutableNativeLoaderTargetStagingReceipt
    ),
    expected_target_resolution: (
        RepositoryExecutableNativeLoaderTargetResolutionReceipt
    ),
    lease: RepositoryExecutableNativeLoaderTargetStageLease,
    expected_loader_paths: tuple[Path, ...],
    expected_nested_loader_paths: tuple[Path, ...],
) -> RepositoryExecutableNativeLoaderNestedTargetResolutionReceipt:
    """Measure exactly one newly declared native-loader target hop."""

    try:
        _BUILTIN_REQUIRE_SUPPORTED_PLATFORM()
        first = _BUILTIN_VALIDATED_CHAIN_SNAPSHOT(
            expected_loader_requirements,
            expected_target_runtime,
            expected_target_staging,
            expected_target_resolution,
            lease,
            expected_loader_paths,
            expected_nested_loader_paths,
        )
        (
            derived,
            nested_paths,
            requirements_canonical,
            runtime_canonical,
            staging_canonical,
            resolution_canonical,
            retained_files,
            guard_context,
            root_identity,
            guard_digest,
        ) = first
        first_measurement = _BUILTIN_MEASURE_GUARDED_TARGET_SET(
            tuple(os.fspath(path) for path in nested_paths),
            protected_root_identity=root_identity,
            known_first_hop_identities=frozenset(),
            guard_context=guard_context,
        )

        middle = _BUILTIN_VALIDATED_CHAIN_SNAPSHOT(
            expected_loader_requirements,
            expected_target_runtime,
            expected_target_staging,
            expected_target_resolution,
            lease,
            expected_loader_paths,
            expected_nested_loader_paths,
        )
        if (
            middle[0] != derived
            or middle[1] != nested_paths
            or middle[2] != requirements_canonical
            or middle[3] != runtime_canonical
            or middle[4] != staging_canonical
            or middle[5] != resolution_canonical
            or middle[6] is not retained_files
            or middle[7] != guard_context
            or middle[8] != root_identity
            or middle[9] != guard_digest
        ):
            raise _InvalidNestedNativeLoaderResolution
        second_measurement = _BUILTIN_MEASURE_GUARDED_TARGET_SET(
            tuple(os.fspath(path) for path in nested_paths),
            protected_root_identity=root_identity,
            known_first_hop_identities=frozenset(),
            guard_context=guard_context,
        )
        if second_measurement != first_measurement:
            raise _InvalidNestedNativeLoaderResolution

        final = _BUILTIN_VALIDATED_CHAIN_SNAPSHOT(
            expected_loader_requirements,
            expected_target_runtime,
            expected_target_staging,
            expected_target_resolution,
            lease,
            expected_loader_paths,
            expected_nested_loader_paths,
        )
        if (
            final[0] != derived
            or final[1] != nested_paths
            or final[2] != requirements_canonical
            or final[3] != runtime_canonical
            or final[4] != staging_canonical
            or final[5] != resolution_canonical
            or final[6] is not retained_files
            or final[7] != guard_context
            or final[8] != root_identity
            or final[9] != guard_digest
        ):
            raise _InvalidNestedNativeLoaderResolution

        measurements = tuple(
            _BUILTIN_PUBLIC_MEASUREMENT(item) for item in first_measurement
        )
        measurement_by_path = {
            path: measurement
            for path, measurement in zip(
                nested_paths,
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
        requirement_by_loader_ref = {
            item.target_loader_requirement_ref: item for item in requirements
        }
        lineages = tuple(
            _BUILTIN_PUBLIC_LINEAGE(
                item,
                requirement_by_loader_ref=requirement_by_loader_ref,
            )
            for item in requirements_canonical["lineages"]
        )
        lineage_by_loader_ref = {
            item.target_loader_lineage_ref: item for item in lineages
        }
        bindings: list[
            RepositoryExecutableNativeLoaderNestedTargetBinding
        ] = []
        for upstream in requirements_canonical["bindings"]:
            lineage = lineage_by_loader_ref.get(
                upstream["target_loader_lineage_ref"]
            )
            if (
                lineage is None
                or upstream["staged_file_ref"] != lineage.staged_file_ref
                or upstream["runtime_file_ref"] != lineage.runtime_file_ref
                or upstream["requirement_ref"] != lineage.requirement_ref
                or upstream["target_requirement_ref"]
                != lineage.target_requirement_ref
                or upstream["target_stage_requirement_ref"]
                != lineage.target_stage_requirement_ref
                or upstream["target_runtime_requirement_ref"]
                != lineage.target_runtime_requirement_ref
            ):
                raise _InvalidNestedNativeLoaderResolution
            value = _FIXED_BINDING_TYPE(
                kind=_FIXED_BINDING_KIND,
                command_kind=upstream["command_kind"],
                command_id=upstream["command_id"],
                command_digest=upstream["command_digest"],
                staged_file_ref=upstream["staged_file_ref"],
                runtime_file_ref=upstream["runtime_file_ref"],
                requirement_ref=upstream["requirement_ref"],
                target_requirement_ref=upstream[
                    "target_requirement_ref"
                ],
                target_stage_requirement_ref=upstream[
                    "target_stage_requirement_ref"
                ],
                target_runtime_requirement_ref=upstream[
                    "target_runtime_requirement_ref"
                ],
                target_loader_lineage_ref=upstream[
                    "target_loader_lineage_ref"
                ],
                nested_target_lineage_ref=(
                    lineage.nested_target_lineage_ref
                ),
            )
            _BUILTIN_BINDING_PROJECTION(value)
            bindings.append(value)

        target_loader_lineage_count = sum(
            item.disposition == "nested_loader_requirement_bound"
            for item in lineages
        )
        receipt = _FIXED_RECEIPT_TYPE(
            kind=_FIXED_RECEIPT_KIND,
            schema_version=_FIXED_SCHEMA_VERSION,
            measurement_source=_FIXED_MEASUREMENT_SOURCE,
            resolution_scope=_FIXED_RESOLUTION_SCOPE,
            resolution_depth=_FIXED_RESOLUTION_DEPTH,
            maximum_resolution_depth=_FIXED_MAXIMUM_RESOLUTION_DEPTH,
            cycle_scope=_FIXED_CYCLE_SCOPE,
            target_loader_requirements_receipt_digest=(
                _BUILTIN_CANONICAL_DIGEST(requirements_canonical)
            ),
            target_runtime_manifest_receipt_digest=(
                _BUILTIN_CANONICAL_DIGEST(runtime_canonical)
            ),
            target_staging_receipt_digest=(
                _BUILTIN_CANONICAL_DIGEST(staging_canonical)
            ),
            target_resolution_receipt_digest=(
                _BUILTIN_CANONICAL_DIGEST(resolution_canonical)
            ),
            native_loader_requirements_receipt_digest=(
                requirements_canonical[
                    "native_loader_requirements_receipt_digest"
                ]
            ),
            runtime_manifest_receipt_digest=(
                requirements_canonical["runtime_manifest_receipt_digest"]
            ),
            staging_receipt_digest=(
                requirements_canonical["staging_receipt_digest"]
            ),
            registration_digest=requirements_canonical[
                "registration_digest"
            ],
            repository_ref=requirements_canonical["repository_ref"],
            verification_commands_digest=requirements_canonical[
                "verification_commands_digest"
            ],
            resolution_context_digest=requirements_canonical[
                "resolution_context_digest"
            ],
            source_staging_context_digest=requirements_canonical[
                "source_staging_context_digest"
            ],
            first_loader_path_context_digest=resolution_canonical[
                "loader_path_context_digest"
            ],
            target_staging_context_digest=requirements_canonical[
                "target_staging_context_digest"
            ],
            nested_loader_path_context_digest=(
                _BUILTIN_NESTED_PATH_CONTEXT_DIGEST(nested_paths)
            ),
            guard_context_digest=guard_digest,
            measurements=measurements,
            requirements=requirements,
            lineages=lineages,
            bindings=tuple(bindings),
            requirement_count=len(requirements),
            lineage_count=len(lineages),
            command_count=len(bindings),
            declared_nested_target_requirement_count=sum(
                item.nested_target_disposition
                == "declared_nested_loader_target_measured"
                for item in requirements
            ),
            no_nested_target_requirement_count=sum(
                item.nested_target_disposition
                != "declared_nested_loader_target_measured"
                for item in requirements
            ),
            target_loader_lineage_count=target_loader_lineage_count,
            no_target_lineage_count=(
                len(lineages) - target_loader_lineage_count
            ),
            unique_nested_target_count=len(measurements),
            total_measured_bytes=sum(
                item.content_bytes for item in measurements
            ),
        )
        _BUILTIN_RECEIPT_PROJECTION(receipt)
        closing_canonical, closing_files = (
            _BUILTIN_ACTIVE_TARGET_STAGE_SNAPSHOT(
                expected_target_staging,
                lease,
            )
        )
        if (
            closing_canonical != staging_canonical
            or closing_files is not retained_files
        ):
            raise _InvalidNestedNativeLoaderResolution
        return receipt
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise _FIXED_VALIDATION_ERROR(_INVALID_MESSAGE) from None


__all__ = [
    "CYCLE_SCOPE",
    "MAXIMUM_RESOLUTION_DEPTH",
    "MEASUREMENT_SOURCE",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_BINDING_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_LINEAGE_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_MEASUREMENT_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_REQUIREMENT_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RESOLUTION_EVIDENCE_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RESOLUTION_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RESOLUTION_SCHEMA_VERSION",
    "RESOLUTION_DEPTH",
    "RESOLUTION_SCOPE",
    "RepositoryExecutableNativeLoaderNestedTargetBinding",
    "RepositoryExecutableNativeLoaderNestedTargetLineage",
    "RepositoryExecutableNativeLoaderNestedTargetMeasurement",
    "RepositoryExecutableNativeLoaderNestedTargetRequirement",
    "RepositoryExecutableNativeLoaderNestedTargetResolutionReceipt",
    "inspect_staged_executable_native_loader_nested_targets",
]
