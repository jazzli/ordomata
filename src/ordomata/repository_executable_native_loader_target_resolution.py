"""Measure exact native-loader target files without resolving dependencies.

This Class 0 boundary consumes one exact native-loader requirements chain and
an exactly expected ordered set of canonical absolute paths.  Each path must
cryptographically reproduce a staged ELF ``PT_INTERP`` or thin Mach-O
``LC_LOAD_DYLINKER`` declaration before it is opened with no-follow traversal.
The files are measured only; no loader, shared library, process, or model is
invoked.
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
from .repository_executable_native_loader_requirements import (
    RepositoryExecutableNativeLoaderRequirement,
    RepositoryExecutableNativeLoaderRequirementBinding,
    RepositoryExecutableNativeLoaderRequirementsReceipt,
    _receipt_projection as _native_requirements_projection,
    _runtime_manifest_projection as _runtime_projection,
    _staging_receipt_projection as _staging_projection,
    inspect_staged_executable_native_loader_requirements,
)
from .repository_executable_runtime_manifest import (
    RepositoryExecutableRuntimeManifestReceipt,
    _active_stage_snapshot,
)
from .repository_executable_shebang_target_resolution import (
    _MeasuredTarget,
    _canonical_target_path_from_token as _canonical_target_path,
    _measure_target_set as _measure_target_set,
    _require_supported_platform as _require_supported_platform,
    _target_namespace_matches as _target_namespace_matches,
)
from .repository_executable_staging import (
    RepositoryExecutableStageLease,
    RepositoryExecutableStagingReceipt,
)


REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_RESOLUTION_SCHEMA_VERSION = 1
REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_RESOLUTION_KIND = (
    "repository_executable_native_loader_target_resolution"
)
REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_RESOLUTION_EVIDENCE_KIND = (
    "repository_executable_native_loader_target_resolution_validation"
)
REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_MEASUREMENT_KIND = (
    "repository_executable_native_loader_target_measurement"
)
REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_REQUIREMENT_KIND = (
    "repository_executable_native_loader_target_requirement"
)
REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_BINDING_KIND = (
    "repository_executable_native_loader_target_binding"
)
MEASUREMENT_SOURCE = "controller_measured"
RESOLUTION_SCOPE = "native_loader_declared_absolute_target_nofollow_v1"

_FIXED_SCHEMA_VERSION = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_RESOLUTION_SCHEMA_VERSION
)
_FIXED_RECEIPT_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_RESOLUTION_KIND
)
_FIXED_EVIDENCE_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_RESOLUTION_EVIDENCE_KIND
)
_FIXED_MEASUREMENT_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_MEASUREMENT_KIND
)
_FIXED_REQUIREMENT_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_REQUIREMENT_KIND
)
_FIXED_BINDING_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_BINDING_KIND
)
_FIXED_MEASUREMENT_SOURCE = MEASUREMENT_SOURCE
_FIXED_RESOLUTION_SCOPE = RESOLUTION_SCOPE

_INVALID_MESSAGE = (
    "repository executable native loader target resolution is invalid"
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
_TARGET_DISPOSITIONS = (
    "declared_loader_target_measured",
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
_MAX_FILES = 80
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
_BUILTIN_NATIVE_REQUIREMENTS_PROJECTION = _native_requirements_projection
_BUILTIN_RUNTIME_PROJECTION = _runtime_projection
_BUILTIN_STAGING_PROJECTION = _staging_projection
_BUILTIN_INSPECT_NATIVE_REQUIREMENTS = (
    inspect_staged_executable_native_loader_requirements
)
_BUILTIN_ACTIVE_STAGE_SNAPSHOT = _active_stage_snapshot
_BUILTIN_REQUIRE_SUPPORTED_PLATFORM = _require_supported_platform
_BUILTIN_CANONICAL_TARGET_PATH = _canonical_target_path
_BUILTIN_MEASURE_TARGET_SET = _measure_target_set
_BUILTIN_TARGET_NAMESPACE_MATCHES = _target_namespace_matches
_FIXED_NATIVE_REQUIREMENTS_TYPE = (
    RepositoryExecutableNativeLoaderRequirementsReceipt
)
_FIXED_RUNTIME_TYPE = RepositoryExecutableRuntimeManifestReceipt
_FIXED_STAGING_TYPE = RepositoryExecutableStagingReceipt
_FIXED_LEASE_TYPE = RepositoryExecutableStageLease
_FIXED_MEASURED_TARGET_TYPE = _MeasuredTarget
_FIXED_VALIDATION_ERROR = ValidationError


class _InvalidNativeLoaderTargetResolution(ValueError):
    """Private fail-closed sentinel whose details never cross the API."""


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeLoaderTargetMeasurement:
    """One exact declaration-bound target's point-in-time measurement."""

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
class RepositoryExecutableNativeLoaderTargetRequirement:
    """One upstream loader requirement's measured or no-target outcome."""

    kind: str
    staged_file_ref: str = field(repr=False)
    runtime_file_ref: str = field(repr=False)
    native_loader_requirement_ref: str = field(repr=False)
    runtime_classification: str
    loader_disposition: str
    target_disposition: str
    loader_path_ref: str | None = field(repr=False)
    target_measurement_ref: str | None = field(repr=False)
    target_requirement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_REQUIREMENT_PROJECTION(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeLoaderTargetBinding:
    """One registered command bound to one target requirement."""

    kind: str
    command_kind: str
    command_id: str = field(repr=False)
    command_digest: str = field(repr=False)
    staged_file_ref: str = field(repr=False)
    runtime_file_ref: str = field(repr=False)
    native_loader_requirement_ref: str = field(repr=False)
    target_requirement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_BINDING_PROJECTION(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeLoaderTargetResolutionReceipt:
    """Privacy-bounded historical evidence for exact loader-target reads."""

    kind: str
    schema_version: int
    measurement_source: str
    resolution_scope: str
    native_loader_requirements_receipt_digest: str = field(repr=False)
    runtime_manifest_receipt_digest: str = field(repr=False)
    staging_receipt_digest: str = field(repr=False)
    registration_digest: str = field(repr=False)
    repository_ref: str = field(repr=False)
    verification_commands_digest: str = field(repr=False)
    resolution_context_digest: str = field(repr=False)
    staging_context_digest: str = field(repr=False)
    loader_path_context_digest: str = field(repr=False)
    measurements: tuple[
        RepositoryExecutableNativeLoaderTargetMeasurement, ...
    ] = field(repr=False)
    requirements: tuple[
        RepositoryExecutableNativeLoaderTargetRequirement, ...
    ] = field(repr=False)
    bindings: tuple[
        RepositoryExecutableNativeLoaderTargetBinding, ...
    ] = field(repr=False)
    requirement_count: int
    command_count: int
    declared_target_requirement_count: int
    no_target_requirement_count: int
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


_FIXED_MEASUREMENT_TYPE = RepositoryExecutableNativeLoaderTargetMeasurement
_FIXED_REQUIREMENT_TYPE = RepositoryExecutableNativeLoaderTargetRequirement
_FIXED_BINDING_TYPE = RepositoryExecutableNativeLoaderTargetBinding
_FIXED_RECEIPT_TYPE = RepositoryExecutableNativeLoaderTargetResolutionReceipt


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
        "kind": "repository_executable_native_loader_target_measurement_ref",
        "measurement_source": _FIXED_MEASUREMENT_SOURCE,
        "metadata_digest": metadata_digest,
        "path_ref": path_ref,
        "resolution_scope": _FIXED_RESOLUTION_SCOPE,
        "schema_version": _FIXED_SCHEMA_VERSION,
    }


_BUILTIN_MEASUREMENT_REF_PROJECTION = _measurement_ref_projection


def _measurement_projection(
    value: RepositoryExecutableNativeLoaderTargetMeasurement,
) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_MEASUREMENT_TYPE
        or type(value.kind) is not str
        or value.kind != _FIXED_MEASUREMENT_KIND
        or not _BUILTIN_IS_DIGEST(value.path_ref)
        or not _BUILTIN_IS_DIGEST(value.filesystem_identity_ref)
        or not _BUILTIN_IS_DIGEST(value.metadata_digest)
        or not _BUILTIN_IS_DIGEST(value.content_digest)
        or type(value.content_bytes) is not int
        or not 0 <= value.content_bytes <= _MAX_TARGET_BYTES
        or not _BUILTIN_IS_DIGEST(value.measurement_ref)
    ):
        raise _InvalidNativeLoaderTargetResolution
    reference = _BUILTIN_MEASUREMENT_REF_PROJECTION(
        path_ref=value.path_ref,
        filesystem_identity_ref=value.filesystem_identity_ref,
        metadata_digest=value.metadata_digest,
        content_digest=value.content_digest,
        content_bytes=value.content_bytes,
    )
    if value.measurement_ref != _BUILTIN_CANONICAL_DIGEST(reference):
        raise _InvalidNativeLoaderTargetResolution
    return {**reference, "kind": value.kind, "measurement_ref": value.measurement_ref}


_BUILTIN_MEASUREMENT_PROJECTION = _measurement_projection


def _target_requirement_ref_projection(
    *,
    staged_file_ref: str,
    runtime_file_ref: str,
    native_loader_requirement_ref: str,
    runtime_classification: str,
    loader_disposition: str,
    target_disposition: str,
    loader_path_ref: str | None,
    target_measurement_ref: str | None,
) -> dict[str, Any]:
    return {
        "kind": "repository_executable_native_loader_target_requirement_ref",
        "loader_disposition": loader_disposition,
        "loader_path_ref": loader_path_ref,
        "native_loader_requirement_ref": native_loader_requirement_ref,
        "resolution_scope": _FIXED_RESOLUTION_SCOPE,
        "runtime_classification": runtime_classification,
        "runtime_file_ref": runtime_file_ref,
        "schema_version": _FIXED_SCHEMA_VERSION,
        "staged_file_ref": staged_file_ref,
        "target_disposition": target_disposition,
        "target_measurement_ref": target_measurement_ref,
    }


_BUILTIN_TARGET_REQUIREMENT_REF_PROJECTION = (
    _target_requirement_ref_projection
)


def _expected_target_disposition(loader_disposition: str) -> str:
    if loader_disposition in {
        "elf_interpreter_declared",
        "mach_o_dylinker_declared",
    }:
        return "declared_loader_target_measured"
    if loader_disposition in {
        "elf_interpreter_absent",
        "mach_o_dylinker_absent",
    }:
        return "loader_declaration_absent"
    if loader_disposition == "unsupported_native_layout":
        return "unsupported_native_layout"
    if loader_disposition == "non_native_not_applicable":
        return "non_native_not_applicable"
    raise _InvalidNativeLoaderTargetResolution


_BUILTIN_EXPECTED_TARGET_DISPOSITION = _expected_target_disposition


def _loader_disposition_matches_classification(
    loader_disposition: str,
    runtime_classification: str,
) -> bool:
    if loader_disposition.startswith("elf_"):
        return runtime_classification == "elf"
    if loader_disposition.startswith("mach_o_"):
        return runtime_classification == "mach_o"
    if loader_disposition == "unsupported_native_layout":
        return runtime_classification in {"elf", "mach_o"}
    if loader_disposition == "non_native_not_applicable":
        return runtime_classification not in {"elf", "mach_o"}
    return False


_BUILTIN_LOADER_DISPOSITION_MATCHES_CLASSIFICATION = (
    _loader_disposition_matches_classification
)


def _requirement_projection(
    value: RepositoryExecutableNativeLoaderTargetRequirement,
) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_REQUIREMENT_TYPE
        or type(value.kind) is not str
        or value.kind != _FIXED_REQUIREMENT_KIND
        or not _BUILTIN_IS_DIGEST(value.staged_file_ref)
        or not _BUILTIN_IS_DIGEST(value.runtime_file_ref)
        or not _BUILTIN_IS_DIGEST(value.native_loader_requirement_ref)
        or type(value.runtime_classification) is not str
        or value.runtime_classification not in _RUNTIME_CLASSIFICATIONS
        or type(value.loader_disposition) is not str
        or value.loader_disposition not in _LOADER_DISPOSITIONS
        or not _BUILTIN_LOADER_DISPOSITION_MATCHES_CLASSIFICATION(
            value.loader_disposition,
            value.runtime_classification,
        )
        or type(value.target_disposition) is not str
        or value.target_disposition not in _TARGET_DISPOSITIONS
        or value.target_disposition
        != _BUILTIN_EXPECTED_TARGET_DISPOSITION(value.loader_disposition)
        or (
            value.loader_path_ref is not None
            and not _BUILTIN_IS_DIGEST(value.loader_path_ref)
        )
        or (
            value.target_measurement_ref is not None
            and not _BUILTIN_IS_DIGEST(value.target_measurement_ref)
        )
        or not _BUILTIN_IS_DIGEST(value.target_requirement_ref)
    ):
        raise _InvalidNativeLoaderTargetResolution
    measured = value.target_disposition == "declared_loader_target_measured"
    if (
        measured
        and (
            value.loader_path_ref is None
            or value.target_measurement_ref is None
        )
    ) or (
        not measured
        and (
            value.loader_path_ref is not None
            or value.target_measurement_ref is not None
        )
    ):
        raise _InvalidNativeLoaderTargetResolution
    reference = _BUILTIN_TARGET_REQUIREMENT_REF_PROJECTION(
        staged_file_ref=value.staged_file_ref,
        runtime_file_ref=value.runtime_file_ref,
        native_loader_requirement_ref=value.native_loader_requirement_ref,
        runtime_classification=value.runtime_classification,
        loader_disposition=value.loader_disposition,
        target_disposition=value.target_disposition,
        loader_path_ref=value.loader_path_ref,
        target_measurement_ref=value.target_measurement_ref,
    )
    if value.target_requirement_ref != _BUILTIN_CANONICAL_DIGEST(reference):
        raise _InvalidNativeLoaderTargetResolution
    return {
        **reference,
        "kind": value.kind,
        "target_requirement_ref": value.target_requirement_ref,
    }


_BUILTIN_REQUIREMENT_PROJECTION = _requirement_projection


def _binding_projection(
    value: RepositoryExecutableNativeLoaderTargetBinding,
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
                value.native_loader_requirement_ref,
                value.target_requirement_ref,
            )
        )
    ):
        raise _InvalidNativeLoaderTargetResolution
    return {
        "command_digest": value.command_digest,
        "command_id": value.command_id,
        "command_kind": value.command_kind,
        "kind": value.kind,
        "native_loader_requirement_ref": value.native_loader_requirement_ref,
        "runtime_file_ref": value.runtime_file_ref,
        "staged_file_ref": value.staged_file_ref,
        "target_requirement_ref": value.target_requirement_ref,
    }


_BUILTIN_BINDING_PROJECTION = _binding_projection


def _receipt_projection(
    value: RepositoryExecutableNativeLoaderTargetResolutionReceipt,
) -> dict[str, Any]:
    digest_fields = (
        value.native_loader_requirements_receipt_digest,
        value.runtime_manifest_receipt_digest,
        value.staging_receipt_digest,
        value.registration_digest,
        value.repository_ref,
        value.verification_commands_digest,
        value.resolution_context_digest,
        value.staging_context_digest,
        value.loader_path_context_digest,
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
        or type(value.declared_target_requirement_count) is not int
        or type(value.no_target_requirement_count) is not int
        or type(value.unique_target_count) is not int
        or value.unique_target_count != len(value.measurements)
        or type(value.total_measured_bytes) is not int
        or not 0 <= value.total_measured_bytes <= _MAX_TOTAL_TARGET_BYTES
    ):
        raise _InvalidNativeLoaderTargetResolution

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
        str, RepositoryExecutableNativeLoaderTargetMeasurement
    ] = {}
    path_refs: set[str] = set()
    identity_refs: set[str] = set()
    total_measured_bytes = 0
    for measurement in value.measurements:
        if (
            measurement.measurement_ref in measurement_by_ref
            or measurement.path_ref in path_refs
            or measurement.filesystem_identity_ref in identity_refs
        ):
            raise _InvalidNativeLoaderTargetResolution
        measurement_by_ref[measurement.measurement_ref] = measurement
        path_refs.add(measurement.path_ref)
        identity_refs.add(measurement.filesystem_identity_ref)
        total_measured_bytes += measurement.content_bytes

    requirement_by_native_ref: dict[
        str, RepositoryExecutableNativeLoaderTargetRequirement
    ] = {}
    staged_refs: set[str] = set()
    runtime_refs: set[str] = set()
    target_requirement_refs: set[str] = set()
    used_measurement_refs: set[str] = set()
    ordered_measurement_refs: list[str] = []
    for requirement in value.requirements:
        if (
            requirement.native_loader_requirement_ref
            in requirement_by_native_ref
            or requirement.staged_file_ref in staged_refs
            or requirement.runtime_file_ref in runtime_refs
            or requirement.target_requirement_ref in target_requirement_refs
        ):
            raise _InvalidNativeLoaderTargetResolution
        requirement_by_native_ref[
            requirement.native_loader_requirement_ref
        ] = requirement
        staged_refs.add(requirement.staged_file_ref)
        runtime_refs.add(requirement.runtime_file_ref)
        target_requirement_refs.add(requirement.target_requirement_ref)
        measurement_ref = requirement.target_measurement_ref
        if measurement_ref is not None:
            if measurement_ref not in measurement_by_ref:
                raise _InvalidNativeLoaderTargetResolution
            if measurement_ref not in used_measurement_refs:
                ordered_measurement_refs.append(measurement_ref)
            used_measurement_refs.add(measurement_ref)

    command_ids: set[str] = set()
    bound_target_refs: set[str] = set()
    ordered_bound_target_refs: list[str] = []
    prior_kind_index = -1
    for binding in value.bindings:
        requirement = requirement_by_native_ref.get(
            binding.native_loader_requirement_ref
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
            raise _InvalidNativeLoaderTargetResolution
        command_ids.add(binding.command_id)
        if binding.target_requirement_ref not in bound_target_refs:
            ordered_bound_target_refs.append(binding.target_requirement_ref)
        bound_target_refs.add(binding.target_requirement_ref)
        prior_kind_index = kind_index

    declared_count = sum(
        item.target_disposition == "declared_loader_target_measured"
        for item in value.requirements
    )
    if (
        used_measurement_refs != set(measurement_by_ref)
        or tuple(ordered_measurement_refs)
        != tuple(item.measurement_ref for item in value.measurements)
        or bound_target_refs != target_requirement_refs
        or tuple(ordered_bound_target_refs)
        != tuple(item.target_requirement_ref for item in value.requirements)
        or value.declared_target_requirement_count != declared_count
        or value.no_target_requirement_count
        != len(value.requirements) - declared_count
        or total_measured_bytes != value.total_measured_bytes
        or value.loader_path_context_digest
        != _BUILTIN_CANONICAL_DIGEST(
            {
                "kind": (
                    "repository_executable_native_loader_target_path_context"
                ),
                "ordered_target_path_refs": [
                    item.path_ref for item in value.measurements
                ],
                "resolution_scope": _FIXED_RESOLUTION_SCOPE,
                "schema_version": _FIXED_SCHEMA_VERSION,
            }
        )
    ):
        raise _InvalidNativeLoaderTargetResolution
    return {
        "bindings": bindings,
        "command_count": value.command_count,
        "declared_target_requirement_count": (
            value.declared_target_requirement_count
        ),
        "kind": value.kind,
        "loader_path_context_digest": value.loader_path_context_digest,
        "measurement_source": value.measurement_source,
        "measurements": measurements,
        "native_loader_requirements_receipt_digest": (
            value.native_loader_requirements_receipt_digest
        ),
        "no_target_requirement_count": value.no_target_requirement_count,
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
        "verification_commands_digest": (
            value.verification_commands_digest
        ),
    }


_BUILTIN_RECEIPT_PROJECTION = _receipt_projection


def _evidence_projection(
    value: RepositoryExecutableNativeLoaderTargetResolutionReceipt,
) -> dict[str, Any]:
    canonical = _BUILTIN_RECEIPT_PROJECTION(value)
    dispositions = {
        disposition: sum(
            item.target_disposition == disposition
            for item in value.requirements
        )
        for disposition in _TARGET_DISPOSITIONS
    }
    return {
        "action_receipt_issued": False,
        "active_lease_verified_at_measurement": True,
        "authority_granted": False,
        "authorization_verified": False,
        "billing_eligible": False,
        "bounded_native_loader_target_measurement_complete": True,
        "capacity_eligible": False,
        "circuit_eligible": False,
        "command_count": value.command_count,
        "current_lease_activity_verified": False,
        "current_source_freshness_verified": False,
        "declared_loader_target_measured_count": dispositions[
            "declared_loader_target_measured"
        ],
        "dependency_closure_verified": False,
        "dispatch_enabled": False,
        "durable_control_plane_persistence_enabled": False,
        "dynamic_loader_identity_verified": False,
        "effect_class": 0,
        "environment_coverage_verified": False,
        "exact_loader_path_expectation_verified": True,
        "execution_enabled": False,
        "fat_mach_o_architecture_selection_performed": False,
        "future_execution_correspondence_verified": False,
        "kind": _FIXED_EVIDENCE_KIND,
        "lease_cleanup_performed": False,
        "lease_mutated": False,
        "live_execution_eligible": False,
        "loader_declaration_absent_count": dispositions[
            "loader_declaration_absent"
        ],
        "loader_path_raw_bytes_exposed": False,
        "loader_target_nofollow_measurement_complete": True,
        "model_invocation_performed": False,
        "native_loader_requirements_receipt_digest": (
            value.native_loader_requirements_receipt_digest
        ),
        "network_access_performed": False,
        "non_native_not_applicable_count": dispositions[
            "non_native_not_applicable"
        ],
        "proposal_lineage_extended": False,
        "receipt_authenticity_verified": False,
        "receipt_digest": _BUILTIN_CANONICAL_DIGEST(canonical),
        "registration_digest": value.registration_digest,
        "repository_ref": value.repository_ref,
        "requirement_count": value.requirement_count,
        "resolution_context_digest": value.resolution_context_digest,
        "resolution_scope": value.resolution_scope,
        "route_eligible": False,
        "runtime_manifest_receipt_digest": (
            value.runtime_manifest_receipt_digest
        ),
        "schema_version": value.schema_version,
        "shared_library_closure_verified": False,
        "shared_library_identity_verified": False,
        "staged_source_path_reopen_performed": False,
        "staged_byte_correspondence_verified": True,
        "staging_receipt_digest": value.staging_receipt_digest,
        "subprocess_invocation_performed": False,
        "target_file_identity_measured": value.unique_target_count > 0,
        "target_path_raw_value_exposed": False,
        "target_path_resolution_mode": "exact_declared_nofollow",
        "toolchain_completeness_verified": False,
        "total_measured_bytes": value.total_measured_bytes,
        "unique_target_count": value.unique_target_count,
        "unsupported_native_layout_count": dispositions[
            "unsupported_native_layout"
        ],
        "validation_mode": "read_only",
        "worker_authorized": False,
        "worktree_integration_enabled": False,
    }


_BUILTIN_EVIDENCE_PROJECTION = _evidence_projection


@dataclass(frozen=True, slots=True)
class _DerivedTargetRequirement:
    upstream: RepositoryExecutableNativeLoaderRequirement = field(repr=False)
    target_path: Path | None = field(repr=False)


_FIXED_UPSTREAM_REQUIREMENT_TYPE = (
    RepositoryExecutableNativeLoaderRequirement
)
_FIXED_UPSTREAM_BINDING_TYPE = (
    RepositoryExecutableNativeLoaderRequirementBinding
)
_FIXED_DERIVED_TYPE = _DerivedTargetRequirement


def _validated_path(path: Any) -> tuple[Path, bytes]:
    if type(path) is not _CONCRETE_PATH_TYPE:
        raise _InvalidNativeLoaderTargetResolution
    try:
        encoded = os.fspath(path).encode("ascii")
    except (AttributeError, TypeError, UnicodeEncodeError):
        raise _InvalidNativeLoaderTargetResolution from None
    if (
        not 1 <= len(encoded) <= _MAX_TARGET_PATH_BYTES
        or _BUILTIN_CANONICAL_TARGET_PATH(encoded) != path
    ):
        raise _InvalidNativeLoaderTargetResolution
    return path, encoded


_BUILTIN_VALIDATED_PATH = _validated_path


def _path_ref(path: Path) -> str:
    _, encoded = _BUILTIN_VALIDATED_PATH(path)
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "kind": "repository_executable_native_loader_target_path_ref",
            "resolution_scope": _FIXED_RESOLUTION_SCOPE,
            "schema_version": _FIXED_SCHEMA_VERSION,
            "target_path_ascii": encoded.decode("ascii"),
        }
    )


_BUILTIN_PATH_REF = _path_ref


def _loader_path_context_digest(paths: tuple[Path, ...]) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "kind": (
                "repository_executable_native_loader_target_path_context"
            ),
            "ordered_target_path_refs": [
                _BUILTIN_PATH_REF(path) for path in paths
            ],
            "resolution_scope": _FIXED_RESOLUTION_SCOPE,
            "schema_version": _FIXED_SCHEMA_VERSION,
        }
    )


_BUILTIN_LOADER_PATH_CONTEXT_DIGEST = _loader_path_context_digest


def _declaration_kind(loader_disposition: str) -> str:
    if loader_disposition == "elf_interpreter_declared":
        return "elf_pt_interp"
    if loader_disposition == "mach_o_dylinker_declared":
        return "mach_o_lc_load_dylinker"
    raise _InvalidNativeLoaderTargetResolution


_BUILTIN_DECLARATION_KIND = _declaration_kind


def _expected_loader_path_ref(
    requirement: RepositoryExecutableNativeLoaderRequirement,
    *,
    encoded: bytes,
) -> str:
    if (
        type(requirement) is not _FIXED_UPSTREAM_REQUIREMENT_TYPE
        or requirement.format_class not in _FORMAT_CLASSES
    ):
        raise _InvalidNativeLoaderTargetResolution
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "declaration_kind": _BUILTIN_DECLARATION_KIND(
                requirement.disposition
            ),
            "format_class": requirement.format_class,
            "kind": "repository_executable_native_loader_path_ref",
            "loader_path_hex": encoded.hex(),
            "runtime_file_ref": requirement.runtime_file_ref,
            "schema_version": 1,
        }
    )


_BUILTIN_EXPECTED_LOADER_PATH_REF = _expected_loader_path_ref


def _validate_expected_loader_paths(
    expected_requirements: RepositoryExecutableNativeLoaderRequirementsReceipt,
    expected_loader_paths: Any,
) -> tuple[tuple[_DerivedTargetRequirement, ...], tuple[Path, ...]]:
    if type(expected_loader_paths) is not tuple:
        raise _InvalidNativeLoaderTargetResolution
    if len(expected_loader_paths) > _MAX_TARGET_PATHS:
        raise _InvalidNativeLoaderTargetResolution
    validated: list[tuple[Path, bytes]] = []
    spellings: set[str] = set()
    total_bytes = 0
    for candidate in expected_loader_paths:
        path, encoded = _BUILTIN_VALIDATED_PATH(candidate)
        spelling = os.fspath(path)
        if spelling in spellings:
            raise _InvalidNativeLoaderTargetResolution
        spellings.add(spelling)
        total_bytes += len(encoded)
        if total_bytes > _MAX_TOTAL_TARGET_PATH_BYTES:
            raise _InvalidNativeLoaderTargetResolution
        validated.append((path, encoded))

    derived: list[_DerivedTargetRequirement] = []
    used_paths: list[Path] = []
    used_spellings: set[str] = set()
    for requirement in expected_requirements.requirements:
        if type(requirement) is not _FIXED_UPSTREAM_REQUIREMENT_TYPE:
            raise _InvalidNativeLoaderTargetResolution
        target_path: Path | None = None
        if requirement.loader_path_ref is not None:
            matches = [
                path
                for path, encoded in validated
                if len(encoded) == requirement.loader_path_bytes
                and _BUILTIN_EXPECTED_LOADER_PATH_REF(
                    requirement,
                    encoded=encoded,
                )
                == requirement.loader_path_ref
            ]
            if len(matches) != 1:
                raise _InvalidNativeLoaderTargetResolution
            target_path = matches[0]
            spelling = os.fspath(target_path)
            if spelling not in used_spellings:
                used_paths.append(target_path)
                used_spellings.add(spelling)
        derived.append(
            _FIXED_DERIVED_TYPE(
                upstream=requirement,
                target_path=target_path,
            )
        )
    paths = tuple(path for path, _encoded in validated)
    if tuple(used_paths) != paths:
        raise _InvalidNativeLoaderTargetResolution
    return tuple(derived), paths


_BUILTIN_VALIDATE_EXPECTED_LOADER_PATHS = _validate_expected_loader_paths


def _validated_chain_snapshot(
    expected_requirements: RepositoryExecutableNativeLoaderRequirementsReceipt,
    expected_runtime: RepositoryExecutableRuntimeManifestReceipt,
    expected_staging: RepositoryExecutableStagingReceipt,
    lease: RepositoryExecutableStageLease,
    expected_loader_paths: Any,
) -> tuple[
    tuple[_DerivedTargetRequirement, ...],
    tuple[Path, ...],
    str,
    str,
    str,
]:
    if (
        type(expected_requirements) is not _FIXED_NATIVE_REQUIREMENTS_TYPE
        or type(expected_runtime) is not _FIXED_RUNTIME_TYPE
        or type(expected_staging) is not _FIXED_STAGING_TYPE
        or type(lease) is not _FIXED_LEASE_TYPE
    ):
        raise _InvalidNativeLoaderTargetResolution
    requirements_canonical = _BUILTIN_NATIVE_REQUIREMENTS_PROJECTION(
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
        raise _InvalidNativeLoaderTargetResolution
    fresh_requirements = _BUILTIN_INSPECT_NATIVE_REQUIREMENTS(
        expected_runtime,
        expected_staging=expected_staging,
        lease=lease,
    )
    if (
        _BUILTIN_NATIVE_REQUIREMENTS_PROJECTION(fresh_requirements)
        != requirements_canonical
    ):
        raise _InvalidNativeLoaderTargetResolution
    active_staging_canonical, _retained_files = (
        _BUILTIN_ACTIVE_STAGE_SNAPSHOT(expected_staging, lease)
    )
    if active_staging_canonical != staging_canonical:
        raise _InvalidNativeLoaderTargetResolution
    derived, paths = _BUILTIN_VALIDATE_EXPECTED_LOADER_PATHS(
        expected_requirements,
        expected_loader_paths,
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
        raise _InvalidNativeLoaderTargetResolution
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "device": measured.identity[0],
            "inode": measured.identity[1],
            "kind": (
                "repository_executable_native_loader_target_file_identity"
            ),
            "schema_version": 1,
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
        raise _InvalidNativeLoaderTargetResolution
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "change_time_ns": metadata[8],
            "filesystem_identity_ref": identity_ref,
            "group_id": metadata[5],
            "kind": (
                "repository_executable_native_loader_target_file_metadata"
            ),
            "link_count": metadata[3],
            "mode": metadata[2],
            "modified_time_ns": metadata[7],
            "owner_id": metadata[4],
            "schema_version": 1,
            "size_bytes": metadata[6],
        }
    )


_BUILTIN_MEASUREMENT_METADATA_DIGEST = _measurement_metadata_digest


def _public_measurement(
    measured: _MeasuredTarget,
) -> RepositoryExecutableNativeLoaderTargetMeasurement:
    if (
        type(measured) is not _FIXED_MEASURED_TARGET_TYPE
        or type(measured.path) is not _CONCRETE_PATH_TYPE
        or not _BUILTIN_IS_DIGEST(measured.content_digest)
        or type(measured.content_bytes) is not int
        or not 0 <= measured.content_bytes <= _MAX_TARGET_BYTES
    ):
        raise _InvalidNativeLoaderTargetResolution
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


def _public_requirement(
    derived: _DerivedTargetRequirement,
    *,
    measurement_by_path: dict[
        Path, RepositoryExecutableNativeLoaderTargetMeasurement
    ],
) -> RepositoryExecutableNativeLoaderTargetRequirement:
    if (
        type(derived) is not _FIXED_DERIVED_TYPE
        or type(derived.upstream) is not _FIXED_UPSTREAM_REQUIREMENT_TYPE
    ):
        raise _InvalidNativeLoaderTargetResolution
    upstream = derived.upstream
    target_disposition = _BUILTIN_EXPECTED_TARGET_DISPOSITION(
        upstream.disposition
    )
    target_measurement_ref: str | None = None
    if derived.target_path is not None:
        measurement = measurement_by_path.get(derived.target_path)
        if measurement is None:
            raise _InvalidNativeLoaderTargetResolution
        target_measurement_ref = measurement.measurement_ref
    elif target_disposition == "declared_loader_target_measured":
        raise _InvalidNativeLoaderTargetResolution
    reference = _BUILTIN_TARGET_REQUIREMENT_REF_PROJECTION(
        staged_file_ref=upstream.staged_file_ref,
        runtime_file_ref=upstream.runtime_file_ref,
        native_loader_requirement_ref=upstream.requirement_ref,
        runtime_classification=upstream.runtime_classification,
        loader_disposition=upstream.disposition,
        target_disposition=target_disposition,
        loader_path_ref=upstream.loader_path_ref,
        target_measurement_ref=target_measurement_ref,
    )
    value = _FIXED_REQUIREMENT_TYPE(
        kind=_FIXED_REQUIREMENT_KIND,
        staged_file_ref=upstream.staged_file_ref,
        runtime_file_ref=upstream.runtime_file_ref,
        native_loader_requirement_ref=upstream.requirement_ref,
        runtime_classification=upstream.runtime_classification,
        loader_disposition=upstream.disposition,
        target_disposition=target_disposition,
        loader_path_ref=upstream.loader_path_ref,
        target_measurement_ref=target_measurement_ref,
        target_requirement_ref=_BUILTIN_CANONICAL_DIGEST(reference),
    )
    _BUILTIN_REQUIREMENT_PROJECTION(value)
    return value


_BUILTIN_PUBLIC_REQUIREMENT = _public_requirement


def inspect_staged_executable_native_loader_targets(
    expected_requirements: RepositoryExecutableNativeLoaderRequirementsReceipt,
    *,
    expected_runtime: RepositoryExecutableRuntimeManifestReceipt,
    expected_staging: RepositoryExecutableStagingReceipt,
    lease: RepositoryExecutableStageLease,
    expected_loader_paths: tuple[Path, ...],
) -> RepositoryExecutableNativeLoaderTargetResolutionReceipt:
    """Measure the exact declaration-bound canonical loader target set."""

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
            expected_loader_paths,
        )
        first_measurement = _BUILTIN_MEASURE_TARGET_SET(paths)

        (
            middle_derived,
            middle_paths,
            middle_requirements_digest,
            middle_runtime_digest,
            middle_staging_digest,
        ) = _BUILTIN_VALIDATED_CHAIN_SNAPSHOT(
            expected_requirements,
            expected_runtime,
            expected_staging,
            lease,
            expected_loader_paths,
        )
        if (
            middle_derived != derived
            or middle_paths != paths
            or middle_requirements_digest != requirements_digest
            or middle_runtime_digest != runtime_digest
            or middle_staging_digest != staging_digest
        ):
            raise _InvalidNativeLoaderTargetResolution
        second_measurement = _BUILTIN_MEASURE_TARGET_SET(paths)
        if second_measurement != first_measurement:
            raise _InvalidNativeLoaderTargetResolution

        (
            final_derived,
            final_paths,
            final_requirements_digest,
            final_runtime_digest,
            final_staging_digest,
        ) = _BUILTIN_VALIDATED_CHAIN_SNAPSHOT(
            expected_requirements,
            expected_runtime,
            expected_staging,
            lease,
            expected_loader_paths,
        )
        if (
            final_derived != derived
            or final_paths != paths
            or final_requirements_digest != requirements_digest
            or final_runtime_digest != runtime_digest
            or final_staging_digest != staging_digest
            or any(
                not _BUILTIN_TARGET_NAMESPACE_MATCHES(item)
                for item in first_measurement
            )
        ):
            raise _InvalidNativeLoaderTargetResolution
        closing_staging_canonical, _closing_retained_files = (
            _BUILTIN_ACTIVE_STAGE_SNAPSHOT(expected_staging, lease)
        )
        if (
            _BUILTIN_CANONICAL_DIGEST(closing_staging_canonical)
            != staging_digest
        ):
            raise _InvalidNativeLoaderTargetResolution

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
        requirement_by_native_ref = {
            item.native_loader_requirement_ref: item
            for item in requirements
        }
        bindings: list[RepositoryExecutableNativeLoaderTargetBinding] = []
        for upstream in expected_requirements.bindings:
            if type(upstream) is not _FIXED_UPSTREAM_BINDING_TYPE:
                raise _InvalidNativeLoaderTargetResolution
            target_requirement = requirement_by_native_ref.get(
                upstream.requirement_ref
            )
            if (
                target_requirement is None
                or upstream.staged_file_ref
                != target_requirement.staged_file_ref
                or upstream.runtime_file_ref
                != target_requirement.runtime_file_ref
            ):
                raise _InvalidNativeLoaderTargetResolution
            binding = _FIXED_BINDING_TYPE(
                kind=_FIXED_BINDING_KIND,
                command_kind=upstream.command_kind,
                command_id=upstream.command_id,
                command_digest=upstream.command_digest,
                staged_file_ref=upstream.staged_file_ref,
                runtime_file_ref=upstream.runtime_file_ref,
                native_loader_requirement_ref=upstream.requirement_ref,
                target_requirement_ref=(
                    target_requirement.target_requirement_ref
                ),
            )
            _BUILTIN_BINDING_PROJECTION(binding)
            bindings.append(binding)

        receipt = _FIXED_RECEIPT_TYPE(
            kind=_FIXED_RECEIPT_KIND,
            schema_version=_FIXED_SCHEMA_VERSION,
            measurement_source=_FIXED_MEASUREMENT_SOURCE,
            resolution_scope=_FIXED_RESOLUTION_SCOPE,
            native_loader_requirements_receipt_digest=(
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
            loader_path_context_digest=(
                _BUILTIN_LOADER_PATH_CONTEXT_DIGEST(paths)
            ),
            measurements=measurements,
            requirements=requirements,
            bindings=tuple(bindings),
            requirement_count=len(requirements),
            command_count=len(bindings),
            declared_target_requirement_count=sum(
                item.target_disposition
                == "declared_loader_target_measured"
                for item in requirements
            ),
            no_target_requirement_count=sum(
                item.target_disposition
                != "declared_loader_target_measured"
                for item in requirements
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
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_BINDING_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_MEASUREMENT_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_REQUIREMENT_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_RESOLUTION_EVIDENCE_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_RESOLUTION_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_RESOLUTION_SCHEMA_VERSION",
    "RESOLUTION_SCOPE",
    "RepositoryExecutableNativeLoaderTargetBinding",
    "RepositoryExecutableNativeLoaderTargetMeasurement",
    "RepositoryExecutableNativeLoaderTargetRequirement",
    "RepositoryExecutableNativeLoaderTargetResolutionReceipt",
    "inspect_staged_executable_native_loader_targets",
]
