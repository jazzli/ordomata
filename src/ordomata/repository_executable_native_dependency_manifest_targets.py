"""Measure only exact controller-manifest native dependency targets.

This Class 0 boundary consumes an exact explicit native-dependency manifest
receipt, its direct dependency/runtime/staging chain, and an active local lease.
It re-proves the private ordered manifest before measuring the manifest's exact
canonical targets with no-follow traversal.  It never consults host loader
search state or expands dependency tokens, and it does not stage, load, or
execute a target.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import re
from typing import Any

from .authorization import canonical_json
from .errors import ValidationError
from .repository_executable_native_dependency_manifest import (
    RepositoryExecutableNativeDependencyManifestBinding,
    RepositoryExecutableNativeDependencyManifestCommandBinding,
    RepositoryExecutableNativeDependencyManifestEntry,
    RepositoryExecutableNativeDependencyManifestReceipt,
    _manifest_target_ref as _manifest_target_ref,
    _receipt_projection as _manifest_receipt_projection,
    inspect_staged_executable_native_dependency_manifest,
)
from .repository_executable_native_dependency_requirements import (
    RepositoryExecutableNativeDependencyRequirementsReceipt,
    _receipt_projection as _dependency_receipt_projection,
)
from .repository_executable_native_loader_target_resolution import (
    _MeasuredTarget,
    _measure_target_set as _measure_target_set,
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


REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGETS_SCHEMA_VERSION = 1
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGETS_KIND = (
    "repository_executable_native_dependency_manifest_targets"
)
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGETS_EVIDENCE_KIND = (
    "repository_executable_native_dependency_manifest_targets_validation"
)
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_MEASUREMENT_KIND = (
    "repository_executable_native_dependency_manifest_target_measurement"
)
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_BINDING_KIND = (
    "repository_executable_native_dependency_manifest_target_binding"
)
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_COMMAND_BINDING_KIND = (
    "repository_executable_native_dependency_manifest_target_command_binding"
)
MEASUREMENT_SOURCE = "controller_measured"
MEASUREMENT_SCOPE = "explicit_nonabsolute_native_dependency_manifest_target_nofollow_v1"

_FIXED_SCHEMA_VERSION = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGETS_SCHEMA_VERSION
_FIXED_RECEIPT_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGETS_KIND
_FIXED_EVIDENCE_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGETS_EVIDENCE_KIND
_FIXED_MEASUREMENT_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_MEASUREMENT_KIND
_FIXED_BINDING_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_BINDING_KIND
_FIXED_COMMAND_BINDING_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_COMMAND_BINDING_KIND
_FIXED_MEASUREMENT_SOURCE = MEASUREMENT_SOURCE
_FIXED_MEASUREMENT_SCOPE = MEASUREMENT_SCOPE

_INVALID_MESSAGE = "repository executable native dependency manifest targets are invalid"
_DIGEST_PREFIX = "sha256:"
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER_PATTERN = re.compile(r"[a-z][a-z0-9_.-]{0,119}\Z")
_COMMAND_KINDS = ("format", "lint", "type_check", "test", "build")
_FORMAT_CLASSES = (
    "elf32",
    "elf64",
    "mach_o32",
    "mach_o64",
    "mach_o_fat32",
    "mach_o_fat64",
)
_PATH_STYLES = (
    "bare",
    "relative",
    "at_rpath",
    "at_loader_path",
    "at_executable_path",
)
_MAX_FILES = 80
_MAX_COMMANDS = 80
_MAX_BINDINGS = 512
_MAX_TARGET_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_TARGET_BYTES = 256 * 1024 * 1024
_CONCRETE_PATH_TYPE = type(Path())

_BUILTIN_SHA256 = hashlib.sha256
_BUILTIN_CANONICAL_JSON = canonical_json


def _captured_canonical_digest(value: Any) -> str:
    encoded = _BUILTIN_CANONICAL_JSON(value).encode("utf-8")
    return _DIGEST_PREFIX + _BUILTIN_SHA256(encoded).hexdigest()


_BUILTIN_CANONICAL_DIGEST = _captured_canonical_digest
_BUILTIN_MANIFEST_RECEIPT_PROJECTION = _manifest_receipt_projection
_BUILTIN_DEPENDENCY_RECEIPT_PROJECTION = _dependency_receipt_projection
_BUILTIN_RUNTIME_PROJECTION = _runtime_manifest_projection
_BUILTIN_STAGING_PROJECTION = _staging_receipt_projection
_BUILTIN_INSPECT_MANIFEST = inspect_staged_executable_native_dependency_manifest
_BUILTIN_MANIFEST_TARGET_REF = _manifest_target_ref
_BUILTIN_ACTIVE_STAGE_SNAPSHOT = _active_stage_snapshot
_BUILTIN_MEASURE_TARGET_SET = _measure_target_set
_BUILTIN_TARGET_NAMESPACE_MATCHES = _target_namespace_matches
_FIXED_MANIFEST_RECEIPT_TYPE = RepositoryExecutableNativeDependencyManifestReceipt
_FIXED_MANIFEST_ENTRY_TYPE = RepositoryExecutableNativeDependencyManifestEntry
_FIXED_UPSTREAM_BINDING_TYPE = RepositoryExecutableNativeDependencyManifestBinding
_FIXED_UPSTREAM_COMMAND_BINDING_TYPE = RepositoryExecutableNativeDependencyManifestCommandBinding
_FIXED_DEPENDENCY_RECEIPT_TYPE = RepositoryExecutableNativeDependencyRequirementsReceipt
_FIXED_RUNTIME_TYPE = RepositoryExecutableRuntimeManifestReceipt
_FIXED_STAGING_TYPE = RepositoryExecutableStagingReceipt
_FIXED_LEASE_TYPE = RepositoryExecutableStageLease
_FIXED_MEASURED_TARGET_TYPE = _MeasuredTarget
_FIXED_VALIDATION_ERROR = ValidationError


class _InvalidNativeDependencyManifestTargets(ValueError):
    """Private fail-closed sentinel whose details never cross the API."""


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeDependencyManifestTargetMeasurement:
    """One exact controller-manifest target's point-in-time measurement."""

    kind: str
    manifest_target_ref: str = field(repr=False)
    filesystem_identity_ref: str = field(repr=False)
    metadata_digest: str = field(repr=False)
    content_digest: str = field(repr=False)
    content_bytes: int
    measurement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_MEASUREMENT_PROJECTION(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeDependencyManifestTargetBinding:
    """One manifest declaration binding joined to its target measurement."""

    kind: str
    runtime_file_ref: str = field(repr=False)
    dependency_declaration_ref: str = field(repr=False)
    dependency_name_ref: str = field(repr=False)
    format_class: str
    ordinal: int
    path_style: str
    manifest_requirement_ref: str = field(repr=False)
    manifest_binding_ref: str = field(repr=False)
    manifest_target_ref: str = field(repr=False)
    target_measurement_ref: str = field(repr=False)
    target_binding_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_BINDING_PROJECTION(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeDependencyManifestTargetCommandBinding:
    """One registered command retaining manifest-target lineage."""

    kind: str
    command_kind: str
    command_id: str = field(repr=False)
    command_digest: str = field(repr=False)
    staged_file_ref: str = field(repr=False)
    runtime_file_ref: str = field(repr=False)
    native_dependency_requirement_ref: str = field(repr=False)
    manifest_requirement_ref: str = field(repr=False)
    target_command_binding_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_COMMAND_BINDING_PROJECTION(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeDependencyManifestTargetsReceipt:
    """Digest-only historical evidence for manifest-target no-follow reads."""

    kind: str
    schema_version: int
    measurement_source: str
    measurement_scope: str
    native_dependency_manifest_receipt_digest: str = field(repr=False)
    native_dependency_requirements_receipt_digest: str = field(repr=False)
    runtime_manifest_receipt_digest: str = field(repr=False)
    staging_receipt_digest: str = field(repr=False)
    registration_digest: str = field(repr=False)
    repository_ref: str = field(repr=False)
    verification_commands_digest: str = field(repr=False)
    resolution_context_digest: str = field(repr=False)
    staging_context_digest: str = field(repr=False)
    manifest_context_digest: str = field(repr=False)
    manifest_binding_context_digest: str = field(repr=False)
    measurements: tuple[RepositoryExecutableNativeDependencyManifestTargetMeasurement, ...] = field(repr=False)
    bindings: tuple[RepositoryExecutableNativeDependencyManifestTargetBinding, ...] = field(repr=False)
    command_bindings: tuple[RepositoryExecutableNativeDependencyManifestTargetCommandBinding, ...] = field(repr=False)
    requirement_count: int
    command_count: int
    manifest_binding_count: int
    unique_target_count: int
    total_measured_bytes: int

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_RECEIPT_PROJECTION(self)

    @property
    def receipt_digest(self) -> str:
        return _BUILTIN_CANONICAL_DIGEST(_BUILTIN_RECEIPT_PROJECTION(self))

    def to_evidence(self) -> dict[str, Any]:
        return _BUILTIN_EVIDENCE_PROJECTION(self)


_FIXED_MEASUREMENT_TYPE = RepositoryExecutableNativeDependencyManifestTargetMeasurement
_FIXED_BINDING_TYPE = RepositoryExecutableNativeDependencyManifestTargetBinding
_FIXED_COMMAND_BINDING_TYPE = RepositoryExecutableNativeDependencyManifestTargetCommandBinding
_FIXED_RECEIPT_TYPE = RepositoryExecutableNativeDependencyManifestTargetsReceipt


def _is_digest(value: Any) -> bool:
    return type(value) is str and _DIGEST_PATTERN.fullmatch(value) is not None


_BUILTIN_IS_DIGEST = _is_digest


def _measurement_ref_projection(
    *,
    manifest_target_ref: str,
    filesystem_identity_ref: str,
    metadata_digest: str,
    content_digest: str,
    content_bytes: int,
) -> dict[str, Any]:
    return {
        "content_bytes": content_bytes,
        "content_digest": content_digest,
        "filesystem_identity_ref": filesystem_identity_ref,
        "kind": "repository_executable_native_dependency_manifest_target_measurement_ref",
        "manifest_target_ref": manifest_target_ref,
        "measurement_scope": _FIXED_MEASUREMENT_SCOPE,
        "measurement_source": _FIXED_MEASUREMENT_SOURCE,
        "metadata_digest": metadata_digest,
        "schema_version": _FIXED_SCHEMA_VERSION,
    }


_BUILTIN_MEASUREMENT_REF_PROJECTION = _measurement_ref_projection


def _measurement_projection(
    value: RepositoryExecutableNativeDependencyManifestTargetMeasurement,
) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_MEASUREMENT_TYPE
        or value.kind != _FIXED_MEASUREMENT_KIND
        or not all(
            _BUILTIN_IS_DIGEST(item)
            for item in (
                value.manifest_target_ref,
                value.filesystem_identity_ref,
                value.metadata_digest,
                value.content_digest,
                value.measurement_ref,
            )
        )
        or type(value.content_bytes) is not int
        or not 0 <= value.content_bytes <= _MAX_TARGET_BYTES
    ):
        raise _InvalidNativeDependencyManifestTargets
    reference = _BUILTIN_MEASUREMENT_REF_PROJECTION(
        manifest_target_ref=value.manifest_target_ref,
        filesystem_identity_ref=value.filesystem_identity_ref,
        metadata_digest=value.metadata_digest,
        content_digest=value.content_digest,
        content_bytes=value.content_bytes,
    )
    if value.measurement_ref != _BUILTIN_CANONICAL_DIGEST(reference):
        raise _InvalidNativeDependencyManifestTargets
    return {**reference, "kind": value.kind, "measurement_ref": value.measurement_ref}


_BUILTIN_MEASUREMENT_PROJECTION = _measurement_projection


def _binding_ref_projection(
    *,
    runtime_file_ref: str,
    dependency_declaration_ref: str,
    dependency_name_ref: str,
    format_class: str,
    ordinal: int,
    path_style: str,
    manifest_requirement_ref: str,
    manifest_binding_ref: str,
    manifest_target_ref: str,
    target_measurement_ref: str,
) -> dict[str, Any]:
    return {
        "dependency_declaration_ref": dependency_declaration_ref,
        "dependency_name_ref": dependency_name_ref,
        "format_class": format_class,
        "kind": "repository_executable_native_dependency_manifest_target_binding_ref",
        "manifest_binding_ref": manifest_binding_ref,
        "manifest_requirement_ref": manifest_requirement_ref,
        "manifest_target_ref": manifest_target_ref,
        "measurement_scope": _FIXED_MEASUREMENT_SCOPE,
        "ordinal": ordinal,
        "path_style": path_style,
        "runtime_file_ref": runtime_file_ref,
        "schema_version": _FIXED_SCHEMA_VERSION,
        "target_measurement_ref": target_measurement_ref,
    }


_BUILTIN_BINDING_REF_PROJECTION = _binding_ref_projection


def _binding_projection(
    value: RepositoryExecutableNativeDependencyManifestTargetBinding,
) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_BINDING_TYPE
        or value.kind != _FIXED_BINDING_KIND
        or not all(
            _BUILTIN_IS_DIGEST(item)
            for item in (
                value.runtime_file_ref,
                value.dependency_declaration_ref,
                value.dependency_name_ref,
                value.manifest_requirement_ref,
                value.manifest_binding_ref,
                value.manifest_target_ref,
                value.target_measurement_ref,
                value.target_binding_ref,
            )
        )
        or value.format_class not in _FORMAT_CLASSES
        or type(value.ordinal) is not int
        or not 0 <= value.ordinal < _MAX_BINDINGS
        or value.path_style not in _PATH_STYLES
    ):
        raise _InvalidNativeDependencyManifestTargets
    reference = _BUILTIN_BINDING_REF_PROJECTION(
        runtime_file_ref=value.runtime_file_ref,
        dependency_declaration_ref=value.dependency_declaration_ref,
        dependency_name_ref=value.dependency_name_ref,
        format_class=value.format_class,
        ordinal=value.ordinal,
        path_style=value.path_style,
        manifest_requirement_ref=value.manifest_requirement_ref,
        manifest_binding_ref=value.manifest_binding_ref,
        manifest_target_ref=value.manifest_target_ref,
        target_measurement_ref=value.target_measurement_ref,
    )
    if value.target_binding_ref != _BUILTIN_CANONICAL_DIGEST(reference):
        raise _InvalidNativeDependencyManifestTargets
    return {**reference, "kind": value.kind, "target_binding_ref": value.target_binding_ref}


_BUILTIN_BINDING_PROJECTION = _binding_projection


def _command_binding_ref_projection(
    *,
    command_kind: str,
    command_id: str,
    command_digest: str,
    staged_file_ref: str,
    runtime_file_ref: str,
    native_dependency_requirement_ref: str,
    manifest_requirement_ref: str,
) -> dict[str, Any]:
    return {
        "command_digest": command_digest,
        "command_id": command_id,
        "command_kind": command_kind,
        "kind": "repository_executable_native_dependency_manifest_target_command_binding_ref",
        "manifest_requirement_ref": manifest_requirement_ref,
        "measurement_scope": _FIXED_MEASUREMENT_SCOPE,
        "native_dependency_requirement_ref": native_dependency_requirement_ref,
        "runtime_file_ref": runtime_file_ref,
        "schema_version": _FIXED_SCHEMA_VERSION,
        "staged_file_ref": staged_file_ref,
    }


_BUILTIN_COMMAND_BINDING_REF_PROJECTION = _command_binding_ref_projection


def _command_binding_projection(
    value: RepositoryExecutableNativeDependencyManifestTargetCommandBinding,
) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_COMMAND_BINDING_TYPE
        or value.kind != _FIXED_COMMAND_BINDING_KIND
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
                value.manifest_requirement_ref,
                value.target_command_binding_ref,
            )
        )
    ):
        raise _InvalidNativeDependencyManifestTargets
    reference = _BUILTIN_COMMAND_BINDING_REF_PROJECTION(
        command_kind=value.command_kind,
        command_id=value.command_id,
        command_digest=value.command_digest,
        staged_file_ref=value.staged_file_ref,
        runtime_file_ref=value.runtime_file_ref,
        native_dependency_requirement_ref=value.native_dependency_requirement_ref,
        manifest_requirement_ref=value.manifest_requirement_ref,
    )
    if value.target_command_binding_ref != _BUILTIN_CANONICAL_DIGEST(reference):
        raise _InvalidNativeDependencyManifestTargets
    return {**reference, "kind": value.kind, "target_command_binding_ref": value.target_command_binding_ref}


_BUILTIN_COMMAND_BINDING_PROJECTION = _command_binding_projection


def _receipt_projection(
    value: RepositoryExecutableNativeDependencyManifestTargetsReceipt,
) -> dict[str, Any]:
    digest_fields = (
        value.native_dependency_manifest_receipt_digest,
        value.native_dependency_requirements_receipt_digest,
        value.runtime_manifest_receipt_digest,
        value.staging_receipt_digest,
        value.registration_digest,
        value.repository_ref,
        value.verification_commands_digest,
        value.resolution_context_digest,
        value.staging_context_digest,
        value.manifest_context_digest,
        value.manifest_binding_context_digest,
    )
    count_fields = (
        value.manifest_binding_count,
        value.unique_target_count,
        value.total_measured_bytes,
    )
    if (
        type(value) is not _FIXED_RECEIPT_TYPE
        or value.kind != _FIXED_RECEIPT_KIND
        or type(value.schema_version) is not int
        or value.schema_version != _FIXED_SCHEMA_VERSION
        or value.measurement_source != _FIXED_MEASUREMENT_SOURCE
        or value.measurement_scope != _FIXED_MEASUREMENT_SCOPE
        or not all(_BUILTIN_IS_DIGEST(item) for item in digest_fields)
        or type(value.measurements) is not tuple
        or not 0 <= len(value.measurements) <= _MAX_BINDINGS
        or type(value.bindings) is not tuple
        or not 0 <= len(value.bindings) <= _MAX_BINDINGS
        or type(value.command_bindings) is not tuple
        or not 1 <= len(value.command_bindings) <= _MAX_COMMANDS
        or type(value.requirement_count) is not int
        or not 1 <= value.requirement_count <= _MAX_FILES
        or type(value.command_count) is not int
        or value.command_count != len(value.command_bindings)
        or any(type(item) is not int or item < 0 for item in count_fields)
        or value.manifest_binding_count != len(value.bindings)
        or value.unique_target_count != len(value.measurements)
        or value.total_measured_bytes > _MAX_TOTAL_TARGET_BYTES
    ):
        raise _InvalidNativeDependencyManifestTargets
    measurements = [_BUILTIN_MEASUREMENT_PROJECTION(item) for item in value.measurements]
    bindings = [_BUILTIN_BINDING_PROJECTION(item) for item in value.bindings]
    command_bindings = [_BUILTIN_COMMAND_BINDING_PROJECTION(item) for item in value.command_bindings]
    measurements_by_ref: dict[str, RepositoryExecutableNativeDependencyManifestTargetMeasurement] = {}
    target_refs: set[str] = set()
    total_bytes = 0
    for measurement in value.measurements:
        if (
            measurement.measurement_ref in measurements_by_ref
            or measurement.manifest_target_ref in target_refs
        ):
            raise _InvalidNativeDependencyManifestTargets
        measurements_by_ref[measurement.measurement_ref] = measurement
        target_refs.add(measurement.manifest_target_ref)
        total_bytes += measurement.content_bytes
    binding_refs: set[str] = set()
    source_binding_refs: set[str] = set()
    declaration_refs: set[str] = set()
    requirement_refs: set[str] = set()
    for binding in value.bindings:
        measurement = measurements_by_ref.get(binding.target_measurement_ref)
        if (
            binding.target_binding_ref in binding_refs
            or binding.manifest_binding_ref in source_binding_refs
            or binding.dependency_declaration_ref in declaration_refs
            or measurement is None
            or binding.manifest_target_ref != measurement.manifest_target_ref
        ):
            raise _InvalidNativeDependencyManifestTargets
        binding_refs.add(binding.target_binding_ref)
        source_binding_refs.add(binding.manifest_binding_ref)
        declaration_refs.add(binding.dependency_declaration_ref)
        requirement_refs.add(binding.manifest_requirement_ref)
    command_ids: set[str] = set()
    command_refs: set[str] = set()
    command_requirement_refs: set[str] = set()
    prior_kind_index = -1
    for command in value.command_bindings:
        kind_index = _COMMAND_KINDS.index(command.command_kind)
        if (
            command.target_command_binding_ref in command_refs
            or command.command_id in command_ids
            or kind_index < prior_kind_index
        ):
            raise _InvalidNativeDependencyManifestTargets
        command_refs.add(command.target_command_binding_ref)
        command_ids.add(command.command_id)
        command_requirement_refs.add(command.manifest_requirement_ref)
        prior_kind_index = kind_index
    if (
        total_bytes != value.total_measured_bytes
        or requirement_refs - command_requirement_refs
        or len(command_requirement_refs) != value.requirement_count
        or value.manifest_binding_context_digest
        != _BUILTIN_CANONICAL_DIGEST(
            {
                "kind": "repository_executable_native_dependency_manifest_target_binding_context",
                "measurement_scope": _FIXED_MEASUREMENT_SCOPE,
                "ordered_manifest_binding_refs": [
                    item.manifest_binding_ref for item in value.bindings
                ],
                "schema_version": _FIXED_SCHEMA_VERSION,
            }
        )
    ):
        raise _InvalidNativeDependencyManifestTargets
    return {
        "bindings": bindings,
        "command_bindings": command_bindings,
        "command_count": value.command_count,
        "kind": value.kind,
        "manifest_binding_count": value.manifest_binding_count,
        "manifest_binding_context_digest": value.manifest_binding_context_digest,
        "manifest_context_digest": value.manifest_context_digest,
        "measurement_scope": value.measurement_scope,
        "measurement_source": value.measurement_source,
        "measurements": measurements,
        "native_dependency_manifest_receipt_digest": value.native_dependency_manifest_receipt_digest,
        "native_dependency_requirements_receipt_digest": value.native_dependency_requirements_receipt_digest,
        "registration_digest": value.registration_digest,
        "repository_ref": value.repository_ref,
        "requirement_count": value.requirement_count,
        "resolution_context_digest": value.resolution_context_digest,
        "runtime_manifest_receipt_digest": value.runtime_manifest_receipt_digest,
        "schema_version": value.schema_version,
        "staging_context_digest": value.staging_context_digest,
        "staging_receipt_digest": value.staging_receipt_digest,
        "total_measured_bytes": value.total_measured_bytes,
        "unique_target_count": value.unique_target_count,
        "verification_commands_digest": value.verification_commands_digest,
    }


_BUILTIN_RECEIPT_PROJECTION = _receipt_projection


def _evidence_projection(
    value: RepositoryExecutableNativeDependencyManifestTargetsReceipt,
) -> dict[str, Any]:
    canonical = _BUILTIN_RECEIPT_PROJECTION(value)
    return {
        "action_receipt_issued": False,
        "active_lease_verified_at_measurement": True,
        "ambient_loader_environment_consulted": False,
        "ambient_loader_search_semantics_applied": False,
        "authority_granted": False,
        "authorization_verified": False,
        "billing_eligible": False,
        "capacity_eligible": False,
        "circuit_eligible": False,
        "command_count": value.command_count,
        "controller_explicit_manifest_reproduced": True,
        "dependency_closure_verified": False,
        "dispatch_enabled": False,
        "durable_control_plane_persistence_enabled": False,
        "effect_class": 0,
        "execution_enabled": False,
        "future_execution_correspondence_verified": False,
        "harness_invocation_performed": False,
        "host_loader_cache_consulted": False,
        "kind": _FIXED_EVIDENCE_KIND,
        "lease_cleanup_performed": False,
        "lease_mutated": False,
        "live_execution_eligible": False,
        "loader_invocation_performed": False,
        "manifest_binding_count": value.manifest_binding_count,
        "manifest_target_raw_values_exposed": False,
        "model_invocation_performed": False,
        "network_access_performed": False,
        "path_lookup_performed": bool(value.measurements),
        "proposal_lineage_extended": False,
        "receipt_authenticity_verified": False,
        "receipt_digest": _BUILTIN_CANONICAL_DIGEST(canonical),
        "recursive_dependency_resolution_verified": False,
        "registration_digest": value.registration_digest,
        "repository_ref": value.repository_ref,
        "requirement_count": value.requirement_count,
        "route_eligible": False,
        "shared_library_closure_verified": False,
        "source_path_reopen_performed": False,
        "subprocess_invocation_performed": False,
        "target_nofollow_measurement_complete": True,
        "tokenized_loader_path_expansion_performed": False,
        "total_measured_bytes": value.total_measured_bytes,
        "unique_target_count": value.unique_target_count,
        "validation_mode": "read_only",
        "worker_authorized": False,
        "worktree_integration_enabled": False,
    }


_BUILTIN_EVIDENCE_PROJECTION = _evidence_projection


@dataclass(frozen=True, slots=True)
class _DerivedManifestTarget:
    upstream: RepositoryExecutableNativeDependencyManifestBinding = field(repr=False)
    target_path: Path = field(repr=False)


_FIXED_DERIVED_TYPE = _DerivedManifestTarget


def _validate_inputs_and_reproduce_manifest(
    expected_manifest: RepositoryExecutableNativeDependencyManifestReceipt,
    expected_requirements: RepositoryExecutableNativeDependencyRequirementsReceipt,
    expected_runtime: RepositoryExecutableRuntimeManifestReceipt,
    expected_staging: RepositoryExecutableStagingReceipt,
    lease: RepositoryExecutableStageLease,
    expected_non_absolute_dependency_manifest: Any,
) -> tuple[tuple[_DerivedManifestTarget, ...], tuple[Path, ...], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    if (
        type(expected_manifest) is not _FIXED_MANIFEST_RECEIPT_TYPE
        or type(expected_requirements) is not _FIXED_DEPENDENCY_RECEIPT_TYPE
        or type(expected_runtime) is not _FIXED_RUNTIME_TYPE
        or type(expected_staging) is not _FIXED_STAGING_TYPE
        or type(lease) is not _FIXED_LEASE_TYPE
        or type(expected_non_absolute_dependency_manifest) is not tuple
        or len(expected_non_absolute_dependency_manifest) > _MAX_BINDINGS
    ):
        raise _InvalidNativeDependencyManifestTargets
    manifest_canonical = _BUILTIN_MANIFEST_RECEIPT_PROJECTION(expected_manifest)
    requirements_canonical = _BUILTIN_DEPENDENCY_RECEIPT_PROJECTION(expected_requirements)
    runtime_canonical = _BUILTIN_RUNTIME_PROJECTION(expected_runtime)
    staging_canonical = _BUILTIN_STAGING_PROJECTION(expected_staging)
    requirements_digest = _BUILTIN_CANONICAL_DIGEST(requirements_canonical)
    runtime_digest = _BUILTIN_CANONICAL_DIGEST(runtime_canonical)
    staging_digest = _BUILTIN_CANONICAL_DIGEST(staging_canonical)
    if (
        expected_manifest.native_dependency_requirements_receipt_digest != requirements_digest
        or expected_manifest.runtime_manifest_receipt_digest != runtime_digest
        or expected_manifest.staging_receipt_digest != staging_digest
        or expected_requirements.runtime_manifest_receipt_digest != runtime_digest
        or expected_requirements.staging_receipt_digest != staging_digest
        or expected_manifest.registration_digest != expected_requirements.registration_digest
        or expected_manifest.registration_digest != expected_runtime.registration_digest
        or expected_manifest.registration_digest != expected_staging.registration_digest
        or expected_manifest.repository_ref != expected_requirements.repository_ref
        or expected_manifest.repository_ref != expected_runtime.repository_ref
        or expected_manifest.repository_ref != expected_staging.repository_ref
        or expected_manifest.verification_commands_digest != expected_requirements.verification_commands_digest
        or expected_manifest.verification_commands_digest != expected_runtime.verification_commands_digest
        or expected_manifest.verification_commands_digest != expected_staging.verification_commands_digest
        or expected_manifest.resolution_context_digest != expected_requirements.resolution_context_digest
        or expected_manifest.resolution_context_digest != expected_runtime.resolution_context_digest
        or expected_manifest.resolution_context_digest != expected_staging.resolution_context_digest
        or expected_manifest.staging_context_digest != expected_requirements.staging_context_digest
        or expected_manifest.staging_context_digest != expected_runtime.staging_context_digest
        or expected_manifest.staging_context_digest != expected_staging.staging_context_digest
    ):
        raise _InvalidNativeDependencyManifestTargets
    fresh_manifest = _BUILTIN_INSPECT_MANIFEST(
        expected_requirements,
        expected_runtime=expected_runtime,
        expected_staging=expected_staging,
        lease=lease,
        expected_non_absolute_dependency_manifest=expected_non_absolute_dependency_manifest,
    )
    if _BUILTIN_MANIFEST_RECEIPT_PROJECTION(fresh_manifest) != manifest_canonical:
        raise _InvalidNativeDependencyManifestTargets
    active_staging_canonical, _retained_files = _BUILTIN_ACTIVE_STAGE_SNAPSHOT(expected_staging, lease)
    if active_staging_canonical != staging_canonical:
        raise _InvalidNativeDependencyManifestTargets
    upstream = tuple(
        binding
        for requirement in fresh_manifest.requirements
        for binding in requirement.bindings
    )
    if len(upstream) != len(expected_non_absolute_dependency_manifest):
        raise _InvalidNativeDependencyManifestTargets
    derived: list[_DerivedManifestTarget] = []
    paths: list[Path] = []
    by_target_ref: dict[str, Path] = {}
    for binding, entry in zip(upstream, expected_non_absolute_dependency_manifest, strict=True):
        if (
            type(binding) is not _FIXED_UPSTREAM_BINDING_TYPE
            or type(entry) is not _FIXED_MANIFEST_ENTRY_TYPE
            or type(entry.target_path) is not _CONCRETE_PATH_TYPE
            or _BUILTIN_MANIFEST_TARGET_REF(entry.target_path) != binding.manifest_target_ref
        ):
            raise _InvalidNativeDependencyManifestTargets
        original = by_target_ref.get(binding.manifest_target_ref)
        if original is None:
            by_target_ref[binding.manifest_target_ref] = entry.target_path
            paths.append(entry.target_path)
        elif original != entry.target_path:
            raise _InvalidNativeDependencyManifestTargets
        derived.append(_FIXED_DERIVED_TYPE(upstream=binding, target_path=entry.target_path))
    return (
        tuple(derived),
        tuple(paths),
        manifest_canonical,
        requirements_canonical,
        runtime_canonical,
        staging_canonical,
    )


_BUILTIN_VALIDATE_INPUTS_AND_REPRODUCE_MANIFEST = _validate_inputs_and_reproduce_manifest


def _measurement_identity_ref(measured: _MeasuredTarget) -> str:
    if (
        type(measured) is not _FIXED_MEASURED_TARGET_TYPE
        or type(measured.identity) is not tuple
        or len(measured.identity) != 2
        or any(type(item) is not int for item in measured.identity)
    ):
        raise _InvalidNativeDependencyManifestTargets
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "device": measured.identity[0],
            "inode": measured.identity[1],
            "kind": "repository_executable_native_dependency_manifest_target_file_identity",
            "schema_version": _FIXED_SCHEMA_VERSION,
        }
    )


_BUILTIN_MEASUREMENT_IDENTITY_REF = _measurement_identity_ref


def _measurement_metadata_digest(measured: _MeasuredTarget, *, identity_ref: str) -> str:
    metadata = measured.metadata
    if (
        type(metadata) is not tuple
        or len(metadata) != 9
        or any(type(item) is not int for item in metadata)
        or not _BUILTIN_IS_DIGEST(identity_ref)
        or metadata[0:2] != measured.identity
        or metadata[6] != measured.content_bytes
    ):
        raise _InvalidNativeDependencyManifestTargets
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "change_time_ns": metadata[8],
            "filesystem_identity_ref": identity_ref,
            "group_id": metadata[5],
            "kind": "repository_executable_native_dependency_manifest_target_file_metadata",
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
    *,
    manifest_target_ref: str,
) -> RepositoryExecutableNativeDependencyManifestTargetMeasurement:
    if (
        type(measured) is not _FIXED_MEASURED_TARGET_TYPE
        or type(measured.path) is not _CONCRETE_PATH_TYPE
        or not _BUILTIN_IS_DIGEST(manifest_target_ref)
        or not _BUILTIN_IS_DIGEST(measured.content_digest)
        or type(measured.content_bytes) is not int
        or not 0 <= measured.content_bytes <= _MAX_TARGET_BYTES
    ):
        raise _InvalidNativeDependencyManifestTargets
    identity_ref = _BUILTIN_MEASUREMENT_IDENTITY_REF(measured)
    metadata_digest = _BUILTIN_MEASUREMENT_METADATA_DIGEST(measured, identity_ref=identity_ref)
    reference = _BUILTIN_MEASUREMENT_REF_PROJECTION(
        manifest_target_ref=manifest_target_ref,
        filesystem_identity_ref=identity_ref,
        metadata_digest=metadata_digest,
        content_digest=measured.content_digest,
        content_bytes=measured.content_bytes,
    )
    value = _FIXED_MEASUREMENT_TYPE(
        kind=_FIXED_MEASUREMENT_KIND,
        manifest_target_ref=manifest_target_ref,
        filesystem_identity_ref=identity_ref,
        metadata_digest=metadata_digest,
        content_digest=measured.content_digest,
        content_bytes=measured.content_bytes,
        measurement_ref=_BUILTIN_CANONICAL_DIGEST(reference),
    )
    _BUILTIN_MEASUREMENT_PROJECTION(value)
    return value


_BUILTIN_PUBLIC_MEASUREMENT = _public_measurement


def _public_binding(
    derived: _DerivedManifestTarget,
    *,
    measurement_by_path: dict[Path, RepositoryExecutableNativeDependencyManifestTargetMeasurement],
    requirement_by_binding_ref: dict[str, str],
) -> RepositoryExecutableNativeDependencyManifestTargetBinding:
    if (
        type(derived) is not _FIXED_DERIVED_TYPE
        or type(derived.upstream) is not _FIXED_UPSTREAM_BINDING_TYPE
    ):
        raise _InvalidNativeDependencyManifestTargets
    upstream = derived.upstream
    measurement = measurement_by_path.get(derived.target_path)
    requirement_ref = requirement_by_binding_ref.get(upstream.manifest_binding_ref)
    if (
        measurement is None
        or requirement_ref is None
        or measurement.manifest_target_ref != upstream.manifest_target_ref
    ):
        raise _InvalidNativeDependencyManifestTargets
    reference = _BUILTIN_BINDING_REF_PROJECTION(
        runtime_file_ref=upstream.runtime_file_ref,
        dependency_declaration_ref=upstream.dependency_declaration_ref,
        dependency_name_ref=upstream.dependency_name_ref,
        format_class=upstream.format_class,
        ordinal=upstream.ordinal,
        path_style=upstream.path_style,
        manifest_requirement_ref=requirement_ref,
        manifest_binding_ref=upstream.manifest_binding_ref,
        manifest_target_ref=upstream.manifest_target_ref,
        target_measurement_ref=measurement.measurement_ref,
    )
    value = _FIXED_BINDING_TYPE(
        kind=_FIXED_BINDING_KIND,
        runtime_file_ref=upstream.runtime_file_ref,
        dependency_declaration_ref=upstream.dependency_declaration_ref,
        dependency_name_ref=upstream.dependency_name_ref,
        format_class=upstream.format_class,
        ordinal=upstream.ordinal,
        path_style=upstream.path_style,
        manifest_requirement_ref=requirement_ref,
        manifest_binding_ref=upstream.manifest_binding_ref,
        manifest_target_ref=upstream.manifest_target_ref,
        target_measurement_ref=measurement.measurement_ref,
        target_binding_ref=_BUILTIN_CANONICAL_DIGEST(reference),
    )
    _BUILTIN_BINDING_PROJECTION(value)
    return value


_BUILTIN_PUBLIC_BINDING = _public_binding


def _public_command_binding(
    upstream: RepositoryExecutableNativeDependencyManifestCommandBinding,
) -> RepositoryExecutableNativeDependencyManifestTargetCommandBinding:
    if type(upstream) is not _FIXED_UPSTREAM_COMMAND_BINDING_TYPE:
        raise _InvalidNativeDependencyManifestTargets
    reference = _BUILTIN_COMMAND_BINDING_REF_PROJECTION(
        command_kind=upstream.command_kind,
        command_id=upstream.command_id,
        command_digest=upstream.command_digest,
        staged_file_ref=upstream.staged_file_ref,
        runtime_file_ref=upstream.runtime_file_ref,
        native_dependency_requirement_ref=upstream.native_dependency_requirement_ref,
        manifest_requirement_ref=upstream.manifest_requirement_ref,
    )
    value = _FIXED_COMMAND_BINDING_TYPE(
        kind=_FIXED_COMMAND_BINDING_KIND,
        command_kind=upstream.command_kind,
        command_id=upstream.command_id,
        command_digest=upstream.command_digest,
        staged_file_ref=upstream.staged_file_ref,
        runtime_file_ref=upstream.runtime_file_ref,
        native_dependency_requirement_ref=upstream.native_dependency_requirement_ref,
        manifest_requirement_ref=upstream.manifest_requirement_ref,
        target_command_binding_ref=_BUILTIN_CANONICAL_DIGEST(reference),
    )
    _BUILTIN_COMMAND_BINDING_PROJECTION(value)
    return value


_BUILTIN_PUBLIC_COMMAND_BINDING = _public_command_binding


def inspect_staged_executable_native_dependency_manifest_targets(
    expected_manifest: RepositoryExecutableNativeDependencyManifestReceipt,
    *,
    expected_requirements: RepositoryExecutableNativeDependencyRequirementsReceipt,
    expected_runtime: RepositoryExecutableRuntimeManifestReceipt,
    expected_staging: RepositoryExecutableStagingReceipt,
    lease: RepositoryExecutableStageLease,
    expected_non_absolute_dependency_manifest: tuple[RepositoryExecutableNativeDependencyManifestEntry, ...],
) -> RepositoryExecutableNativeDependencyManifestTargetsReceipt:
    """Measure only targets from an exact controller-owned manifest."""

    try:
        first = _BUILTIN_VALIDATE_INPUTS_AND_REPRODUCE_MANIFEST(
            expected_manifest,
            expected_requirements,
            expected_runtime,
            expected_staging,
            lease,
            expected_non_absolute_dependency_manifest,
        )
        derived, paths, manifest_canonical, requirements_canonical, runtime_canonical, staging_canonical = first
        first_measurement = _BUILTIN_MEASURE_TARGET_SET(paths)
        middle = _BUILTIN_VALIDATE_INPUTS_AND_REPRODUCE_MANIFEST(
            expected_manifest,
            expected_requirements,
            expected_runtime,
            expected_staging,
            lease,
            expected_non_absolute_dependency_manifest,
        )
        if middle != first:
            raise _InvalidNativeDependencyManifestTargets
        second_measurement = _BUILTIN_MEASURE_TARGET_SET(paths)
        if second_measurement != first_measurement:
            raise _InvalidNativeDependencyManifestTargets
        final = _BUILTIN_VALIDATE_INPUTS_AND_REPRODUCE_MANIFEST(
            expected_manifest,
            expected_requirements,
            expected_runtime,
            expected_staging,
            lease,
            expected_non_absolute_dependency_manifest,
        )
        if (
            final != first
            or any(not _BUILTIN_TARGET_NAMESPACE_MATCHES(item) for item in first_measurement)
        ):
            raise _InvalidNativeDependencyManifestTargets
        if _BUILTIN_ACTIVE_STAGE_SNAPSHOT(expected_staging, lease)[0] != staging_canonical:
            raise _InvalidNativeDependencyManifestTargets
        target_ref_by_path = {
            item.target_path: item.upstream.manifest_target_ref for item in derived
        }
        measurements = tuple(
            _BUILTIN_PUBLIC_MEASUREMENT(
                measured,
                manifest_target_ref=target_ref_by_path[measured.path],
            )
            for measured in first_measurement
        )
        measurement_by_path = {
            measured.path: public
            for measured, public in zip(first_measurement, measurements, strict=True)
        }
        requirement_by_binding_ref = {
            binding.manifest_binding_ref: requirement.manifest_requirement_ref
            for requirement in expected_manifest.requirements
            for binding in requirement.bindings
        }
        bindings = tuple(
            _BUILTIN_PUBLIC_BINDING(
                item,
                measurement_by_path=measurement_by_path,
                requirement_by_binding_ref=requirement_by_binding_ref,
            )
            for item in derived
        )
        command_bindings = tuple(
            _BUILTIN_PUBLIC_COMMAND_BINDING(item)
            for item in expected_manifest.command_bindings
        )
        receipt = _FIXED_RECEIPT_TYPE(
            kind=_FIXED_RECEIPT_KIND,
            schema_version=_FIXED_SCHEMA_VERSION,
            measurement_source=_FIXED_MEASUREMENT_SOURCE,
            measurement_scope=_FIXED_MEASUREMENT_SCOPE,
            native_dependency_manifest_receipt_digest=_BUILTIN_CANONICAL_DIGEST(manifest_canonical),
            native_dependency_requirements_receipt_digest=_BUILTIN_CANONICAL_DIGEST(requirements_canonical),
            runtime_manifest_receipt_digest=_BUILTIN_CANONICAL_DIGEST(runtime_canonical),
            staging_receipt_digest=_BUILTIN_CANONICAL_DIGEST(staging_canonical),
            registration_digest=expected_manifest.registration_digest,
            repository_ref=expected_manifest.repository_ref,
            verification_commands_digest=expected_manifest.verification_commands_digest,
            resolution_context_digest=expected_manifest.resolution_context_digest,
            staging_context_digest=expected_manifest.staging_context_digest,
            manifest_context_digest=expected_manifest.manifest_context_digest,
            manifest_binding_context_digest=_BUILTIN_CANONICAL_DIGEST(
                {
                    "kind": "repository_executable_native_dependency_manifest_target_binding_context",
                    "measurement_scope": _FIXED_MEASUREMENT_SCOPE,
                    "ordered_manifest_binding_refs": [
                        item.manifest_binding_ref for item in bindings
                    ],
                    "schema_version": _FIXED_SCHEMA_VERSION,
                }
            ),
            measurements=measurements,
            bindings=bindings,
            command_bindings=command_bindings,
            requirement_count=expected_manifest.requirement_count,
            command_count=len(command_bindings),
            manifest_binding_count=len(bindings),
            unique_target_count=len(measurements),
            total_measured_bytes=sum(item.content_bytes for item in measurements),
        )
        _BUILTIN_RECEIPT_PROJECTION(receipt)
        return receipt
    except (KeyboardInterrupt, SystemExit):
        raise
    except _InvalidNativeDependencyManifestTargets:
        raise _FIXED_VALIDATION_ERROR(_INVALID_MESSAGE) from None
    except Exception:
        raise _FIXED_VALIDATION_ERROR(_INVALID_MESSAGE) from None


__all__ = [
    "MEASUREMENT_SCOPE",
    "MEASUREMENT_SOURCE",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_BINDING_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_COMMAND_BINDING_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_MEASUREMENT_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGETS_EVIDENCE_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGETS_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGETS_SCHEMA_VERSION",
    "RepositoryExecutableNativeDependencyManifestTargetBinding",
    "RepositoryExecutableNativeDependencyManifestTargetCommandBinding",
    "RepositoryExecutableNativeDependencyManifestTargetMeasurement",
    "RepositoryExecutableNativeDependencyManifestTargetsReceipt",
    "inspect_staged_executable_native_dependency_manifest_targets",
]
