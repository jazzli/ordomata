"""Measure only controller-mapped dependencies of detached manifest targets.

This Class 0 boundary re-proves the explicit staged-target dependency mapping
around matching no-follow measurements.  It neither derives a loader search
path nor opens any declaration not supplied by the private controller mapping.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import re
from typing import Any

from .authorization import canonical_json
from .errors import ValidationError
from .repository_executable_native_dependency_manifest_target_dependency_manifest import (
    RepositoryExecutableNativeDependencyManifestTargetDependencyManifestBinding,
    RepositoryExecutableNativeDependencyManifestTargetDependencyManifestEntry,
    RepositoryExecutableNativeDependencyManifestTargetDependencyManifestReceipt,
    _receipt_projection as _manifest_projection,
    inspect_staged_executable_native_dependency_manifest_target_dependency_manifest,
)
from .repository_executable_native_dependency_manifest_target_dependency_requirements import (
    RepositoryExecutableNativeDependencyManifestTargetDependencyRequirementsReceipt,
    _receipt_projection as _dependency_projection,
)
from .repository_executable_native_dependency_manifest_target_runtime_manifest import (
    RepositoryExecutableNativeDependencyManifestTargetRuntimeManifestReceipt,
    _runtime_manifest_projection,
)
from .repository_executable_native_dependency_manifest_target_staging import (
    RepositoryExecutableNativeDependencyManifestTargetStageLease,
    RepositoryExecutableNativeDependencyManifestTargetStagingReceipt,
    _staging_receipt_projection,
)
from .repository_executable_native_loader_target_resolution import (
    _MeasuredTarget,
    _measure_target_set,
    _target_namespace_matches,
)


REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_TARGETS_SCHEMA_VERSION = 1
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_TARGETS_KIND = "repository_executable_native_dependency_manifest_target_dependency_manifest_targets"
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_TARGETS_EVIDENCE_KIND = "repository_executable_native_dependency_manifest_target_dependency_manifest_targets_validation"
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_TARGET_MEASUREMENT_KIND = "repository_executable_native_dependency_manifest_target_dependency_manifest_target_measurement"
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_TARGET_BINDING_KIND = "repository_executable_native_dependency_manifest_target_dependency_manifest_target_binding"
MEASUREMENT_SOURCE = "controller_measured"
MEASUREMENT_SCOPE = "explicit_staged_manifest_target_dependency_mapping_nofollow_v1"

_FIXED_SCHEMA_VERSION = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_TARGETS_SCHEMA_VERSION
_FIXED_RECEIPT_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_TARGETS_KIND
_FIXED_EVIDENCE_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_TARGETS_EVIDENCE_KIND
_FIXED_MEASUREMENT_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_TARGET_MEASUREMENT_KIND
_FIXED_BINDING_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_TARGET_BINDING_KIND
_FIXED_SOURCE = MEASUREMENT_SOURCE
_FIXED_SCOPE = MEASUREMENT_SCOPE
_INVALID_MESSAGE = "repository executable native dependency manifest target dependency manifest targets are invalid"
_DIGEST_PREFIX = "sha256:"
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_BINDINGS = 512
_MAX_TARGET_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_TARGET_BYTES = 256 * 1024 * 1024
_CONCRETE_PATH_TYPE = type(Path())


def _captured_canonical_digest(value: Any) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


_BUILTIN_CANONICAL_DIGEST = _captured_canonical_digest
_BUILTIN_MANIFEST_PROJECTION = _manifest_projection
_BUILTIN_DEPENDENCY_PROJECTION = _dependency_projection
_BUILTIN_RUNTIME_PROJECTION = _runtime_manifest_projection
_BUILTIN_STAGING_PROJECTION = _staging_receipt_projection
_BUILTIN_INSPECT_MANIFEST = inspect_staged_executable_native_dependency_manifest_target_dependency_manifest
_BUILTIN_MEASURE_TARGET_SET = _measure_target_set
_BUILTIN_NAMESPACE_MATCHES = _target_namespace_matches
_FIXED_MANIFEST_TYPE = RepositoryExecutableNativeDependencyManifestTargetDependencyManifestReceipt
_FIXED_MANIFEST_ENTRY_TYPE = RepositoryExecutableNativeDependencyManifestTargetDependencyManifestEntry
_FIXED_MANIFEST_BINDING_TYPE = RepositoryExecutableNativeDependencyManifestTargetDependencyManifestBinding
_FIXED_DEPENDENCY_TYPE = RepositoryExecutableNativeDependencyManifestTargetDependencyRequirementsReceipt
_FIXED_RUNTIME_TYPE = RepositoryExecutableNativeDependencyManifestTargetRuntimeManifestReceipt
_FIXED_STAGING_TYPE = RepositoryExecutableNativeDependencyManifestTargetStagingReceipt
_FIXED_LEASE_TYPE = RepositoryExecutableNativeDependencyManifestTargetStageLease
_FIXED_MEASURED_TARGET_TYPE = _MeasuredTarget
_FIXED_VALIDATION_ERROR = ValidationError


class _InvalidManifestTargets(ValueError):
    """Private sentinel whose details are never returned to callers."""


def _is_digest(value: Any) -> bool:
    return type(value) is str and _DIGEST_PATTERN.fullmatch(value) is not None


_BUILTIN_IS_DIGEST = _is_digest


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeDependencyManifestTargetDependencyManifestTargetMeasurement:
    """Digest-only no-follow measurement of one mapped next-hop target."""

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
class RepositoryExecutableNativeDependencyManifestTargetDependencyManifestTargetBinding:
    """One exact staged declaration joined to its mapped target measurement."""

    kind: str
    target_runtime_file_ref: str = field(repr=False)
    dependency_declaration_ref: str = field(repr=False)
    dependency_name_ref: str = field(repr=False)
    format_class: str
    ordinal: int
    path_style: str
    manifest_target_ref: str = field(repr=False)
    manifest_binding_ref: str = field(repr=False)
    target_measurement_ref: str = field(repr=False)
    target_binding_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_BINDING_PROJECTION(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeDependencyManifestTargetDependencyManifestTargetsReceipt:
    """Digest-only target-measurement evidence for one active staged chain."""

    kind: str
    schema_version: int
    measurement_source: str
    measurement_scope: str
    target_dependency_manifest_receipt_digest: str = field(repr=False)
    target_dependency_requirements_receipt_digest: str = field(repr=False)
    target_runtime_manifest_receipt_digest: str = field(repr=False)
    target_staging_receipt_digest: str = field(repr=False)
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
    target_staging_context_digest: str = field(repr=False)
    measurements: tuple[RepositoryExecutableNativeDependencyManifestTargetDependencyManifestTargetMeasurement, ...] = field(repr=False)
    bindings: tuple[RepositoryExecutableNativeDependencyManifestTargetDependencyManifestTargetBinding, ...] = field(repr=False)
    requirement_count: int
    dependency_declaration_count: int
    manifest_bound_dependency_count: int
    unique_target_count: int
    total_measured_bytes: int

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_RECEIPT_PROJECTION(self)

    @property
    def receipt_digest(self) -> str:
        return _BUILTIN_CANONICAL_DIGEST(_receipt_projection(self))

    def to_evidence(self) -> dict[str, Any]:
        return _BUILTIN_EVIDENCE_PROJECTION(self)


_FIXED_MEASUREMENT_TYPE = RepositoryExecutableNativeDependencyManifestTargetDependencyManifestTargetMeasurement
_FIXED_BINDING_TYPE = RepositoryExecutableNativeDependencyManifestTargetDependencyManifestTargetBinding
_FIXED_RECEIPT_TYPE = RepositoryExecutableNativeDependencyManifestTargetDependencyManifestTargetsReceipt


def _measurement_ref_projection(*, manifest_target_ref: str, filesystem_identity_ref: str, metadata_digest: str, content_digest: str, content_bytes: int) -> dict[str, Any]:
    return {"content_bytes": content_bytes, "content_digest": content_digest, "filesystem_identity_ref": filesystem_identity_ref, "kind": "repository_executable_native_dependency_manifest_target_dependency_manifest_target_measurement_ref", "manifest_target_ref": manifest_target_ref, "measurement_scope": _FIXED_SCOPE, "measurement_source": _FIXED_SOURCE, "metadata_digest": metadata_digest, "schema_version": _FIXED_SCHEMA_VERSION}


def _measurement_projection(value: Any) -> dict[str, Any]:
    if type(value) is not _FIXED_MEASUREMENT_TYPE or value.kind != _FIXED_MEASUREMENT_KIND or not all(_BUILTIN_IS_DIGEST(item) for item in (value.manifest_target_ref, value.filesystem_identity_ref, value.metadata_digest, value.content_digest, value.measurement_ref)) or type(value.content_bytes) is not int or not 0 <= value.content_bytes <= _MAX_TARGET_BYTES:
        raise _InvalidManifestTargets
    reference = _BUILTIN_MEASUREMENT_REF_PROJECTION(manifest_target_ref=value.manifest_target_ref, filesystem_identity_ref=value.filesystem_identity_ref, metadata_digest=value.metadata_digest, content_digest=value.content_digest, content_bytes=value.content_bytes)
    if value.measurement_ref != _BUILTIN_CANONICAL_DIGEST(reference):
        raise _InvalidManifestTargets
    return {**reference, "kind": value.kind, "measurement_ref": value.measurement_ref}


def _binding_ref_projection(*, target_runtime_file_ref: str, dependency_declaration_ref: str, dependency_name_ref: str, format_class: str, ordinal: int, path_style: str, manifest_target_ref: str, manifest_binding_ref: str, target_measurement_ref: str) -> dict[str, Any]:
    return {"dependency_declaration_ref": dependency_declaration_ref, "dependency_name_ref": dependency_name_ref, "format_class": format_class, "kind": "repository_executable_native_dependency_manifest_target_dependency_manifest_target_binding_ref", "manifest_binding_ref": manifest_binding_ref, "manifest_target_ref": manifest_target_ref, "measurement_scope": _FIXED_SCOPE, "ordinal": ordinal, "path_style": path_style, "schema_version": _FIXED_SCHEMA_VERSION, "target_measurement_ref": target_measurement_ref, "target_runtime_file_ref": target_runtime_file_ref}


def _binding_projection(value: Any) -> dict[str, Any]:
    if type(value) is not _FIXED_BINDING_TYPE or value.kind != _FIXED_BINDING_KIND or not all(_BUILTIN_IS_DIGEST(item) for item in (value.target_runtime_file_ref, value.dependency_declaration_ref, value.dependency_name_ref, value.manifest_target_ref, value.manifest_binding_ref, value.target_measurement_ref, value.target_binding_ref)) or value.format_class not in {"elf32", "elf64", "mach_o32", "mach_o64"} or type(value.ordinal) is not int or value.ordinal < 0 or value.path_style not in {"bare", "relative", "at_rpath", "at_loader_path", "at_executable_path"}:
        raise _InvalidManifestTargets
    reference = _BUILTIN_BINDING_REF_PROJECTION(target_runtime_file_ref=value.target_runtime_file_ref, dependency_declaration_ref=value.dependency_declaration_ref, dependency_name_ref=value.dependency_name_ref, format_class=value.format_class, ordinal=value.ordinal, path_style=value.path_style, manifest_target_ref=value.manifest_target_ref, manifest_binding_ref=value.manifest_binding_ref, target_measurement_ref=value.target_measurement_ref)
    if value.target_binding_ref != _BUILTIN_CANONICAL_DIGEST(reference):
        raise _InvalidManifestTargets
    return {**reference, "kind": value.kind, "target_binding_ref": value.target_binding_ref}


_BUILTIN_MEASUREMENT_REF_PROJECTION = _measurement_ref_projection
_BUILTIN_MEASUREMENT_PROJECTION = _measurement_projection
_BUILTIN_BINDING_REF_PROJECTION = _binding_ref_projection
_BUILTIN_BINDING_PROJECTION = _binding_projection


def _receipt_projection(value: Any) -> dict[str, Any]:
    digests = (value.target_dependency_manifest_receipt_digest, value.target_dependency_requirements_receipt_digest, value.target_runtime_manifest_receipt_digest, value.target_staging_receipt_digest, value.native_dependency_manifest_targets_receipt_digest, value.native_dependency_manifest_receipt_digest, value.native_dependency_requirements_receipt_digest, value.runtime_manifest_receipt_digest, value.staging_receipt_digest, value.registration_digest, value.repository_ref, value.verification_commands_digest, value.resolution_context_digest, value.source_staging_context_digest, value.manifest_context_digest, value.target_staging_context_digest)
    if type(value) is not _FIXED_RECEIPT_TYPE or value.kind != _FIXED_RECEIPT_KIND or value.schema_version != _FIXED_SCHEMA_VERSION or value.measurement_source != _FIXED_SOURCE or value.measurement_scope != _FIXED_SCOPE or not all(_BUILTIN_IS_DIGEST(item) for item in digests) or type(value.measurements) is not tuple or type(value.bindings) is not tuple or len(value.measurements) > _MAX_BINDINGS or len(value.bindings) > _MAX_BINDINGS or type(value.requirement_count) is not int or value.requirement_count < 0 or any(type(item) is not int or item < 0 for item in (value.dependency_declaration_count, value.manifest_bound_dependency_count, value.unique_target_count, value.total_measured_bytes)) or value.manifest_bound_dependency_count != len(value.bindings) or value.unique_target_count != len(value.measurements) or value.total_measured_bytes > _MAX_TOTAL_TARGET_BYTES:
        raise _InvalidManifestTargets
    measurements = [_BUILTIN_MEASUREMENT_PROJECTION(item) for item in value.measurements]
    bindings = [_BUILTIN_BINDING_PROJECTION(item) for item in value.bindings]
    by_measurement = {item["measurement_ref"]: item for item in measurements}
    if len(by_measurement) != len(measurements) or len({item["manifest_target_ref"] for item in measurements}) != len(measurements) or len({item["target_binding_ref"] for item in bindings}) != len(bindings) or len({item["manifest_binding_ref"] for item in bindings}) != len(bindings) or any(item["target_measurement_ref"] not in by_measurement or by_measurement[item["target_measurement_ref"]]["manifest_target_ref"] != item["manifest_target_ref"] for item in bindings) or sum(item["content_bytes"] for item in measurements) != value.total_measured_bytes:
        raise _InvalidManifestTargets
    return {"bindings": bindings, "dependency_declaration_count": value.dependency_declaration_count, "kind": value.kind, "manifest_bound_dependency_count": value.manifest_bound_dependency_count, "manifest_context_digest": value.manifest_context_digest, "measurements": measurements, "measurement_scope": value.measurement_scope, "measurement_source": value.measurement_source, "native_dependency_manifest_receipt_digest": value.native_dependency_manifest_receipt_digest, "native_dependency_manifest_targets_receipt_digest": value.native_dependency_manifest_targets_receipt_digest, "native_dependency_requirements_receipt_digest": value.native_dependency_requirements_receipt_digest, "registration_digest": value.registration_digest, "repository_ref": value.repository_ref, "requirement_count": value.requirement_count, "resolution_context_digest": value.resolution_context_digest, "runtime_manifest_receipt_digest": value.runtime_manifest_receipt_digest, "schema_version": value.schema_version, "source_staging_context_digest": value.source_staging_context_digest, "staging_receipt_digest": value.staging_receipt_digest, "target_dependency_manifest_receipt_digest": value.target_dependency_manifest_receipt_digest, "target_dependency_requirements_receipt_digest": value.target_dependency_requirements_receipt_digest, "target_runtime_manifest_receipt_digest": value.target_runtime_manifest_receipt_digest, "target_staging_context_digest": value.target_staging_context_digest, "target_staging_receipt_digest": value.target_staging_receipt_digest, "total_measured_bytes": value.total_measured_bytes, "unique_target_count": value.unique_target_count, "verification_commands_digest": value.verification_commands_digest}


def _evidence_projection(value: Any) -> dict[str, Any]:
    canonical = _BUILTIN_RECEIPT_PROJECTION(value)
    return {"ambient_loader_environment_consulted": False, "authority_granted": False, "controller_explicit_mapping_reproduced": True, "dependency_closure_verified": False, "dependency_path_lookup_performed": bool(value.measurements), "dispatch_enabled": False, "effect_class": 0, "execution_enabled": False, "kind": _FIXED_EVIDENCE_KIND, "loader_invocation_performed": False, "manifest_target_raw_values_exposed": False, "model_invocation_performed": False, "network_access_performed": False, "path_open_performed": bool(value.measurements), "receipt_digest": _BUILTIN_CANONICAL_DIGEST(canonical), "recursive_dependency_resolution_verified": False, "staging_performed": False, "subprocess_invocation_performed": False, "target_nofollow_measurement_complete": True, "tokenized_loader_path_expansion_performed": False, "validation_mode": "read_only"}


_BUILTIN_RECEIPT_PROJECTION = _receipt_projection
_BUILTIN_EVIDENCE_PROJECTION = _evidence_projection


@dataclass(frozen=True, slots=True)
class _DerivedTarget:
    binding: RepositoryExecutableNativeDependencyManifestTargetDependencyManifestBinding = field(repr=False)
    target_path: Path = field(repr=False)


_FIXED_DERIVED_TYPE = _DerivedTarget


def _reproduce(expected_manifest: Any, expected_dependencies: Any, expected_runtime: Any, expected_staging: Any, lease: Any, entries: Any) -> tuple[tuple[_DerivedTarget, ...], tuple[Path, ...], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    if type(expected_manifest) is not _FIXED_MANIFEST_TYPE or type(expected_dependencies) is not _FIXED_DEPENDENCY_TYPE or type(expected_runtime) is not _FIXED_RUNTIME_TYPE or type(expected_staging) is not _FIXED_STAGING_TYPE or type(lease) is not _FIXED_LEASE_TYPE or type(entries) is not tuple or len(entries) > _MAX_BINDINGS:
        raise _InvalidManifestTargets
    manifest_canonical = _BUILTIN_MANIFEST_PROJECTION(expected_manifest)
    dependencies_canonical = _BUILTIN_DEPENDENCY_PROJECTION(expected_dependencies)
    runtime_canonical = _BUILTIN_RUNTIME_PROJECTION(expected_runtime)
    staging_canonical = _BUILTIN_STAGING_PROJECTION(expected_staging)
    if expected_manifest.target_dependency_requirements_receipt_digest != _BUILTIN_CANONICAL_DIGEST(dependencies_canonical) or expected_manifest.target_runtime_manifest_receipt_digest != _BUILTIN_CANONICAL_DIGEST(runtime_canonical) or expected_manifest.target_staging_receipt_digest != _BUILTIN_CANONICAL_DIGEST(staging_canonical):
        raise _InvalidManifestTargets
    fresh = _BUILTIN_INSPECT_MANIFEST(expected_dependencies, expected_target_runtime=expected_runtime, expected_target_staging=expected_staging, lease=lease, expected_non_absolute_dependency_manifest=entries)
    if _BUILTIN_MANIFEST_PROJECTION(fresh) != manifest_canonical:
        raise _InvalidManifestTargets
    upstream = tuple(binding for requirement in fresh.requirements for binding in requirement.bindings)
    if len(upstream) != len(entries):
        raise _InvalidManifestTargets
    paths_by_target: dict[str, Path] = {}
    derived: list[_DerivedTarget] = []
    for binding, entry in zip(upstream, entries, strict=True):
        if type(binding) is not _FIXED_MANIFEST_BINDING_TYPE or type(entry) is not _FIXED_MANIFEST_ENTRY_TYPE or type(entry.target_path) is not _CONCRETE_PATH_TYPE or entry.target_runtime_file_ref != binding.target_runtime_file_ref or entry.dependency_declaration_ref != binding.dependency_declaration_ref:
            raise _InvalidManifestTargets
        prior = paths_by_target.get(binding.manifest_target_ref)
        if prior is None:
            paths_by_target[binding.manifest_target_ref] = entry.target_path
        elif prior != entry.target_path:
            raise _InvalidManifestTargets
        derived.append(_FIXED_DERIVED_TYPE(binding=binding, target_path=entry.target_path))
    return tuple(derived), tuple(paths_by_target.values()), manifest_canonical, dependencies_canonical, runtime_canonical, staging_canonical


def _identity_ref(measured: Any) -> str:
    if type(measured) is not _FIXED_MEASURED_TARGET_TYPE or type(measured.identity) is not tuple or len(measured.identity) != 2 or any(type(item) is not int for item in measured.identity):
        raise _InvalidManifestTargets
    return _BUILTIN_CANONICAL_DIGEST({"device": measured.identity[0], "inode": measured.identity[1], "kind": "repository_executable_native_dependency_manifest_target_dependency_manifest_target_file_identity", "schema_version": _FIXED_SCHEMA_VERSION})


def _public_measurement(measured: Any, *, manifest_target_ref: str) -> RepositoryExecutableNativeDependencyManifestTargetDependencyManifestTargetMeasurement:
    if type(measured) is not _FIXED_MEASURED_TARGET_TYPE or type(measured.path) is not _CONCRETE_PATH_TYPE or not _BUILTIN_IS_DIGEST(manifest_target_ref) or not _BUILTIN_IS_DIGEST(measured.content_digest) or type(measured.content_bytes) is not int or not 0 <= measured.content_bytes <= _MAX_TARGET_BYTES or type(measured.metadata) is not tuple or len(measured.metadata) != 9 or any(type(item) is not int for item in measured.metadata) or measured.metadata[:2] != measured.identity or measured.metadata[6] != measured.content_bytes:
        raise _InvalidManifestTargets
    identity_ref = _BUILTIN_IDENTITY_REF(measured)
    metadata_digest = _BUILTIN_CANONICAL_DIGEST({"change_time_ns": measured.metadata[8], "filesystem_identity_ref": identity_ref, "group_id": measured.metadata[5], "kind": "repository_executable_native_dependency_manifest_target_dependency_manifest_target_file_metadata", "link_count": measured.metadata[3], "mode": measured.metadata[2], "modified_time_ns": measured.metadata[7], "owner_id": measured.metadata[4], "schema_version": _FIXED_SCHEMA_VERSION, "size_bytes": measured.metadata[6]})
    reference = _BUILTIN_MEASUREMENT_REF_PROJECTION(manifest_target_ref=manifest_target_ref, filesystem_identity_ref=identity_ref, metadata_digest=metadata_digest, content_digest=measured.content_digest, content_bytes=measured.content_bytes)
    value = _FIXED_MEASUREMENT_TYPE(kind=_FIXED_MEASUREMENT_KIND, manifest_target_ref=manifest_target_ref, filesystem_identity_ref=identity_ref, metadata_digest=metadata_digest, content_digest=measured.content_digest, content_bytes=measured.content_bytes, measurement_ref=_BUILTIN_CANONICAL_DIGEST(reference))
    _BUILTIN_MEASUREMENT_PROJECTION(value)
    return value


def _public_binding(derived: Any, measurements: dict[Path, RepositoryExecutableNativeDependencyManifestTargetDependencyManifestTargetMeasurement]) -> RepositoryExecutableNativeDependencyManifestTargetDependencyManifestTargetBinding:
    if type(derived) is not _FIXED_DERIVED_TYPE or type(derived.binding) is not _FIXED_MANIFEST_BINDING_TYPE:
        raise _InvalidManifestTargets
    source = derived.binding
    measurement = measurements.get(derived.target_path)
    if measurement is None or measurement.manifest_target_ref != source.manifest_target_ref:
        raise _InvalidManifestTargets
    reference = _BUILTIN_BINDING_REF_PROJECTION(target_runtime_file_ref=source.target_runtime_file_ref, dependency_declaration_ref=source.dependency_declaration_ref, dependency_name_ref=source.dependency_name_ref, format_class=source.format_class, ordinal=source.ordinal, path_style=source.path_style, manifest_target_ref=source.manifest_target_ref, manifest_binding_ref=source.manifest_binding_ref, target_measurement_ref=measurement.measurement_ref)
    value = _FIXED_BINDING_TYPE(kind=_FIXED_BINDING_KIND, target_runtime_file_ref=source.target_runtime_file_ref, dependency_declaration_ref=source.dependency_declaration_ref, dependency_name_ref=source.dependency_name_ref, format_class=source.format_class, ordinal=source.ordinal, path_style=source.path_style, manifest_target_ref=source.manifest_target_ref, manifest_binding_ref=source.manifest_binding_ref, target_measurement_ref=measurement.measurement_ref, target_binding_ref=_BUILTIN_CANONICAL_DIGEST(reference))
    _BUILTIN_BINDING_PROJECTION(value)
    return value


_BUILTIN_REPRODUCE = _reproduce
_BUILTIN_IDENTITY_REF = _identity_ref
_BUILTIN_PUBLIC_MEASUREMENT = _public_measurement
_BUILTIN_PUBLIC_BINDING = _public_binding


def inspect_staged_executable_native_dependency_manifest_target_dependency_manifest_targets(expected_manifest: RepositoryExecutableNativeDependencyManifestTargetDependencyManifestReceipt, *, expected_dependencies: RepositoryExecutableNativeDependencyManifestTargetDependencyRequirementsReceipt, expected_target_runtime: RepositoryExecutableNativeDependencyManifestTargetRuntimeManifestReceipt, expected_target_staging: RepositoryExecutableNativeDependencyManifestTargetStagingReceipt, lease: RepositoryExecutableNativeDependencyManifestTargetStageLease, expected_non_absolute_dependency_manifest: tuple[RepositoryExecutableNativeDependencyManifestTargetDependencyManifestEntry, ...]) -> RepositoryExecutableNativeDependencyManifestTargetDependencyManifestTargetsReceipt:
    """Measure exact next-hop targets from a freshly reproduced private mapping."""

    try:
        first = _BUILTIN_REPRODUCE(expected_manifest, expected_dependencies, expected_target_runtime, expected_target_staging, lease, expected_non_absolute_dependency_manifest)
        derived, paths, manifest_canonical, dependencies_canonical, runtime_canonical, staging_canonical = first
        first_measurement = _BUILTIN_MEASURE_TARGET_SET(paths)
        middle = _BUILTIN_REPRODUCE(expected_manifest, expected_dependencies, expected_target_runtime, expected_target_staging, lease, expected_non_absolute_dependency_manifest)
        if middle != first:
            raise _InvalidManifestTargets
        second_measurement = _BUILTIN_MEASURE_TARGET_SET(paths)
        final = _BUILTIN_REPRODUCE(expected_manifest, expected_dependencies, expected_target_runtime, expected_target_staging, lease, expected_non_absolute_dependency_manifest)
        if second_measurement != first_measurement or final != first or any(not _BUILTIN_NAMESPACE_MATCHES(item) for item in first_measurement):
            raise _InvalidManifestTargets
        target_refs = {item.target_path: item.binding.manifest_target_ref for item in derived}
        measurements = tuple(_BUILTIN_PUBLIC_MEASUREMENT(item, manifest_target_ref=target_refs[item.path]) for item in first_measurement)
        measurements_by_path = {item.path: public for item, public in zip(first_measurement, measurements, strict=True)}
        bindings = tuple(_BUILTIN_PUBLIC_BINDING(item, measurements_by_path) for item in derived)
        receipt = _FIXED_RECEIPT_TYPE(kind=_FIXED_RECEIPT_KIND, schema_version=_FIXED_SCHEMA_VERSION, measurement_source=_FIXED_SOURCE, measurement_scope=_FIXED_SCOPE, target_dependency_manifest_receipt_digest=_BUILTIN_CANONICAL_DIGEST(manifest_canonical), target_dependency_requirements_receipt_digest=_BUILTIN_CANONICAL_DIGEST(dependencies_canonical), target_runtime_manifest_receipt_digest=_BUILTIN_CANONICAL_DIGEST(runtime_canonical), target_staging_receipt_digest=_BUILTIN_CANONICAL_DIGEST(staging_canonical), native_dependency_manifest_targets_receipt_digest=staging_canonical["native_dependency_manifest_targets_receipt_digest"], native_dependency_manifest_receipt_digest=staging_canonical["native_dependency_manifest_receipt_digest"], native_dependency_requirements_receipt_digest=staging_canonical["native_dependency_requirements_receipt_digest"], runtime_manifest_receipt_digest=staging_canonical["runtime_manifest_receipt_digest"], staging_receipt_digest=staging_canonical["staging_receipt_digest"], registration_digest=staging_canonical["registration_digest"], repository_ref=staging_canonical["repository_ref"], verification_commands_digest=staging_canonical["verification_commands_digest"], resolution_context_digest=staging_canonical["resolution_context_digest"], source_staging_context_digest=staging_canonical["source_staging_context_digest"], manifest_context_digest=staging_canonical["manifest_context_digest"], target_staging_context_digest=staging_canonical["target_staging_context_digest"], measurements=measurements, bindings=bindings, requirement_count=expected_manifest.requirement_count, dependency_declaration_count=expected_manifest.dependency_declaration_count, manifest_bound_dependency_count=len(bindings), unique_target_count=len(measurements), total_measured_bytes=sum(item.content_bytes for item in measurements))
        _BUILTIN_RECEIPT_PROJECTION(receipt)
        return receipt
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _FIXED_VALIDATION_ERROR(_INVALID_MESSAGE) from None


__all__ = [
    "MEASUREMENT_SCOPE", "MEASUREMENT_SOURCE",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_TARGETS_SCHEMA_VERSION",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_TARGETS_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_TARGETS_EVIDENCE_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_TARGET_MEASUREMENT_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_TARGET_BINDING_KIND",
    "RepositoryExecutableNativeDependencyManifestTargetDependencyManifestTargetMeasurement",
    "RepositoryExecutableNativeDependencyManifestTargetDependencyManifestTargetBinding",
    "RepositoryExecutableNativeDependencyManifestTargetDependencyManifestTargetsReceipt",
    "inspect_staged_executable_native_dependency_manifest_target_dependency_manifest_targets",
]
