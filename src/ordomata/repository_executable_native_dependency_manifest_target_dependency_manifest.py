"""Bind non-absolute dependencies from detached manifest targets explicitly.

This Class 0 boundary accepts no ambient loader search input.  It validates a
fresh staged-target dependency receipt around an ordered controller-supplied
private spelling-to-canonical-path mapping and emits only digest-bound lineage.
Mapped paths are neither opened nor staged here.
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
from .repository_executable_native_dependency_manifest_target_dependency_requirements import (
    RepositoryExecutableNativeDependencyManifestTargetDependencyRequirementsReceipt,
    _receipt_projection as _dependency_receipt_projection,
    inspect_staged_executable_native_dependency_manifest_target_dependency_requirements,
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
from .repository_executable_native_dependency_requirements import _dependency_name_ref


REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_SCHEMA_VERSION = 1
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_KIND = (
    "repository_executable_native_dependency_manifest_target_dependency_manifest"
)
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_EVIDENCE_KIND = (
    "repository_executable_native_dependency_manifest_target_dependency_manifest_validation"
)
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_ENTRY_KIND = (
    "repository_executable_native_dependency_manifest_target_dependency_manifest_entry"
)
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_REQUIREMENT_KIND = (
    "repository_executable_native_dependency_manifest_target_dependency_manifest_requirement"
)
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_BINDING_KIND = (
    "repository_executable_native_dependency_manifest_target_dependency_manifest_binding"
)
MANIFEST_SOURCE = "controller_explicit"
MANIFEST_SCOPE = "explicit_staged_manifest_target_dependency_mapping_v1"

_FIXED_SCHEMA_VERSION = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_SCHEMA_VERSION
_FIXED_RECEIPT_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_KIND
_FIXED_EVIDENCE_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_EVIDENCE_KIND
_FIXED_ENTRY_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_ENTRY_KIND
_FIXED_REQUIREMENT_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_REQUIREMENT_KIND
_FIXED_BINDING_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_BINDING_KIND
_FIXED_MANIFEST_SOURCE = MANIFEST_SOURCE
_FIXED_MANIFEST_SCOPE = MANIFEST_SCOPE
_INVALID_MESSAGE = "repository executable native dependency manifest target dependency manifest is invalid"
_DIGEST_PREFIX = "sha256:"
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_BINDINGS = 512
_MAX_TARGET_PATH_BYTES = 4_095
_CONCRETE_PATH_TYPE = type(Path())


def _captured_canonical_digest(value: Any) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


_BUILTIN_CANONICAL_DIGEST = _captured_canonical_digest
_BUILTIN_DEPENDENCY_PROJECTION = _dependency_receipt_projection
_BUILTIN_RUNTIME_PROJECTION = _runtime_manifest_projection
_BUILTIN_STAGING_PROJECTION = _staging_receipt_projection
_BUILTIN_INSPECT_DEPENDENCIES = inspect_staged_executable_native_dependency_manifest_target_dependency_requirements
_BUILTIN_DEPENDENCY_NAME_REF = _dependency_name_ref
_FIXED_DEPENDENCY_RECEIPT_TYPE = RepositoryExecutableNativeDependencyManifestTargetDependencyRequirementsReceipt
_FIXED_RUNTIME_RECEIPT_TYPE = RepositoryExecutableNativeDependencyManifestTargetRuntimeManifestReceipt
_FIXED_STAGING_RECEIPT_TYPE = RepositoryExecutableNativeDependencyManifestTargetStagingReceipt
_FIXED_STAGE_LEASE_TYPE = RepositoryExecutableNativeDependencyManifestTargetStageLease
_FIXED_VALIDATION_ERROR = ValidationError
_BUILTIN_FSPATH = os.fspath


class _InvalidTargetDependencyManifest(ValueError):
    """Private sentinel whose diagnostics never cross this boundary."""


def _is_digest(value: Any) -> bool:
    return type(value) is str and _DIGEST_PATTERN.fullmatch(value) is not None


def _canonical_target_path(path: Any) -> Path:
    if type(path) is not _CONCRETE_PATH_TYPE:
        raise _InvalidTargetDependencyManifest
    try:
        spelling = _BUILTIN_FSPATH(path)
        encoded = spelling.encode("ascii")
    except (AttributeError, TypeError, UnicodeEncodeError):
        raise _InvalidTargetDependencyManifest from None
    if not spelling.startswith("/") or spelling == "/" or spelling.endswith("/") or "//" in spelling or not 1 <= len(encoded) <= _MAX_TARGET_PATH_BYTES:
        raise _InvalidTargetDependencyManifest
    components = spelling[1:].split("/")
    if any(not component or component in {".", ".."} or any(ord(character) < 0x20 or ord(character) == 0x7F for character in component) for component in components):
        raise _InvalidTargetDependencyManifest
    return path


def _target_ref(path: Path) -> str:
    canonical = _BUILTIN_CANONICAL_TARGET_PATH(path)
    return _BUILTIN_CANONICAL_DIGEST({
        "kind": "repository_executable_native_dependency_manifest_target_dependency_manifest_target_ref",
        "manifest_scope": _FIXED_MANIFEST_SCOPE,
        "schema_version": _FIXED_SCHEMA_VERSION,
        "target_path_ascii": _BUILTIN_FSPATH(canonical),
    })


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeDependencyManifestTargetDependencyManifestEntry:
    """One private controller mapping for a non-absolute staged-target declaration."""

    kind: str
    target_runtime_file_ref: str = field(repr=False)
    dependency_declaration_ref: str = field(repr=False)
    dependency_name: bytes = field(repr=False)
    target_path: Path = field(repr=False)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeDependencyManifestTargetDependencyManifestBinding:
    """One declaration retained as a digest-bound explicit mapping."""

    kind: str
    target_runtime_file_ref: str = field(repr=False)
    dependency_declaration_ref: str = field(repr=False)
    dependency_name_ref: str = field(repr=False)
    format_class: str
    ordinal: int
    path_style: str
    manifest_target_ref: str = field(repr=False)
    manifest_binding_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _binding_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeDependencyManifestTargetDependencyManifestRequirement:
    """One staged target's mapped non-absolute declarations."""

    kind: str
    target_runtime_file_ref: str = field(repr=False)
    dependency_requirement_ref: str = field(repr=False)
    bindings: tuple[RepositoryExecutableNativeDependencyManifestTargetDependencyManifestBinding, ...] = field(repr=False)
    manifest_requirement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _requirement_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeDependencyManifestTargetDependencyManifestReceipt:
    """Digest-only explicit mapping evidence for one active staged-target chain."""

    kind: str
    schema_version: int
    manifest_source: str
    manifest_scope: str
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
    requirements: tuple[RepositoryExecutableNativeDependencyManifestTargetDependencyManifestRequirement, ...] = field(repr=False)
    requirement_count: int
    dependency_declaration_count: int
    non_absolute_dependency_declaration_count: int
    manifest_bound_dependency_count: int
    unique_manifest_target_count: int

    def to_canonical(self) -> dict[str, Any]:
        return _receipt_projection(self)

    @property
    def receipt_digest(self) -> str:
        return _BUILTIN_CANONICAL_DIGEST(_receipt_projection(self))

    def to_evidence(self) -> dict[str, Any]:
        return _evidence_projection(self)


_FIXED_ENTRY_TYPE = RepositoryExecutableNativeDependencyManifestTargetDependencyManifestEntry
_FIXED_BINDING_TYPE = RepositoryExecutableNativeDependencyManifestTargetDependencyManifestBinding
_FIXED_REQUIREMENT_TYPE = RepositoryExecutableNativeDependencyManifestTargetDependencyManifestRequirement
_FIXED_RECEIPT_TYPE = RepositoryExecutableNativeDependencyManifestTargetDependencyManifestReceipt


def _binding_ref_projection(*, target_runtime_file_ref: str, dependency_declaration_ref: str, dependency_name_ref: str, format_class: str, ordinal: int, path_style: str, manifest_target_ref: str) -> dict[str, Any]:
    return {
        "dependency_declaration_ref": dependency_declaration_ref,
        "dependency_name_ref": dependency_name_ref,
        "format_class": format_class,
        "kind": "repository_executable_native_dependency_manifest_target_dependency_manifest_binding_ref",
        "manifest_scope": _FIXED_MANIFEST_SCOPE,
        "manifest_target_ref": manifest_target_ref,
        "ordinal": ordinal,
        "path_style": path_style,
        "schema_version": _FIXED_SCHEMA_VERSION,
        "target_runtime_file_ref": target_runtime_file_ref,
    }


def _binding_projection(value: RepositoryExecutableNativeDependencyManifestTargetDependencyManifestBinding) -> dict[str, Any]:
    if type(value) is not _FIXED_BINDING_TYPE or value.kind != _FIXED_BINDING_KIND or not all(_is_digest(item) for item in (value.target_runtime_file_ref, value.dependency_declaration_ref, value.dependency_name_ref, value.manifest_target_ref, value.manifest_binding_ref)) or value.format_class not in {"elf32", "elf64", "mach_o32", "mach_o64"} or type(value.ordinal) is not int or value.ordinal < 0 or value.path_style not in {"bare", "relative", "at_rpath", "at_loader_path", "at_executable_path"}:
        raise _InvalidTargetDependencyManifest
    reference = _BUILTIN_BINDING_REF_PROJECTION(target_runtime_file_ref=value.target_runtime_file_ref, dependency_declaration_ref=value.dependency_declaration_ref, dependency_name_ref=value.dependency_name_ref, format_class=value.format_class, ordinal=value.ordinal, path_style=value.path_style, manifest_target_ref=value.manifest_target_ref)
    if value.manifest_binding_ref != _BUILTIN_CANONICAL_DIGEST(reference):
        raise _InvalidTargetDependencyManifest
    return {**reference, "kind": value.kind, "manifest_binding_ref": value.manifest_binding_ref}


def _requirement_ref_projection(*, target_runtime_file_ref: str, dependency_requirement_ref: str, bindings: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "bindings": bindings,
        "dependency_requirement_ref": dependency_requirement_ref,
        "kind": "repository_executable_native_dependency_manifest_target_dependency_manifest_requirement_ref",
        "manifest_scope": _FIXED_MANIFEST_SCOPE,
        "schema_version": _FIXED_SCHEMA_VERSION,
        "target_runtime_file_ref": target_runtime_file_ref,
    }


def _requirement_projection(value: RepositoryExecutableNativeDependencyManifestTargetDependencyManifestRequirement) -> dict[str, Any]:
    if type(value) is not _FIXED_REQUIREMENT_TYPE or value.kind != _FIXED_REQUIREMENT_KIND or not all(_is_digest(item) for item in (value.target_runtime_file_ref, value.dependency_requirement_ref, value.manifest_requirement_ref)) or type(value.bindings) is not tuple:
        raise _InvalidTargetDependencyManifest
    bindings = [_BUILTIN_BINDING_PROJECTION(item) for item in value.bindings]
    if len({item["manifest_binding_ref"] for item in bindings}) != len(bindings) or any(item["target_runtime_file_ref"] != value.target_runtime_file_ref for item in bindings):
        raise _InvalidTargetDependencyManifest
    reference = _BUILTIN_REQUIREMENT_REF_PROJECTION(target_runtime_file_ref=value.target_runtime_file_ref, dependency_requirement_ref=value.dependency_requirement_ref, bindings=bindings)
    if value.manifest_requirement_ref != _BUILTIN_CANONICAL_DIGEST(reference):
        raise _InvalidTargetDependencyManifest
    return {**reference, "kind": value.kind, "manifest_requirement_ref": value.manifest_requirement_ref}


def _receipt_projection(value: RepositoryExecutableNativeDependencyManifestTargetDependencyManifestReceipt) -> dict[str, Any]:
    digests = (value.target_dependency_requirements_receipt_digest, value.target_runtime_manifest_receipt_digest, value.target_staging_receipt_digest, value.native_dependency_manifest_targets_receipt_digest, value.native_dependency_manifest_receipt_digest, value.native_dependency_requirements_receipt_digest, value.runtime_manifest_receipt_digest, value.staging_receipt_digest, value.registration_digest, value.repository_ref, value.verification_commands_digest, value.resolution_context_digest, value.source_staging_context_digest, value.manifest_context_digest, value.target_staging_context_digest)
    counts = ("dependency_declaration_count", "non_absolute_dependency_declaration_count", "manifest_bound_dependency_count", "unique_manifest_target_count")
    if type(value) is not _FIXED_RECEIPT_TYPE or value.kind != _FIXED_RECEIPT_KIND or value.schema_version != _FIXED_SCHEMA_VERSION or value.manifest_source != _FIXED_MANIFEST_SOURCE or value.manifest_scope != _FIXED_MANIFEST_SCOPE or not all(_is_digest(item) for item in digests) or type(value.requirements) is not tuple or type(value.requirement_count) is not int or value.requirement_count != len(value.requirements) or any(type(getattr(value, item)) is not int for item in counts):
        raise _InvalidTargetDependencyManifest
    requirements = tuple(_BUILTIN_REQUIREMENT_PROJECTION(item) for item in value.requirements)
    bindings = [binding for requirement in requirements for binding in requirement["bindings"]]
    if (
        value.dependency_declaration_count < value.non_absolute_dependency_declaration_count
        or value.non_absolute_dependency_declaration_count != len(bindings)
        or value.manifest_bound_dependency_count != len(bindings)
        or value.unique_manifest_target_count != len({item["manifest_target_ref"] for item in bindings})
        or len({item["manifest_binding_ref"] for item in bindings}) != len(bindings)
    ):
        raise _InvalidTargetDependencyManifest
    return {
        "dependency_declaration_count": value.dependency_declaration_count,
        "kind": value.kind,
        "manifest_bound_dependency_count": value.manifest_bound_dependency_count,
        "manifest_context_digest": value.manifest_context_digest,
        "manifest_scope": value.manifest_scope,
        "manifest_source": value.manifest_source,
        "native_dependency_manifest_receipt_digest": value.native_dependency_manifest_receipt_digest,
        "native_dependency_manifest_targets_receipt_digest": value.native_dependency_manifest_targets_receipt_digest,
        "native_dependency_requirements_receipt_digest": value.native_dependency_requirements_receipt_digest,
        "non_absolute_dependency_declaration_count": value.non_absolute_dependency_declaration_count,
        "registration_digest": value.registration_digest,
        "repository_ref": value.repository_ref,
        "requirement_count": value.requirement_count,
        "requirements": requirements,
        "resolution_context_digest": value.resolution_context_digest,
        "runtime_manifest_receipt_digest": value.runtime_manifest_receipt_digest,
        "schema_version": value.schema_version,
        "source_staging_context_digest": value.source_staging_context_digest,
        "staging_receipt_digest": value.staging_receipt_digest,
        "target_dependency_requirements_receipt_digest": value.target_dependency_requirements_receipt_digest,
        "target_runtime_manifest_receipt_digest": value.target_runtime_manifest_receipt_digest,
        "target_staging_context_digest": value.target_staging_context_digest,
        "target_staging_receipt_digest": value.target_staging_receipt_digest,
        "unique_manifest_target_count": value.unique_manifest_target_count,
        "verification_commands_digest": value.verification_commands_digest,
    }


def _evidence_projection(value: RepositoryExecutableNativeDependencyManifestTargetDependencyManifestReceipt) -> dict[str, Any]:
    canonical = _receipt_projection(value)
    return {
        "ambient_loader_environment_consulted": False,
        "authority_granted": False,
        "controller_explicit_mapping_reproduced": True,
        "dependency_closure_verified": False,
        "dependency_path_lookup_performed": False,
        "dispatch_enabled": False,
        "effect_class": 0,
        "execution_enabled": False,
        "loader_invocation_performed": False,
        "manifest_target_raw_values_exposed": False,
        "model_invocation_performed": False,
        "network_access_performed": False,
        "path_open_performed": False,
        "receipt_digest": _BUILTIN_CANONICAL_DIGEST(canonical),
        "recursive_dependency_resolution_verified": False,
        "staging_performed": False,
        "subprocess_invocation_performed": False,
        "tokenized_loader_path_expansion_performed": False,
        "validation_mode": "read_only",
        "manifest_bound_dependency_count": value.manifest_bound_dependency_count,
    }


_BUILTIN_BINDING_PROJECTION = _binding_projection
_BUILTIN_REQUIREMENT_PROJECTION = _requirement_projection
_BUILTIN_RECEIPT_PROJECTION = _receipt_projection
_BUILTIN_CANONICAL_TARGET_PATH = _canonical_target_path
_BUILTIN_TARGET_REF = _target_ref
_BUILTIN_BINDING_REF_PROJECTION = _binding_ref_projection
_BUILTIN_REQUIREMENT_REF_PROJECTION = _requirement_ref_projection


def _reproduce(expected_dependencies: Any, expected_runtime: Any, expected_staging: Any, lease: Any, entries: Any) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], tuple[RepositoryExecutableNativeDependencyManifestTargetDependencyManifestRequirement, ...]]:
    if type(expected_dependencies) is not _FIXED_DEPENDENCY_RECEIPT_TYPE or type(expected_runtime) is not _FIXED_RUNTIME_RECEIPT_TYPE or type(expected_staging) is not _FIXED_STAGING_RECEIPT_TYPE or type(lease) is not _FIXED_STAGE_LEASE_TYPE or type(entries) is not tuple or len(entries) > _MAX_BINDINGS:
        raise _InvalidTargetDependencyManifest
    dependency_canonical = _BUILTIN_DEPENDENCY_PROJECTION(expected_dependencies)
    runtime_canonical = _BUILTIN_RUNTIME_PROJECTION(expected_runtime)
    staging_canonical = _BUILTIN_STAGING_PROJECTION(expected_staging)
    if (
        dependency_canonical["target_runtime_manifest_receipt_digest"] != _BUILTIN_CANONICAL_DIGEST(runtime_canonical)
        or dependency_canonical["target_staging_receipt_digest"] != _BUILTIN_CANONICAL_DIGEST(staging_canonical)
    ):
        raise _InvalidTargetDependencyManifest
    fresh = _BUILTIN_INSPECT_DEPENDENCIES(expected_runtime, expected_target_staging=expected_staging, lease=lease)
    if _BUILTIN_DEPENDENCY_PROJECTION(fresh) != dependency_canonical:
        raise _InvalidTargetDependencyManifest
    declarations = tuple(
        (requirement, declaration)
        for requirement in expected_dependencies.requirements
        for declaration in requirement.declarations
        if declaration.path_style != "absolute"
    )
    if len(declarations) != len(entries):
        raise _InvalidTargetDependencyManifest
    bindings_by_runtime: dict[str, list[RepositoryExecutableNativeDependencyManifestTargetDependencyManifestBinding]] = {}
    target_by_ref: dict[str, Path] = {}
    for (requirement, declaration), entry in zip(declarations, entries, strict=True):
        if type(entry) is not _FIXED_ENTRY_TYPE or entry.kind != _FIXED_ENTRY_KIND or type(entry.dependency_name) is not bytes or not 1 <= len(entry.dependency_name) <= 4_095 or entry.target_runtime_file_ref != requirement.target_runtime_file_ref or entry.dependency_declaration_ref != declaration.declaration_ref:
            raise _InvalidTargetDependencyManifest
        target = _BUILTIN_CANONICAL_TARGET_PATH(entry.target_path)
        if _BUILTIN_DEPENDENCY_NAME_REF(runtime_file_ref=requirement.target_runtime_file_ref, format_class=declaration.format_class, dependency_name=entry.dependency_name) != declaration.dependency_name_ref:
            raise _InvalidTargetDependencyManifest
        manifest_target_ref = _BUILTIN_TARGET_REF(target)
        previous = target_by_ref.get(manifest_target_ref)
        if previous is None:
            target_by_ref[manifest_target_ref] = target
        elif previous != target:
            raise _InvalidTargetDependencyManifest
        reference = _BUILTIN_BINDING_REF_PROJECTION(target_runtime_file_ref=requirement.target_runtime_file_ref, dependency_declaration_ref=declaration.declaration_ref, dependency_name_ref=declaration.dependency_name_ref, format_class=declaration.format_class, ordinal=declaration.ordinal, path_style=declaration.path_style, manifest_target_ref=manifest_target_ref)
        binding = _FIXED_BINDING_TYPE(kind=_FIXED_BINDING_KIND, target_runtime_file_ref=requirement.target_runtime_file_ref, dependency_declaration_ref=declaration.declaration_ref, dependency_name_ref=declaration.dependency_name_ref, format_class=declaration.format_class, ordinal=declaration.ordinal, path_style=declaration.path_style, manifest_target_ref=manifest_target_ref, manifest_binding_ref=_BUILTIN_CANONICAL_DIGEST(reference))
        _BUILTIN_BINDING_PROJECTION(binding)
        bindings_by_runtime.setdefault(requirement.target_runtime_file_ref, []).append(binding)
    requirements: list[RepositoryExecutableNativeDependencyManifestTargetDependencyManifestRequirement] = []
    for requirement in expected_dependencies.requirements:
        bindings = tuple(bindings_by_runtime.get(requirement.target_runtime_file_ref, ()))
        projections = [_BUILTIN_BINDING_PROJECTION(item) for item in bindings]
        reference = _BUILTIN_REQUIREMENT_REF_PROJECTION(target_runtime_file_ref=requirement.target_runtime_file_ref, dependency_requirement_ref=requirement.requirement_ref, bindings=projections)
        item = _FIXED_REQUIREMENT_TYPE(kind=_FIXED_REQUIREMENT_KIND, target_runtime_file_ref=requirement.target_runtime_file_ref, dependency_requirement_ref=requirement.requirement_ref, bindings=bindings, manifest_requirement_ref=_BUILTIN_CANONICAL_DIGEST(reference))
        _BUILTIN_REQUIREMENT_PROJECTION(item)
        requirements.append(item)
    return dependency_canonical, runtime_canonical, staging_canonical, tuple(requirements)


_BUILTIN_REPRODUCE = _reproduce


def inspect_staged_executable_native_dependency_manifest_target_dependency_manifest(
    expected_dependencies: RepositoryExecutableNativeDependencyManifestTargetDependencyRequirementsReceipt,
    *,
    expected_target_runtime: RepositoryExecutableNativeDependencyManifestTargetRuntimeManifestReceipt,
    expected_target_staging: RepositoryExecutableNativeDependencyManifestTargetStagingReceipt,
    lease: RepositoryExecutableNativeDependencyManifestTargetStageLease,
    expected_non_absolute_dependency_manifest: tuple[RepositoryExecutableNativeDependencyManifestTargetDependencyManifestEntry, ...],
) -> RepositoryExecutableNativeDependencyManifestTargetDependencyManifestReceipt:
    """Bind exact non-absolute staged-target declarations without path lookup."""

    try:
        first = _BUILTIN_REPRODUCE(expected_dependencies, expected_target_runtime, expected_target_staging, lease, expected_non_absolute_dependency_manifest)
        middle = _BUILTIN_REPRODUCE(expected_dependencies, expected_target_runtime, expected_target_staging, lease, expected_non_absolute_dependency_manifest)
        final = _BUILTIN_REPRODUCE(expected_dependencies, expected_target_runtime, expected_target_staging, lease, expected_non_absolute_dependency_manifest)
        if middle != first or final != first:
            raise _InvalidTargetDependencyManifest
        dependency_canonical, runtime_canonical, staging_canonical, requirements = first
        bindings = tuple(item for requirement in requirements for item in requirement.bindings)
        receipt = _FIXED_RECEIPT_TYPE(
            kind=_FIXED_RECEIPT_KIND, schema_version=_FIXED_SCHEMA_VERSION, manifest_source=_FIXED_MANIFEST_SOURCE, manifest_scope=_FIXED_MANIFEST_SCOPE,
            target_dependency_requirements_receipt_digest=_BUILTIN_CANONICAL_DIGEST(dependency_canonical), target_runtime_manifest_receipt_digest=_BUILTIN_CANONICAL_DIGEST(runtime_canonical), target_staging_receipt_digest=_BUILTIN_CANONICAL_DIGEST(staging_canonical),
            native_dependency_manifest_targets_receipt_digest=staging_canonical["native_dependency_manifest_targets_receipt_digest"], native_dependency_manifest_receipt_digest=staging_canonical["native_dependency_manifest_receipt_digest"], native_dependency_requirements_receipt_digest=staging_canonical["native_dependency_requirements_receipt_digest"], runtime_manifest_receipt_digest=staging_canonical["runtime_manifest_receipt_digest"], staging_receipt_digest=staging_canonical["staging_receipt_digest"], registration_digest=staging_canonical["registration_digest"], repository_ref=staging_canonical["repository_ref"], verification_commands_digest=staging_canonical["verification_commands_digest"], resolution_context_digest=staging_canonical["resolution_context_digest"], source_staging_context_digest=staging_canonical["source_staging_context_digest"], manifest_context_digest=staging_canonical["manifest_context_digest"], target_staging_context_digest=staging_canonical["target_staging_context_digest"],
            requirements=requirements, requirement_count=len(requirements), dependency_declaration_count=expected_dependencies.dependency_declaration_count, non_absolute_dependency_declaration_count=len(bindings), manifest_bound_dependency_count=len(bindings), unique_manifest_target_count=len({item.manifest_target_ref for item in bindings}),
        )
        _BUILTIN_RECEIPT_PROJECTION(receipt)
        return receipt
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _FIXED_VALIDATION_ERROR(_INVALID_MESSAGE) from None


__all__ = [
    "MANIFEST_SCOPE", "MANIFEST_SOURCE",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_BINDING_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_ENTRY_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_EVIDENCE_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_REQUIREMENT_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_SCHEMA_VERSION",
    "RepositoryExecutableNativeDependencyManifestTargetDependencyManifestBinding",
    "RepositoryExecutableNativeDependencyManifestTargetDependencyManifestEntry",
    "RepositoryExecutableNativeDependencyManifestTargetDependencyManifestReceipt",
    "RepositoryExecutableNativeDependencyManifestTargetDependencyManifestRequirement",
    "inspect_staged_executable_native_dependency_manifest_target_dependency_manifest",
]
