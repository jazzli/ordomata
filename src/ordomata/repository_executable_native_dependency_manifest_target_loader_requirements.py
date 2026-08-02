"""Inspect direct native-loader declarations from staged manifest targets.

This read-only boundary operates only on the anonymous descriptors retained by
the manifest-target staging lease.  It reports bounded ELF ``PT_INTERP`` and
Mach-O ``LC_LOAD_DYLINKER`` syntax, but does not resolve, open, load, or execute
the declared path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from types import SimpleNamespace
import re
from typing import Any

from .authorization import canonical_json
from .errors import ValidationError
from .repository_executable_native_dependency_manifest_target_runtime_manifest import (
    RepositoryExecutableNativeDependencyManifestTargetRuntimeManifestReceipt,
    _active_stage_snapshot,
    _read_and_verify,
    _runtime_manifest_projection,
    inspect_staged_executable_native_dependency_manifest_target_runtime_manifest,
)
from .repository_executable_native_dependency_manifest_target_staging import (
    RepositoryExecutableNativeDependencyManifestTargetStageLease,
    RepositoryExecutableNativeDependencyManifestTargetStagingReceipt,
)
from .repository_executable_native_loader_requirements import (
    RepositoryExecutableNativeLoaderRequirement,
    _build_requirement as _build_native_loader_requirement,
    _requirement_projection as _native_loader_requirement_projection,
)


REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_LOADER_REQUIREMENTS_SCHEMA_VERSION = 1
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_LOADER_REQUIREMENTS_KIND = (
    "repository_executable_native_dependency_manifest_target_loader_requirements"
)
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_LOADER_REQUIREMENTS_EVIDENCE_KIND = (
    "repository_executable_native_dependency_manifest_target_loader_requirements_validation"
)
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_LOADER_REQUIREMENT_KIND = (
    "repository_executable_native_dependency_manifest_target_loader_requirement"
)
REQUIREMENTS_SOURCE = "controller_inspected"
REQUIREMENTS_SCOPE = "staged_explicit_manifest_target_loader_declarations_v1"

_FIXED_SCHEMA_VERSION = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_LOADER_REQUIREMENTS_SCHEMA_VERSION
_FIXED_RECEIPT_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_LOADER_REQUIREMENTS_KIND
_FIXED_EVIDENCE_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_LOADER_REQUIREMENTS_EVIDENCE_KIND
_FIXED_REQUIREMENT_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_LOADER_REQUIREMENT_KIND
_FIXED_REQUIREMENTS_SOURCE = REQUIREMENTS_SOURCE
_FIXED_REQUIREMENTS_SCOPE = REQUIREMENTS_SCOPE
_INVALID_MESSAGE = "repository executable native dependency manifest target loader requirements are invalid"
_DIGEST_PREFIX = "sha256:"
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_FILES = 80
_MAX_LOADER_PATH_BYTES = 4_095
_MAX_TOTAL_LOADER_PATH_BYTES = _MAX_FILES * _MAX_LOADER_PATH_BYTES


def _captured_canonical_digest(value: Any) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


_BUILTIN_CANONICAL_DIGEST = _captured_canonical_digest
_BUILTIN_RUNTIME_PROJECTION = _runtime_manifest_projection
_BUILTIN_ACTIVE_STAGE_SNAPSHOT = _active_stage_snapshot
_BUILTIN_READ_AND_VERIFY = _read_and_verify
_BUILTIN_INSPECT_RUNTIME = inspect_staged_executable_native_dependency_manifest_target_runtime_manifest
_BUILTIN_BUILD_NATIVE_LOADER_REQUIREMENT = _build_native_loader_requirement
_BUILTIN_NATIVE_LOADER_REQUIREMENT_PROJECTION = _native_loader_requirement_projection
_FIXED_RUNTIME_RECEIPT_TYPE = RepositoryExecutableNativeDependencyManifestTargetRuntimeManifestReceipt
_FIXED_STAGE_RECEIPT_TYPE = RepositoryExecutableNativeDependencyManifestTargetStagingReceipt
_FIXED_STAGE_LEASE_TYPE = RepositoryExecutableNativeDependencyManifestTargetStageLease
_FIXED_NATIVE_LOADER_REQUIREMENT_TYPE = RepositoryExecutableNativeLoaderRequirement
_FIXED_VALIDATION_ERROR = ValidationError


class _InvalidTargetLoaderRequirements(ValueError):
    """Private invalid-input sentinel whose details never cross the API."""


def _is_digest(value: Any) -> bool:
    return type(value) is str and _DIGEST_PATTERN.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeDependencyManifestTargetLoaderRequirement:
    """One staged manifest target's direct native-loader declaration result."""

    kind: str
    manifest_target_ref: str = field(repr=False)
    target_staged_file_ref: str = field(repr=False)
    target_runtime_file_ref: str = field(repr=False)
    runtime_classification: str
    format_class: str | None
    byte_order: str | None
    image_kind: str | None
    disposition: str
    loader_path_ref: str | None = field(repr=False)
    loader_path_bytes: int
    loader_path_absolute: bool | None
    layout_supported: bool
    requirement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _requirement_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeDependencyManifestTargetLoaderRequirementsReceipt:
    """Digest-only direct-loader syntax evidence from an active target stage."""

    kind: str
    schema_version: int
    requirements_source: str
    requirements_scope: str
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
    requirements: tuple[RepositoryExecutableNativeDependencyManifestTargetLoaderRequirement, ...] = field(repr=False)
    requirement_count: int
    native_requirement_count: int
    loader_declared_count: int
    unsupported_native_layout_count: int
    non_native_not_applicable_count: int
    total_loader_path_bytes: int

    def to_canonical(self) -> dict[str, Any]:
        return _receipt_projection(self)

    @property
    def receipt_digest(self) -> str:
        return _BUILTIN_CANONICAL_DIGEST(_receipt_projection(self))

    def to_evidence(self) -> dict[str, Any]:
        return _evidence_projection(self)


_FIXED_REQUIREMENT_TYPE = RepositoryExecutableNativeDependencyManifestTargetLoaderRequirement
_FIXED_RECEIPT_TYPE = RepositoryExecutableNativeDependencyManifestTargetLoaderRequirementsReceipt


def _requirement_ref_projection(
    *,
    manifest_target_ref: str,
    target_staged_file_ref: str,
    target_runtime_file_ref: str,
    runtime_classification: str,
    format_class: str | None,
    byte_order: str | None,
    image_kind: str | None,
    disposition: str,
    loader_path_ref: str | None,
    loader_path_bytes: int,
    loader_path_absolute: bool | None,
    layout_supported: bool,
) -> dict[str, Any]:
    return {
        "byte_order": byte_order,
        "disposition": disposition,
        "format_class": format_class,
        "image_kind": image_kind,
        "kind": "repository_executable_native_dependency_manifest_target_loader_requirement_ref",
        "layout_supported": layout_supported,
        "loader_path_absolute": loader_path_absolute,
        "loader_path_bytes": loader_path_bytes,
        "loader_path_ref": loader_path_ref,
        "manifest_target_ref": manifest_target_ref,
        "requirements_scope": _FIXED_REQUIREMENTS_SCOPE,
        "runtime_classification": runtime_classification,
        "schema_version": _FIXED_SCHEMA_VERSION,
        "target_runtime_file_ref": target_runtime_file_ref,
        "target_staged_file_ref": target_staged_file_ref,
    }


def _requirement_projection(value: RepositoryExecutableNativeDependencyManifestTargetLoaderRequirement) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_REQUIREMENT_TYPE
        or value.kind != _FIXED_REQUIREMENT_KIND
        or not all(_is_digest(item) for item in (value.manifest_target_ref, value.target_staged_file_ref, value.target_runtime_file_ref, value.requirement_ref))
        or value.runtime_classification not in {"elf", "mach_o", "posix_shebang", "unsupported_shebang", "unknown"}
        or value.format_class not in {None, "elf32", "elf64", "mach_o32", "mach_o64", "mach_o_fat32", "mach_o_fat64"}
        or value.byte_order not in {None, "little", "big"}
        or value.image_kind not in {None, "executable", "shared_object", "dynamic_linker", "other"}
        or value.disposition not in {"elf_interpreter_declared", "elf_interpreter_absent", "mach_o_dylinker_declared", "mach_o_dylinker_absent", "unsupported_native_layout", "non_native_not_applicable"}
        or (value.loader_path_ref is not None and not _is_digest(value.loader_path_ref))
        or type(value.loader_path_bytes) is not int
        or not 0 <= value.loader_path_bytes <= _MAX_LOADER_PATH_BYTES
        or value.loader_path_absolute not in {None, True}
        or type(value.layout_supported) is not bool
    ):
        raise _InvalidTargetLoaderRequirements
    native = value.runtime_classification in {"elf", "mach_o"}
    declared = value.disposition in {"elf_interpreter_declared", "mach_o_dylinker_declared"}
    absent = value.disposition in {"elf_interpreter_absent", "mach_o_dylinker_absent"}
    if not native:
        if value.disposition != "non_native_not_applicable" or any(item is not None for item in (value.format_class, value.byte_order, value.image_kind, value.loader_path_ref, value.loader_path_absolute)) or value.loader_path_bytes or value.layout_supported:
            raise _InvalidTargetLoaderRequirements
    elif value.format_class is None or value.byte_order is None:
        raise _InvalidTargetLoaderRequirements
    elif value.disposition == "unsupported_native_layout":
        if value.layout_supported or value.image_kind is not None or value.loader_path_ref is not None or value.loader_path_bytes or value.loader_path_absolute is not None:
            raise _InvalidTargetLoaderRequirements
    elif not value.layout_supported or value.image_kind is None:
        raise _InvalidTargetLoaderRequirements
    elif declared:
        if value.loader_path_ref is None or not value.loader_path_bytes or value.loader_path_absolute is not True:
            raise _InvalidTargetLoaderRequirements
    elif absent:
        if value.loader_path_ref is not None or value.loader_path_bytes or value.loader_path_absolute is not None:
            raise _InvalidTargetLoaderRequirements
    reference = _requirement_ref_projection(
        manifest_target_ref=value.manifest_target_ref,
        target_staged_file_ref=value.target_staged_file_ref,
        target_runtime_file_ref=value.target_runtime_file_ref,
        runtime_classification=value.runtime_classification,
        format_class=value.format_class,
        byte_order=value.byte_order,
        image_kind=value.image_kind,
        disposition=value.disposition,
        loader_path_ref=value.loader_path_ref,
        loader_path_bytes=value.loader_path_bytes,
        loader_path_absolute=value.loader_path_absolute,
        layout_supported=value.layout_supported,
    )
    if value.requirement_ref != _BUILTIN_CANONICAL_DIGEST(reference):
        raise _InvalidTargetLoaderRequirements
    return {**reference, "kind": value.kind, "requirement_ref": value.requirement_ref}


def _receipt_projection(value: RepositoryExecutableNativeDependencyManifestTargetLoaderRequirementsReceipt) -> dict[str, Any]:
    digests = (
        value.target_runtime_manifest_receipt_digest, value.target_staging_receipt_digest,
        value.native_dependency_manifest_targets_receipt_digest, value.native_dependency_manifest_receipt_digest,
        value.native_dependency_requirements_receipt_digest, value.runtime_manifest_receipt_digest,
        value.staging_receipt_digest, value.registration_digest, value.repository_ref,
        value.verification_commands_digest, value.resolution_context_digest,
        value.source_staging_context_digest, value.manifest_context_digest,
        value.target_staging_context_digest,
    )
    if (
        type(value) is not _FIXED_RECEIPT_TYPE
        or value.kind != _FIXED_RECEIPT_KIND
        or value.schema_version != _FIXED_SCHEMA_VERSION
        or value.requirements_source != _FIXED_REQUIREMENTS_SOURCE
        or value.requirements_scope != _FIXED_REQUIREMENTS_SCOPE
        or not all(_is_digest(item) for item in digests)
        or type(value.requirements) is not tuple
        or not 0 <= len(value.requirements) <= _MAX_FILES
        or type(value.requirement_count) is not int
        or value.requirement_count != len(value.requirements)
        or any(type(getattr(value, item)) is not int for item in ("native_requirement_count", "loader_declared_count", "unsupported_native_layout_count", "non_native_not_applicable_count", "total_loader_path_bytes"))
    ):
        raise _InvalidTargetLoaderRequirements
    requirements = tuple(_BUILTIN_REQUIREMENT_PROJECTION(item) for item in value.requirements)
    if (
        len({item["requirement_ref"] for item in requirements}) != len(requirements)
        or value.native_requirement_count != sum(item["runtime_classification"] in {"elf", "mach_o"} for item in requirements)
        or value.loader_declared_count != sum(item["disposition"] in {"elf_interpreter_declared", "mach_o_dylinker_declared"} for item in requirements)
        or value.unsupported_native_layout_count != sum(item["disposition"] == "unsupported_native_layout" for item in requirements)
        or value.non_native_not_applicable_count != sum(item["disposition"] == "non_native_not_applicable" for item in requirements)
        or value.total_loader_path_bytes != sum(item["loader_path_bytes"] for item in requirements)
        or not 0 <= value.total_loader_path_bytes <= _MAX_TOTAL_LOADER_PATH_BYTES
    ):
        raise _InvalidTargetLoaderRequirements
    return {
        "kind": value.kind,
        "manifest_context_digest": value.manifest_context_digest,
        "native_dependency_manifest_receipt_digest": value.native_dependency_manifest_receipt_digest,
        "native_dependency_manifest_targets_receipt_digest": value.native_dependency_manifest_targets_receipt_digest,
        "native_dependency_requirements_receipt_digest": value.native_dependency_requirements_receipt_digest,
        "native_requirement_count": value.native_requirement_count,
        "non_native_not_applicable_count": value.non_native_not_applicable_count,
        "registration_digest": value.registration_digest,
        "repository_ref": value.repository_ref,
        "requirement_count": value.requirement_count,
        "requirements": requirements,
        "requirements_scope": value.requirements_scope,
        "requirements_source": value.requirements_source,
        "resolution_context_digest": value.resolution_context_digest,
        "runtime_manifest_receipt_digest": value.runtime_manifest_receipt_digest,
        "schema_version": value.schema_version,
        "source_staging_context_digest": value.source_staging_context_digest,
        "staging_receipt_digest": value.staging_receipt_digest,
        "target_runtime_manifest_receipt_digest": value.target_runtime_manifest_receipt_digest,
        "target_staging_context_digest": value.target_staging_context_digest,
        "target_staging_receipt_digest": value.target_staging_receipt_digest,
        "total_loader_path_bytes": value.total_loader_path_bytes,
        "unsupported_native_layout_count": value.unsupported_native_layout_count,
        "verification_commands_digest": value.verification_commands_digest,
        "loader_declared_count": value.loader_declared_count,
    }


def _evidence_projection(value: RepositoryExecutableNativeDependencyManifestTargetLoaderRequirementsReceipt) -> dict[str, Any]:
    canonical = _receipt_projection(value)
    return {
        "ambient_loader_environment_consulted": False,
        "authority_granted": False,
        "dependency_closure_verified": False,
        "dispatch_enabled": False,
        "effect_class": 0,
        "execution_enabled": False,
        "loader_declaration_syntax_inspection_complete": True,
        "loader_invocation_performed": False,
        "loader_path_lookup_performed": False,
        "manifest_target_raw_values_exposed": False,
        "model_invocation_performed": False,
        "network_access_performed": False,
        "path_open_performed": False,
        "receipt_digest": _BUILTIN_CANONICAL_DIGEST(canonical),
        "recursive_dependency_resolution_verified": False,
        "staged_descriptor_full_remeasurement_complete": True,
        "subprocess_invocation_performed": False,
        "validation_mode": "read_only",
        "requirement_count": value.requirement_count,
        "loader_declared_count": value.loader_declared_count,
    }


_BUILTIN_REQUIREMENT_PROJECTION = _requirement_projection
_BUILTIN_RECEIPT_PROJECTION = _receipt_projection


def _build_requirement(runtime_file: Any, header: bytes, descriptor: int) -> RepositoryExecutableNativeDependencyManifestTargetLoaderRequirement:
    if (
        runtime_file.header_bytes != len(header)
        or type(runtime_file.target_staged_file_ref) is not str
        or type(runtime_file.target_runtime_file_ref) is not str
    ):
        raise _InvalidTargetLoaderRequirements
    parser_input = SimpleNamespace(
        staged_file_ref=runtime_file.target_staged_file_ref,
        runtime_file_ref=runtime_file.target_runtime_file_ref,
        runtime_classification=runtime_file.classification,
        content_bytes=runtime_file.content_bytes,
        header_bytes=runtime_file.header_bytes,
        header_digest=runtime_file.header_digest,
        classification=runtime_file.classification,
    )
    generic = _BUILTIN_BUILD_NATIVE_LOADER_REQUIREMENT(parser_input, descriptor=descriptor, header=header)
    generic_canonical = _BUILTIN_NATIVE_LOADER_REQUIREMENT_PROJECTION(generic)
    if (
        generic_canonical["staged_file_ref"] != runtime_file.target_staged_file_ref
        or generic_canonical["runtime_file_ref"] != runtime_file.target_runtime_file_ref
        or generic_canonical["runtime_classification"] != runtime_file.classification
    ):
        raise _InvalidTargetLoaderRequirements
    reference = _requirement_ref_projection(
        manifest_target_ref=runtime_file.manifest_target_ref,
        target_staged_file_ref=runtime_file.target_staged_file_ref,
        target_runtime_file_ref=runtime_file.target_runtime_file_ref,
        runtime_classification=generic.runtime_classification,
        format_class=generic.format_class,
        byte_order=generic.byte_order,
        image_kind=generic.image_kind,
        disposition=generic.disposition,
        loader_path_ref=generic.loader_path_ref,
        loader_path_bytes=generic.loader_path_bytes,
        loader_path_absolute=generic.loader_path_absolute,
        layout_supported=generic.layout_supported,
    )
    value = _FIXED_REQUIREMENT_TYPE(
        kind=_FIXED_REQUIREMENT_KIND,
        manifest_target_ref=runtime_file.manifest_target_ref,
        target_staged_file_ref=runtime_file.target_staged_file_ref,
        target_runtime_file_ref=runtime_file.target_runtime_file_ref,
        runtime_classification=generic.runtime_classification,
        format_class=generic.format_class,
        byte_order=generic.byte_order,
        image_kind=generic.image_kind,
        disposition=generic.disposition,
        loader_path_ref=generic.loader_path_ref,
        loader_path_bytes=generic.loader_path_bytes,
        loader_path_absolute=generic.loader_path_absolute,
        layout_supported=generic.layout_supported,
        requirement_ref=_BUILTIN_CANONICAL_DIGEST(reference),
    )
    _BUILTIN_REQUIREMENT_PROJECTION(value)
    return value


_BUILTIN_BUILD_REQUIREMENT = _build_requirement


def inspect_staged_executable_native_dependency_manifest_target_loader_requirements(
    expected_target_runtime: RepositoryExecutableNativeDependencyManifestTargetRuntimeManifestReceipt,
    *,
    expected_target_staging: RepositoryExecutableNativeDependencyManifestTargetStagingReceipt,
    lease: RepositoryExecutableNativeDependencyManifestTargetStageLease,
) -> RepositoryExecutableNativeDependencyManifestTargetLoaderRequirementsReceipt:
    """Read bounded direct-loader syntax from one active detached target stage."""

    try:
        if type(expected_target_runtime) is not _FIXED_RUNTIME_RECEIPT_TYPE or type(expected_target_staging) is not _FIXED_STAGE_RECEIPT_TYPE or type(lease) is not _FIXED_STAGE_LEASE_TYPE:
            raise _InvalidTargetLoaderRequirements
        runtime_canonical = _BUILTIN_RUNTIME_PROJECTION(expected_target_runtime)
        staging_canonical, retained = _BUILTIN_ACTIVE_STAGE_SNAPSHOT(expected_target_staging, lease)
        if runtime_canonical["target_staging_receipt_digest"] != _BUILTIN_CANONICAL_DIGEST(staging_canonical):
            raise _InvalidTargetLoaderRequirements
        fresh = _BUILTIN_INSPECT_RUNTIME(expected_target_staging, lease=lease)
        if _BUILTIN_RUNTIME_PROJECTION(fresh) != runtime_canonical:
            raise _InvalidTargetLoaderRequirements
        anchored = tuple(dict(item) for item in staging_canonical["staged_files"])
        if len(anchored) != len(runtime_canonical["files"]) or len(anchored) != len(retained):
            raise _InvalidTargetLoaderRequirements
        requirements: list[RepositoryExecutableNativeDependencyManifestTargetLoaderRequirement] = []
        for retained_file, staged_file, runtime_file in zip(retained, anchored, expected_target_runtime.files, strict=True):
            if (
                runtime_file.target_staged_file_ref != staged_file["staged_file_ref"]
                or runtime_file.manifest_target_ref != staged_file["manifest_target_ref"]
                or runtime_file.content_digest != staged_file["content_digest"]
                or runtime_file.content_bytes != staged_file["content_bytes"]
            ):
                raise _InvalidTargetLoaderRequirements
            header = _BUILTIN_READ_AND_VERIFY(retained_file, staged_file)
            requirements.append(_BUILTIN_BUILD_REQUIREMENT(runtime_file, header, retained_file.descriptor))
            if _BUILTIN_READ_AND_VERIFY(retained_file, staged_file) != header:
                raise _InvalidTargetLoaderRequirements
        final = _BUILTIN_INSPECT_RUNTIME(expected_target_staging, lease=lease)
        final_canonical, final_retained = _BUILTIN_ACTIVE_STAGE_SNAPSHOT(expected_target_staging, lease)
        if _BUILTIN_RUNTIME_PROJECTION(final) != runtime_canonical or final_canonical != staging_canonical or final_retained is not retained:
            raise _InvalidTargetLoaderRequirements
        receipt = _FIXED_RECEIPT_TYPE(
            kind=_FIXED_RECEIPT_KIND,
            schema_version=_FIXED_SCHEMA_VERSION,
            requirements_source=_FIXED_REQUIREMENTS_SOURCE,
            requirements_scope=_FIXED_REQUIREMENTS_SCOPE,
            target_runtime_manifest_receipt_digest=_BUILTIN_CANONICAL_DIGEST(runtime_canonical),
            target_staging_receipt_digest=_BUILTIN_CANONICAL_DIGEST(staging_canonical),
            native_dependency_manifest_targets_receipt_digest=staging_canonical["native_dependency_manifest_targets_receipt_digest"],
            native_dependency_manifest_receipt_digest=staging_canonical["native_dependency_manifest_receipt_digest"],
            native_dependency_requirements_receipt_digest=staging_canonical["native_dependency_requirements_receipt_digest"],
            runtime_manifest_receipt_digest=staging_canonical["runtime_manifest_receipt_digest"],
            staging_receipt_digest=staging_canonical["staging_receipt_digest"],
            registration_digest=staging_canonical["registration_digest"],
            repository_ref=staging_canonical["repository_ref"],
            verification_commands_digest=staging_canonical["verification_commands_digest"],
            resolution_context_digest=staging_canonical["resolution_context_digest"],
            source_staging_context_digest=staging_canonical["source_staging_context_digest"],
            manifest_context_digest=staging_canonical["manifest_context_digest"],
            target_staging_context_digest=staging_canonical["target_staging_context_digest"],
            requirements=tuple(requirements),
            requirement_count=len(requirements),
            native_requirement_count=sum(item.runtime_classification in {"elf", "mach_o"} for item in requirements),
            loader_declared_count=sum(item.disposition in {"elf_interpreter_declared", "mach_o_dylinker_declared"} for item in requirements),
            unsupported_native_layout_count=sum(item.disposition == "unsupported_native_layout" for item in requirements),
            non_native_not_applicable_count=sum(item.disposition == "non_native_not_applicable" for item in requirements),
            total_loader_path_bytes=sum(item.loader_path_bytes for item in requirements),
        )
        _BUILTIN_RECEIPT_PROJECTION(receipt)
        closing_canonical, closing_retained = _BUILTIN_ACTIVE_STAGE_SNAPSHOT(expected_target_staging, lease)
        if closing_canonical != staging_canonical or closing_retained is not retained:
            raise _InvalidTargetLoaderRequirements
        return receipt
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _FIXED_VALIDATION_ERROR(_INVALID_MESSAGE) from None


__all__ = [
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_LOADER_REQUIREMENT_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_LOADER_REQUIREMENTS_EVIDENCE_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_LOADER_REQUIREMENTS_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_LOADER_REQUIREMENTS_SCHEMA_VERSION",
    "REQUIREMENTS_SCOPE",
    "REQUIREMENTS_SOURCE",
    "RepositoryExecutableNativeDependencyManifestTargetLoaderRequirement",
    "RepositoryExecutableNativeDependencyManifestTargetLoaderRequirementsReceipt",
    "inspect_staged_executable_native_dependency_manifest_target_loader_requirements",
]
