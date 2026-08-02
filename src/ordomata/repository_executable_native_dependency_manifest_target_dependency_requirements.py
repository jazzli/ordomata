"""Read direct native dependency declarations from detached manifest targets.

Only bounded ELF ``DT_NEEDED`` and thin Mach-O dylib-load syntax is inspected.
The primitive never resolves a declaration, opens a pathname, loads a binary,
or establishes recursive/shared-library closure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
from types import SimpleNamespace
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
from .repository_executable_native_dependency_requirements import (
    RepositoryExecutableNativeDependencyDeclaration,
    _declaration_projection,
    _elf_dependency_fields,
    _mach_o_dependency_fields,
)


REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_REQUIREMENTS_SCHEMA_VERSION = 1
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_REQUIREMENTS_KIND = (
    "repository_executable_native_dependency_manifest_target_dependency_requirements"
)
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_REQUIREMENTS_EVIDENCE_KIND = (
    "repository_executable_native_dependency_manifest_target_dependency_requirements_validation"
)
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_REQUIREMENT_KIND = (
    "repository_executable_native_dependency_manifest_target_dependency_requirement"
)
REQUIREMENTS_SOURCE = "controller_inspected"
REQUIREMENTS_SCOPE = "staged_explicit_manifest_target_dependency_declarations_v1"

_FIXED_SCHEMA_VERSION = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_REQUIREMENTS_SCHEMA_VERSION
_FIXED_RECEIPT_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_REQUIREMENTS_KIND
_FIXED_EVIDENCE_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_REQUIREMENTS_EVIDENCE_KIND
_FIXED_REQUIREMENT_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_REQUIREMENT_KIND
_FIXED_REQUIREMENTS_SOURCE = REQUIREMENTS_SOURCE
_FIXED_REQUIREMENTS_SCOPE = REQUIREMENTS_SCOPE
_INVALID_MESSAGE = "repository executable native dependency manifest target dependency requirements are invalid"
_DIGEST_PREFIX = "sha256:"
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_FILES = 80
_MAX_DEPENDENCIES_PER_FILE = 512
_MAX_DEPENDENCIES = _MAX_FILES * _MAX_DEPENDENCIES_PER_FILE
_MAX_DEPENDENCY_NAME_BYTES = 4_095
_MAX_TOTAL_NAME_BYTES = _MAX_DEPENDENCIES * _MAX_DEPENDENCY_NAME_BYTES


def _captured_canonical_digest(value: Any) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


_BUILTIN_CANONICAL_DIGEST = _captured_canonical_digest
_BUILTIN_SHA256 = hashlib.sha256
_BUILTIN_RUNTIME_PROJECTION = _runtime_manifest_projection
_BUILTIN_ACTIVE_STAGE_SNAPSHOT = _active_stage_snapshot
_BUILTIN_READ_AND_VERIFY = _read_and_verify
_BUILTIN_INSPECT_RUNTIME = inspect_staged_executable_native_dependency_manifest_target_runtime_manifest
_BUILTIN_DECLARATION_PROJECTION = _declaration_projection
_BUILTIN_ELF_FIELDS = _elf_dependency_fields
_BUILTIN_MACH_FIELDS = _mach_o_dependency_fields
_FIXED_RUNTIME_RECEIPT_TYPE = RepositoryExecutableNativeDependencyManifestTargetRuntimeManifestReceipt
_FIXED_STAGE_RECEIPT_TYPE = RepositoryExecutableNativeDependencyManifestTargetStagingReceipt
_FIXED_STAGE_LEASE_TYPE = RepositoryExecutableNativeDependencyManifestTargetStageLease
_FIXED_DECLARATION_TYPE = RepositoryExecutableNativeDependencyDeclaration
_FIXED_VALIDATION_ERROR = ValidationError


class _InvalidTargetDependencyRequirements(ValueError):
    """Private sentinel whose diagnostics never cross this boundary."""


def _is_digest(value: Any) -> bool:
    return type(value) is str and _DIGEST_PATTERN.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeDependencyManifestTargetDependencyRequirement:
    """One staged target's bounded direct native dependency syntax."""

    kind: str
    manifest_target_ref: str = field(repr=False)
    target_staged_file_ref: str = field(repr=False)
    target_runtime_file_ref: str = field(repr=False)
    runtime_classification: str
    format_class: str | None
    byte_order: str | None
    image_kind: str | None
    disposition: str
    declarations: tuple[RepositoryExecutableNativeDependencyDeclaration, ...] = field(repr=False)
    declaration_count: int
    required_dependency_count: int
    weak_dependency_count: int
    total_dependency_name_bytes: int
    layout_supported: bool
    requirement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _requirement_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeDependencyManifestTargetDependencyRequirementsReceipt:
    """Digest-only direct dependency syntax evidence for one active target stage."""

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
    requirements: tuple[RepositoryExecutableNativeDependencyManifestTargetDependencyRequirement, ...] = field(repr=False)
    requirement_count: int
    native_requirement_count: int
    dependency_declared_requirement_count: int
    dependency_declaration_count: int
    required_dependency_count: int
    weak_dependency_count: int
    unsupported_native_layout_count: int
    non_native_not_applicable_count: int
    total_dependency_name_bytes: int

    def to_canonical(self) -> dict[str, Any]:
        return _receipt_projection(self)

    @property
    def receipt_digest(self) -> str:
        return _BUILTIN_CANONICAL_DIGEST(_receipt_projection(self))

    def to_evidence(self) -> dict[str, Any]:
        return _evidence_projection(self)


_FIXED_REQUIREMENT_TYPE = RepositoryExecutableNativeDependencyManifestTargetDependencyRequirement
_FIXED_RECEIPT_TYPE = RepositoryExecutableNativeDependencyManifestTargetDependencyRequirementsReceipt


def _requirement_ref_projection(*, manifest_target_ref: str, target_staged_file_ref: str, target_runtime_file_ref: str, runtime_classification: str, format_class: str | None, byte_order: str | None, image_kind: str | None, disposition: str, declarations: list[dict[str, Any]], layout_supported: bool) -> dict[str, Any]:
    return {
        "byte_order": byte_order,
        "declarations": declarations,
        "disposition": disposition,
        "format_class": format_class,
        "image_kind": image_kind,
        "kind": "repository_executable_native_dependency_manifest_target_dependency_requirement_ref",
        "layout_supported": layout_supported,
        "manifest_target_ref": manifest_target_ref,
        "requirements_scope": _FIXED_REQUIREMENTS_SCOPE,
        "runtime_classification": runtime_classification,
        "schema_version": _FIXED_SCHEMA_VERSION,
        "target_runtime_file_ref": target_runtime_file_ref,
        "target_staged_file_ref": target_staged_file_ref,
    }


def _requirement_projection(value: RepositoryExecutableNativeDependencyManifestTargetDependencyRequirement) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_REQUIREMENT_TYPE
        or value.kind != _FIXED_REQUIREMENT_KIND
        or not all(_is_digest(item) for item in (value.manifest_target_ref, value.target_staged_file_ref, value.target_runtime_file_ref, value.requirement_ref))
        or value.runtime_classification not in {"elf", "mach_o", "posix_shebang", "unsupported_shebang", "unknown"}
        or value.format_class not in {None, "elf32", "elf64", "mach_o32", "mach_o64", "mach_o_fat32", "mach_o_fat64"}
        or value.byte_order not in {None, "little", "big"}
        or value.image_kind not in {None, "executable", "shared_object", "dynamic_linker", "other"}
        or value.disposition not in {"elf_dependencies_declared", "elf_dependencies_absent", "mach_o_dependencies_declared", "mach_o_dependencies_absent", "unsupported_native_layout", "non_native_not_applicable"}
        or type(value.declarations) is not tuple
        or not 0 <= len(value.declarations) <= _MAX_DEPENDENCIES_PER_FILE
        or any(type(getattr(value, item)) is not int for item in ("declaration_count", "required_dependency_count", "weak_dependency_count", "total_dependency_name_bytes"))
        or type(value.layout_supported) is not bool
    ):
        raise _InvalidTargetDependencyRequirements
    declarations = [_BUILTIN_DECLARATION_PROJECTION(item) for item in value.declarations]
    native = value.runtime_classification in {"elf", "mach_o"}
    declared = value.disposition in {"elf_dependencies_declared", "mach_o_dependencies_declared"}
    absent = value.disposition in {"elf_dependencies_absent", "mach_o_dependencies_absent"}
    if (
        value.declaration_count != len(declarations)
        or value.required_dependency_count != sum(item["load_kind"] not in {"weak", "lazy"} for item in declarations)
        or value.weak_dependency_count != len(declarations) - value.required_dependency_count
        or value.total_dependency_name_bytes != sum(item["dependency_name_bytes"] for item in declarations)
        or not 0 <= value.total_dependency_name_bytes <= _MAX_DEPENDENCIES_PER_FILE * _MAX_DEPENDENCY_NAME_BYTES
    ):
        raise _InvalidTargetDependencyRequirements
    if not native:
        if value.disposition != "non_native_not_applicable" or any(item is not None for item in (value.format_class, value.byte_order, value.image_kind)) or declarations or value.layout_supported:
            raise _InvalidTargetDependencyRequirements
    elif value.format_class is None or value.byte_order is None:
        raise _InvalidTargetDependencyRequirements
    elif value.disposition == "unsupported_native_layout":
        if value.layout_supported or value.image_kind is not None or declarations:
            raise _InvalidTargetDependencyRequirements
    elif not value.layout_supported or value.image_kind is None:
        raise _InvalidTargetDependencyRequirements
    elif absent and declarations:
        raise _InvalidTargetDependencyRequirements
    elif declared and not declarations:
        raise _InvalidTargetDependencyRequirements
    reference = _requirement_ref_projection(
        manifest_target_ref=value.manifest_target_ref,
        target_staged_file_ref=value.target_staged_file_ref,
        target_runtime_file_ref=value.target_runtime_file_ref,
        runtime_classification=value.runtime_classification,
        format_class=value.format_class,
        byte_order=value.byte_order,
        image_kind=value.image_kind,
        disposition=value.disposition,
        declarations=declarations,
        layout_supported=value.layout_supported,
    )
    if value.requirement_ref != _BUILTIN_CANONICAL_DIGEST(reference):
        raise _InvalidTargetDependencyRequirements
    return {**reference, "declaration_count": value.declaration_count, "kind": value.kind, "required_dependency_count": value.required_dependency_count, "requirement_ref": value.requirement_ref, "total_dependency_name_bytes": value.total_dependency_name_bytes, "weak_dependency_count": value.weak_dependency_count}


def _receipt_projection(value: RepositoryExecutableNativeDependencyManifestTargetDependencyRequirementsReceipt) -> dict[str, Any]:
    digests = (value.target_runtime_manifest_receipt_digest, value.target_staging_receipt_digest, value.native_dependency_manifest_targets_receipt_digest, value.native_dependency_manifest_receipt_digest, value.native_dependency_requirements_receipt_digest, value.runtime_manifest_receipt_digest, value.staging_receipt_digest, value.registration_digest, value.repository_ref, value.verification_commands_digest, value.resolution_context_digest, value.source_staging_context_digest, value.manifest_context_digest, value.target_staging_context_digest)
    counts = ("native_requirement_count", "dependency_declared_requirement_count", "dependency_declaration_count", "required_dependency_count", "weak_dependency_count", "unsupported_native_layout_count", "non_native_not_applicable_count", "total_dependency_name_bytes")
    if type(value) is not _FIXED_RECEIPT_TYPE or value.kind != _FIXED_RECEIPT_KIND or value.schema_version != _FIXED_SCHEMA_VERSION or value.requirements_source != _FIXED_REQUIREMENTS_SOURCE or value.requirements_scope != _FIXED_REQUIREMENTS_SCOPE or not all(_is_digest(item) for item in digests) or type(value.requirements) is not tuple or not 0 <= len(value.requirements) <= _MAX_FILES or type(value.requirement_count) is not int or value.requirement_count != len(value.requirements) or any(type(getattr(value, item)) is not int for item in counts):
        raise _InvalidTargetDependencyRequirements
    requirements = tuple(_BUILTIN_REQUIREMENT_PROJECTION(item) for item in value.requirements)
    if (
        len({item["requirement_ref"] for item in requirements}) != len(requirements)
        or value.native_requirement_count != sum(item["runtime_classification"] in {"elf", "mach_o"} for item in requirements)
        or value.dependency_declared_requirement_count != sum(bool(item["declarations"]) for item in requirements)
        or value.dependency_declaration_count != sum(item["declaration_count"] for item in requirements)
        or value.required_dependency_count != sum(item["required_dependency_count"] for item in requirements)
        or value.weak_dependency_count != sum(item["weak_dependency_count"] for item in requirements)
        or value.unsupported_native_layout_count != sum(item["disposition"] == "unsupported_native_layout" for item in requirements)
        or value.non_native_not_applicable_count != sum(item["disposition"] == "non_native_not_applicable" for item in requirements)
        or value.total_dependency_name_bytes != sum(item["total_dependency_name_bytes"] for item in requirements)
        or not 0 <= value.total_dependency_name_bytes <= _MAX_TOTAL_NAME_BYTES
    ):
        raise _InvalidTargetDependencyRequirements
    return {
        "dependency_declared_requirement_count": value.dependency_declared_requirement_count,
        "dependency_declaration_count": value.dependency_declaration_count,
        "kind": value.kind,
        "manifest_context_digest": value.manifest_context_digest,
        "native_dependency_manifest_receipt_digest": value.native_dependency_manifest_receipt_digest,
        "native_dependency_manifest_targets_receipt_digest": value.native_dependency_manifest_targets_receipt_digest,
        "native_dependency_requirements_receipt_digest": value.native_dependency_requirements_receipt_digest,
        "native_requirement_count": value.native_requirement_count,
        "non_native_not_applicable_count": value.non_native_not_applicable_count,
        "registration_digest": value.registration_digest,
        "repository_ref": value.repository_ref,
        "required_dependency_count": value.required_dependency_count,
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
        "total_dependency_name_bytes": value.total_dependency_name_bytes,
        "unsupported_native_layout_count": value.unsupported_native_layout_count,
        "verification_commands_digest": value.verification_commands_digest,
        "weak_dependency_count": value.weak_dependency_count,
    }


def _evidence_projection(value: RepositoryExecutableNativeDependencyManifestTargetDependencyRequirementsReceipt) -> dict[str, Any]:
    canonical = _receipt_projection(value)
    return {
        "authority_granted": False,
        "dependency_closure_verified": False,
        "dependency_declaration_syntax_inspection_complete": True,
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
        "staged_descriptor_full_remeasurement_complete": True,
        "subprocess_invocation_performed": False,
        "validation_mode": "read_only",
        "dependency_declaration_count": value.dependency_declaration_count,
        "requirement_count": value.requirement_count,
    }


_BUILTIN_REQUIREMENT_PROJECTION = _requirement_projection
_BUILTIN_RECEIPT_PROJECTION = _receipt_projection


def _loader_context(runtime_file: Any, header: bytes) -> dict[str, Any]:
    if runtime_file.classification == "elf":
        if len(header) < 16 or header[4] not in {1, 2} or header[5] not in {1, 2}:
            raise _InvalidTargetDependencyRequirements
        format_class = "elf32" if header[4] == 1 else "elf64"
        byte_order = "little" if header[5] == 1 else "big"
        image_kind = None
        if len(header) >= 18:
            image_type = int.from_bytes(header[16:18], byte_order)
            image_kind = "executable" if image_type == 2 else "shared_object" if image_type == 3 else "other"
        return {"format_class": format_class, "byte_order": byte_order, "image_kind": image_kind}
    if runtime_file.classification == "mach_o":
        magic = header[:4]
        mapping = {
            b"\xfe\xed\xfa\xce": ("mach_o32", "big"), b"\xce\xfa\xed\xfe": ("mach_o32", "little"),
            b"\xfe\xed\xfa\xcf": ("mach_o64", "big"), b"\xcf\xfa\xed\xfe": ("mach_o64", "little"),
        }
        pair = mapping.get(magic)
        if pair is None:
            raise _InvalidTargetDependencyRequirements
        image_kind = None
        if len(header) >= 16:
            file_type = int.from_bytes(header[12:16], pair[1])
            image_kind = "executable" if file_type == 2 else "shared_object" if file_type == 6 else "dynamic_linker" if file_type == 7 else "other"
        return {"format_class": pair[0], "byte_order": pair[1], "image_kind": image_kind}
    return {}


_BUILTIN_LOADER_CONTEXT = _loader_context


def _build_requirement(runtime_file: Any, header: bytes, descriptor: int) -> RepositoryExecutableNativeDependencyManifestTargetDependencyRequirement:
    if runtime_file.header_bytes != len(header):
        raise _InvalidTargetDependencyRequirements
    header_digest = _DIGEST_PREFIX + _BUILTIN_SHA256(runtime_file.target_staged_file_ref.encode("ascii") + b"\x00" + header).hexdigest()
    if header_digest != runtime_file.header_digest:
        raise _InvalidTargetDependencyRequirements
    if runtime_file.classification in {"elf", "mach_o"}:
        context = _BUILTIN_LOADER_CONTEXT(runtime_file, header)
        parser_input = SimpleNamespace(runtime_file_ref=runtime_file.target_runtime_file_ref, content_bytes=runtime_file.content_bytes)
        fields = (_BUILTIN_ELF_FIELDS if runtime_file.classification == "elf" else _BUILTIN_MACH_FIELDS)(parser_input, context, descriptor=descriptor, header=header)
    elif runtime_file.classification in {"posix_shebang", "unsupported_shebang", "unknown"}:
        fields = (None, None, None, "non_native_not_applicable", (), False)
    else:
        raise _InvalidTargetDependencyRequirements
    format_class, byte_order, image_kind, disposition, declarations, layout_supported = fields
    declaration_values = tuple(declarations)
    if any(type(item) is not _FIXED_DECLARATION_TYPE for item in declaration_values):
        raise _InvalidTargetDependencyRequirements
    projections = [_BUILTIN_DECLARATION_PROJECTION(item) for item in declaration_values]
    reference = _requirement_ref_projection(
        manifest_target_ref=runtime_file.manifest_target_ref,
        target_staged_file_ref=runtime_file.target_staged_file_ref,
        target_runtime_file_ref=runtime_file.target_runtime_file_ref,
        runtime_classification=runtime_file.classification,
        format_class=format_class,
        byte_order=byte_order,
        image_kind=image_kind,
        disposition=disposition,
        declarations=projections,
        layout_supported=layout_supported,
    )
    required = sum(item.load_kind not in {"weak", "lazy"} for item in declaration_values)
    value = _FIXED_REQUIREMENT_TYPE(
        kind=_FIXED_REQUIREMENT_KIND,
        manifest_target_ref=runtime_file.manifest_target_ref,
        target_staged_file_ref=runtime_file.target_staged_file_ref,
        target_runtime_file_ref=runtime_file.target_runtime_file_ref,
        runtime_classification=runtime_file.classification,
        format_class=format_class,
        byte_order=byte_order,
        image_kind=image_kind,
        disposition=disposition,
        declarations=declaration_values,
        declaration_count=len(declaration_values),
        required_dependency_count=required,
        weak_dependency_count=len(declaration_values) - required,
        total_dependency_name_bytes=sum(item.dependency_name_bytes for item in declaration_values),
        layout_supported=layout_supported,
        requirement_ref=_BUILTIN_CANONICAL_DIGEST(reference),
    )
    _BUILTIN_REQUIREMENT_PROJECTION(value)
    return value


_BUILTIN_BUILD_REQUIREMENT = _build_requirement


def inspect_staged_executable_native_dependency_manifest_target_dependency_requirements(
    expected_target_runtime: RepositoryExecutableNativeDependencyManifestTargetRuntimeManifestReceipt,
    *,
    expected_target_staging: RepositoryExecutableNativeDependencyManifestTargetStagingReceipt,
    lease: RepositoryExecutableNativeDependencyManifestTargetStageLease,
) -> RepositoryExecutableNativeDependencyManifestTargetDependencyRequirementsReceipt:
    """Inspect direct native dependency declaration syntax without name lookup."""

    try:
        if type(expected_target_runtime) is not _FIXED_RUNTIME_RECEIPT_TYPE or type(expected_target_staging) is not _FIXED_STAGE_RECEIPT_TYPE or type(lease) is not _FIXED_STAGE_LEASE_TYPE:
            raise _InvalidTargetDependencyRequirements
        runtime_canonical = _BUILTIN_RUNTIME_PROJECTION(expected_target_runtime)
        staging_canonical, retained = _BUILTIN_ACTIVE_STAGE_SNAPSHOT(expected_target_staging, lease)
        if runtime_canonical["target_staging_receipt_digest"] != _BUILTIN_CANONICAL_DIGEST(staging_canonical):
            raise _InvalidTargetDependencyRequirements
        fresh = _BUILTIN_INSPECT_RUNTIME(expected_target_staging, lease=lease)
        if _BUILTIN_RUNTIME_PROJECTION(fresh) != runtime_canonical:
            raise _InvalidTargetDependencyRequirements
        anchored = tuple(dict(item) for item in staging_canonical["staged_files"])
        if len(anchored) != len(expected_target_runtime.files) or len(anchored) != len(retained):
            raise _InvalidTargetDependencyRequirements
        requirements: list[RepositoryExecutableNativeDependencyManifestTargetDependencyRequirement] = []
        for retained_file, staged_file, runtime_file in zip(retained, anchored, expected_target_runtime.files, strict=True):
            if runtime_file.target_staged_file_ref != staged_file["staged_file_ref"] or runtime_file.manifest_target_ref != staged_file["manifest_target_ref"] or runtime_file.content_digest != staged_file["content_digest"] or runtime_file.content_bytes != staged_file["content_bytes"]:
                raise _InvalidTargetDependencyRequirements
            header = _BUILTIN_READ_AND_VERIFY(retained_file, staged_file)
            requirements.append(_BUILTIN_BUILD_REQUIREMENT(runtime_file, header, retained_file.descriptor))
            if _BUILTIN_READ_AND_VERIFY(retained_file, staged_file) != header:
                raise _InvalidTargetDependencyRequirements
        final = _BUILTIN_INSPECT_RUNTIME(expected_target_staging, lease=lease)
        final_canonical, final_retained = _BUILTIN_ACTIVE_STAGE_SNAPSHOT(expected_target_staging, lease)
        if _BUILTIN_RUNTIME_PROJECTION(final) != runtime_canonical or final_canonical != staging_canonical or final_retained is not retained:
            raise _InvalidTargetDependencyRequirements
        receipt = _FIXED_RECEIPT_TYPE(
            kind=_FIXED_RECEIPT_KIND, schema_version=_FIXED_SCHEMA_VERSION,
            requirements_source=_FIXED_REQUIREMENTS_SOURCE, requirements_scope=_FIXED_REQUIREMENTS_SCOPE,
            target_runtime_manifest_receipt_digest=_BUILTIN_CANONICAL_DIGEST(runtime_canonical), target_staging_receipt_digest=_BUILTIN_CANONICAL_DIGEST(staging_canonical),
            native_dependency_manifest_targets_receipt_digest=staging_canonical["native_dependency_manifest_targets_receipt_digest"], native_dependency_manifest_receipt_digest=staging_canonical["native_dependency_manifest_receipt_digest"], native_dependency_requirements_receipt_digest=staging_canonical["native_dependency_requirements_receipt_digest"], runtime_manifest_receipt_digest=staging_canonical["runtime_manifest_receipt_digest"], staging_receipt_digest=staging_canonical["staging_receipt_digest"], registration_digest=staging_canonical["registration_digest"], repository_ref=staging_canonical["repository_ref"], verification_commands_digest=staging_canonical["verification_commands_digest"], resolution_context_digest=staging_canonical["resolution_context_digest"], source_staging_context_digest=staging_canonical["source_staging_context_digest"], manifest_context_digest=staging_canonical["manifest_context_digest"], target_staging_context_digest=staging_canonical["target_staging_context_digest"],
            requirements=tuple(requirements), requirement_count=len(requirements), native_requirement_count=sum(item.runtime_classification in {"elf", "mach_o"} for item in requirements), dependency_declared_requirement_count=sum(bool(item.declarations) for item in requirements), dependency_declaration_count=sum(item.declaration_count for item in requirements), required_dependency_count=sum(item.required_dependency_count for item in requirements), weak_dependency_count=sum(item.weak_dependency_count for item in requirements), unsupported_native_layout_count=sum(item.disposition == "unsupported_native_layout" for item in requirements), non_native_not_applicable_count=sum(item.disposition == "non_native_not_applicable" for item in requirements), total_dependency_name_bytes=sum(item.total_dependency_name_bytes for item in requirements),
        )
        _BUILTIN_RECEIPT_PROJECTION(receipt)
        closing_canonical, closing_retained = _BUILTIN_ACTIVE_STAGE_SNAPSHOT(expected_target_staging, lease)
        if closing_canonical != staging_canonical or closing_retained is not retained:
            raise _InvalidTargetDependencyRequirements
        return receipt
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _FIXED_VALIDATION_ERROR(_INVALID_MESSAGE) from None


__all__ = [
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_REQUIREMENT_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_REQUIREMENTS_EVIDENCE_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_REQUIREMENTS_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_REQUIREMENTS_SCHEMA_VERSION",
    "REQUIREMENTS_SCOPE",
    "REQUIREMENTS_SOURCE",
    "RepositoryExecutableNativeDependencyManifestTargetDependencyRequirement",
    "RepositoryExecutableNativeDependencyManifestTargetDependencyRequirementsReceipt",
    "inspect_staged_executable_native_dependency_manifest_target_dependency_requirements",
]
