"""Digest-only native dependency declarations from an active executable stage.

This Class 0 boundary consumes one exact native-loader requirements receipt,
runtime manifest, staging receipt, and active process-local lease. It parses
only bounded ELF ``DT_NEEDED`` entries and thin Mach-O dylib load commands.
It does not resolve a dependency name, open a path, mutate the lease, or
execute a process.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
from typing import Any

from .authorization import canonical_json
from .errors import ValidationError
from .repository_executable_native_loader_requirements import (
    RepositoryExecutableNativeLoaderRequirementsReceipt,
    _UnsupportedNativeLayout as _DirectUnsupportedNativeLayout,
    _header_digest as _direct_header_digest,
    _independent_descriptor_remeasurement as _direct_descriptor_remeasurement,
    _integer as _direct_integer,
    _read_exact_range as _direct_read_exact_range,
    _receipt_projection as _native_loader_receipt_projection,
    inspect_staged_executable_native_loader_requirements,
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


REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_REQUIREMENTS_SCHEMA_VERSION = 1
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_REQUIREMENTS_KIND = (
    "repository_executable_native_dependency_requirements"
)
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_REQUIREMENTS_EVIDENCE_KIND = (
    "repository_executable_native_dependency_requirements_validation"
)
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_REQUIREMENT_KIND = (
    "repository_executable_native_dependency_requirement"
)
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_DECLARATION_KIND = (
    "repository_executable_native_dependency_declaration"
)
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_REQUIREMENT_BINDING_KIND = (
    "repository_executable_native_dependency_requirement_binding"
)
REQUIREMENTS_SOURCE = "controller_inspected"
REQUIREMENTS_SCOPE = "staged_native_dependency_declarations_v1"

_FIXED_SCHEMA_VERSION = (
    REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_REQUIREMENTS_SCHEMA_VERSION
)
_FIXED_RECEIPT_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_REQUIREMENTS_KIND
_FIXED_EVIDENCE_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_REQUIREMENTS_EVIDENCE_KIND
)
_FIXED_REQUIREMENT_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_REQUIREMENT_KIND
)
_FIXED_DECLARATION_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_DECLARATION_KIND
)
_FIXED_BINDING_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_REQUIREMENT_BINDING_KIND
)
_FIXED_REQUIREMENTS_SOURCE = REQUIREMENTS_SOURCE
_FIXED_REQUIREMENTS_SCOPE = REQUIREMENTS_SCOPE

_INVALID_MESSAGE = "repository executable native dependency requirements are invalid"
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
_BYTE_ORDERS = ("little", "big")
_IMAGE_KINDS = ("executable", "shared_object", "dynamic_linker", "other")
_DISPOSITIONS = (
    "elf_dependencies_declared",
    "elf_dependencies_absent",
    "mach_o_dependencies_declared",
    "mach_o_dependencies_absent",
    "unsupported_native_layout",
    "non_native_not_applicable",
)
_LOAD_KINDS = ("required", "weak", "reexport", "upward", "lazy")
_WEAK_LOAD_KINDS = ("weak", "lazy")
_PATH_STYLES = (
    "absolute",
    "bare",
    "relative",
    "at_rpath",
    "at_loader_path",
    "at_executable_path",
)
_MAX_FILES = 80
_MAX_COMMANDS = 80
_MAX_PROGRAM_HEADERS = 1_024
_MAX_LOAD_COMMANDS = 4_096
_MAX_TABLE_BYTES = 1024 * 1024
_MAX_STRING_TABLE_BYTES = 1024 * 1024
_MAX_DEPENDENCIES_PER_FILE = 512
_MAX_DEPENDENCIES = _MAX_FILES * _MAX_DEPENDENCIES_PER_FILE
_MAX_DEPENDENCY_NAME_BYTES = 4_095
_MAX_TOTAL_DEPENDENCY_NAME_BYTES = (
    _MAX_DEPENDENCIES * _MAX_DEPENDENCY_NAME_BYTES
)
_PT_LOAD = 1
_PT_DYNAMIC = 2
_DT_NULL = 0
_DT_NEEDED = 1
_DT_STRTAB = 5
_DT_STRSZ = 10
_LC_REQ_DYLD = 0x80000000
_MACH_O_DEPENDENCY_COMMANDS = {
    0xC: "required",
    0x18 | _LC_REQ_DYLD: "weak",
    0x1F | _LC_REQ_DYLD: "reexport",
    0x20: "lazy",
    0x23 | _LC_REQ_DYLD: "upward",
}
_THIN_MACH_O = {
    b"\xfe\xed\xfa\xce": ("mach_o32", "big", 28),
    b"\xce\xfa\xed\xfe": ("mach_o32", "little", 28),
    b"\xfe\xed\xfa\xcf": ("mach_o64", "big", 32),
    b"\xcf\xfa\xed\xfe": ("mach_o64", "little", 32),
}
_FAT_MACH_O = {
    b"\xca\xfe\xba\xbe": ("mach_o_fat32", "big"),
    b"\xbe\xba\xfe\xca": ("mach_o_fat32", "little"),
    b"\xca\xfe\xba\xbf": ("mach_o_fat64", "big"),
    b"\xbf\xba\xfe\xca": ("mach_o_fat64", "little"),
}

_BUILTIN_SHA256 = hashlib.sha256
_BUILTIN_CANONICAL_JSON = canonical_json


def _captured_canonical_digest(value: Any) -> str:
    encoded = _BUILTIN_CANONICAL_JSON(value).encode("utf-8")
    return _DIGEST_PREFIX + _BUILTIN_SHA256(encoded).hexdigest()


_BUILTIN_CANONICAL_DIGEST = _captured_canonical_digest
_BUILTIN_NATIVE_LOADER_PROJECTION = _native_loader_receipt_projection
_BUILTIN_RUNTIME_PROJECTION = _runtime_manifest_projection
_BUILTIN_STAGING_PROJECTION = _staging_receipt_projection
_BUILTIN_ACTIVE_STAGE_SNAPSHOT = _active_stage_snapshot
_BUILTIN_INSPECT_NATIVE_LOADER = (
    inspect_staged_executable_native_loader_requirements
)
_BUILTIN_DESCRIPTOR_REMEASUREMENT = _direct_descriptor_remeasurement
_BUILTIN_HEADER_DIGEST = _direct_header_digest
_BUILTIN_INTEGER = _direct_integer
_BUILTIN_READ_EXACT_RANGE = _direct_read_exact_range
_FIXED_VALIDATION_ERROR = ValidationError
_FIXED_NATIVE_LOADER_RECEIPT_TYPE = (
    RepositoryExecutableNativeLoaderRequirementsReceipt
)
_FIXED_RUNTIME_RECEIPT_TYPE = RepositoryExecutableRuntimeManifestReceipt
_FIXED_STAGING_RECEIPT_TYPE = RepositoryExecutableStagingReceipt
_FIXED_STAGE_LEASE_TYPE = RepositoryExecutableStageLease


class _InvalidNativeDependencyRequirements(ValueError):
    """Private fail-closed sentinel whose details never cross the API."""


class _UnsupportedDependencyLayout(ValueError):
    """A bounded dependency layout that this schema does not model."""


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeDependencyDeclaration:
    """One bounded dependency-name declaration from a native image."""

    kind: str
    runtime_file_ref: str = field(repr=False)
    format_class: str
    ordinal: int
    load_kind: str
    dependency_name_ref: str = field(repr=False)
    dependency_name_bytes: int
    path_style: str
    compatibility_version: int | None
    current_version: int | None
    declaration_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_DECLARATION_PROJECTION(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeDependencyRequirement:
    """One runtime file's bounded native dependency syntax."""

    kind: str
    staged_file_ref: str = field(repr=False)
    runtime_file_ref: str = field(repr=False)
    native_loader_requirement_ref: str = field(repr=False)
    runtime_classification: str
    format_class: str | None
    byte_order: str | None
    image_kind: str | None
    disposition: str
    declarations: tuple[
        RepositoryExecutableNativeDependencyDeclaration, ...
    ] = field(repr=False)
    declaration_count: int
    required_dependency_count: int
    weak_dependency_count: int
    total_dependency_name_bytes: int
    layout_supported: bool
    requirement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_REQUIREMENT_PROJECTION(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeDependencyRequirementBinding:
    """One registered command bound to one dependency requirement."""

    kind: str
    command_kind: str
    command_id: str = field(repr=False)
    command_digest: str = field(repr=False)
    staged_file_ref: str = field(repr=False)
    runtime_file_ref: str = field(repr=False)
    native_loader_requirement_ref: str = field(repr=False)
    dependency_requirement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_BINDING_PROJECTION(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeDependencyRequirementsReceipt:
    """Historical native dependency-declaration evidence."""

    kind: str
    schema_version: int
    requirements_source: str
    requirements_scope: str
    native_loader_requirements_receipt_digest: str = field(repr=False)
    runtime_manifest_receipt_digest: str = field(repr=False)
    staging_receipt_digest: str = field(repr=False)
    registration_digest: str = field(repr=False)
    repository_ref: str = field(repr=False)
    verification_commands_digest: str = field(repr=False)
    resolution_context_digest: str = field(repr=False)
    staging_context_digest: str = field(repr=False)
    requirements: tuple[
        RepositoryExecutableNativeDependencyRequirement, ...
    ] = field(repr=False)
    bindings: tuple[
        RepositoryExecutableNativeDependencyRequirementBinding, ...
    ] = field(repr=False)
    requirement_count: int
    command_count: int
    native_requirement_count: int
    dependency_declared_requirement_count: int
    dependency_declaration_count: int
    required_dependency_count: int
    weak_dependency_count: int
    unsupported_native_layout_count: int
    non_native_not_applicable_count: int
    total_dependency_name_bytes: int

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_RECEIPT_PROJECTION(self)

    @property
    def receipt_digest(self) -> str:
        return _BUILTIN_CANONICAL_DIGEST(
            _BUILTIN_RECEIPT_PROJECTION(self)
        )

    def to_evidence(self) -> dict[str, Any]:
        return _BUILTIN_EVIDENCE_PROJECTION(self)


_FIXED_DECLARATION_TYPE = RepositoryExecutableNativeDependencyDeclaration
_FIXED_REQUIREMENT_TYPE = RepositoryExecutableNativeDependencyRequirement
_FIXED_BINDING_TYPE = RepositoryExecutableNativeDependencyRequirementBinding
_FIXED_RECEIPT_TYPE = RepositoryExecutableNativeDependencyRequirementsReceipt


def _is_digest(value: Any) -> bool:
    return (
        type(value) is str
        and _DIGEST_PATTERN.fullmatch(value) is not None
    )


_BUILTIN_IS_DIGEST = _is_digest


def _declaration_ref_projection(
    *,
    runtime_file_ref: str,
    format_class: str,
    ordinal: int,
    load_kind: str,
    dependency_name_ref: str,
    dependency_name_bytes: int,
    path_style: str,
    compatibility_version: int | None,
    current_version: int | None,
) -> dict[str, Any]:
    return {
        "compatibility_version": compatibility_version,
        "current_version": current_version,
        "dependency_name_bytes": dependency_name_bytes,
        "dependency_name_ref": dependency_name_ref,
        "format_class": format_class,
        "kind": "repository_executable_native_dependency_declaration_ref",
        "load_kind": load_kind,
        "ordinal": ordinal,
        "path_style": path_style,
        "requirements_scope": _FIXED_REQUIREMENTS_SCOPE,
        "runtime_file_ref": runtime_file_ref,
        "schema_version": _FIXED_SCHEMA_VERSION,
    }


_BUILTIN_DECLARATION_REF_PROJECTION = _declaration_ref_projection


def _declaration_projection(
    value: RepositoryExecutableNativeDependencyDeclaration,
) -> dict[str, Any]:
    versions = (value.compatibility_version, value.current_version)
    mach_o = value.format_class in {"mach_o32", "mach_o64"}
    if (
        type(value) is not _FIXED_DECLARATION_TYPE
        or value.kind != _FIXED_DECLARATION_KIND
        or not _BUILTIN_IS_DIGEST(value.runtime_file_ref)
        or value.format_class not in _FORMAT_CLASSES
        or type(value.ordinal) is not int
        or not 0 <= value.ordinal < _MAX_DEPENDENCIES_PER_FILE
        or value.load_kind not in _LOAD_KINDS
        or not _BUILTIN_IS_DIGEST(value.dependency_name_ref)
        or type(value.dependency_name_bytes) is not int
        or not 1 <= value.dependency_name_bytes <= _MAX_DEPENDENCY_NAME_BYTES
        or value.path_style not in _PATH_STYLES
        or any(
            item is not None
            and (type(item) is not int or not 0 <= item <= 0xFFFFFFFF)
            for item in versions
        )
        or mach_o != all(item is not None for item in versions)
        or (not mach_o and any(item is not None for item in versions))
        or (not mach_o and value.load_kind != "required")
        or not _BUILTIN_IS_DIGEST(value.declaration_ref)
    ):
        raise _InvalidNativeDependencyRequirements
    reference = _BUILTIN_DECLARATION_REF_PROJECTION(
        runtime_file_ref=value.runtime_file_ref,
        format_class=value.format_class,
        ordinal=value.ordinal,
        load_kind=value.load_kind,
        dependency_name_ref=value.dependency_name_ref,
        dependency_name_bytes=value.dependency_name_bytes,
        path_style=value.path_style,
        compatibility_version=value.compatibility_version,
        current_version=value.current_version,
    )
    if value.declaration_ref != _BUILTIN_CANONICAL_DIGEST(reference):
        raise _InvalidNativeDependencyRequirements
    return {**reference, "kind": value.kind, "declaration_ref": value.declaration_ref}


_BUILTIN_DECLARATION_PROJECTION = _declaration_projection


def _requirement_ref_projection(
    *,
    staged_file_ref: str,
    runtime_file_ref: str,
    native_loader_requirement_ref: str,
    runtime_classification: str,
    format_class: str | None,
    byte_order: str | None,
    image_kind: str | None,
    disposition: str,
    declarations: list[dict[str, Any]],
    layout_supported: bool,
) -> dict[str, Any]:
    return {
        "byte_order": byte_order,
        "declarations": declarations,
        "disposition": disposition,
        "format_class": format_class,
        "image_kind": image_kind,
        "kind": "repository_executable_native_dependency_requirement_ref",
        "layout_supported": layout_supported,
        "native_loader_requirement_ref": native_loader_requirement_ref,
        "requirements_scope": _FIXED_REQUIREMENTS_SCOPE,
        "runtime_classification": runtime_classification,
        "runtime_file_ref": runtime_file_ref,
        "schema_version": _FIXED_SCHEMA_VERSION,
        "staged_file_ref": staged_file_ref,
    }


_BUILTIN_REQUIREMENT_REF_PROJECTION = _requirement_ref_projection


def _requirement_projection(
    value: RepositoryExecutableNativeDependencyRequirement,
) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_REQUIREMENT_TYPE
        or value.kind != _FIXED_REQUIREMENT_KIND
        or not all(
            _BUILTIN_IS_DIGEST(item)
            for item in (
                value.staged_file_ref,
                value.runtime_file_ref,
                value.native_loader_requirement_ref,
                value.requirement_ref,
            )
        )
        or value.runtime_classification not in _RUNTIME_CLASSIFICATIONS
        or (
            value.format_class is not None
            and value.format_class not in _FORMAT_CLASSES
        )
        or (
            value.byte_order is not None
            and value.byte_order not in _BYTE_ORDERS
        )
        or (
            value.image_kind is not None
            and value.image_kind not in _IMAGE_KINDS
        )
        or value.disposition not in _DISPOSITIONS
        or type(value.declarations) is not tuple
        or len(value.declarations) > _MAX_DEPENDENCIES_PER_FILE
        or type(value.declaration_count) is not int
        or value.declaration_count != len(value.declarations)
        or any(
            type(item) is not int or item < 0
            for item in (
                value.required_dependency_count,
                value.weak_dependency_count,
                value.total_dependency_name_bytes,
            )
        )
        or type(value.layout_supported) is not bool
    ):
        raise _InvalidNativeDependencyRequirements
    declarations = [
        _BUILTIN_DECLARATION_PROJECTION(item) for item in value.declarations
    ]
    if any(
        item.runtime_file_ref != value.runtime_file_ref
        or item.format_class != value.format_class
        or item.ordinal != index
        for index, item in enumerate(value.declarations)
    ):
        raise _InvalidNativeDependencyRequirements
    native = value.runtime_classification in {"elf", "mach_o"}
    declared = value.disposition in {
        "elf_dependencies_declared",
        "mach_o_dependencies_declared",
    }
    absent = value.disposition in {
        "elf_dependencies_absent",
        "mach_o_dependencies_absent",
    }
    if not native:
        if (
            value.disposition != "non_native_not_applicable"
            or value.format_class is not None
            or value.byte_order is not None
            or value.image_kind is not None
            or value.declarations
            or value.layout_supported
        ):
            raise _InvalidNativeDependencyRequirements
    else:
        prefix = "elf_" if value.runtime_classification == "elf" else "mach_o_"
        if (
            value.format_class is None
            or value.byte_order is None
            or (
                not value.disposition.startswith(prefix)
                and value.disposition != "unsupported_native_layout"
            )
        ):
            raise _InvalidNativeDependencyRequirements
        if value.disposition == "unsupported_native_layout":
            if (
                value.image_kind is not None
                or value.declarations
                or value.layout_supported
            ):
                raise _InvalidNativeDependencyRequirements
        elif not value.layout_supported or value.image_kind is None:
            raise _InvalidNativeDependencyRequirements
        if declared != bool(value.declarations) or (absent and value.declarations):
            raise _InvalidNativeDependencyRequirements
    required_count = sum(
        item.load_kind not in _WEAK_LOAD_KINDS for item in value.declarations
    )
    weak_count = len(value.declarations) - required_count
    total_name_bytes = sum(
        item.dependency_name_bytes for item in value.declarations
    )
    if (
        required_count != value.required_dependency_count
        or weak_count != value.weak_dependency_count
        or total_name_bytes != value.total_dependency_name_bytes
    ):
        raise _InvalidNativeDependencyRequirements
    reference = _BUILTIN_REQUIREMENT_REF_PROJECTION(
        staged_file_ref=value.staged_file_ref,
        runtime_file_ref=value.runtime_file_ref,
        native_loader_requirement_ref=value.native_loader_requirement_ref,
        runtime_classification=value.runtime_classification,
        format_class=value.format_class,
        byte_order=value.byte_order,
        image_kind=value.image_kind,
        disposition=value.disposition,
        declarations=declarations,
        layout_supported=value.layout_supported,
    )
    if value.requirement_ref != _BUILTIN_CANONICAL_DIGEST(reference):
        raise _InvalidNativeDependencyRequirements
    return {
        **reference,
        "declaration_count": value.declaration_count,
        "kind": value.kind,
        "required_dependency_count": value.required_dependency_count,
        "requirement_ref": value.requirement_ref,
        "total_dependency_name_bytes": value.total_dependency_name_bytes,
        "weak_dependency_count": value.weak_dependency_count,
    }


_BUILTIN_REQUIREMENT_PROJECTION = _requirement_projection


def _binding_projection(
    value: RepositoryExecutableNativeDependencyRequirementBinding,
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
                value.native_loader_requirement_ref,
                value.dependency_requirement_ref,
            )
        )
    ):
        raise _InvalidNativeDependencyRequirements
    return {
        "command_digest": value.command_digest,
        "command_id": value.command_id,
        "command_kind": value.command_kind,
        "dependency_requirement_ref": value.dependency_requirement_ref,
        "kind": value.kind,
        "native_loader_requirement_ref": value.native_loader_requirement_ref,
        "runtime_file_ref": value.runtime_file_ref,
        "staged_file_ref": value.staged_file_ref,
    }


_BUILTIN_BINDING_PROJECTION = _binding_projection


def _receipt_projection(
    value: RepositoryExecutableNativeDependencyRequirementsReceipt,
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
    )
    count_fields = (
        value.native_requirement_count,
        value.dependency_declared_requirement_count,
        value.dependency_declaration_count,
        value.required_dependency_count,
        value.weak_dependency_count,
        value.unsupported_native_layout_count,
        value.non_native_not_applicable_count,
        value.total_dependency_name_bytes,
    )
    if (
        type(value) is not _FIXED_RECEIPT_TYPE
        or value.kind != _FIXED_RECEIPT_KIND
        or type(value.schema_version) is not int
        or value.schema_version != _FIXED_SCHEMA_VERSION
        or value.requirements_source != _FIXED_REQUIREMENTS_SOURCE
        or value.requirements_scope != _FIXED_REQUIREMENTS_SCOPE
        or not all(_BUILTIN_IS_DIGEST(item) for item in digest_fields)
        or type(value.requirements) is not tuple
        or not 1 <= len(value.requirements) <= _MAX_FILES
        or type(value.bindings) is not tuple
        or not 1 <= len(value.bindings) <= _MAX_COMMANDS
        or type(value.requirement_count) is not int
        or value.requirement_count != len(value.requirements)
        or type(value.command_count) is not int
        or value.command_count != len(value.bindings)
        or any(type(item) is not int or item < 0 for item in count_fields)
        or value.dependency_declaration_count > _MAX_DEPENDENCIES
        or value.total_dependency_name_bytes
        > _MAX_TOTAL_DEPENDENCY_NAME_BYTES
    ):
        raise _InvalidNativeDependencyRequirements
    requirements = [
        _BUILTIN_REQUIREMENT_PROJECTION(item) for item in value.requirements
    ]
    bindings = [
        _BUILTIN_BINDING_PROJECTION(item) for item in value.bindings
    ]
    requirement_by_ref: dict[
        str, RepositoryExecutableNativeDependencyRequirement
    ] = {}
    runtime_file_refs: set[str] = set()
    staged_file_refs: set[str] = set()
    declaration_refs: set[str] = set()
    for item in value.requirements:
        item_declaration_refs = {
            declaration.declaration_ref for declaration in item.declarations
        }
        if (
            item.requirement_ref in requirement_by_ref
            or item.runtime_file_ref in runtime_file_refs
            or item.staged_file_ref in staged_file_refs
            or len(item_declaration_refs) != len(item.declarations)
            or declaration_refs.intersection(item_declaration_refs)
        ):
            raise _InvalidNativeDependencyRequirements
        requirement_by_ref[item.requirement_ref] = item
        runtime_file_refs.add(item.runtime_file_ref)
        staged_file_refs.add(item.staged_file_ref)
        declaration_refs.update(item_declaration_refs)

    command_ids: set[str] = set()
    used_requirement_refs: set[str] = set()
    ordered_first_use: list[str] = []
    prior_kind_index = -1
    for item in value.bindings:
        requirement = requirement_by_ref.get(item.dependency_requirement_ref)
        kind_index = _COMMAND_KINDS.index(item.command_kind)
        if (
            requirement is None
            or item.staged_file_ref != requirement.staged_file_ref
            or item.runtime_file_ref != requirement.runtime_file_ref
            or item.native_loader_requirement_ref
            != requirement.native_loader_requirement_ref
            or item.command_id in command_ids
            or kind_index < prior_kind_index
        ):
            raise _InvalidNativeDependencyRequirements
        command_ids.add(item.command_id)
        if item.dependency_requirement_ref not in used_requirement_refs:
            ordered_first_use.append(item.dependency_requirement_ref)
        used_requirement_refs.add(item.dependency_requirement_ref)
        prior_kind_index = kind_index

    native_count = sum(
        item.runtime_classification in {"elf", "mach_o"}
        for item in value.requirements
    )
    declared_requirement_count = sum(
        bool(item.declarations) for item in value.requirements
    )
    declaration_count = sum(
        item.declaration_count for item in value.requirements
    )
    required_count = sum(
        item.required_dependency_count for item in value.requirements
    )
    weak_count = sum(
        item.weak_dependency_count for item in value.requirements
    )
    unsupported_count = sum(
        item.disposition == "unsupported_native_layout"
        for item in value.requirements
    )
    non_native_count = sum(
        item.disposition == "non_native_not_applicable"
        for item in value.requirements
    )
    total_name_bytes = sum(
        item.total_dependency_name_bytes for item in value.requirements
    )
    if (
        used_requirement_refs != set(requirement_by_ref)
        or tuple(ordered_first_use)
        != tuple(item.requirement_ref for item in value.requirements)
        or native_count != value.native_requirement_count
        or declared_requirement_count
        != value.dependency_declared_requirement_count
        or declaration_count != value.dependency_declaration_count
        or required_count != value.required_dependency_count
        or weak_count != value.weak_dependency_count
        or unsupported_count != value.unsupported_native_layout_count
        or non_native_count != value.non_native_not_applicable_count
        or total_name_bytes != value.total_dependency_name_bytes
        or required_count + weak_count != declaration_count
    ):
        raise _InvalidNativeDependencyRequirements
    return {
        "bindings": bindings,
        "command_count": value.command_count,
        "dependency_declaration_count": value.dependency_declaration_count,
        "dependency_declared_requirement_count": (
            value.dependency_declared_requirement_count
        ),
        "kind": value.kind,
        "native_loader_requirements_receipt_digest": (
            value.native_loader_requirements_receipt_digest
        ),
        "native_requirement_count": value.native_requirement_count,
        "non_native_not_applicable_count": (
            value.non_native_not_applicable_count
        ),
        "registration_digest": value.registration_digest,
        "repository_ref": value.repository_ref,
        "required_dependency_count": value.required_dependency_count,
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
        "total_dependency_name_bytes": value.total_dependency_name_bytes,
        "unsupported_native_layout_count": (
            value.unsupported_native_layout_count
        ),
        "verification_commands_digest": value.verification_commands_digest,
        "weak_dependency_count": value.weak_dependency_count,
    }


_BUILTIN_RECEIPT_PROJECTION = _receipt_projection


def _evidence_projection(
    value: RepositoryExecutableNativeDependencyRequirementsReceipt,
) -> dict[str, Any]:
    canonical = _BUILTIN_RECEIPT_PROJECTION(value)
    dispositions = {
        disposition: sum(
            item.disposition == disposition for item in value.requirements
        )
        for disposition in _DISPOSITIONS
    }
    return {
        "action_receipt_issued": False,
        "active_stage_lease_verified_at_measurement": True,
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
        "dependency_declaration_syntax_inspection_complete": True,
        "dependency_declared_requirement_count": (
            value.dependency_declared_requirement_count
        ),
        "dependency_name_raw_bytes_exposed": False,
        "dependency_path_lookup_performed": False,
        "dispatch_enabled": False,
        "durable_control_plane_persistence_enabled": False,
        "effect_class": 0,
        "elf_dependencies_absent_count": dispositions[
            "elf_dependencies_absent"
        ],
        "elf_dependencies_declared_count": dispositions[
            "elf_dependencies_declared"
        ],
        "environment_coverage_verified": False,
        "execution_enabled": False,
        "fat_mach_o_architecture_selection_performed": False,
        "future_execution_correspondence_verified": False,
        "harness_invocation_performed": False,
        "kind": _FIXED_EVIDENCE_KIND,
        "lease_cleanup_performed": False,
        "lease_mutated": False,
        "live_execution_eligible": False,
        "mach_o_dependencies_absent_count": dispositions[
            "mach_o_dependencies_absent"
        ],
        "mach_o_dependencies_declared_count": dispositions[
            "mach_o_dependencies_declared"
        ],
        "model_invocation_performed": False,
        "native_loader_authenticity_verified": False,
        "native_loader_compatibility_verified": False,
        "native_loader_identity_verified": False,
        "native_requirement_count": value.native_requirement_count,
        "network_access_performed": False,
        "non_native_not_applicable_count": (
            value.non_native_not_applicable_count
        ),
        "path_lookup_performed": False,
        "proposal_lineage_extended": False,
        "receipt_authenticity_verified": False,
        "receipt_digest": _BUILTIN_CANONICAL_DIGEST(canonical),
        "recursive_dependency_resolution_verified": False,
        "registration_digest": value.registration_digest,
        "repository_ref": value.repository_ref,
        "required_dependency_count": value.required_dependency_count,
        "requirement_count": value.requirement_count,
        "requirements_scope": value.requirements_scope,
        "requirements_source": value.requirements_source,
        "route_eligible": False,
        "runtime_manifest_complete": False,
        "schema_version": value.schema_version,
        "shared_library_closure_verified": False,
        "source_path_reopen_performed": False,
        "staged_byte_correspondence_verified": True,
        "staged_descriptor_full_remeasurement_complete": True,
        "subprocess_invocation_performed": False,
        "toolchain_completeness_verified": False,
        "total_dependency_name_bytes": value.total_dependency_name_bytes,
        "unsupported_native_layout_count": (
            value.unsupported_native_layout_count
        ),
        "validation_mode": "read_only",
        "weak_dependency_count": value.weak_dependency_count,
        "worker_authorized": False,
        "worktree_integration_enabled": False,
    }


_BUILTIN_EVIDENCE_PROJECTION = _evidence_projection


def _dependency_name_ref(
    *,
    runtime_file_ref: str,
    format_class: str,
    dependency_name: bytes,
) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "dependency_name_hex": dependency_name.hex(),
            "format_class": format_class,
            "kind": "repository_executable_native_dependency_name_ref",
            "runtime_file_ref": runtime_file_ref,
            "schema_version": _FIXED_SCHEMA_VERSION,
        }
    )


_BUILTIN_DEPENDENCY_NAME_REF = _dependency_name_ref


def _dependency_path_style(name: bytes) -> str:
    if (
        type(name) is not bytes
        or not 1 <= len(name) <= _MAX_DEPENDENCY_NAME_BYTES
        or b"\x00" in name
    ):
        raise _UnsupportedDependencyLayout
    if name.startswith(b"@rpath/"):
        return "at_rpath"
    if name.startswith(b"@loader_path/"):
        return "at_loader_path"
    if name.startswith(b"@executable_path/"):
        return "at_executable_path"
    if name.startswith(b"/"):
        return "absolute"
    if b"/" in name:
        return "relative"
    return "bare"


_BUILTIN_DEPENDENCY_PATH_STYLE = _dependency_path_style


def _build_declaration(
    *,
    runtime_file_ref: str,
    format_class: str,
    ordinal: int,
    load_kind: str,
    dependency_name: bytes,
    compatibility_version: int | None,
    current_version: int | None,
) -> RepositoryExecutableNativeDependencyDeclaration:
    dependency_name_ref = _BUILTIN_DEPENDENCY_NAME_REF(
        runtime_file_ref=runtime_file_ref,
        format_class=format_class,
        dependency_name=dependency_name,
    )
    path_style = _BUILTIN_DEPENDENCY_PATH_STYLE(dependency_name)
    reference = _BUILTIN_DECLARATION_REF_PROJECTION(
        runtime_file_ref=runtime_file_ref,
        format_class=format_class,
        ordinal=ordinal,
        load_kind=load_kind,
        dependency_name_ref=dependency_name_ref,
        dependency_name_bytes=len(dependency_name),
        path_style=path_style,
        compatibility_version=compatibility_version,
        current_version=current_version,
    )
    value = _FIXED_DECLARATION_TYPE(
        kind=_FIXED_DECLARATION_KIND,
        runtime_file_ref=runtime_file_ref,
        format_class=format_class,
        ordinal=ordinal,
        load_kind=load_kind,
        dependency_name_ref=dependency_name_ref,
        dependency_name_bytes=len(dependency_name),
        path_style=path_style,
        compatibility_version=compatibility_version,
        current_version=current_version,
        declaration_ref=_BUILTIN_CANONICAL_DIGEST(reference),
    )
    _BUILTIN_DECLARATION_PROJECTION(value)
    return value


_BUILTIN_BUILD_DECLARATION = _build_declaration


def _elf_dependency_fields(
    runtime_file: Any,
    loader_requirement: dict[str, Any],
    *,
    descriptor: int,
    header: bytes,
) -> tuple[
    str,
    str,
    str | None,
    str,
    tuple[RepositoryExecutableNativeDependencyDeclaration, ...],
    bool,
]:
    if len(header) < 16 or not header.startswith(b"\x7fELF"):
        raise _InvalidNativeDependencyRequirements
    elf_class = header[4]
    data_encoding = header[5]
    if elf_class not in {1, 2} or data_encoding not in {1, 2} or header[6] != 1:
        raise _InvalidNativeDependencyRequirements
    format_class = "elf32" if elf_class == 1 else "elf64"
    byte_order = "little" if data_encoding == 1 else "big"
    try:
        header_size = 52 if elf_class == 1 else 64
        program_header_size = 32 if elf_class == 1 else 56
        dynamic_entry_size = 8 if elf_class == 1 else 16
        if len(header) < header_size:
            raise _UnsupportedDependencyLayout
        image_type = _BUILTIN_INTEGER(header, 16, 2, byte_order)
        image_kind = (
            "executable"
            if image_type == 2
            else "shared_object"
            if image_type == 3
            else "other"
        )
        if elf_class == 1:
            table_offset = _BUILTIN_INTEGER(header, 28, 4, byte_order)
            declared_header_size = _BUILTIN_INTEGER(header, 40, 2, byte_order)
            entry_size = _BUILTIN_INTEGER(header, 42, 2, byte_order)
            entry_count = _BUILTIN_INTEGER(header, 44, 2, byte_order)
        else:
            table_offset = _BUILTIN_INTEGER(header, 32, 8, byte_order)
            declared_header_size = _BUILTIN_INTEGER(header, 52, 2, byte_order)
            entry_size = _BUILTIN_INTEGER(header, 54, 2, byte_order)
            entry_count = _BUILTIN_INTEGER(header, 56, 2, byte_order)
        if (
            declared_header_size != header_size
            or entry_size != program_header_size
            or entry_count > _MAX_PROGRAM_HEADERS
        ):
            raise _UnsupportedDependencyLayout
        table = _BUILTIN_READ_EXACT_RANGE(
            descriptor,
            offset=table_offset,
            size=entry_count * entry_size,
            content_bytes=runtime_file.content_bytes,
            maximum_bytes=_MAX_TABLE_BYTES,
        )
        load_segments: list[tuple[int, int, int]] = []
        dynamic_segments: list[tuple[int, int]] = []
        for index in range(entry_count):
            entry = table[index * entry_size : (index + 1) * entry_size]
            segment_type = _BUILTIN_INTEGER(entry, 0, 4, byte_order)
            if elf_class == 1:
                segment_offset = _BUILTIN_INTEGER(entry, 4, 4, byte_order)
                virtual_address = _BUILTIN_INTEGER(entry, 8, 4, byte_order)
                file_size = _BUILTIN_INTEGER(entry, 16, 4, byte_order)
                memory_size = _BUILTIN_INTEGER(entry, 20, 4, byte_order)
            else:
                segment_offset = _BUILTIN_INTEGER(entry, 8, 8, byte_order)
                virtual_address = _BUILTIN_INTEGER(entry, 16, 8, byte_order)
                file_size = _BUILTIN_INTEGER(entry, 32, 8, byte_order)
                memory_size = _BUILTIN_INTEGER(entry, 40, 8, byte_order)
            if (
                segment_type in {_PT_LOAD, _PT_DYNAMIC}
                and file_size > memory_size
            ):
                raise _UnsupportedDependencyLayout
            if segment_type == _PT_LOAD:
                load_segments.append(
                    (segment_offset, virtual_address, file_size)
                )
            elif segment_type == _PT_DYNAMIC:
                dynamic_segments.append((segment_offset, file_size))
        if len(dynamic_segments) > 1:
            raise _UnsupportedDependencyLayout
        if not dynamic_segments:
            return (
                format_class,
                byte_order,
                image_kind,
                "elf_dependencies_absent",
                (),
                True,
            )
        dynamic_offset, dynamic_size = dynamic_segments[0]
        if dynamic_size % dynamic_entry_size != 0:
            raise _UnsupportedDependencyLayout
        dynamic_table = _BUILTIN_READ_EXACT_RANGE(
            descriptor,
            offset=dynamic_offset,
            size=dynamic_size,
            content_bytes=runtime_file.content_bytes,
            maximum_bytes=_MAX_TABLE_BYTES,
        )
        needed_offsets: list[int] = []
        string_addresses: list[int] = []
        string_sizes: list[int] = []
        terminated = False
        for cursor in range(0, len(dynamic_table), dynamic_entry_size):
            entry = dynamic_table[cursor : cursor + dynamic_entry_size]
            value_size = 4 if elf_class == 1 else 8
            tag = _BUILTIN_INTEGER(entry, 0, value_size, byte_order)
            value_offset = value_size
            item_value = _BUILTIN_INTEGER(
                entry,
                value_offset,
                value_size,
                byte_order,
            )
            if terminated:
                if tag != 0 or item_value != 0:
                    raise _UnsupportedDependencyLayout
                continue
            if tag == _DT_NULL:
                terminated = True
            elif tag == _DT_NEEDED:
                needed_offsets.append(item_value)
            elif tag == _DT_STRTAB:
                string_addresses.append(item_value)
            elif tag == _DT_STRSZ:
                string_sizes.append(item_value)
        if not terminated or len(needed_offsets) > _MAX_DEPENDENCIES_PER_FILE:
            raise _UnsupportedDependencyLayout
        if not needed_offsets:
            return (
                format_class,
                byte_order,
                image_kind,
                "elf_dependencies_absent",
                (),
                True,
            )
        if len(string_addresses) != 1 or len(string_sizes) != 1:
            raise _UnsupportedDependencyLayout
        string_address = string_addresses[0]
        string_size = string_sizes[0]
        if not 1 <= string_size <= _MAX_STRING_TABLE_BYTES:
            raise _UnsupportedDependencyLayout
        mappings: list[int] = []
        for segment_offset, virtual_address, file_size in load_segments:
            if (
                virtual_address <= string_address
                and string_address - virtual_address <= file_size
                and string_size <= file_size - (string_address - virtual_address)
            ):
                mappings.append(
                    segment_offset + (string_address - virtual_address)
                )
        if len(mappings) != 1:
            raise _UnsupportedDependencyLayout
        string_table = _BUILTIN_READ_EXACT_RANGE(
            descriptor,
            offset=mappings[0],
            size=string_size,
            content_bytes=runtime_file.content_bytes,
            maximum_bytes=_MAX_STRING_TABLE_BYTES,
        )
        declarations: list[
            RepositoryExecutableNativeDependencyDeclaration
        ] = []
        for ordinal, name_offset in enumerate(needed_offsets):
            if name_offset >= len(string_table):
                raise _UnsupportedDependencyLayout
            terminator = string_table.find(b"\x00", name_offset)
            if terminator < 0:
                raise _UnsupportedDependencyLayout
            dependency_name = string_table[name_offset:terminator]
            declarations.append(
                _BUILTIN_BUILD_DECLARATION(
                    runtime_file_ref=runtime_file.runtime_file_ref,
                    format_class=format_class,
                    ordinal=ordinal,
                    load_kind="required",
                    dependency_name=dependency_name,
                    compatibility_version=None,
                    current_version=None,
                )
            )
        if (
            loader_requirement.get("format_class") != format_class
            or loader_requirement.get("byte_order") != byte_order
            or loader_requirement.get("image_kind") != image_kind
        ):
            raise _InvalidNativeDependencyRequirements
        return (
            format_class,
            byte_order,
            image_kind,
            "elf_dependencies_declared",
            tuple(declarations),
            True,
        )
    except (_UnsupportedDependencyLayout, _DirectUnsupportedNativeLayout):
        return (
            format_class,
            byte_order,
            None,
            "unsupported_native_layout",
            (),
            False,
        )


_BUILTIN_ELF_DEPENDENCY_FIELDS = _elf_dependency_fields


def _mach_o_dependency_fields(
    runtime_file: Any,
    loader_requirement: dict[str, Any],
    *,
    descriptor: int,
    header: bytes,
) -> tuple[
    str,
    str,
    str | None,
    str,
    tuple[RepositoryExecutableNativeDependencyDeclaration, ...],
    bool,
]:
    magic = header[:4]
    if magic in _FAT_MACH_O:
        format_class, byte_order = _FAT_MACH_O[magic]
        return (
            format_class,
            byte_order,
            None,
            "unsupported_native_layout",
            (),
            False,
        )
    thin = _THIN_MACH_O.get(magic)
    if thin is None:
        raise _InvalidNativeDependencyRequirements
    format_class, byte_order, header_size = thin
    try:
        if len(header) < header_size:
            raise _UnsupportedDependencyLayout
        file_type = _BUILTIN_INTEGER(header, 12, 4, byte_order)
        image_kind = (
            "executable"
            if file_type == 2
            else "shared_object"
            if file_type == 6
            else "dynamic_linker"
            if file_type == 7
            else "other"
        )
        command_count = _BUILTIN_INTEGER(header, 16, 4, byte_order)
        command_bytes = _BUILTIN_INTEGER(header, 20, 4, byte_order)
        if command_count > _MAX_LOAD_COMMANDS or command_bytes > _MAX_TABLE_BYTES:
            raise _UnsupportedDependencyLayout
        table = _BUILTIN_READ_EXACT_RANGE(
            descriptor,
            offset=header_size,
            size=command_bytes,
            content_bytes=runtime_file.content_bytes,
            maximum_bytes=_MAX_TABLE_BYTES,
        )
        cursor = 0
        declarations: list[
            RepositoryExecutableNativeDependencyDeclaration
        ] = []
        for _ in range(command_count):
            if cursor + 8 > len(table):
                raise _UnsupportedDependencyLayout
            command = _BUILTIN_INTEGER(table, cursor, 4, byte_order)
            command_size = _BUILTIN_INTEGER(table, cursor + 4, 4, byte_order)
            if (
                command_size < 8
                or command_size % 4 != 0
                or command_size > len(table) - cursor
            ):
                raise _UnsupportedDependencyLayout
            load_kind = _MACH_O_DEPENDENCY_COMMANDS.get(command)
            if load_kind is not None:
                if (
                    command_size < 24
                    or len(declarations) >= _MAX_DEPENDENCIES_PER_FILE
                ):
                    raise _UnsupportedDependencyLayout
                name_offset = _BUILTIN_INTEGER(
                    table,
                    cursor + 8,
                    4,
                    byte_order,
                )
                current_version = _BUILTIN_INTEGER(
                    table,
                    cursor + 16,
                    4,
                    byte_order,
                )
                compatibility_version = _BUILTIN_INTEGER(
                    table,
                    cursor + 20,
                    4,
                    byte_order,
                )
                if name_offset < 24 or name_offset >= command_size:
                    raise _UnsupportedDependencyLayout
                command_data = table[cursor : cursor + command_size]
                raw_tail = command_data[name_offset:]
                terminator = raw_tail.find(b"\x00")
                if terminator < 0 or any(raw_tail[terminator + 1 :]):
                    raise _UnsupportedDependencyLayout
                dependency_name = raw_tail[:terminator]
                declarations.append(
                    _BUILTIN_BUILD_DECLARATION(
                        runtime_file_ref=runtime_file.runtime_file_ref,
                        format_class=format_class,
                        ordinal=len(declarations),
                        load_kind=load_kind,
                        dependency_name=dependency_name,
                        compatibility_version=compatibility_version,
                        current_version=current_version,
                    )
                )
            cursor += command_size
        if cursor != len(table):
            raise _UnsupportedDependencyLayout
        if (
            loader_requirement.get("format_class") != format_class
            or loader_requirement.get("byte_order") != byte_order
            or loader_requirement.get("image_kind") != image_kind
        ):
            raise _InvalidNativeDependencyRequirements
        disposition = (
            "mach_o_dependencies_declared"
            if declarations
            else "mach_o_dependencies_absent"
        )
        return (
            format_class,
            byte_order,
            image_kind,
            disposition,
            tuple(declarations),
            True,
        )
    except (_UnsupportedDependencyLayout, _DirectUnsupportedNativeLayout):
        return (
            format_class,
            byte_order,
            None,
            "unsupported_native_layout",
            (),
            False,
        )


_BUILTIN_MACH_O_DEPENDENCY_FIELDS = _mach_o_dependency_fields


def _build_requirement(
    runtime_file: Any,
    loader_requirement: dict[str, Any],
    *,
    descriptor: int,
    header: bytes,
) -> RepositoryExecutableNativeDependencyRequirement:
    if (
        type(loader_requirement) is not dict
        or loader_requirement.get("runtime_file_ref")
        != runtime_file.runtime_file_ref
        or loader_requirement.get("staged_file_ref")
        != runtime_file.staged_file_ref
        or runtime_file.header_bytes != len(header)
        or runtime_file.header_digest
        != _BUILTIN_HEADER_DIGEST(runtime_file.staged_file_ref, header)
    ):
        raise _InvalidNativeDependencyRequirements
    classification = runtime_file.classification
    loader_disposition = loader_requirement.get("disposition")
    if loader_disposition == "unsupported_native_layout":
        fields = (
            loader_requirement.get("format_class"),
            loader_requirement.get("byte_order"),
            None,
            "unsupported_native_layout",
            (),
            False,
        )
    elif classification == "elf":
        fields = _BUILTIN_ELF_DEPENDENCY_FIELDS(
            runtime_file,
            loader_requirement,
            descriptor=descriptor,
            header=header,
        )
    elif classification == "mach_o":
        fields = _BUILTIN_MACH_O_DEPENDENCY_FIELDS(
            runtime_file,
            loader_requirement,
            descriptor=descriptor,
            header=header,
        )
    elif classification in {
        "posix_shebang",
        "unsupported_shebang",
        "unknown",
    }:
        if loader_disposition != "non_native_not_applicable":
            raise _InvalidNativeDependencyRequirements
        fields = (None, None, None, "non_native_not_applicable", (), False)
    else:
        raise _InvalidNativeDependencyRequirements
    (
        format_class,
        byte_order,
        image_kind,
        disposition,
        declarations,
        layout_supported,
    ) = fields
    if (
        loader_requirement.get("runtime_classification") != classification
        or loader_requirement.get("format_class") != format_class
        or loader_requirement.get("byte_order") != byte_order
        or (
            layout_supported
            and loader_requirement.get("image_kind") != image_kind
        )
    ):
        raise _InvalidNativeDependencyRequirements
    declaration_projections = [
        _BUILTIN_DECLARATION_PROJECTION(item) for item in declarations
    ]
    reference = _BUILTIN_REQUIREMENT_REF_PROJECTION(
        staged_file_ref=runtime_file.staged_file_ref,
        runtime_file_ref=runtime_file.runtime_file_ref,
        native_loader_requirement_ref=loader_requirement["requirement_ref"],
        runtime_classification=classification,
        format_class=format_class,
        byte_order=byte_order,
        image_kind=image_kind,
        disposition=disposition,
        declarations=declaration_projections,
        layout_supported=layout_supported,
    )
    required_count = sum(
        item.load_kind not in _WEAK_LOAD_KINDS for item in declarations
    )
    value = _FIXED_REQUIREMENT_TYPE(
        kind=_FIXED_REQUIREMENT_KIND,
        staged_file_ref=runtime_file.staged_file_ref,
        runtime_file_ref=runtime_file.runtime_file_ref,
        native_loader_requirement_ref=loader_requirement["requirement_ref"],
        runtime_classification=classification,
        format_class=format_class,
        byte_order=byte_order,
        image_kind=image_kind,
        disposition=disposition,
        declarations=declarations,
        declaration_count=len(declarations),
        required_dependency_count=required_count,
        weak_dependency_count=len(declarations) - required_count,
        total_dependency_name_bytes=sum(
            item.dependency_name_bytes for item in declarations
        ),
        layout_supported=layout_supported,
        requirement_ref=_BUILTIN_CANONICAL_DIGEST(reference),
    )
    _BUILTIN_REQUIREMENT_PROJECTION(value)
    return value


_BUILTIN_BUILD_REQUIREMENT = _build_requirement


def _remeasure_requirements(
    expected_runtime: RepositoryExecutableRuntimeManifestReceipt,
    expected_staging: RepositoryExecutableStagingReceipt,
    loader_canonical: dict[str, Any],
    retained_files: tuple[Any, ...],
) -> tuple[RepositoryExecutableNativeDependencyRequirement, ...]:
    loader_requirements = loader_canonical["requirements"]
    if (
        len(expected_runtime.files) != len(expected_staging.staged_files)
        or len(expected_runtime.files) != len(retained_files)
        or len(expected_runtime.files) != len(loader_requirements)
    ):
        raise _InvalidNativeDependencyRequirements
    requirements: list[RepositoryExecutableNativeDependencyRequirement] = []
    for retained, staged_file, runtime_file, loader_requirement in zip(
        retained_files,
        expected_staging.staged_files,
        expected_runtime.files,
        loader_requirements,
        strict=True,
    ):
        if (
            runtime_file.staged_file_ref != staged_file.staged_file_ref
            or runtime_file.staged_filesystem_identity_ref
            != staged_file.staged_filesystem_identity_ref
            or runtime_file.content_digest != staged_file.content_digest
            or runtime_file.content_bytes != staged_file.content_bytes
        ):
            raise _InvalidNativeDependencyRequirements
        before_header = _BUILTIN_DESCRIPTOR_REMEASUREMENT(
            retained,
            staged_file,
        )
        requirement = _BUILTIN_BUILD_REQUIREMENT(
            runtime_file,
            loader_requirement,
            descriptor=retained.descriptor,
            header=before_header,
        )
        after_header = _BUILTIN_DESCRIPTOR_REMEASUREMENT(
            retained,
            staged_file,
        )
        if after_header != before_header:
            raise _InvalidNativeDependencyRequirements
        requirements.append(requirement)
    return tuple(requirements)


_BUILTIN_REMEASURE_REQUIREMENTS = _remeasure_requirements


def _validate_correspondence(
    native_loader: RepositoryExecutableNativeLoaderRequirementsReceipt,
    loader_canonical: dict[str, Any],
    runtime: RepositoryExecutableRuntimeManifestReceipt,
    runtime_canonical: dict[str, Any],
    staging: RepositoryExecutableStagingReceipt,
    staging_canonical: dict[str, Any],
) -> None:
    runtime_digest = _BUILTIN_CANONICAL_DIGEST(runtime_canonical)
    staging_digest = _BUILTIN_CANONICAL_DIGEST(staging_canonical)
    if (
        native_loader.runtime_manifest_receipt_digest != runtime_digest
        or native_loader.staging_receipt_digest != staging_digest
        or runtime.staging_receipt_digest != staging_digest
        or native_loader.registration_digest != runtime.registration_digest
        or runtime.registration_digest != staging.registration_digest
        or native_loader.repository_ref != runtime.repository_ref
        or runtime.repository_ref != staging.repository_ref
        or native_loader.verification_commands_digest
        != runtime.verification_commands_digest
        or runtime.verification_commands_digest
        != staging.verification_commands_digest
        or native_loader.resolution_context_digest
        != runtime.resolution_context_digest
        or runtime.resolution_context_digest
        != staging.resolution_context_digest
        or native_loader.staging_context_digest != runtime.staging_context_digest
        or runtime.staging_context_digest != staging.staging_context_digest
        or loader_canonical["requirement_count"]
        != runtime_canonical["file_count"]
        or loader_canonical["command_count"]
        != runtime_canonical["command_count"]
        or runtime_canonical["file_count"]
        != staging_canonical["unique_file_count"]
        or runtime_canonical["command_count"]
        != len(staging_canonical["bindings"])
    ):
        raise _InvalidNativeDependencyRequirements


_BUILTIN_VALIDATE_CORRESPONDENCE = _validate_correspondence


def inspect_staged_executable_native_dependency_requirements(
    expected_native_loader_requirements: (
        RepositoryExecutableNativeLoaderRequirementsReceipt
    ),
    *,
    expected_runtime: RepositoryExecutableRuntimeManifestReceipt,
    expected_staging: RepositoryExecutableStagingReceipt,
    lease: RepositoryExecutableStageLease,
) -> RepositoryExecutableNativeDependencyRequirementsReceipt:
    """Inspect bounded native dependency declarations from one active stage."""

    try:
        if (
            type(expected_native_loader_requirements)
            is not _FIXED_NATIVE_LOADER_RECEIPT_TYPE
            or type(expected_runtime) is not _FIXED_RUNTIME_RECEIPT_TYPE
            or type(expected_staging) is not _FIXED_STAGING_RECEIPT_TYPE
            or type(lease) is not _FIXED_STAGE_LEASE_TYPE
        ):
            raise _InvalidNativeDependencyRequirements
        loader_canonical = _BUILTIN_NATIVE_LOADER_PROJECTION(
            expected_native_loader_requirements
        )
        runtime_canonical = _BUILTIN_RUNTIME_PROJECTION(expected_runtime)
        staging_canonical = _BUILTIN_STAGING_PROJECTION(expected_staging)
        _BUILTIN_VALIDATE_CORRESPONDENCE(
            expected_native_loader_requirements,
            loader_canonical,
            expected_runtime,
            runtime_canonical,
            expected_staging,
            staging_canonical,
        )

        fresh_loader = _BUILTIN_INSPECT_NATIVE_LOADER(
            expected_runtime,
            expected_staging=expected_staging,
            lease=lease,
        )
        if _BUILTIN_NATIVE_LOADER_PROJECTION(fresh_loader) != loader_canonical:
            raise _InvalidNativeDependencyRequirements
        active_canonical, retained_files = _BUILTIN_ACTIVE_STAGE_SNAPSHOT(
            expected_staging,
            lease,
        )
        if active_canonical != staging_canonical:
            raise _InvalidNativeDependencyRequirements
        requirements = _BUILTIN_REMEASURE_REQUIREMENTS(
            expected_runtime,
            expected_staging,
            loader_canonical,
            retained_files,
        )

        final_loader = _BUILTIN_INSPECT_NATIVE_LOADER(
            expected_runtime,
            expected_staging=expected_staging,
            lease=lease,
        )
        final_canonical, final_retained_files = (
            _BUILTIN_ACTIVE_STAGE_SNAPSHOT(expected_staging, lease)
        )
        if (
            _BUILTIN_NATIVE_LOADER_PROJECTION(final_loader)
            != loader_canonical
            or final_canonical != staging_canonical
            or final_retained_files is not retained_files
            or _BUILTIN_REMEASURE_REQUIREMENTS(
                expected_runtime,
                expected_staging,
                loader_canonical,
                retained_files,
            )
            != requirements
        ):
            raise _InvalidNativeDependencyRequirements

        by_loader_ref = {
            item.native_loader_requirement_ref: item for item in requirements
        }
        bindings: list[
            RepositoryExecutableNativeDependencyRequirementBinding
        ] = []
        for upstream in loader_canonical["bindings"]:
            requirement = by_loader_ref.get(upstream["requirement_ref"])
            if (
                requirement is None
                or upstream["staged_file_ref"] != requirement.staged_file_ref
                or upstream["runtime_file_ref"] != requirement.runtime_file_ref
            ):
                raise _InvalidNativeDependencyRequirements
            bindings.append(
                _FIXED_BINDING_TYPE(
                    kind=_FIXED_BINDING_KIND,
                    command_kind=upstream["command_kind"],
                    command_id=upstream["command_id"],
                    command_digest=upstream["command_digest"],
                    staged_file_ref=upstream["staged_file_ref"],
                    runtime_file_ref=upstream["runtime_file_ref"],
                    native_loader_requirement_ref=upstream["requirement_ref"],
                    dependency_requirement_ref=requirement.requirement_ref,
                )
            )

        receipt = _FIXED_RECEIPT_TYPE(
            kind=_FIXED_RECEIPT_KIND,
            schema_version=_FIXED_SCHEMA_VERSION,
            requirements_source=_FIXED_REQUIREMENTS_SOURCE,
            requirements_scope=_FIXED_REQUIREMENTS_SCOPE,
            native_loader_requirements_receipt_digest=(
                _BUILTIN_CANONICAL_DIGEST(loader_canonical)
            ),
            runtime_manifest_receipt_digest=(
                _BUILTIN_CANONICAL_DIGEST(runtime_canonical)
            ),
            staging_receipt_digest=(
                _BUILTIN_CANONICAL_DIGEST(staging_canonical)
            ),
            registration_digest=expected_runtime.registration_digest,
            repository_ref=expected_runtime.repository_ref,
            verification_commands_digest=(
                expected_runtime.verification_commands_digest
            ),
            resolution_context_digest=(
                expected_runtime.resolution_context_digest
            ),
            staging_context_digest=expected_runtime.staging_context_digest,
            requirements=requirements,
            bindings=tuple(bindings),
            requirement_count=len(requirements),
            command_count=len(bindings),
            native_requirement_count=sum(
                item.runtime_classification in {"elf", "mach_o"}
                for item in requirements
            ),
            dependency_declared_requirement_count=sum(
                bool(item.declarations) for item in requirements
            ),
            dependency_declaration_count=sum(
                item.declaration_count for item in requirements
            ),
            required_dependency_count=sum(
                item.required_dependency_count for item in requirements
            ),
            weak_dependency_count=sum(
                item.weak_dependency_count for item in requirements
            ),
            unsupported_native_layout_count=sum(
                item.disposition == "unsupported_native_layout"
                for item in requirements
            ),
            non_native_not_applicable_count=sum(
                item.disposition == "non_native_not_applicable"
                for item in requirements
            ),
            total_dependency_name_bytes=sum(
                item.total_dependency_name_bytes for item in requirements
            ),
        )
        _BUILTIN_RECEIPT_PROJECTION(receipt)
        closing_canonical, closing_retained_files = (
            _BUILTIN_ACTIVE_STAGE_SNAPSHOT(expected_staging, lease)
        )
        if (
            closing_canonical != staging_canonical
            or closing_retained_files is not retained_files
        ):
            raise _InvalidNativeDependencyRequirements
        return receipt
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise _FIXED_VALIDATION_ERROR(_INVALID_MESSAGE) from None


__all__ = [
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_DECLARATION_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_REQUIREMENT_BINDING_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_REQUIREMENT_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_REQUIREMENTS_EVIDENCE_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_REQUIREMENTS_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_REQUIREMENTS_SCHEMA_VERSION",
    "REQUIREMENTS_SCOPE",
    "REQUIREMENTS_SOURCE",
    "RepositoryExecutableNativeDependencyDeclaration",
    "RepositoryExecutableNativeDependencyRequirement",
    "RepositoryExecutableNativeDependencyRequirementBinding",
    "RepositoryExecutableNativeDependencyRequirementsReceipt",
    "inspect_staged_executable_native_dependency_requirements",
]
