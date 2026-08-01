"""Read-only loader-of-loader syntax evidence for detached native loaders.

This module inspects whether a staged native-loader target itself declares an
ELF ``PT_INTERP`` interpreter or a thin Mach-O ``LC_LOAD_DYLINKER``.  It binds
that bounded syntax result to the exact target-runtime manifest and active
target-staging lease, while resolving no path, mutating no lease, and executing
nothing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
from typing import Any

from .authorization import canonical_json
from .errors import ValidationError
from .repository_executable_native_loader_requirements import (
    _elf_requirement_fields as _direct_elf_requirement_fields,
    _mach_o_requirement_fields as _direct_mach_o_requirement_fields,
)
from .repository_executable_native_loader_target_runtime_manifest import (
    RepositoryExecutableNativeLoaderTargetRuntimeManifestReceipt,
    _active_target_stage_snapshot as _target_stage_snapshot,
    _header_digest as _target_header_digest,
    _runtime_manifest_projection as _target_runtime_projection,
    _verify_anchored_retained_target as _verify_retained_target,
    inspect_staged_executable_native_loader_target_runtime_manifest,
)
from .repository_executable_native_loader_target_staging import (
    RepositoryExecutableNativeLoaderTargetStageLease,
    RepositoryExecutableNativeLoaderTargetStagingReceipt,
    _staging_receipt_projection as _target_staging_projection,
)


REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_LOADER_REQUIREMENTS_SCHEMA_VERSION = 1
REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_LOADER_REQUIREMENTS_KIND = (
    "repository_executable_native_loader_target_loader_requirements"
)
REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_LOADER_REQUIREMENTS_EVIDENCE_KIND = (
    "repository_executable_native_loader_target_loader_requirements_validation"
)
REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_LOADER_REQUIREMENT_KIND = (
    "repository_executable_native_loader_target_loader_requirement"
)
REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_LOADER_LINEAGE_KIND = (
    "repository_executable_native_loader_target_loader_lineage"
)
REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_LOADER_BINDING_KIND = (
    "repository_executable_native_loader_target_loader_binding"
)
REQUIREMENTS_SOURCE = "controller_inspected"
REQUIREMENTS_SCOPE = "staged_native_loader_target_loader_declarations_v1"

_FIXED_SCHEMA_VERSION = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_LOADER_REQUIREMENTS_SCHEMA_VERSION
)
_FIXED_RECEIPT_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_LOADER_REQUIREMENTS_KIND
)
_FIXED_EVIDENCE_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_LOADER_REQUIREMENTS_EVIDENCE_KIND
)
_FIXED_REQUIREMENT_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_LOADER_REQUIREMENT_KIND
)
_FIXED_LINEAGE_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_LOADER_LINEAGE_KIND
)
_FIXED_BINDING_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_LOADER_BINDING_KIND
)
_FIXED_REQUIREMENTS_SOURCE = REQUIREMENTS_SOURCE
_FIXED_REQUIREMENTS_SCOPE = REQUIREMENTS_SCOPE

_INVALID_MESSAGE = (
    "repository executable native loader target loader requirements are invalid"
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
_BYTE_ORDERS = ("little", "big")
_IMAGE_KINDS = ("executable", "shared_object", "dynamic_linker", "other")
_REQUIREMENT_DISPOSITIONS = (
    "elf_interpreter_declared",
    "elf_interpreter_absent",
    "mach_o_dylinker_declared",
    "mach_o_dylinker_absent",
    "unsupported_native_layout",
    "non_native_not_applicable",
)
_UPSTREAM_DISPOSITIONS = (
    "declared_loader_target_runtime_inspected",
    "loader_declaration_absent",
    "unsupported_native_layout",
    "non_native_not_applicable",
)
_LINEAGE_DISPOSITIONS = (
    "target_loader_requirements_inspected",
    "loader_declaration_absent",
    "unsupported_native_layout",
    "non_native_not_applicable",
)
_MAX_FILES = 80
_MAX_REQUIREMENTS = 80
_MAX_COMMANDS = 80
_MAX_LOADER_PATH_BYTES = 4_095

_BUILTIN_SHA256 = hashlib.sha256
_BUILTIN_CANONICAL_JSON = canonical_json


def _captured_canonical_digest(value: Any) -> str:
    encoded = _BUILTIN_CANONICAL_JSON(value).encode("utf-8")
    return _DIGEST_PREFIX + _BUILTIN_SHA256(encoded).hexdigest()


_BUILTIN_CANONICAL_DIGEST = _captured_canonical_digest
_BUILTIN_IS_DIGEST_PATTERN = _DIGEST_PATTERN
_BUILTIN_TARGET_RUNTIME_PROJECTION = _target_runtime_projection
_BUILTIN_TARGET_STAGING_PROJECTION = _target_staging_projection
_BUILTIN_TARGET_STAGE_SNAPSHOT = _target_stage_snapshot
_BUILTIN_VERIFY_RETAINED_TARGET = _verify_retained_target
_BUILTIN_TARGET_HEADER_DIGEST = _target_header_digest
_BUILTIN_INSPECT_TARGET_RUNTIME = (
    inspect_staged_executable_native_loader_target_runtime_manifest
)
_BUILTIN_ELF_REQUIREMENT_FIELDS = _direct_elf_requirement_fields
_BUILTIN_MACH_O_REQUIREMENT_FIELDS = _direct_mach_o_requirement_fields
_FIXED_VALIDATION_ERROR = ValidationError
_FIXED_RUNTIME_RECEIPT_TYPE = (
    RepositoryExecutableNativeLoaderTargetRuntimeManifestReceipt
)
_FIXED_STAGING_RECEIPT_TYPE = (
    RepositoryExecutableNativeLoaderTargetStagingReceipt
)
_FIXED_STAGE_LEASE_TYPE = RepositoryExecutableNativeLoaderTargetStageLease


class _InvalidTargetLoaderRequirements(ValueError):
    """Private fail-closed sentinel whose details never cross the API."""


@dataclass(frozen=True, slots=True)
class _ParserRuntimeFile:
    """Minimal immutable adapter for the captured native-header parsers."""

    content_bytes: int
    runtime_file_ref: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeLoaderTargetLoaderRequirement:
    """One unique staged loader target's own loader declaration syntax."""

    kind: str
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
    target_loader_requirement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_REQUIREMENT_PROJECTION(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeLoaderTargetLoaderLineage:
    """One upstream source requirement bound to a target-loader result."""

    kind: str
    staged_file_ref: str = field(repr=False)
    runtime_file_ref: str = field(repr=False)
    requirement_ref: str = field(repr=False)
    target_requirement_ref: str = field(repr=False)
    target_stage_requirement_ref: str = field(repr=False)
    target_runtime_requirement_ref: str = field(repr=False)
    target_runtime_file_ref: str | None = field(repr=False)
    source_runtime_classification: str
    disposition: str
    target_loader_requirement_ref: str | None = field(repr=False)
    target_loader_lineage_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_LINEAGE_PROJECTION(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeLoaderTargetLoaderBinding:
    """One registered command bound through the complete loader lineage."""

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

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_BINDING_PROJECTION(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeLoaderTargetLoaderRequirementsReceipt:
    """Historical one-hop loader-of-loader declaration evidence."""

    kind: str
    schema_version: int
    requirements_source: str
    requirements_scope: str
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
    loader_path_context_digest: str = field(repr=False)
    target_staging_context_digest: str = field(repr=False)
    requirements: tuple[
        RepositoryExecutableNativeLoaderTargetLoaderRequirement, ...
    ] = field(repr=False)
    lineages: tuple[
        RepositoryExecutableNativeLoaderTargetLoaderLineage, ...
    ] = field(repr=False)
    bindings: tuple[
        RepositoryExecutableNativeLoaderTargetLoaderBinding, ...
    ] = field(repr=False)
    requirement_count: int
    lineage_count: int
    command_count: int
    target_native_requirement_count: int
    nested_loader_declared_count: int
    unsupported_native_layout_count: int
    non_native_not_applicable_count: int
    target_required_lineage_count: int
    no_target_lineage_count: int
    total_loader_path_bytes: int

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_RECEIPT_PROJECTION(self)

    @property
    def receipt_digest(self) -> str:
        return _BUILTIN_CANONICAL_DIGEST(
            _BUILTIN_RECEIPT_PROJECTION(self)
        )

    def to_evidence(self) -> dict[str, Any]:
        return _BUILTIN_EVIDENCE_PROJECTION(self)


_FIXED_REQUIREMENT_TYPE = (
    RepositoryExecutableNativeLoaderTargetLoaderRequirement
)
_FIXED_LINEAGE_TYPE = RepositoryExecutableNativeLoaderTargetLoaderLineage
_FIXED_BINDING_TYPE = RepositoryExecutableNativeLoaderTargetLoaderBinding
_FIXED_RECEIPT_TYPE = (
    RepositoryExecutableNativeLoaderTargetLoaderRequirementsReceipt
)


def _is_digest(value: Any) -> bool:
    return (
        type(value) is str
        and _BUILTIN_IS_DIGEST_PATTERN.fullmatch(value) is not None
    )


_BUILTIN_IS_DIGEST = _is_digest


def _requirement_ref_projection(
    *,
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
        "kind": (
            "repository_executable_native_loader_target_loader_"
            "requirement_ref"
        ),
        "layout_supported": layout_supported,
        "loader_path_absolute": loader_path_absolute,
        "loader_path_bytes": loader_path_bytes,
        "loader_path_ref": loader_path_ref,
        "requirements_scope": _FIXED_REQUIREMENTS_SCOPE,
        "runtime_classification": runtime_classification,
        "schema_version": _FIXED_SCHEMA_VERSION,
        "target_runtime_file_ref": target_runtime_file_ref,
        "target_staged_file_ref": target_staged_file_ref,
    }


_BUILTIN_REQUIREMENT_REF_PROJECTION = _requirement_ref_projection


def _requirement_projection(
    value: RepositoryExecutableNativeLoaderTargetLoaderRequirement,
) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_REQUIREMENT_TYPE
        or type(value.kind) is not str
        or value.kind != _FIXED_REQUIREMENT_KIND
        or not _BUILTIN_IS_DIGEST(value.target_staged_file_ref)
        or not _BUILTIN_IS_DIGEST(value.target_runtime_file_ref)
        or not _BUILTIN_IS_DIGEST(value.target_loader_requirement_ref)
        or type(value.runtime_classification) is not str
        or value.runtime_classification not in _RUNTIME_CLASSIFICATIONS
        or (
            value.format_class is not None
            and (
                type(value.format_class) is not str
                or value.format_class not in _FORMAT_CLASSES
            )
        )
        or (
            value.byte_order is not None
            and (
                type(value.byte_order) is not str
                or value.byte_order not in _BYTE_ORDERS
            )
        )
        or (
            value.image_kind is not None
            and (
                type(value.image_kind) is not str
                or value.image_kind not in _IMAGE_KINDS
            )
        )
        or type(value.disposition) is not str
        or value.disposition not in _REQUIREMENT_DISPOSITIONS
        or (
            value.loader_path_ref is not None
            and not _BUILTIN_IS_DIGEST(value.loader_path_ref)
        )
        or type(value.loader_path_bytes) is not int
        or not 0 <= value.loader_path_bytes <= _MAX_LOADER_PATH_BYTES
        or (
            value.loader_path_absolute is not None
            and type(value.loader_path_absolute) is not bool
        )
        or type(value.layout_supported) is not bool
    ):
        raise _InvalidTargetLoaderRequirements

    native = value.runtime_classification in {"elf", "mach_o"}
    declared = value.disposition in {
        "elf_interpreter_declared",
        "mach_o_dylinker_declared",
    }
    absent = value.disposition in {
        "elf_interpreter_absent",
        "mach_o_dylinker_absent",
    }
    if not native:
        if (
            value.disposition != "non_native_not_applicable"
            or value.format_class is not None
            or value.byte_order is not None
            or value.image_kind is not None
            or value.loader_path_ref is not None
            or value.loader_path_bytes != 0
            or value.loader_path_absolute is not None
            or value.layout_supported
        ):
            raise _InvalidTargetLoaderRequirements
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
            raise _InvalidTargetLoaderRequirements
        if value.disposition == "unsupported_native_layout":
            if (
                value.layout_supported
                or value.image_kind is not None
                or value.loader_path_ref is not None
                or value.loader_path_bytes != 0
                or value.loader_path_absolute is not None
            ):
                raise _InvalidTargetLoaderRequirements
        elif not value.layout_supported or value.image_kind is None:
            raise _InvalidTargetLoaderRequirements
        if declared:
            if (
                value.loader_path_ref is None
                or not 1 <= value.loader_path_bytes <= _MAX_LOADER_PATH_BYTES
                or value.loader_path_absolute is not True
            ):
                raise _InvalidTargetLoaderRequirements
        elif absent:
            if (
                value.loader_path_ref is not None
                or value.loader_path_bytes != 0
                or value.loader_path_absolute is not None
            ):
                raise _InvalidTargetLoaderRequirements

    reference = _BUILTIN_REQUIREMENT_REF_PROJECTION(
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
    if value.target_loader_requirement_ref != _BUILTIN_CANONICAL_DIGEST(
        reference
    ):
        raise _InvalidTargetLoaderRequirements
    return {
        **reference,
        "kind": value.kind,
        "target_loader_requirement_ref": value.target_loader_requirement_ref,
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
    source_runtime_classification: str,
    disposition: str,
    target_loader_requirement_ref: str | None,
) -> dict[str, Any]:
    return {
        "disposition": disposition,
        "kind": (
            "repository_executable_native_loader_target_loader_lineage_ref"
        ),
        "requirement_ref": requirement_ref,
        "runtime_file_ref": runtime_file_ref,
        "schema_version": _FIXED_SCHEMA_VERSION,
        "source_runtime_classification": source_runtime_classification,
        "staged_file_ref": staged_file_ref,
        "target_loader_requirement_ref": target_loader_requirement_ref,
        "target_requirement_ref": target_requirement_ref,
        "target_runtime_file_ref": target_runtime_file_ref,
        "target_runtime_requirement_ref": target_runtime_requirement_ref,
        "target_stage_requirement_ref": target_stage_requirement_ref,
    }


_BUILTIN_LINEAGE_REF_PROJECTION = _lineage_ref_projection


def _lineage_projection(
    value: RepositoryExecutableNativeLoaderTargetLoaderLineage,
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
            )
        )
        or type(value.source_runtime_classification) is not str
        or value.source_runtime_classification not in _RUNTIME_CLASSIFICATIONS
        or type(value.disposition) is not str
        or value.disposition not in _LINEAGE_DISPOSITIONS
        or (
            value.target_runtime_file_ref is not None
            and not _BUILTIN_IS_DIGEST(value.target_runtime_file_ref)
        )
        or (
            value.target_loader_requirement_ref is not None
            and not _BUILTIN_IS_DIGEST(value.target_loader_requirement_ref)
        )
        or (
            value.disposition == "target_loader_requirements_inspected"
            and (
                value.source_runtime_classification not in {"elf", "mach_o"}
                or value.target_runtime_file_ref is None
                or value.target_loader_requirement_ref is None
            )
        )
        or (
            value.disposition != "target_loader_requirements_inspected"
            and (
                value.target_runtime_file_ref is not None
                or value.target_loader_requirement_ref is not None
            )
        )
        or (
            value.disposition
            in {"loader_declaration_absent", "unsupported_native_layout"}
            and value.source_runtime_classification not in {"elf", "mach_o"}
        )
        or (
            value.disposition == "non_native_not_applicable"
            and value.source_runtime_classification in {"elf", "mach_o"}
        )
    ):
        raise _InvalidTargetLoaderRequirements
    reference = _BUILTIN_LINEAGE_REF_PROJECTION(
        staged_file_ref=value.staged_file_ref,
        runtime_file_ref=value.runtime_file_ref,
        requirement_ref=value.requirement_ref,
        target_requirement_ref=value.target_requirement_ref,
        target_stage_requirement_ref=value.target_stage_requirement_ref,
        target_runtime_requirement_ref=value.target_runtime_requirement_ref,
        target_runtime_file_ref=value.target_runtime_file_ref,
        source_runtime_classification=value.source_runtime_classification,
        disposition=value.disposition,
        target_loader_requirement_ref=value.target_loader_requirement_ref,
    )
    if value.target_loader_lineage_ref != _BUILTIN_CANONICAL_DIGEST(reference):
        raise _InvalidTargetLoaderRequirements
    return {
        **reference,
        "kind": value.kind,
        "target_loader_lineage_ref": value.target_loader_lineage_ref,
    }


_BUILTIN_LINEAGE_PROJECTION = _lineage_projection


def _binding_projection(
    value: RepositoryExecutableNativeLoaderTargetLoaderBinding,
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
            )
        )
    ):
        raise _InvalidTargetLoaderRequirements
    return {
        "command_digest": value.command_digest,
        "command_id": value.command_id,
        "command_kind": value.command_kind,
        "kind": value.kind,
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
    value: RepositoryExecutableNativeLoaderTargetLoaderRequirementsReceipt,
) -> dict[str, Any]:
    digest_fields = (
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
        value.loader_path_context_digest,
        value.target_staging_context_digest,
    )
    count_fields = (
        value.target_native_requirement_count,
        value.nested_loader_declared_count,
        value.unsupported_native_layout_count,
        value.non_native_not_applicable_count,
        value.target_required_lineage_count,
        value.no_target_lineage_count,
    )
    if (
        type(value) is not _FIXED_RECEIPT_TYPE
        or type(value.kind) is not str
        or value.kind != _FIXED_RECEIPT_KIND
        or type(value.schema_version) is not int
        or value.schema_version != _FIXED_SCHEMA_VERSION
        or type(value.requirements_source) is not str
        or value.requirements_source != _FIXED_REQUIREMENTS_SOURCE
        or type(value.requirements_scope) is not str
        or value.requirements_scope != _FIXED_REQUIREMENTS_SCOPE
        or not all(_BUILTIN_IS_DIGEST(item) for item in digest_fields)
        or type(value.requirements) is not tuple
        or not 0 <= len(value.requirements) <= _MAX_FILES
        or type(value.lineages) is not tuple
        or not 1 <= len(value.lineages) <= _MAX_REQUIREMENTS
        or type(value.bindings) is not tuple
        or not 1 <= len(value.bindings) <= _MAX_COMMANDS
        or type(value.requirement_count) is not int
        or value.requirement_count != len(value.requirements)
        or type(value.lineage_count) is not int
        or value.lineage_count != len(value.lineages)
        or type(value.command_count) is not int
        or value.command_count != len(value.bindings)
        or any(type(item) is not int or item < 0 for item in count_fields)
        or type(value.total_loader_path_bytes) is not int
        or not 0
        <= value.total_loader_path_bytes
        <= _MAX_FILES * _MAX_LOADER_PATH_BYTES
    ):
        raise _InvalidTargetLoaderRequirements

    requirements = [
        _BUILTIN_REQUIREMENT_PROJECTION(item) for item in value.requirements
    ]
    lineages = [
        _BUILTIN_LINEAGE_PROJECTION(item) for item in value.lineages
    ]
    bindings = [
        _BUILTIN_BINDING_PROJECTION(item) for item in value.bindings
    ]

    requirement_by_ref: dict[
        str, RepositoryExecutableNativeLoaderTargetLoaderRequirement
    ] = {}
    runtime_file_refs: set[str] = set()
    staged_file_refs: set[str] = set()
    for item in value.requirements:
        if (
            item.target_loader_requirement_ref in requirement_by_ref
            or item.target_runtime_file_ref in runtime_file_refs
            or item.target_staged_file_ref in staged_file_refs
        ):
            raise _InvalidTargetLoaderRequirements
        requirement_by_ref[item.target_loader_requirement_ref] = item
        runtime_file_refs.add(item.target_runtime_file_ref)
        staged_file_refs.add(item.target_staged_file_ref)

    lineage_by_ref: dict[
        str, RepositoryExecutableNativeLoaderTargetLoaderLineage
    ] = {}
    runtime_lineage_refs: set[str] = set()
    upstream_requirement_refs: set[str] = set()
    used_requirement_refs: set[str] = set()
    ordered_first_use: list[str] = []
    target_required = 0
    no_target = 0
    for item in value.lineages:
        if (
            item.target_loader_lineage_ref in lineage_by_ref
            or item.target_runtime_requirement_ref in runtime_lineage_refs
            or item.requirement_ref in upstream_requirement_refs
        ):
            raise _InvalidTargetLoaderRequirements
        lineage_by_ref[item.target_loader_lineage_ref] = item
        runtime_lineage_refs.add(item.target_runtime_requirement_ref)
        upstream_requirement_refs.add(item.requirement_ref)
        if item.disposition == "target_loader_requirements_inspected":
            target_required += 1
            target_ref = item.target_loader_requirement_ref
            if target_ref is None or target_ref not in requirement_by_ref:
                raise _InvalidTargetLoaderRequirements
            target_requirement = requirement_by_ref[target_ref]
            if (
                item.target_runtime_file_ref
                != target_requirement.target_runtime_file_ref
            ):
                raise _InvalidTargetLoaderRequirements
            if target_ref not in used_requirement_refs:
                ordered_first_use.append(target_ref)
            used_requirement_refs.add(target_ref)
        else:
            no_target += 1

    command_ids: set[str] = set()
    bound_lineage_refs: set[str] = set()
    ordered_bound_lineages: list[str] = []
    prior_kind_index = -1
    for item in value.bindings:
        lineage = lineage_by_ref.get(item.target_loader_lineage_ref)
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
            or item.command_id in command_ids
            or kind_index < prior_kind_index
        ):
            raise _InvalidTargetLoaderRequirements
        command_ids.add(item.command_id)
        if item.target_loader_lineage_ref not in bound_lineage_refs:
            ordered_bound_lineages.append(item.target_loader_lineage_ref)
        bound_lineage_refs.add(item.target_loader_lineage_ref)
        prior_kind_index = kind_index

    native_count = sum(
        item.runtime_classification in {"elf", "mach_o"}
        for item in value.requirements
    )
    declared_count = sum(
        item.disposition
        in {"elf_interpreter_declared", "mach_o_dylinker_declared"}
        for item in value.requirements
    )
    unsupported_count = sum(
        item.disposition == "unsupported_native_layout"
        for item in value.requirements
    )
    non_native_count = sum(
        item.disposition == "non_native_not_applicable"
        for item in value.requirements
    )
    total_path_bytes = sum(
        item.loader_path_bytes for item in value.requirements
    )
    if (
        used_requirement_refs != set(requirement_by_ref)
        or tuple(ordered_first_use)
        != tuple(
            item.target_loader_requirement_ref for item in value.requirements
        )
        or bound_lineage_refs != set(lineage_by_ref)
        or tuple(ordered_bound_lineages)
        != tuple(item.target_loader_lineage_ref for item in value.lineages)
        or native_count != value.target_native_requirement_count
        or declared_count != value.nested_loader_declared_count
        or unsupported_count != value.unsupported_native_layout_count
        or non_native_count != value.non_native_not_applicable_count
        or target_required != value.target_required_lineage_count
        or no_target != value.no_target_lineage_count
        or target_required + no_target != value.lineage_count
        or value.requirement_count != len(used_requirement_refs)
        or total_path_bytes != value.total_loader_path_bytes
        or (value.requirement_count == 0 and target_required != 0)
        or (value.requirement_count > 0 and target_required == 0)
    ):
        raise _InvalidTargetLoaderRequirements

    return {
        "bindings": bindings,
        "command_count": value.command_count,
        "kind": value.kind,
        "lineage_count": value.lineage_count,
        "lineages": lineages,
        "loader_path_context_digest": value.loader_path_context_digest,
        "native_loader_requirements_receipt_digest": (
            value.native_loader_requirements_receipt_digest
        ),
        "nested_loader_declared_count": value.nested_loader_declared_count,
        "no_target_lineage_count": value.no_target_lineage_count,
        "non_native_not_applicable_count": (
            value.non_native_not_applicable_count
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
        "source_staging_context_digest": value.source_staging_context_digest,
        "staging_receipt_digest": value.staging_receipt_digest,
        "target_native_requirement_count": (
            value.target_native_requirement_count
        ),
        "target_required_lineage_count": value.target_required_lineage_count,
        "target_resolution_receipt_digest": (
            value.target_resolution_receipt_digest
        ),
        "target_runtime_manifest_receipt_digest": (
            value.target_runtime_manifest_receipt_digest
        ),
        "target_staging_context_digest": value.target_staging_context_digest,
        "target_staging_receipt_digest": value.target_staging_receipt_digest,
        "total_loader_path_bytes": value.total_loader_path_bytes,
        "unsupported_native_layout_count": (
            value.unsupported_native_layout_count
        ),
        "verification_commands_digest": value.verification_commands_digest,
    }


_BUILTIN_RECEIPT_PROJECTION = _receipt_projection


def _evidence_projection(
    value: RepositoryExecutableNativeLoaderTargetLoaderRequirementsReceipt,
) -> dict[str, Any]:
    canonical = _BUILTIN_RECEIPT_PROJECTION(value)
    dispositions = {
        disposition: sum(
            item.disposition == disposition for item in value.requirements
        )
        for disposition in _REQUIREMENT_DISPOSITIONS
    }
    return {
        "action_receipt_issued": False,
        "active_target_stage_lease_verified_at_measurement": True,
        "authority_granted": False,
        "authorization_verified": False,
        "billing_eligible": False,
        "bounded_loader_of_loader_syntax_inspection_complete": True,
        "capacity_eligible": False,
        "circuit_eligible": False,
        "command_count": value.command_count,
        "current_lease_activity_verified": False,
        "current_source_freshness_verified": False,
        "dependency_closure_verified": False,
        "dispatch_enabled": False,
        "durable_control_plane_persistence_enabled": False,
        "dynamic_loader_authenticity_verified": False,
        "dynamic_loader_compatibility_verified": False,
        "dynamic_loader_identity_verified": False,
        "effect_class": 0,
        "elf_interpreter_absent_count": dispositions[
            "elf_interpreter_absent"
        ],
        "elf_interpreter_declared_count": dispositions[
            "elf_interpreter_declared"
        ],
        "environment_coverage_verified": False,
        "exact_target_runtime_correspondence_verified": True,
        "exact_target_staging_correspondence_verified": True,
        "execution_enabled": False,
        "fat_mach_o_architecture_selection_performed": False,
        "future_execution_correspondence_verified": False,
        "harness_invocation_performed": False,
        "kind": _FIXED_EVIDENCE_KIND,
        "lease_cleanup_performed": False,
        "lease_mutated": False,
        "lineage_count": value.lineage_count,
        "live_execution_eligible": False,
        "loader_invocation_performed": False,
        "loader_path_lookup_performed": False,
        "loader_path_raw_bytes_exposed": False,
        "loader_path_resolution_verified": False,
        "mach_o_dylinker_absent_count": dispositions[
            "mach_o_dylinker_absent"
        ],
        "mach_o_dylinker_declared_count": dispositions[
            "mach_o_dylinker_declared"
        ],
        "model_invocation_performed": False,
        "nested_loader_declared_count": value.nested_loader_declared_count,
        "network_access_performed": False,
        "no_target_lineage_count": value.no_target_lineage_count,
        "non_native_not_applicable_count": (
            value.non_native_not_applicable_count
        ),
        "path_lookup_performed": False,
        "proposal_lineage_extended": False,
        "receipt_authenticity_verified": False,
        "receipt_digest": _BUILTIN_CANONICAL_DIGEST(canonical),
        "recursive_native_loader_resolution_verified": False,
        "registration_digest": value.registration_digest,
        "repository_ref": value.repository_ref,
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
        "target_native_requirement_count": (
            value.target_native_requirement_count
        ),
        "target_required_lineage_count": value.target_required_lineage_count,
        "target_runtime_manifest_receipt_digest": (
            value.target_runtime_manifest_receipt_digest
        ),
        "target_staging_receipt_digest": value.target_staging_receipt_digest,
        "toolchain_completeness_verified": False,
        "total_loader_path_bytes": value.total_loader_path_bytes,
        "unsupported_native_layout_count": (
            value.unsupported_native_layout_count
        ),
        "validation_mode": "read_only",
        "worker_authorized": False,
        "worktree_integration_enabled": False,
    }


_BUILTIN_EVIDENCE_PROJECTION = _evidence_projection


def _build_requirement(
    runtime_file: Any,
    *,
    descriptor: int,
    header: bytes,
) -> RepositoryExecutableNativeLoaderTargetLoaderRequirement:
    if (
        type(runtime_file) is not dict
        or type(descriptor) is not int
        or descriptor < 0
        or type(header) is not bytes
        or runtime_file.get("header_bytes") != len(header)
        or runtime_file.get("header_digest")
        != _BUILTIN_TARGET_HEADER_DIGEST(
            runtime_file.get("target_staged_file_ref"),
            header,
        )
    ):
        raise _InvalidTargetLoaderRequirements
    classification = runtime_file.get("classification")
    adapter = _ParserRuntimeFile(
        content_bytes=runtime_file["content_bytes"],
        runtime_file_ref=runtime_file["target_runtime_file_ref"],
    )
    if classification == "elf":
        fields = _BUILTIN_ELF_REQUIREMENT_FIELDS(
            adapter,
            descriptor=descriptor,
            header=header,
        )
    elif classification == "mach_o":
        fields = _BUILTIN_MACH_O_REQUIREMENT_FIELDS(
            adapter,
            descriptor=descriptor,
            header=header,
        )
    elif classification in {
        "posix_shebang",
        "unsupported_shebang",
        "unknown",
    }:
        fields = (
            None,
            None,
            None,
            "non_native_not_applicable",
            None,
            0,
            None,
            False,
        )
    else:
        raise _InvalidTargetLoaderRequirements
    (
        format_class,
        byte_order,
        image_kind,
        disposition,
        loader_path_ref,
        loader_path_bytes,
        loader_path_absolute,
        layout_supported,
    ) = fields
    reference = _BUILTIN_REQUIREMENT_REF_PROJECTION(
        target_staged_file_ref=runtime_file["target_staged_file_ref"],
        target_runtime_file_ref=runtime_file["target_runtime_file_ref"],
        runtime_classification=classification,
        format_class=format_class,
        byte_order=byte_order,
        image_kind=image_kind,
        disposition=disposition,
        loader_path_ref=loader_path_ref,
        loader_path_bytes=loader_path_bytes,
        loader_path_absolute=loader_path_absolute,
        layout_supported=layout_supported,
    )
    value = _FIXED_REQUIREMENT_TYPE(
        kind=_FIXED_REQUIREMENT_KIND,
        target_staged_file_ref=runtime_file["target_staged_file_ref"],
        target_runtime_file_ref=runtime_file["target_runtime_file_ref"],
        runtime_classification=classification,
        format_class=format_class,
        byte_order=byte_order,
        image_kind=image_kind,
        disposition=disposition,
        loader_path_ref=loader_path_ref,
        loader_path_bytes=loader_path_bytes,
        loader_path_absolute=loader_path_absolute,
        layout_supported=layout_supported,
        target_loader_requirement_ref=_BUILTIN_CANONICAL_DIGEST(reference),
    )
    _BUILTIN_REQUIREMENT_PROJECTION(value)
    return value


_BUILTIN_BUILD_REQUIREMENT = _build_requirement


def _remeasure_requirements(
    runtime_canonical: dict[str, Any],
    staging_canonical: dict[str, Any],
    retained_files: tuple[Any, ...],
) -> tuple[RepositoryExecutableNativeLoaderTargetLoaderRequirement, ...]:
    runtime_files = runtime_canonical["files"]
    staged_files = staging_canonical["staged_files"]
    if len(runtime_files) != len(staged_files) or len(runtime_files) != len(
        retained_files
    ):
        raise _InvalidTargetLoaderRequirements
    values: list[
        RepositoryExecutableNativeLoaderTargetLoaderRequirement
    ] = []
    for retained, staged_file, runtime_file in zip(
        retained_files,
        staged_files,
        runtime_files,
        strict=True,
    ):
        if (
            runtime_file["target_staged_file_ref"]
            != staged_file["target_staged_file_ref"]
            or runtime_file["staged_filesystem_identity_ref"]
            != staged_file["staged_filesystem_identity_ref"]
            or runtime_file["content_digest"] != staged_file["content_digest"]
            or runtime_file["content_bytes"] != staged_file["content_bytes"]
        ):
            raise _InvalidTargetLoaderRequirements
        before_header = _BUILTIN_VERIFY_RETAINED_TARGET(
            retained,
            staged_file,
            target_staging_context_digest=staging_canonical[
                "target_staging_context_digest"
            ],
        )
        value = _BUILTIN_BUILD_REQUIREMENT(
            runtime_file,
            descriptor=retained.descriptor,
            header=before_header,
        )
        after_header = _BUILTIN_VERIFY_RETAINED_TARGET(
            retained,
            staged_file,
            target_staging_context_digest=staging_canonical[
                "target_staging_context_digest"
            ],
        )
        if after_header != before_header:
            raise _InvalidTargetLoaderRequirements
        values.append(value)
    return tuple(values)


_BUILTIN_REMEASURE_REQUIREMENTS = _remeasure_requirements


def _build_lineage(
    upstream: dict[str, Any],
    *,
    requirement_by_runtime_ref: dict[
        str, RepositoryExecutableNativeLoaderTargetLoaderRequirement
    ],
) -> RepositoryExecutableNativeLoaderTargetLoaderLineage:
    upstream_disposition = upstream.get("disposition")
    if upstream_disposition not in _UPSTREAM_DISPOSITIONS:
        raise _InvalidTargetLoaderRequirements
    if upstream_disposition == "declared_loader_target_runtime_inspected":
        target_runtime_file_ref = upstream.get("target_runtime_file_ref")
        target_requirement = requirement_by_runtime_ref.get(
            target_runtime_file_ref
        )
        if target_requirement is None:
            raise _InvalidTargetLoaderRequirements
        disposition = "target_loader_requirements_inspected"
        target_runtime_file_ref = target_requirement.target_runtime_file_ref
        target_loader_requirement_ref = (
            target_requirement.target_loader_requirement_ref
        )
    else:
        disposition = upstream_disposition
        target_runtime_file_ref = None
        target_loader_requirement_ref = None
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
        target_runtime_file_ref=target_runtime_file_ref,
        source_runtime_classification=upstream["runtime_classification"],
        disposition=disposition,
        target_loader_requirement_ref=target_loader_requirement_ref,
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
        target_runtime_file_ref=target_runtime_file_ref,
        source_runtime_classification=upstream["runtime_classification"],
        disposition=disposition,
        target_loader_requirement_ref=target_loader_requirement_ref,
        target_loader_lineage_ref=_BUILTIN_CANONICAL_DIGEST(reference),
    )
    _BUILTIN_LINEAGE_PROJECTION(value)
    return value


_BUILTIN_BUILD_LINEAGE = _build_lineage


def _validate_runtime_stage_correspondence(
    runtime: RepositoryExecutableNativeLoaderTargetRuntimeManifestReceipt,
    runtime_canonical: dict[str, Any],
    staging: RepositoryExecutableNativeLoaderTargetStagingReceipt,
    staging_canonical: dict[str, Any],
) -> None:
    stage_digest = _BUILTIN_CANONICAL_DIGEST(staging_canonical)
    if (
        runtime.target_staging_receipt_digest != stage_digest
        or runtime.target_resolution_receipt_digest
        != staging.expected_target_resolution_receipt_digest
        or runtime.native_loader_requirements_receipt_digest
        != staging.native_loader_requirements_receipt_digest
        or runtime.runtime_manifest_receipt_digest
        != staging.runtime_manifest_receipt_digest
        or runtime.staging_receipt_digest != staging.staging_receipt_digest
        or runtime.registration_digest != staging.registration_digest
        or runtime.repository_ref != staging.repository_ref
        or runtime.verification_commands_digest
        != staging.verification_commands_digest
        or runtime.resolution_context_digest
        != staging.resolution_context_digest
        or runtime.source_staging_context_digest
        != staging.source_staging_context_digest
        or runtime.loader_path_context_digest
        != staging.loader_path_context_digest
        or runtime.target_staging_context_digest
        != staging.target_staging_context_digest
        or runtime_canonical["file_count"]
        != staging_canonical["unique_target_count"]
        or runtime_canonical["requirement_count"]
        != staging_canonical["requirement_count"]
        or runtime_canonical["command_count"]
        != staging_canonical["command_count"]
    ):
        raise _InvalidTargetLoaderRequirements


_BUILTIN_VALIDATE_RUNTIME_STAGE = _validate_runtime_stage_correspondence


def inspect_staged_executable_native_loader_target_loader_requirements(
    expected_target_runtime: (
        RepositoryExecutableNativeLoaderTargetRuntimeManifestReceipt
    ),
    *,
    expected_target_staging: (
        RepositoryExecutableNativeLoaderTargetStagingReceipt
    ),
    lease: RepositoryExecutableNativeLoaderTargetStageLease,
) -> RepositoryExecutableNativeLoaderTargetLoaderRequirementsReceipt:
    """Inspect one loader-of-loader syntax hop from an exact active stage."""

    try:
        if (
            type(expected_target_runtime) is not _FIXED_RUNTIME_RECEIPT_TYPE
            or type(expected_target_staging) is not _FIXED_STAGING_RECEIPT_TYPE
            or type(lease) is not _FIXED_STAGE_LEASE_TYPE
        ):
            raise _InvalidTargetLoaderRequirements
        runtime_canonical = _BUILTIN_TARGET_RUNTIME_PROJECTION(
            expected_target_runtime
        )
        staging_canonical = _BUILTIN_TARGET_STAGING_PROJECTION(
            expected_target_staging
        )
        _BUILTIN_VALIDATE_RUNTIME_STAGE(
            expected_target_runtime,
            runtime_canonical,
            expected_target_staging,
            staging_canonical,
        )

        fresh_runtime = _BUILTIN_INSPECT_TARGET_RUNTIME(
            expected_target_staging,
            lease=lease,
        )
        if (
            _BUILTIN_TARGET_RUNTIME_PROJECTION(fresh_runtime)
            != runtime_canonical
        ):
            raise _InvalidTargetLoaderRequirements
        active_canonical, retained_files = _BUILTIN_TARGET_STAGE_SNAPSHOT(
            expected_target_staging,
            lease,
        )
        if active_canonical != staging_canonical:
            raise _InvalidTargetLoaderRequirements

        requirements = _BUILTIN_REMEASURE_REQUIREMENTS(
            runtime_canonical,
            staging_canonical,
            retained_files,
        )

        final_runtime = _BUILTIN_INSPECT_TARGET_RUNTIME(
            expected_target_staging,
            lease=lease,
        )
        final_canonical, final_retained_files = (
            _BUILTIN_TARGET_STAGE_SNAPSHOT(
                expected_target_staging,
                lease,
            )
        )
        if (
            _BUILTIN_TARGET_RUNTIME_PROJECTION(final_runtime)
            != runtime_canonical
            or final_canonical != staging_canonical
            or final_retained_files is not retained_files
            or _BUILTIN_REMEASURE_REQUIREMENTS(
                runtime_canonical,
                staging_canonical,
                retained_files,
            )
            != requirements
        ):
            raise _InvalidTargetLoaderRequirements

        requirement_by_runtime_ref = {
            item.target_runtime_file_ref: item for item in requirements
        }
        lineages = tuple(
            _BUILTIN_BUILD_LINEAGE(
                item,
                requirement_by_runtime_ref=requirement_by_runtime_ref,
            )
            for item in runtime_canonical["requirements"]
        )
        lineage_by_runtime_requirement_ref = {
            item.target_runtime_requirement_ref: item for item in lineages
        }
        bindings: list[
            RepositoryExecutableNativeLoaderTargetLoaderBinding
        ] = []
        for upstream in runtime_canonical["bindings"]:
            lineage = lineage_by_runtime_requirement_ref.get(
                upstream["target_runtime_requirement_ref"]
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
            ):
                raise _InvalidTargetLoaderRequirements
            bindings.append(
                _FIXED_BINDING_TYPE(
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
                    target_loader_lineage_ref=(
                        lineage.target_loader_lineage_ref
                    ),
                )
            )

        target_required_lineage_count = sum(
            item.disposition == "target_loader_requirements_inspected"
            for item in lineages
        )
        receipt = _FIXED_RECEIPT_TYPE(
            kind=_FIXED_RECEIPT_KIND,
            schema_version=_FIXED_SCHEMA_VERSION,
            requirements_source=_FIXED_REQUIREMENTS_SOURCE,
            requirements_scope=_FIXED_REQUIREMENTS_SCOPE,
            target_runtime_manifest_receipt_digest=(
                _BUILTIN_CANONICAL_DIGEST(runtime_canonical)
            ),
            target_staging_receipt_digest=(
                _BUILTIN_CANONICAL_DIGEST(staging_canonical)
            ),
            target_resolution_receipt_digest=(
                expected_target_runtime.target_resolution_receipt_digest
            ),
            native_loader_requirements_receipt_digest=(
                expected_target_runtime.native_loader_requirements_receipt_digest
            ),
            runtime_manifest_receipt_digest=(
                expected_target_runtime.runtime_manifest_receipt_digest
            ),
            staging_receipt_digest=(
                expected_target_runtime.staging_receipt_digest
            ),
            registration_digest=expected_target_runtime.registration_digest,
            repository_ref=expected_target_runtime.repository_ref,
            verification_commands_digest=(
                expected_target_runtime.verification_commands_digest
            ),
            resolution_context_digest=(
                expected_target_runtime.resolution_context_digest
            ),
            source_staging_context_digest=(
                expected_target_runtime.source_staging_context_digest
            ),
            loader_path_context_digest=(
                expected_target_runtime.loader_path_context_digest
            ),
            target_staging_context_digest=(
                expected_target_runtime.target_staging_context_digest
            ),
            requirements=requirements,
            lineages=lineages,
            bindings=tuple(bindings),
            requirement_count=len(requirements),
            lineage_count=len(lineages),
            command_count=len(bindings),
            target_native_requirement_count=sum(
                item.runtime_classification in {"elf", "mach_o"}
                for item in requirements
            ),
            nested_loader_declared_count=sum(
                item.loader_path_ref is not None for item in requirements
            ),
            unsupported_native_layout_count=sum(
                item.disposition == "unsupported_native_layout"
                for item in requirements
            ),
            non_native_not_applicable_count=sum(
                item.disposition == "non_native_not_applicable"
                for item in requirements
            ),
            target_required_lineage_count=target_required_lineage_count,
            no_target_lineage_count=(
                len(lineages) - target_required_lineage_count
            ),
            total_loader_path_bytes=sum(
                item.loader_path_bytes for item in requirements
            ),
        )
        _BUILTIN_RECEIPT_PROJECTION(receipt)
        closing_canonical, closing_retained_files = (
            _BUILTIN_TARGET_STAGE_SNAPSHOT(
                expected_target_staging,
                lease,
            )
        )
        if (
            closing_canonical != staging_canonical
            or closing_retained_files is not retained_files
        ):
            raise _InvalidTargetLoaderRequirements
        return receipt
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise _FIXED_VALIDATION_ERROR(_INVALID_MESSAGE) from None


__all__ = [
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_LOADER_BINDING_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_LOADER_LINEAGE_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_LOADER_REQUIREMENT_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_LOADER_REQUIREMENTS_EVIDENCE_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_LOADER_REQUIREMENTS_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_LOADER_REQUIREMENTS_SCHEMA_VERSION",
    "REQUIREMENTS_SCOPE",
    "REQUIREMENTS_SOURCE",
    "RepositoryExecutableNativeLoaderTargetLoaderBinding",
    "RepositoryExecutableNativeLoaderTargetLoaderLineage",
    "RepositoryExecutableNativeLoaderTargetLoaderRequirement",
    "RepositoryExecutableNativeLoaderTargetLoaderRequirementsReceipt",
    "inspect_staged_executable_native_loader_target_loader_requirements",
]
