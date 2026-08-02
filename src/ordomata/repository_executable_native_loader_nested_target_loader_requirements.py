"""Read-only loader syntax evidence for detached depth-two native loaders.

This module inspects whether a staged depth-two native-loader target declares
an ELF ``PT_INTERP`` interpreter or a thin Mach-O ``LC_LOAD_DYLINKER``.  It
binds that bounded syntax result to the exact nested-target runtime manifest
and active nested-target staging lease, while resolving no path, mutating no
lease, following no declaration, and executing nothing.
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
from .repository_executable_native_loader_nested_target_runtime_manifest import (
    RepositoryExecutableNativeLoaderNestedTargetRuntimeManifestReceipt,
    _active_nested_target_stage_snapshot as _nested_target_stage_snapshot,
    _header_digest as _nested_target_header_digest,
    _runtime_manifest_projection as _nested_target_runtime_projection,
    _verify_anchored_retained_nested_target as _verify_retained_nested_target,
    inspect_staged_executable_native_loader_nested_target_runtime_manifest,
)
from .repository_executable_native_loader_nested_target_staging import (
    RepositoryExecutableNativeLoaderNestedTargetStageLease,
    RepositoryExecutableNativeLoaderNestedTargetStagingReceipt,
    _staging_receipt_projection as _nested_target_staging_projection,
)


REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_LOADER_REQUIREMENTS_SCHEMA_VERSION = 1
REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_LOADER_REQUIREMENTS_KIND = (
    "repository_executable_native_loader_nested_target_loader_requirements"
)
REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_LOADER_REQUIREMENTS_EVIDENCE_KIND = (
    "repository_executable_native_loader_nested_target_loader_requirements_validation"
)
REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_LOADER_REQUIREMENT_KIND = (
    "repository_executable_native_loader_nested_target_loader_requirement"
)
REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_LOADER_LINEAGE_KIND = (
    "repository_executable_native_loader_nested_target_loader_lineage"
)
REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_LOADER_BINDING_KIND = (
    "repository_executable_native_loader_nested_target_loader_binding"
)
REQUIREMENTS_SOURCE = "controller_inspected"
REQUIREMENTS_SCOPE = "staged_native_loader_nested_target_loader_declarations_v1"

_FIXED_SCHEMA_VERSION = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_LOADER_REQUIREMENTS_SCHEMA_VERSION
)
_FIXED_RECEIPT_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_LOADER_REQUIREMENTS_KIND
)
_FIXED_EVIDENCE_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_LOADER_REQUIREMENTS_EVIDENCE_KIND
)
_FIXED_REQUIREMENT_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_LOADER_REQUIREMENT_KIND
)
_FIXED_LINEAGE_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_LOADER_LINEAGE_KIND
)
_FIXED_BINDING_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_LOADER_BINDING_KIND
)
_FIXED_REQUIREMENTS_SOURCE = REQUIREMENTS_SOURCE
_FIXED_REQUIREMENTS_SCOPE = REQUIREMENTS_SCOPE

_INVALID_MESSAGE = (
    "repository executable native loader nested target loader requirements are invalid"
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
    "runtime_requirement_bound",
    "loader_declaration_absent",
    "unsupported_native_layout",
    "non_native_not_applicable",
)
_LINEAGE_DISPOSITIONS = (
    "nested_target_loader_requirements_inspected",
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
_BUILTIN_NESTED_TARGET_RUNTIME_PROJECTION = _nested_target_runtime_projection
_BUILTIN_NESTED_TARGET_STAGING_PROJECTION = _nested_target_staging_projection
_BUILTIN_NESTED_TARGET_STAGE_SNAPSHOT = _nested_target_stage_snapshot
_BUILTIN_VERIFY_RETAINED_NESTED_TARGET = _verify_retained_nested_target
_BUILTIN_NESTED_TARGET_HEADER_DIGEST = _nested_target_header_digest
_BUILTIN_INSPECT_NESTED_TARGET_RUNTIME = (
    inspect_staged_executable_native_loader_nested_target_runtime_manifest
)
_BUILTIN_ELF_REQUIREMENT_FIELDS = _direct_elf_requirement_fields
_BUILTIN_MACH_O_REQUIREMENT_FIELDS = _direct_mach_o_requirement_fields
_FIXED_VALIDATION_ERROR = ValidationError
_FIXED_RUNTIME_RECEIPT_TYPE = (
    RepositoryExecutableNativeLoaderNestedTargetRuntimeManifestReceipt
)
_FIXED_STAGING_RECEIPT_TYPE = (
    RepositoryExecutableNativeLoaderNestedTargetStagingReceipt
)
_FIXED_STAGE_LEASE_TYPE = RepositoryExecutableNativeLoaderNestedTargetStageLease


class _InvalidNestedTargetLoaderRequirements(ValueError):
    """Private fail-closed sentinel whose details never cross the API."""


@dataclass(frozen=True, slots=True)
class _ParserRuntimeFile:
    """Minimal immutable adapter for the captured native-header parsers."""

    content_bytes: int
    runtime_file_ref: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeLoaderNestedTargetLoaderRequirement:
    """One unique staged depth-two target's loader declaration syntax."""

    kind: str
    nested_target_staged_file_ref: str = field(repr=False)
    nested_target_runtime_file_ref: str = field(repr=False)
    runtime_classification: str
    format_class: str | None
    byte_order: str | None
    image_kind: str | None
    disposition: str
    loader_path_ref: str | None = field(repr=False)
    loader_path_bytes: int
    loader_path_absolute: bool | None
    layout_supported: bool
    nested_target_loader_requirement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_REQUIREMENT_PROJECTION(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeLoaderNestedTargetLoaderLineage:
    """One upstream source requirement bound to a nested-target-loader result."""

    kind: str
    staged_file_ref: str = field(repr=False)
    runtime_file_ref: str = field(repr=False)
    requirement_ref: str = field(repr=False)
    target_requirement_ref: str = field(repr=False)
    target_stage_requirement_ref: str = field(repr=False)
    target_runtime_requirement_ref: str = field(repr=False)
    target_loader_lineage_ref: str = field(repr=False)
    nested_target_lineage_ref: str = field(repr=False)
    chain_guard_lineage_ref: str = field(repr=False)
    nested_target_stage_lineage_ref: str = field(repr=False)
    nested_target_runtime_lineage_ref: str = field(repr=False)
    nested_target_runtime_requirement_ref: str | None = field(repr=False)
    nested_target_runtime_file_ref: str | None = field(repr=False)
    runtime_disposition: str
    disposition: str
    nested_target_loader_requirement_ref: str | None = field(repr=False)
    nested_target_loader_lineage_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_LINEAGE_PROJECTION(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeLoaderNestedTargetLoaderBinding:
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
    nested_target_lineage_ref: str = field(repr=False)
    chain_guard_lineage_ref: str = field(repr=False)
    nested_target_stage_lineage_ref: str = field(repr=False)
    nested_target_runtime_lineage_ref: str = field(repr=False)
    nested_target_loader_lineage_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_BINDING_PROJECTION(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeLoaderNestedTargetLoaderRequirementsReceipt:
    """Historical depth-two loader-declaration evidence."""

    kind: str
    schema_version: int
    requirements_source: str
    requirements_scope: str
    nested_target_runtime_manifest_receipt_digest: str = field(repr=False)
    nested_target_staging_receipt_digest: str = field(repr=False)
    nested_target_resolution_receipt_digest: str = field(repr=False)
    expected_chain_guard_receipt_digest: str = field(repr=False)
    action_chain_guard_receipt_digest: str = field(repr=False)
    post_stage_chain_guard_receipt_digest: str = field(repr=False)
    target_loader_requirements_receipt_digest: str = field(repr=False)
    target_runtime_manifest_receipt_digest: str = field(repr=False)
    target_staging_receipt_digest: str = field(repr=False)
    target_resolution_receipt_digest: str = field(repr=False)
    native_loader_requirements_receipt_digest: str = field(repr=False)
    runtime_manifest_receipt_digest: str = field(repr=False)
    source_staging_receipt_digest: str = field(repr=False)
    registration_digest: str = field(repr=False)
    repository_ref: str = field(repr=False)
    verification_commands_digest: str = field(repr=False)
    resolution_context_digest: str = field(repr=False)
    source_staging_context_digest: str = field(repr=False)
    first_loader_path_context_digest: str = field(repr=False)
    target_staging_context_digest: str = field(repr=False)
    nested_loader_path_context_digest: str = field(repr=False)
    nested_target_staging_context_digest: str = field(repr=False)
    known_source_identity_set_digest: str = field(repr=False)
    known_target_identity_set_digest: str = field(repr=False)
    protected_staging_root_identity_set_digest: str = field(repr=False)
    guard_summary_ref: str = field(repr=False)
    requirements: tuple[
        RepositoryExecutableNativeLoaderNestedTargetLoaderRequirement, ...
    ] = field(repr=False)
    lineages: tuple[
        RepositoryExecutableNativeLoaderNestedTargetLoaderLineage, ...
    ] = field(repr=False)
    bindings: tuple[
        RepositoryExecutableNativeLoaderNestedTargetLoaderBinding, ...
    ] = field(repr=False)
    requirement_count: int
    lineage_count: int
    command_count: int
    nested_target_native_requirement_count: int
    further_loader_declared_count: int
    unsupported_native_layout_count: int
    non_native_not_applicable_count: int
    nested_target_required_lineage_count: int
    terminal_lineage_count: int
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
    RepositoryExecutableNativeLoaderNestedTargetLoaderRequirement
)
_FIXED_LINEAGE_TYPE = RepositoryExecutableNativeLoaderNestedTargetLoaderLineage
_FIXED_BINDING_TYPE = RepositoryExecutableNativeLoaderNestedTargetLoaderBinding
_FIXED_RECEIPT_TYPE = (
    RepositoryExecutableNativeLoaderNestedTargetLoaderRequirementsReceipt
)


def _is_digest(value: Any) -> bool:
    return (
        type(value) is str
        and _BUILTIN_IS_DIGEST_PATTERN.fullmatch(value) is not None
    )


_BUILTIN_IS_DIGEST = _is_digest


def _requirement_ref_projection(
    *,
    nested_target_staged_file_ref: str,
    nested_target_runtime_file_ref: str,
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
            "repository_executable_native_loader_nested_target_loader_"
            "requirement_ref"
        ),
        "layout_supported": layout_supported,
        "loader_path_absolute": loader_path_absolute,
        "loader_path_bytes": loader_path_bytes,
        "loader_path_ref": loader_path_ref,
        "requirements_scope": _FIXED_REQUIREMENTS_SCOPE,
        "runtime_classification": runtime_classification,
        "schema_version": _FIXED_SCHEMA_VERSION,
        "nested_target_runtime_file_ref": nested_target_runtime_file_ref,
        "nested_target_staged_file_ref": nested_target_staged_file_ref,
    }


_BUILTIN_REQUIREMENT_REF_PROJECTION = _requirement_ref_projection


def _requirement_projection(
    value: RepositoryExecutableNativeLoaderNestedTargetLoaderRequirement,
) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_REQUIREMENT_TYPE
        or type(value.kind) is not str
        or value.kind != _FIXED_REQUIREMENT_KIND
        or not _BUILTIN_IS_DIGEST(value.nested_target_staged_file_ref)
        or not _BUILTIN_IS_DIGEST(value.nested_target_runtime_file_ref)
        or not _BUILTIN_IS_DIGEST(value.nested_target_loader_requirement_ref)
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
        raise _InvalidNestedTargetLoaderRequirements

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
            raise _InvalidNestedTargetLoaderRequirements
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
            raise _InvalidNestedTargetLoaderRequirements
        if value.disposition == "unsupported_native_layout":
            if (
                value.layout_supported
                or value.image_kind is not None
                or value.loader_path_ref is not None
                or value.loader_path_bytes != 0
                or value.loader_path_absolute is not None
            ):
                raise _InvalidNestedTargetLoaderRequirements
        elif not value.layout_supported or value.image_kind is None:
            raise _InvalidNestedTargetLoaderRequirements
        if declared:
            if (
                value.loader_path_ref is None
                or not 1 <= value.loader_path_bytes <= _MAX_LOADER_PATH_BYTES
                or value.loader_path_absolute is not True
            ):
                raise _InvalidNestedTargetLoaderRequirements
        elif absent:
            if (
                value.loader_path_ref is not None
                or value.loader_path_bytes != 0
                or value.loader_path_absolute is not None
            ):
                raise _InvalidNestedTargetLoaderRequirements

    reference = _BUILTIN_REQUIREMENT_REF_PROJECTION(
        nested_target_staged_file_ref=value.nested_target_staged_file_ref,
        nested_target_runtime_file_ref=value.nested_target_runtime_file_ref,
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
    if value.nested_target_loader_requirement_ref != _BUILTIN_CANONICAL_DIGEST(
        reference
    ):
        raise _InvalidNestedTargetLoaderRequirements
    return {
        **reference,
        "kind": value.kind,
        "nested_target_loader_requirement_ref": (
            value.nested_target_loader_requirement_ref
        ),
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
    target_loader_lineage_ref: str,
    nested_target_lineage_ref: str,
    chain_guard_lineage_ref: str,
    nested_target_stage_lineage_ref: str,
    nested_target_runtime_lineage_ref: str,
    nested_target_runtime_requirement_ref: str | None,
    nested_target_runtime_file_ref: str | None,
    runtime_disposition: str,
    disposition: str,
    nested_target_loader_requirement_ref: str | None,
) -> dict[str, Any]:
    return {
        "chain_guard_lineage_ref": chain_guard_lineage_ref,
        "disposition": disposition,
        "kind": (
            "repository_executable_native_loader_nested_target_loader_lineage_ref"
        ),
        "nested_target_lineage_ref": nested_target_lineage_ref,
        "requirement_ref": requirement_ref,
        "runtime_file_ref": runtime_file_ref,
        "runtime_disposition": runtime_disposition,
        "schema_version": _FIXED_SCHEMA_VERSION,
        "staged_file_ref": staged_file_ref,
        "nested_target_loader_requirement_ref": nested_target_loader_requirement_ref,
        "nested_target_runtime_lineage_ref": (
            nested_target_runtime_lineage_ref
        ),
        "nested_target_runtime_requirement_ref": (
            nested_target_runtime_requirement_ref
        ),
        "nested_target_stage_lineage_ref": nested_target_stage_lineage_ref,
        "target_requirement_ref": target_requirement_ref,
        "nested_target_runtime_file_ref": nested_target_runtime_file_ref,
        "target_loader_lineage_ref": target_loader_lineage_ref,
        "target_runtime_requirement_ref": target_runtime_requirement_ref,
        "target_stage_requirement_ref": target_stage_requirement_ref,
    }


_BUILTIN_LINEAGE_REF_PROJECTION = _lineage_ref_projection


def _lineage_projection(
    value: RepositoryExecutableNativeLoaderNestedTargetLoaderLineage,
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
                value.chain_guard_lineage_ref,
                value.nested_target_stage_lineage_ref,
                value.nested_target_runtime_lineage_ref,
            )
        )
        or type(value.runtime_disposition) is not str
        or value.runtime_disposition not in _UPSTREAM_DISPOSITIONS
        or type(value.disposition) is not str
        or value.disposition not in _LINEAGE_DISPOSITIONS
        or (
            value.nested_target_runtime_requirement_ref is not None
            and not _BUILTIN_IS_DIGEST(
                value.nested_target_runtime_requirement_ref
            )
        )
        or (
            value.nested_target_runtime_file_ref is not None
            and not _BUILTIN_IS_DIGEST(value.nested_target_runtime_file_ref)
        )
        or (
            value.nested_target_loader_requirement_ref is not None
            and not _BUILTIN_IS_DIGEST(value.nested_target_loader_requirement_ref)
        )
        or (
            value.disposition == "nested_target_loader_requirements_inspected"
            and (
                value.runtime_disposition != "runtime_requirement_bound"
                or value.nested_target_runtime_requirement_ref is None
                or value.nested_target_runtime_file_ref is None
                or value.nested_target_loader_requirement_ref is None
            )
        )
        or (
            value.disposition != "nested_target_loader_requirements_inspected"
            and (
                value.nested_target_runtime_file_ref is not None
                or value.nested_target_loader_requirement_ref is not None
                or (
                    value.runtime_disposition == "runtime_requirement_bound"
                    and value.nested_target_runtime_requirement_ref is None
                )
                or (
                    value.runtime_disposition != "runtime_requirement_bound"
                    and (
                        value.runtime_disposition != value.disposition
                        or value.nested_target_runtime_requirement_ref is not None
                    )
                )
            )
        )
    ):
        raise _InvalidNestedTargetLoaderRequirements
    reference = _BUILTIN_LINEAGE_REF_PROJECTION(
        staged_file_ref=value.staged_file_ref,
        runtime_file_ref=value.runtime_file_ref,
        requirement_ref=value.requirement_ref,
        target_requirement_ref=value.target_requirement_ref,
        target_stage_requirement_ref=value.target_stage_requirement_ref,
        target_runtime_requirement_ref=value.target_runtime_requirement_ref,
        target_loader_lineage_ref=value.target_loader_lineage_ref,
        nested_target_lineage_ref=value.nested_target_lineage_ref,
        chain_guard_lineage_ref=value.chain_guard_lineage_ref,
        nested_target_stage_lineage_ref=value.nested_target_stage_lineage_ref,
        nested_target_runtime_lineage_ref=(
            value.nested_target_runtime_lineage_ref
        ),
        nested_target_runtime_requirement_ref=(
            value.nested_target_runtime_requirement_ref
        ),
        nested_target_runtime_file_ref=value.nested_target_runtime_file_ref,
        runtime_disposition=value.runtime_disposition,
        disposition=value.disposition,
        nested_target_loader_requirement_ref=value.nested_target_loader_requirement_ref,
    )
    if value.nested_target_loader_lineage_ref != _BUILTIN_CANONICAL_DIGEST(
        reference
    ):
        raise _InvalidNestedTargetLoaderRequirements
    return {
        **reference,
        "kind": value.kind,
        "nested_target_loader_lineage_ref": (
            value.nested_target_loader_lineage_ref
        ),
    }


_BUILTIN_LINEAGE_PROJECTION = _lineage_projection


def _binding_projection(
    value: RepositoryExecutableNativeLoaderNestedTargetLoaderBinding,
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
                value.chain_guard_lineage_ref,
                value.nested_target_stage_lineage_ref,
                value.nested_target_runtime_lineage_ref,
                value.nested_target_loader_lineage_ref,
            )
        )
    ):
        raise _InvalidNestedTargetLoaderRequirements
    return {
        "command_digest": value.command_digest,
        "command_id": value.command_id,
        "command_kind": value.command_kind,
        "kind": value.kind,
        "requirement_ref": value.requirement_ref,
        "runtime_file_ref": value.runtime_file_ref,
        "staged_file_ref": value.staged_file_ref,
        "chain_guard_lineage_ref": value.chain_guard_lineage_ref,
        "nested_target_lineage_ref": value.nested_target_lineage_ref,
        "nested_target_loader_lineage_ref": (
            value.nested_target_loader_lineage_ref
        ),
        "nested_target_runtime_lineage_ref": (
            value.nested_target_runtime_lineage_ref
        ),
        "nested_target_stage_lineage_ref": (
            value.nested_target_stage_lineage_ref
        ),
        "target_requirement_ref": value.target_requirement_ref,
        "target_loader_lineage_ref": value.target_loader_lineage_ref,
        "target_runtime_requirement_ref": value.target_runtime_requirement_ref,
        "target_stage_requirement_ref": value.target_stage_requirement_ref,
    }


_BUILTIN_BINDING_PROJECTION = _binding_projection


def _receipt_projection(
    value: RepositoryExecutableNativeLoaderNestedTargetLoaderRequirementsReceipt,
) -> dict[str, Any]:
    digest_fields = (
        value.nested_target_runtime_manifest_receipt_digest,
        value.nested_target_staging_receipt_digest,
        value.nested_target_resolution_receipt_digest,
        value.expected_chain_guard_receipt_digest,
        value.action_chain_guard_receipt_digest,
        value.post_stage_chain_guard_receipt_digest,
        value.target_loader_requirements_receipt_digest,
        value.target_runtime_manifest_receipt_digest,
        value.target_staging_receipt_digest,
        value.target_resolution_receipt_digest,
        value.native_loader_requirements_receipt_digest,
        value.runtime_manifest_receipt_digest,
        value.source_staging_receipt_digest,
        value.registration_digest,
        value.repository_ref,
        value.verification_commands_digest,
        value.resolution_context_digest,
        value.source_staging_context_digest,
        value.first_loader_path_context_digest,
        value.target_staging_context_digest,
        value.nested_loader_path_context_digest,
        value.nested_target_staging_context_digest,
        value.known_source_identity_set_digest,
        value.known_target_identity_set_digest,
        value.protected_staging_root_identity_set_digest,
        value.guard_summary_ref,
    )
    count_fields = (
        value.nested_target_native_requirement_count,
        value.further_loader_declared_count,
        value.unsupported_native_layout_count,
        value.non_native_not_applicable_count,
        value.nested_target_required_lineage_count,
        value.terminal_lineage_count,
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
        raise _InvalidNestedTargetLoaderRequirements

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
        str, RepositoryExecutableNativeLoaderNestedTargetLoaderRequirement
    ] = {}
    runtime_file_refs: set[str] = set()
    staged_file_refs: set[str] = set()
    for item in value.requirements:
        if (
            item.nested_target_loader_requirement_ref in requirement_by_ref
            or item.nested_target_runtime_file_ref in runtime_file_refs
            or item.nested_target_staged_file_ref in staged_file_refs
        ):
            raise _InvalidNestedTargetLoaderRequirements
        requirement_by_ref[item.nested_target_loader_requirement_ref] = item
        runtime_file_refs.add(item.nested_target_runtime_file_ref)
        staged_file_refs.add(item.nested_target_staged_file_ref)

    lineage_by_ref: dict[
        str, RepositoryExecutableNativeLoaderNestedTargetLoaderLineage
    ] = {}
    runtime_lineage_refs: set[str] = set()
    used_requirement_refs: set[str] = set()
    ordered_first_use: list[str] = []
    target_required = 0
    no_target = 0
    for item in value.lineages:
        if (
            item.nested_target_loader_lineage_ref in lineage_by_ref
            or item.nested_target_runtime_lineage_ref in runtime_lineage_refs
        ):
            raise _InvalidNestedTargetLoaderRequirements
        lineage_by_ref[item.nested_target_loader_lineage_ref] = item
        runtime_lineage_refs.add(item.nested_target_runtime_lineage_ref)
        if item.disposition == "nested_target_loader_requirements_inspected":
            target_required += 1
            target_ref = item.nested_target_loader_requirement_ref
            if target_ref is None or target_ref not in requirement_by_ref:
                raise _InvalidNestedTargetLoaderRequirements
            target_requirement = requirement_by_ref[target_ref]
            if (
                item.nested_target_runtime_file_ref
                != target_requirement.nested_target_runtime_file_ref
            ):
                raise _InvalidNestedTargetLoaderRequirements
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
        lineage = lineage_by_ref.get(item.nested_target_loader_lineage_ref)
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
            or item.nested_target_lineage_ref
            != lineage.nested_target_lineage_ref
            or item.chain_guard_lineage_ref != lineage.chain_guard_lineage_ref
            or item.nested_target_stage_lineage_ref
            != lineage.nested_target_stage_lineage_ref
            or item.nested_target_runtime_lineage_ref
            != lineage.nested_target_runtime_lineage_ref
            or item.command_id in command_ids
            or kind_index < prior_kind_index
        ):
            raise _InvalidNestedTargetLoaderRequirements
        command_ids.add(item.command_id)
        if item.nested_target_loader_lineage_ref not in bound_lineage_refs:
            ordered_bound_lineages.append(
                item.nested_target_loader_lineage_ref
            )
        bound_lineage_refs.add(item.nested_target_loader_lineage_ref)
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
            item.nested_target_loader_requirement_ref for item in value.requirements
        )
        or bound_lineage_refs != set(lineage_by_ref)
        or tuple(ordered_bound_lineages)
        != tuple(
            item.nested_target_loader_lineage_ref for item in value.lineages
        )
        or native_count != value.nested_target_native_requirement_count
        or declared_count != value.further_loader_declared_count
        or unsupported_count != value.unsupported_native_layout_count
        or non_native_count != value.non_native_not_applicable_count
        or target_required != value.nested_target_required_lineage_count
        or no_target != value.terminal_lineage_count
        or target_required + no_target != value.lineage_count
        or value.requirement_count != len(used_requirement_refs)
        or total_path_bytes != value.total_loader_path_bytes
        or (value.requirement_count == 0 and target_required != 0)
        or (value.requirement_count > 0 and target_required == 0)
    ):
        raise _InvalidNestedTargetLoaderRequirements

    return {
        "action_chain_guard_receipt_digest": (
            value.action_chain_guard_receipt_digest
        ),
        "bindings": bindings,
        "command_count": value.command_count,
        "expected_chain_guard_receipt_digest": (
            value.expected_chain_guard_receipt_digest
        ),
        "first_loader_path_context_digest": (
            value.first_loader_path_context_digest
        ),
        "guard_summary_ref": value.guard_summary_ref,
        "kind": value.kind,
        "known_source_identity_set_digest": (
            value.known_source_identity_set_digest
        ),
        "known_target_identity_set_digest": (
            value.known_target_identity_set_digest
        ),
        "lineage_count": value.lineage_count,
        "lineages": lineages,
        "nested_loader_path_context_digest": (
            value.nested_loader_path_context_digest
        ),
        "native_loader_requirements_receipt_digest": (
            value.native_loader_requirements_receipt_digest
        ),
        "further_loader_declared_count": value.further_loader_declared_count,
        "nested_target_resolution_receipt_digest": (
            value.nested_target_resolution_receipt_digest
        ),
        "nested_target_runtime_manifest_receipt_digest": (
            value.nested_target_runtime_manifest_receipt_digest
        ),
        "nested_target_staging_context_digest": (
            value.nested_target_staging_context_digest
        ),
        "nested_target_staging_receipt_digest": (
            value.nested_target_staging_receipt_digest
        ),
        "non_native_not_applicable_count": (
            value.non_native_not_applicable_count
        ),
        "post_stage_chain_guard_receipt_digest": (
            value.post_stage_chain_guard_receipt_digest
        ),
        "protected_staging_root_identity_set_digest": (
            value.protected_staging_root_identity_set_digest
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
        "source_staging_receipt_digest": value.source_staging_receipt_digest,
        "nested_target_native_requirement_count": (
            value.nested_target_native_requirement_count
        ),
        "nested_target_required_lineage_count": (
            value.nested_target_required_lineage_count
        ),
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
        "terminal_lineage_count": value.terminal_lineage_count,
        "total_loader_path_bytes": value.total_loader_path_bytes,
        "unsupported_native_layout_count": (
            value.unsupported_native_layout_count
        ),
        "verification_commands_digest": value.verification_commands_digest,
    }


_BUILTIN_RECEIPT_PROJECTION = _receipt_projection


def _evidence_projection(
    value: RepositoryExecutableNativeLoaderNestedTargetLoaderRequirementsReceipt,
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
        "active_nested_target_stage_lease_verified_at_measurement": True,
        "authority_granted": False,
        "authorization_verified": False,
        "billing_eligible": False,
        "bounded_depth_two_loader_syntax_inspection_complete": True,
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
        "exact_nested_target_runtime_correspondence_verified": True,
        "exact_nested_target_staging_correspondence_verified": True,
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
        "further_loader_declared_count": value.further_loader_declared_count,
        "network_access_performed": False,
        "terminal_lineage_count": value.terminal_lineage_count,
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
        "nested_target_native_requirement_count": (
            value.nested_target_native_requirement_count
        ),
        "nested_target_required_lineage_count": (
            value.nested_target_required_lineage_count
        ),
        "nested_target_runtime_manifest_receipt_digest": (
            value.nested_target_runtime_manifest_receipt_digest
        ),
        "nested_target_staging_receipt_digest": (
            value.nested_target_staging_receipt_digest
        ),
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
) -> RepositoryExecutableNativeLoaderNestedTargetLoaderRequirement:
    if (
        type(runtime_file) is not dict
        or type(descriptor) is not int
        or descriptor < 0
        or type(header) is not bytes
        or runtime_file.get("header_bytes") != len(header)
        or runtime_file.get("header_digest")
        != _BUILTIN_NESTED_TARGET_HEADER_DIGEST(
            runtime_file.get("nested_target_staged_file_ref"),
            header,
        )
    ):
        raise _InvalidNestedTargetLoaderRequirements
    classification = runtime_file.get("classification")
    adapter = _ParserRuntimeFile(
        content_bytes=runtime_file["content_bytes"],
        runtime_file_ref=runtime_file["nested_target_runtime_file_ref"],
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
        raise _InvalidNestedTargetLoaderRequirements
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
        nested_target_staged_file_ref=runtime_file[
            "nested_target_staged_file_ref"
        ],
        nested_target_runtime_file_ref=runtime_file[
            "nested_target_runtime_file_ref"
        ],
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
        nested_target_staged_file_ref=runtime_file[
            "nested_target_staged_file_ref"
        ],
        nested_target_runtime_file_ref=runtime_file[
            "nested_target_runtime_file_ref"
        ],
        runtime_classification=classification,
        format_class=format_class,
        byte_order=byte_order,
        image_kind=image_kind,
        disposition=disposition,
        loader_path_ref=loader_path_ref,
        loader_path_bytes=loader_path_bytes,
        loader_path_absolute=loader_path_absolute,
        layout_supported=layout_supported,
        nested_target_loader_requirement_ref=_BUILTIN_CANONICAL_DIGEST(reference),
    )
    _BUILTIN_REQUIREMENT_PROJECTION(value)
    return value


_BUILTIN_BUILD_REQUIREMENT = _build_requirement


def _remeasure_requirements(
    runtime_canonical: dict[str, Any],
    staging_canonical: dict[str, Any],
    retained_files: tuple[Any, ...],
) -> tuple[RepositoryExecutableNativeLoaderNestedTargetLoaderRequirement, ...]:
    runtime_files = runtime_canonical["files"]
    staged_files = staging_canonical["staged_files"]
    if len(runtime_files) != len(staged_files) or len(runtime_files) != len(
        retained_files
    ):
        raise _InvalidNestedTargetLoaderRequirements
    values: list[
        RepositoryExecutableNativeLoaderNestedTargetLoaderRequirement
    ] = []
    for retained, staged_file, runtime_file in zip(
        retained_files,
        staged_files,
        runtime_files,
        strict=True,
    ):
        if (
            runtime_file["nested_target_staged_file_ref"]
            != staged_file["nested_target_staged_file_ref"]
            or runtime_file["staged_filesystem_identity_ref"]
            != staged_file["staged_filesystem_identity_ref"]
            or runtime_file["content_digest"] != staged_file["content_digest"]
            or runtime_file["content_bytes"] != staged_file["content_bytes"]
        ):
            raise _InvalidNestedTargetLoaderRequirements
        before_header = _BUILTIN_VERIFY_RETAINED_NESTED_TARGET(
            retained, staged_file
        )
        value = _BUILTIN_BUILD_REQUIREMENT(
            runtime_file,
            descriptor=retained.descriptor,
            header=before_header,
        )
        after_header = _BUILTIN_VERIFY_RETAINED_NESTED_TARGET(
            retained, staged_file
        )
        if after_header != before_header:
            raise _InvalidNestedTargetLoaderRequirements
        values.append(value)
    return tuple(values)


_BUILTIN_REMEASURE_REQUIREMENTS = _remeasure_requirements


def _build_lineage(
    upstream: dict[str, Any],
    *,
    runtime_requirement_by_ref: dict[str, dict[str, Any]],
    requirement_by_runtime_ref: dict[
        str, RepositoryExecutableNativeLoaderNestedTargetLoaderRequirement
    ],
) -> RepositoryExecutableNativeLoaderNestedTargetLoaderLineage:
    upstream_disposition = upstream.get("disposition")
    if upstream_disposition not in _UPSTREAM_DISPOSITIONS:
        raise _InvalidNestedTargetLoaderRequirements
    runtime_requirement_ref = upstream.get(
        "nested_target_runtime_requirement_ref"
    )
    if upstream_disposition == "runtime_requirement_bound":
        runtime_requirement = runtime_requirement_by_ref.get(
            runtime_requirement_ref
        )
        if runtime_requirement is None:
            raise _InvalidNestedTargetLoaderRequirements
        runtime_requirement_disposition = runtime_requirement.get(
            "disposition"
        )
        nested_target_runtime_file_ref = runtime_requirement.get(
            "nested_target_runtime_file_ref"
        )
        if runtime_requirement_disposition == "known_chain_guard_runtime_inspected":
            loader_requirement = requirement_by_runtime_ref.get(
                nested_target_runtime_file_ref
            )
            if loader_requirement is None:
                raise _InvalidNestedTargetLoaderRequirements
            disposition = "nested_target_loader_requirements_inspected"
            nested_target_loader_requirement_ref = (
                loader_requirement.nested_target_loader_requirement_ref
            )
        elif runtime_requirement_disposition in _UPSTREAM_DISPOSITIONS[1:]:
            if nested_target_runtime_file_ref is not None:
                raise _InvalidNestedTargetLoaderRequirements
            disposition = runtime_requirement_disposition
            nested_target_loader_requirement_ref = None
        else:
            raise _InvalidNestedTargetLoaderRequirements
    else:
        disposition = upstream_disposition
        runtime_requirement_ref = None
        nested_target_runtime_file_ref = None
        nested_target_loader_requirement_ref = None
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
        target_loader_lineage_ref=upstream["target_loader_lineage_ref"],
        nested_target_lineage_ref=upstream["nested_target_lineage_ref"],
        chain_guard_lineage_ref=upstream["chain_guard_lineage_ref"],
        nested_target_stage_lineage_ref=upstream[
            "nested_target_stage_lineage_ref"
        ],
        nested_target_runtime_lineage_ref=upstream[
            "nested_target_runtime_lineage_ref"
        ],
        nested_target_runtime_requirement_ref=runtime_requirement_ref,
        nested_target_runtime_file_ref=nested_target_runtime_file_ref,
        runtime_disposition=upstream_disposition,
        disposition=disposition,
        nested_target_loader_requirement_ref=nested_target_loader_requirement_ref,
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
        target_loader_lineage_ref=upstream["target_loader_lineage_ref"],
        nested_target_lineage_ref=upstream["nested_target_lineage_ref"],
        chain_guard_lineage_ref=upstream["chain_guard_lineage_ref"],
        nested_target_stage_lineage_ref=upstream[
            "nested_target_stage_lineage_ref"
        ],
        nested_target_runtime_lineage_ref=upstream[
            "nested_target_runtime_lineage_ref"
        ],
        nested_target_runtime_requirement_ref=runtime_requirement_ref,
        nested_target_runtime_file_ref=nested_target_runtime_file_ref,
        runtime_disposition=upstream_disposition,
        disposition=disposition,
        nested_target_loader_requirement_ref=nested_target_loader_requirement_ref,
        nested_target_loader_lineage_ref=_BUILTIN_CANONICAL_DIGEST(reference),
    )
    _BUILTIN_LINEAGE_PROJECTION(value)
    return value


_BUILTIN_BUILD_LINEAGE = _build_lineage


def _validate_runtime_stage_correspondence(
    runtime: RepositoryExecutableNativeLoaderNestedTargetRuntimeManifestReceipt,
    runtime_canonical: dict[str, Any],
    staging: RepositoryExecutableNativeLoaderNestedTargetStagingReceipt,
    staging_canonical: dict[str, Any],
) -> None:
    stage_digest = _BUILTIN_CANONICAL_DIGEST(staging_canonical)
    if (
        runtime.nested_target_staging_receipt_digest != stage_digest
        or runtime.nested_target_resolution_receipt_digest
        != staging.nested_target_resolution_receipt_digest
        or runtime.expected_chain_guard_receipt_digest
        != staging.expected_chain_guard_receipt_digest
        or runtime.action_chain_guard_receipt_digest
        != staging.action_chain_guard_receipt_digest
        or runtime.post_stage_chain_guard_receipt_digest
        != staging.post_stage_chain_guard_receipt_digest
        or runtime.target_loader_requirements_receipt_digest
        != staging.target_loader_requirements_receipt_digest
        or runtime.target_runtime_manifest_receipt_digest
        != staging.target_runtime_manifest_receipt_digest
        or runtime.target_staging_receipt_digest
        != staging.target_staging_receipt_digest
        or runtime.target_resolution_receipt_digest
        != staging.target_resolution_receipt_digest
        or runtime.native_loader_requirements_receipt_digest
        != staging.native_loader_requirements_receipt_digest
        or runtime.runtime_manifest_receipt_digest
        != staging.runtime_manifest_receipt_digest
        or runtime.source_staging_receipt_digest
        != staging.source_staging_receipt_digest
        or runtime.registration_digest != staging.registration_digest
        or runtime.repository_ref != staging.repository_ref
        or runtime.verification_commands_digest
        != staging.verification_commands_digest
        or runtime.resolution_context_digest
        != staging.resolution_context_digest
        or runtime.source_staging_context_digest
        != staging.source_staging_context_digest
        or runtime.first_loader_path_context_digest
        != staging.first_loader_path_context_digest
        or runtime.target_staging_context_digest
        != staging.target_staging_context_digest
        or runtime.nested_loader_path_context_digest
        != staging.nested_loader_path_context_digest
        or runtime.nested_target_staging_context_digest
        != staging.nested_target_staging_context_digest
        or runtime.known_source_identity_set_digest
        != staging.known_source_identity_set_digest
        or runtime.known_target_identity_set_digest
        != staging.known_target_identity_set_digest
        or runtime.protected_staging_root_identity_set_digest
        != staging.protected_staging_root_identity_set_digest
        or runtime.guard_summary_ref != staging.guard_summary_ref
        or runtime_canonical["file_count"]
        != staging_canonical["unique_nested_target_count"]
        or runtime_canonical["requirement_count"]
        != staging_canonical["requirement_count"]
        or runtime_canonical["lineage_count"]
        != staging_canonical["lineage_count"]
        or runtime_canonical["command_count"]
        != staging_canonical["command_count"]
    ):
        raise _InvalidNestedTargetLoaderRequirements


_BUILTIN_VALIDATE_RUNTIME_STAGE = _validate_runtime_stage_correspondence


def inspect_staged_executable_native_loader_nested_target_loader_requirements(
    expected_nested_target_runtime: (
        RepositoryExecutableNativeLoaderNestedTargetRuntimeManifestReceipt
    ),
    *,
    expected_nested_target_staging: (
        RepositoryExecutableNativeLoaderNestedTargetStagingReceipt
    ),
    lease: RepositoryExecutableNativeLoaderNestedTargetStageLease,
) -> RepositoryExecutableNativeLoaderNestedTargetLoaderRequirementsReceipt:
    """Inspect loader syntax from one exact active depth-two stage."""

    try:
        if (
            type(expected_nested_target_runtime)
            is not _FIXED_RUNTIME_RECEIPT_TYPE
            or type(expected_nested_target_staging)
            is not _FIXED_STAGING_RECEIPT_TYPE
            or type(lease) is not _FIXED_STAGE_LEASE_TYPE
        ):
            raise _InvalidNestedTargetLoaderRequirements
        runtime_canonical = _BUILTIN_NESTED_TARGET_RUNTIME_PROJECTION(
            expected_nested_target_runtime
        )
        staging_canonical = _BUILTIN_NESTED_TARGET_STAGING_PROJECTION(
            expected_nested_target_staging
        )
        _BUILTIN_VALIDATE_RUNTIME_STAGE(
            expected_nested_target_runtime,
            runtime_canonical,
            expected_nested_target_staging,
            staging_canonical,
        )

        fresh_runtime = _BUILTIN_INSPECT_NESTED_TARGET_RUNTIME(
            expected_nested_target_staging,
            lease=lease,
        )
        if (
            _BUILTIN_NESTED_TARGET_RUNTIME_PROJECTION(fresh_runtime)
            != runtime_canonical
        ):
            raise _InvalidNestedTargetLoaderRequirements
        active_canonical, retained_files = (
            _BUILTIN_NESTED_TARGET_STAGE_SNAPSHOT(
                expected_nested_target_staging,
                lease,
            )
        )
        if active_canonical != staging_canonical:
            raise _InvalidNestedTargetLoaderRequirements

        requirements = _BUILTIN_REMEASURE_REQUIREMENTS(
            runtime_canonical,
            staging_canonical,
            retained_files,
        )

        final_runtime = _BUILTIN_INSPECT_NESTED_TARGET_RUNTIME(
            expected_nested_target_staging,
            lease=lease,
        )
        final_canonical, final_retained_files = (
            _BUILTIN_NESTED_TARGET_STAGE_SNAPSHOT(
                expected_nested_target_staging,
                lease,
            )
        )
        if (
            _BUILTIN_NESTED_TARGET_RUNTIME_PROJECTION(final_runtime)
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
            raise _InvalidNestedTargetLoaderRequirements

        requirement_by_runtime_ref = {
            item.nested_target_runtime_file_ref: item for item in requirements
        }
        runtime_requirement_by_ref = {
            item["nested_target_runtime_requirement_ref"]: item
            for item in runtime_canonical["requirements"]
        }
        lineages = tuple(
            _BUILTIN_BUILD_LINEAGE(
                item,
                runtime_requirement_by_ref=runtime_requirement_by_ref,
                requirement_by_runtime_ref=requirement_by_runtime_ref,
            )
            for item in runtime_canonical["lineages"]
        )
        lineage_by_runtime_lineage_ref = {
            item.nested_target_runtime_lineage_ref: item for item in lineages
        }
        bindings: list[
            RepositoryExecutableNativeLoaderNestedTargetLoaderBinding
        ] = []
        for upstream in runtime_canonical["bindings"]:
            lineage = lineage_by_runtime_lineage_ref.get(
                upstream["nested_target_runtime_lineage_ref"]
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
                or upstream["target_loader_lineage_ref"]
                != lineage.target_loader_lineage_ref
                or upstream["nested_target_lineage_ref"]
                != lineage.nested_target_lineage_ref
                or upstream["chain_guard_lineage_ref"]
                != lineage.chain_guard_lineage_ref
                or upstream["nested_target_stage_lineage_ref"]
                != lineage.nested_target_stage_lineage_ref
            ):
                raise _InvalidNestedTargetLoaderRequirements
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
                    nested_target_lineage_ref=(
                        lineage.nested_target_lineage_ref
                    ),
                    chain_guard_lineage_ref=(
                        lineage.chain_guard_lineage_ref
                    ),
                    nested_target_stage_lineage_ref=(
                        lineage.nested_target_stage_lineage_ref
                    ),
                    nested_target_runtime_lineage_ref=(
                        lineage.nested_target_runtime_lineage_ref
                    ),
                    nested_target_loader_lineage_ref=(
                        lineage.nested_target_loader_lineage_ref
                    ),
                )
            )

        nested_target_required_lineage_count = sum(
            item.disposition == "nested_target_loader_requirements_inspected"
            for item in lineages
        )
        receipt = _FIXED_RECEIPT_TYPE(
            kind=_FIXED_RECEIPT_KIND,
            schema_version=_FIXED_SCHEMA_VERSION,
            requirements_source=_FIXED_REQUIREMENTS_SOURCE,
            requirements_scope=_FIXED_REQUIREMENTS_SCOPE,
            nested_target_runtime_manifest_receipt_digest=(
                _BUILTIN_CANONICAL_DIGEST(runtime_canonical)
            ),
            nested_target_staging_receipt_digest=(
                _BUILTIN_CANONICAL_DIGEST(staging_canonical)
            ),
            nested_target_resolution_receipt_digest=(
                expected_nested_target_runtime
                .nested_target_resolution_receipt_digest
            ),
            expected_chain_guard_receipt_digest=(
                expected_nested_target_runtime
                .expected_chain_guard_receipt_digest
            ),
            action_chain_guard_receipt_digest=(
                expected_nested_target_runtime
                .action_chain_guard_receipt_digest
            ),
            post_stage_chain_guard_receipt_digest=(
                expected_nested_target_runtime
                .post_stage_chain_guard_receipt_digest
            ),
            target_loader_requirements_receipt_digest=(
                expected_nested_target_runtime
                .target_loader_requirements_receipt_digest
            ),
            target_runtime_manifest_receipt_digest=(
                expected_nested_target_runtime
                .target_runtime_manifest_receipt_digest
            ),
            target_staging_receipt_digest=(
                expected_nested_target_runtime.target_staging_receipt_digest
            ),
            target_resolution_receipt_digest=(
                expected_nested_target_runtime.target_resolution_receipt_digest
            ),
            native_loader_requirements_receipt_digest=(
                expected_nested_target_runtime
                .native_loader_requirements_receipt_digest
            ),
            runtime_manifest_receipt_digest=(
                expected_nested_target_runtime.runtime_manifest_receipt_digest
            ),
            source_staging_receipt_digest=(
                expected_nested_target_runtime.source_staging_receipt_digest
            ),
            registration_digest=(
                expected_nested_target_runtime.registration_digest
            ),
            repository_ref=expected_nested_target_runtime.repository_ref,
            verification_commands_digest=(
                expected_nested_target_runtime.verification_commands_digest
            ),
            resolution_context_digest=(
                expected_nested_target_runtime.resolution_context_digest
            ),
            source_staging_context_digest=(
                expected_nested_target_runtime.source_staging_context_digest
            ),
            first_loader_path_context_digest=(
                expected_nested_target_runtime.first_loader_path_context_digest
            ),
            target_staging_context_digest=(
                expected_nested_target_runtime.target_staging_context_digest
            ),
            nested_loader_path_context_digest=(
                expected_nested_target_runtime.nested_loader_path_context_digest
            ),
            nested_target_staging_context_digest=(
                expected_nested_target_runtime
                .nested_target_staging_context_digest
            ),
            known_source_identity_set_digest=(
                expected_nested_target_runtime
                .known_source_identity_set_digest
            ),
            known_target_identity_set_digest=(
                expected_nested_target_runtime
                .known_target_identity_set_digest
            ),
            protected_staging_root_identity_set_digest=(
                expected_nested_target_runtime
                .protected_staging_root_identity_set_digest
            ),
            guard_summary_ref=(
                expected_nested_target_runtime.guard_summary_ref
            ),
            requirements=requirements,
            lineages=lineages,
            bindings=tuple(bindings),
            requirement_count=len(requirements),
            lineage_count=len(lineages),
            command_count=len(bindings),
            nested_target_native_requirement_count=sum(
                item.runtime_classification in {"elf", "mach_o"}
                for item in requirements
            ),
            further_loader_declared_count=sum(
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
            nested_target_required_lineage_count=(
                nested_target_required_lineage_count
            ),
            terminal_lineage_count=(
                len(lineages) - nested_target_required_lineage_count
            ),
            total_loader_path_bytes=sum(
                item.loader_path_bytes for item in requirements
            ),
        )
        _BUILTIN_RECEIPT_PROJECTION(receipt)
        closing_canonical, closing_retained_files = (
            _BUILTIN_NESTED_TARGET_STAGE_SNAPSHOT(
                expected_nested_target_staging,
                lease,
            )
        )
        if (
            closing_canonical != staging_canonical
            or closing_retained_files is not retained_files
        ):
            raise _InvalidNestedTargetLoaderRequirements
        return receipt
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise _FIXED_VALIDATION_ERROR(_INVALID_MESSAGE) from None


__all__ = [
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_LOADER_BINDING_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_LOADER_LINEAGE_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_LOADER_REQUIREMENT_KIND",
    (
        "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_LOADER_"
        "REQUIREMENTS_EVIDENCE_KIND"
    ),
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_LOADER_REQUIREMENTS_KIND",
    (
        "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_LOADER_"
        "REQUIREMENTS_SCHEMA_VERSION"
    ),
    "REQUIREMENTS_SCOPE",
    "REQUIREMENTS_SOURCE",
    "RepositoryExecutableNativeLoaderNestedTargetLoaderBinding",
    "RepositoryExecutableNativeLoaderNestedTargetLoaderLineage",
    "RepositoryExecutableNativeLoaderNestedTargetLoaderRequirement",
    "RepositoryExecutableNativeLoaderNestedTargetLoaderRequirementsReceipt",
    "inspect_staged_executable_native_loader_nested_target_loader_requirements",
]
