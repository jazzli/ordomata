"""Digest-only native loader declarations from an active executable stage.

This Class 0 boundary consumes one exact staged runtime manifest and reproduces
it from the same active process-local lease. It parses only bounded ELF program
headers and thin Mach-O load commands for a declared dynamic-loader path. It
does not resolve that path, inspect shared libraries, mutate the lease, or
execute a process.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import fcntl
import hashlib
import os
import re
import stat
from typing import Any

from .authorization import canonical_json
from .errors import ValidationError
from .repository_executable_runtime_manifest import (
    RepositoryExecutableRuntimeManifestReceipt,
    _active_stage_snapshot,
    _runtime_manifest_projection,
    inspect_staged_executable_runtime_manifest,
)
from .repository_executable_staging import (
    RepositoryExecutableStageLease,
    RepositoryExecutableStagingReceipt,
    _RetainedStagedFile,
    _staged_file_projection,
    _staging_receipt_projection,
)


REPOSITORY_EXECUTABLE_NATIVE_LOADER_REQUIREMENTS_SCHEMA_VERSION = 1
REPOSITORY_EXECUTABLE_NATIVE_LOADER_REQUIREMENTS_KIND = (
    "repository_executable_native_loader_requirements"
)
REPOSITORY_EXECUTABLE_NATIVE_LOADER_REQUIREMENTS_EVIDENCE_KIND = (
    "repository_executable_native_loader_requirements_validation"
)
REPOSITORY_EXECUTABLE_NATIVE_LOADER_REQUIREMENT_KIND = (
    "repository_executable_native_loader_requirement"
)
REPOSITORY_EXECUTABLE_NATIVE_LOADER_REQUIREMENT_BINDING_KIND = (
    "repository_executable_native_loader_requirement_binding"
)
REQUIREMENTS_SOURCE = "controller_inspected"
REQUIREMENTS_SCOPE = "staged_native_loader_declarations_v1"

_FIXED_SCHEMA_VERSION = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_REQUIREMENTS_SCHEMA_VERSION
)
_FIXED_RECEIPT_KIND = REPOSITORY_EXECUTABLE_NATIVE_LOADER_REQUIREMENTS_KIND
_FIXED_EVIDENCE_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_REQUIREMENTS_EVIDENCE_KIND
)
_FIXED_REQUIREMENT_KIND = REPOSITORY_EXECUTABLE_NATIVE_LOADER_REQUIREMENT_KIND
_FIXED_BINDING_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_REQUIREMENT_BINDING_KIND
)
_FIXED_REQUIREMENTS_SOURCE = REQUIREMENTS_SOURCE
_FIXED_REQUIREMENTS_SCOPE = REQUIREMENTS_SCOPE

_INVALID_MESSAGE = "repository executable native loader requirements are invalid"
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
    "elf_interpreter_declared",
    "elf_interpreter_absent",
    "mach_o_dylinker_declared",
    "mach_o_dylinker_absent",
    "unsupported_native_layout",
    "non_native_not_applicable",
)
_MAX_FILES = 80
_MAX_COMMANDS = 80
_MAX_FILE_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_BYTES = 256 * 1024 * 1024
_MAX_HEADER_BYTES = 4_096
_MAX_PROGRAM_HEADERS = 1_024
_MAX_LOAD_COMMANDS = 4_096
_MAX_TABLE_BYTES = 1024 * 1024
_MAX_LOADER_PATH_BYTES = 4_095
_FULL_REMEASUREMENT_CHUNK_BYTES = 1024 * 1024
_STAGED_FILE_MODE = 0o400
_PT_INTERP = 3
_LC_LOAD_DYLINKER = 0xE
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
_BUILTIN_PREAD = os.pread
_BUILTIN_FSTAT = os.fstat
_BUILTIN_GETEUID = os.geteuid
_BUILTIN_GET_INHERITABLE = os.get_inheritable
_BUILTIN_FCNTL = fcntl.fcntl
_BUILTIN_F_GETFL = fcntl.F_GETFL
_BUILTIN_O_ACCMODE = os.O_ACCMODE
_BUILTIN_O_RDONLY = os.O_RDONLY
_BUILTIN_S_ISREG = stat.S_ISREG
_BUILTIN_S_IMODE = stat.S_IMODE
_FIXED_VALIDATION_ERROR = ValidationError
_FIXED_RUNTIME_RECEIPT_TYPE = RepositoryExecutableRuntimeManifestReceipt
_FIXED_STAGING_RECEIPT_TYPE = RepositoryExecutableStagingReceipt
_FIXED_STAGE_LEASE_TYPE = RepositoryExecutableStageLease
_FIXED_RETAINED_TYPE = _RetainedStagedFile


class _InvalidNativeLoaderRequirements(ValueError):
    """Private fail-closed sentinel whose details never cross the API."""


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeLoaderRequirement:
    """One runtime file's bounded native-loader declaration result."""

    kind: str
    staged_file_ref: str = field(repr=False)
    runtime_file_ref: str = field(repr=False)
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
        return _BUILTIN_REQUIREMENT_PROJECTION(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeLoaderRequirementBinding:
    """One registered command bound to one loader requirement."""

    kind: str
    command_kind: str
    command_id: str = field(repr=False)
    command_digest: str = field(repr=False)
    staged_file_ref: str = field(repr=False)
    runtime_file_ref: str = field(repr=False)
    requirement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_BINDING_PROJECTION(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeLoaderRequirementsReceipt:
    """Historical loader-declaration evidence from one active stage."""

    kind: str
    schema_version: int
    requirements_source: str
    requirements_scope: str
    runtime_manifest_receipt_digest: str = field(repr=False)
    staging_receipt_digest: str = field(repr=False)
    registration_digest: str = field(repr=False)
    repository_ref: str = field(repr=False)
    verification_commands_digest: str = field(repr=False)
    resolution_context_digest: str = field(repr=False)
    staging_context_digest: str = field(repr=False)
    requirements: tuple[RepositoryExecutableNativeLoaderRequirement, ...] = field(
        repr=False
    )
    bindings: tuple[
        RepositoryExecutableNativeLoaderRequirementBinding, ...
    ] = field(repr=False)
    requirement_count: int
    command_count: int
    native_requirement_count: int
    loader_declared_count: int
    unsupported_native_layout_count: int
    non_native_not_applicable_count: int
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


_FIXED_REQUIREMENT_TYPE = RepositoryExecutableNativeLoaderRequirement
_FIXED_BINDING_TYPE = RepositoryExecutableNativeLoaderRequirementBinding
_FIXED_RECEIPT_TYPE = RepositoryExecutableNativeLoaderRequirementsReceipt


def _is_digest(value: Any) -> bool:
    return type(value) is str and _DIGEST_PATTERN.fullmatch(value) is not None


_BUILTIN_IS_DIGEST = _is_digest


def _requirement_ref_projection(
    *,
    staged_file_ref: str,
    runtime_file_ref: str,
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
        "kind": "repository_executable_native_loader_requirement_ref",
        "layout_supported": layout_supported,
        "loader_path_absolute": loader_path_absolute,
        "loader_path_bytes": loader_path_bytes,
        "loader_path_ref": loader_path_ref,
        "requirements_scope": _FIXED_REQUIREMENTS_SCOPE,
        "runtime_classification": runtime_classification,
        "runtime_file_ref": runtime_file_ref,
        "schema_version": _FIXED_SCHEMA_VERSION,
        "staged_file_ref": staged_file_ref,
    }


_BUILTIN_REQUIREMENT_REF_PROJECTION = _requirement_ref_projection


def _requirement_projection(
    value: RepositoryExecutableNativeLoaderRequirement,
) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_REQUIREMENT_TYPE
        or type(value.kind) is not str
        or value.kind != _FIXED_REQUIREMENT_KIND
        or not _BUILTIN_IS_DIGEST(value.staged_file_ref)
        or not _BUILTIN_IS_DIGEST(value.runtime_file_ref)
        or not _BUILTIN_IS_DIGEST(value.requirement_ref)
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
        or value.disposition not in _DISPOSITIONS
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
        raise _InvalidNativeLoaderRequirements

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
            raise _InvalidNativeLoaderRequirements
    else:
        expected_prefix = "elf_" if value.runtime_classification == "elf" else "mach_o_"
        if (
            value.format_class is None
            or value.byte_order is None
            or (
                not value.disposition.startswith(expected_prefix)
                and value.disposition != "unsupported_native_layout"
            )
        ):
            raise _InvalidNativeLoaderRequirements
        if value.disposition == "unsupported_native_layout":
            if (
                value.layout_supported
                or value.image_kind is not None
                or value.loader_path_ref is not None
                or value.loader_path_bytes != 0
                or value.loader_path_absolute is not None
            ):
                raise _InvalidNativeLoaderRequirements
        elif not value.layout_supported or value.image_kind is None:
            raise _InvalidNativeLoaderRequirements
        if declared:
            if (
                value.loader_path_ref is None
                or not 1 <= value.loader_path_bytes <= _MAX_LOADER_PATH_BYTES
                or value.loader_path_absolute is not True
            ):
                raise _InvalidNativeLoaderRequirements
        elif absent:
            if (
                value.loader_path_ref is not None
                or value.loader_path_bytes != 0
                or value.loader_path_absolute is not None
            ):
                raise _InvalidNativeLoaderRequirements

    reference = _BUILTIN_REQUIREMENT_REF_PROJECTION(
        staged_file_ref=value.staged_file_ref,
        runtime_file_ref=value.runtime_file_ref,
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
        raise _InvalidNativeLoaderRequirements
    return {**reference, "kind": value.kind, "requirement_ref": value.requirement_ref}


def _binding_projection(
    value: RepositoryExecutableNativeLoaderRequirementBinding,
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
            )
        )
    ):
        raise _InvalidNativeLoaderRequirements
    return {
        "command_digest": value.command_digest,
        "command_id": value.command_id,
        "command_kind": value.command_kind,
        "kind": value.kind,
        "requirement_ref": value.requirement_ref,
        "runtime_file_ref": value.runtime_file_ref,
        "staged_file_ref": value.staged_file_ref,
    }


_BUILTIN_REQUIREMENT_PROJECTION = _requirement_projection
_BUILTIN_BINDING_PROJECTION = _binding_projection


def _receipt_projection(
    value: RepositoryExecutableNativeLoaderRequirementsReceipt,
) -> dict[str, Any]:
    digest_fields = (
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
        value.loader_declared_count,
        value.unsupported_native_layout_count,
        value.non_native_not_applicable_count,
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
        or not 1 <= len(value.requirements) <= _MAX_FILES
        or type(value.bindings) is not tuple
        or not 1 <= len(value.bindings) <= _MAX_COMMANDS
        or type(value.requirement_count) is not int
        or value.requirement_count != len(value.requirements)
        or type(value.command_count) is not int
        or value.command_count != len(value.bindings)
        or any(type(item) is not int or item < 0 for item in count_fields)
        or type(value.total_loader_path_bytes) is not int
        or not 0
        <= value.total_loader_path_bytes
        <= _MAX_FILES * _MAX_LOADER_PATH_BYTES
    ):
        raise _InvalidNativeLoaderRequirements

    requirements = [
        _BUILTIN_REQUIREMENT_PROJECTION(item) for item in value.requirements
    ]
    bindings = [
        _BUILTIN_BINDING_PROJECTION(item) for item in value.bindings
    ]
    by_runtime_ref: dict[str, RepositoryExecutableNativeLoaderRequirement] = {}
    staged_refs: set[str] = set()
    requirement_refs: set[str] = set()
    for requirement in value.requirements:
        if (
            requirement.runtime_file_ref in by_runtime_ref
            or requirement.staged_file_ref in staged_refs
            or requirement.requirement_ref in requirement_refs
        ):
            raise _InvalidNativeLoaderRequirements
        by_runtime_ref[requirement.runtime_file_ref] = requirement
        staged_refs.add(requirement.staged_file_ref)
        requirement_refs.add(requirement.requirement_ref)

    command_ids: set[str] = set()
    bound_refs: set[str] = set()
    ordered_bound_refs: list[str] = []
    prior_kind_index = -1
    for binding in value.bindings:
        requirement = by_runtime_ref.get(binding.runtime_file_ref)
        kind_index = _COMMAND_KINDS.index(binding.command_kind)
        if (
            requirement is None
            or binding.staged_file_ref != requirement.staged_file_ref
            or binding.requirement_ref != requirement.requirement_ref
            or binding.command_id in command_ids
            or kind_index < prior_kind_index
        ):
            raise _InvalidNativeLoaderRequirements
        command_ids.add(binding.command_id)
        if binding.requirement_ref not in bound_refs:
            ordered_bound_refs.append(binding.requirement_ref)
        bound_refs.add(binding.requirement_ref)
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
        bound_refs != requirement_refs
        or tuple(ordered_bound_refs)
        != tuple(item.requirement_ref for item in value.requirements)
        or value.native_requirement_count != native_count
        or value.loader_declared_count != declared_count
        or value.unsupported_native_layout_count != unsupported_count
        or value.non_native_not_applicable_count != non_native_count
        or value.total_loader_path_bytes != total_path_bytes
    ):
        raise _InvalidNativeLoaderRequirements
    return {
        "bindings": bindings,
        "command_count": value.command_count,
        "kind": value.kind,
        "loader_declared_count": value.loader_declared_count,
        "native_requirement_count": value.native_requirement_count,
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
        "staging_context_digest": value.staging_context_digest,
        "staging_receipt_digest": value.staging_receipt_digest,
        "total_loader_path_bytes": value.total_loader_path_bytes,
        "unsupported_native_layout_count": (
            value.unsupported_native_layout_count
        ),
        "verification_commands_digest": (
            value.verification_commands_digest
        ),
    }


_BUILTIN_RECEIPT_PROJECTION = _receipt_projection


def _evidence_projection(
    value: RepositoryExecutableNativeLoaderRequirementsReceipt,
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
        "active_lease_verified_at_measurement": True,
        "authority_granted": False,
        "authorization_verified": False,
        "billing_eligible": False,
        "bounded_native_loader_declaration_inspection_complete": True,
        "capacity_eligible": False,
        "circuit_eligible": False,
        "command_count": value.command_count,
        "current_lease_activity_verified": False,
        "current_source_freshness_verified": False,
        "dispatch_enabled": False,
        "durable_control_plane_persistence_enabled": False,
        "dynamic_loader_declaration_syntax_verified": True,
        "dynamic_loader_identity_verified": False,
        "effect_class": 0,
        "elf_interpreter_absent_count": dispositions[
            "elf_interpreter_absent"
        ],
        "elf_interpreter_declared_count": dispositions[
            "elf_interpreter_declared"
        ],
        "environment_coverage_verified": False,
        "execution_enabled": False,
        "fat_mach_o_architecture_selection_performed": False,
        "future_execution_correspondence_verified": False,
        "kind": _FIXED_EVIDENCE_KIND,
        "lease_cleanup_performed": False,
        "lease_mutated": False,
        "live_execution_eligible": False,
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
        "native_requirement_count": value.native_requirement_count,
        "network_access_performed": False,
        "non_native_not_applicable_count": (
            value.non_native_not_applicable_count
        ),
        "path_lookup_performed": False,
        "proposal_lineage_extended": False,
        "receipt_authenticity_verified": False,
        "receipt_digest": _BUILTIN_CANONICAL_DIGEST(canonical),
        "registration_digest": value.registration_digest,
        "repository_ref": value.repository_ref,
        "requirement_count": value.requirement_count,
        "requirements_scope": value.requirements_scope,
        "requirements_source": value.requirements_source,
        "resolution_context_digest": value.resolution_context_digest,
        "route_eligible": False,
        "runtime_manifest_complete": False,
        "runtime_manifest_receipt_digest": (
            value.runtime_manifest_receipt_digest
        ),
        "schema_version": value.schema_version,
        "shared_library_closure_verified": False,
        "shared_library_identity_verified": False,
        "source_path_reopen_performed": False,
        "staged_byte_correspondence_verified": True,
        "staged_descriptor_full_remeasurement_complete": True,
        "staging_receipt_digest": value.staging_receipt_digest,
        "subprocess_invocation_performed": False,
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


class _UnsupportedNativeLayout(ValueError):
    """A bounded native layout that this schema deliberately does not model."""


def _integer(data: bytes, offset: int, size: int, byte_order: str) -> int:
    end = offset + size
    if offset < 0 or size <= 0 or end > len(data):
        raise _UnsupportedNativeLayout
    return int.from_bytes(data[offset:end], byte_order)


_BUILTIN_INTEGER = _integer


def _read_exact_range(
    descriptor: int,
    *,
    offset: int,
    size: int,
    content_bytes: int,
    maximum_bytes: int,
) -> bytes:
    if (
        type(offset) is not int
        or type(size) is not int
        or offset < 0
        or size < 0
        or size > maximum_bytes
        or offset > content_bytes
        or size > content_bytes - offset
    ):
        raise _UnsupportedNativeLayout
    chunks: list[bytes] = []
    consumed = 0
    while consumed < size:
        try:
            chunk = _BUILTIN_PREAD(
                descriptor,
                min(_FULL_REMEASUREMENT_CHUNK_BYTES, size - consumed),
                offset + consumed,
            )
        except (BlockingIOError, InterruptedError, OSError, ValueError):
            raise _InvalidNativeLoaderRequirements from None
        if not chunk or len(chunk) > size - consumed:
            raise _InvalidNativeLoaderRequirements
        chunks.append(chunk)
        consumed += len(chunk)
    result = b"".join(chunks)
    if len(result) != size:
        raise _InvalidNativeLoaderRequirements
    return result


_BUILTIN_READ_EXACT_RANGE = _read_exact_range


def _descriptor_signature(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


_BUILTIN_DESCRIPTOR_SIGNATURE = _descriptor_signature


def _independent_descriptor_remeasurement(
    retained: _RetainedStagedFile,
    anchored: Any,
) -> bytes:
    if (
        type(retained) is not _FIXED_RETAINED_TYPE
        or type(retained.descriptor) is not int
        or retained.descriptor < 0
        or type(retained.metadata) is not tuple
        or len(retained.metadata) != 9
        or any(type(item) is not int for item in retained.metadata)
        or _BUILTIN_STAGED_FILE_PROJECTION(retained.staged_file)
        != _BUILTIN_STAGED_FILE_PROJECTION(anchored)
    ):
        raise _InvalidNativeLoaderRequirements
    try:
        before = _BUILTIN_FSTAT(retained.descriptor)
        before_flags = _BUILTIN_FCNTL(retained.descriptor, _BUILTIN_F_GETFL)
        before_inheritable = _BUILTIN_GET_INHERITABLE(retained.descriptor)
    except (OSError, ValueError):
        raise _InvalidNativeLoaderRequirements from None
    before_signature = _BUILTIN_DESCRIPTOR_SIGNATURE(before)
    if (
        before_signature != retained.metadata
        or not _BUILTIN_S_ISREG(before.st_mode)
        or before.st_uid != _BUILTIN_GETEUID()
        or _BUILTIN_S_IMODE(before.st_mode) != _STAGED_FILE_MODE
        or before.st_nlink != 0
        or before.st_size != anchored.content_bytes
        or before_flags & _BUILTIN_O_ACCMODE != _BUILTIN_O_RDONLY
        or before_inheritable
    ):
        raise _InvalidNativeLoaderRequirements

    staged_identity_ref = _BUILTIN_CANONICAL_DIGEST(
        {
            "device": before.st_dev,
            "inode": before.st_ino,
            "kind": "repository_executable_staged_file_identity",
            "schema_version": 1,
        }
    )
    staged_metadata_digest = _BUILTIN_CANONICAL_DIGEST(
        {
            "change_time_ns": before.st_ctime_ns,
            "filesystem_identity_ref": staged_identity_ref,
            "group_id": before.st_gid,
            "kind": "repository_executable_staged_file_metadata",
            "link_count": before.st_nlink,
            "mode": before.st_mode,
            "modified_time_ns": before.st_mtime_ns,
            "owner_id": before.st_uid,
            "schema_version": 1,
            "size_bytes": before.st_size,
        }
    )
    if (
        staged_identity_ref != anchored.staged_filesystem_identity_ref
        or staged_metadata_digest != anchored.staged_metadata_digest
    ):
        raise _InvalidNativeLoaderRequirements

    digest = _BUILTIN_SHA256()
    header_parts: list[bytes] = []
    header_remaining = min(anchored.content_bytes, _MAX_HEADER_BYTES)
    offset = 0
    while offset < anchored.content_bytes:
        requested = min(
            _FULL_REMEASUREMENT_CHUNK_BYTES,
            anchored.content_bytes - offset,
        )
        try:
            chunk = _BUILTIN_PREAD(retained.descriptor, requested, offset)
        except (BlockingIOError, InterruptedError, OSError, ValueError):
            raise _InvalidNativeLoaderRequirements from None
        if not chunk or len(chunk) > requested:
            raise _InvalidNativeLoaderRequirements
        digest.update(chunk)
        if header_remaining:
            captured = chunk[:header_remaining]
            header_parts.append(captured)
            header_remaining -= len(captured)
        offset += len(chunk)
    try:
        boundary = _BUILTIN_PREAD(
            retained.descriptor,
            1,
            anchored.content_bytes,
        )
        after = _BUILTIN_FSTAT(retained.descriptor)
        after_flags = _BUILTIN_FCNTL(retained.descriptor, _BUILTIN_F_GETFL)
        after_inheritable = _BUILTIN_GET_INHERITABLE(retained.descriptor)
    except (OSError, ValueError):
        raise _InvalidNativeLoaderRequirements from None
    header = b"".join(header_parts)
    if (
        boundary != b""
        or _BUILTIN_DESCRIPTOR_SIGNATURE(after) != before_signature
        or after_flags != before_flags
        or after_inheritable != before_inheritable
        or header_remaining != 0
        or len(header) != min(anchored.content_bytes, _MAX_HEADER_BYTES)
        or _DIGEST_PREFIX + digest.hexdigest() != anchored.content_digest
    ):
        raise _InvalidNativeLoaderRequirements
    return header


_BUILTIN_DESCRIPTOR_REMEASUREMENT = _independent_descriptor_remeasurement


def _header_digest(staged_file_ref: str, header: bytes) -> str:
    return _DIGEST_PREFIX + _BUILTIN_SHA256(
        staged_file_ref.encode("ascii") + b"\x00" + header
    ).hexdigest()


_BUILTIN_HEADER_DIGEST = _header_digest


def _canonical_absolute_path(path: bytes) -> bool:
    if (
        not path.startswith(b"/")
        or any(item < 0x20 or item > 0x7E for item in path)
        or (len(path) > 1 and path.endswith(b"/"))
    ):
        return False
    components = path.split(b"/")[1:]
    return all(component not in {b"", b".", b".."} for component in components)


_BUILTIN_CANONICAL_ABSOLUTE_PATH = _canonical_absolute_path


def _loader_path_ref(
    *,
    runtime_file_ref: str,
    format_class: str,
    declaration_kind: str,
    path: bytes,
) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "declaration_kind": declaration_kind,
            "format_class": format_class,
            "kind": "repository_executable_native_loader_path_ref",
            "loader_path_hex": path.hex(),
            "runtime_file_ref": runtime_file_ref,
            "schema_version": _FIXED_SCHEMA_VERSION,
        }
    )


_BUILTIN_LOADER_PATH_REF = _loader_path_ref


def _terminated_loader_path(data: bytes) -> bytes:
    if (
        not 2 <= len(data) <= _MAX_LOADER_PATH_BYTES + 1
        or data[-1:] != b"\x00"
        or b"\x00" in data[:-1]
    ):
        raise _UnsupportedNativeLayout
    path = data[:-1]
    if not _BUILTIN_CANONICAL_ABSOLUTE_PATH(path):
        raise _UnsupportedNativeLayout
    return path


_BUILTIN_TERMINATED_LOADER_PATH = _terminated_loader_path


def _elf_requirement_fields(
    runtime_file: Any,
    *,
    descriptor: int,
    header: bytes,
) -> tuple[str, str, str, str, str | None, int, bool | None, bool]:
    if len(header) < 16 or not header.startswith(b"\x7fELF"):
        raise _InvalidNativeLoaderRequirements
    elf_class = header[4]
    data_encoding = header[5]
    if elf_class not in {1, 2} or data_encoding not in {1, 2} or header[6] != 1:
        raise _InvalidNativeLoaderRequirements
    format_class = "elf32" if elf_class == 1 else "elf64"
    byte_order = "little" if data_encoding == 1 else "big"
    try:
        header_size = 52 if elf_class == 1 else 64
        program_header_size = 32 if elf_class == 1 else 56
        if len(header) < header_size:
            raise _UnsupportedNativeLayout
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
            declared_header_size = _BUILTIN_INTEGER(
                header,
                40,
                2,
                byte_order,
            )
            entry_size = _BUILTIN_INTEGER(header, 42, 2, byte_order)
            entry_count = _BUILTIN_INTEGER(header, 44, 2, byte_order)
        else:
            table_offset = _BUILTIN_INTEGER(header, 32, 8, byte_order)
            declared_header_size = _BUILTIN_INTEGER(
                header,
                52,
                2,
                byte_order,
            )
            entry_size = _BUILTIN_INTEGER(header, 54, 2, byte_order)
            entry_count = _BUILTIN_INTEGER(header, 56, 2, byte_order)
        if (
            declared_header_size != header_size
            or entry_size != program_header_size
            or entry_count > _MAX_PROGRAM_HEADERS
        ):
            raise _UnsupportedNativeLayout
        table_size = entry_count * entry_size
        table = _BUILTIN_READ_EXACT_RANGE(
            descriptor,
            offset=table_offset,
            size=table_size,
            content_bytes=runtime_file.content_bytes,
            maximum_bytes=_MAX_TABLE_BYTES,
        )
        declarations: list[tuple[int, int]] = []
        for index in range(entry_count):
            entry = table[
                index * entry_size : (index + 1) * entry_size
            ]
            if _BUILTIN_INTEGER(entry, 0, 4, byte_order) != _PT_INTERP:
                continue
            if elf_class == 1:
                path_offset = _BUILTIN_INTEGER(entry, 4, 4, byte_order)
                path_size = _BUILTIN_INTEGER(entry, 16, 4, byte_order)
            else:
                path_offset = _BUILTIN_INTEGER(entry, 8, 8, byte_order)
                path_size = _BUILTIN_INTEGER(entry, 32, 8, byte_order)
            declarations.append((path_offset, path_size))
        if len(declarations) > 1:
            raise _UnsupportedNativeLayout
        if not declarations:
            return (
                format_class,
                byte_order,
                image_kind,
                "elf_interpreter_absent",
                None,
                0,
                None,
                True,
            )
        path_offset, path_size = declarations[0]
        raw_path = _BUILTIN_READ_EXACT_RANGE(
            descriptor,
            offset=path_offset,
            size=path_size,
            content_bytes=runtime_file.content_bytes,
            maximum_bytes=_MAX_LOADER_PATH_BYTES + 1,
        )
        path = _BUILTIN_TERMINATED_LOADER_PATH(raw_path)
        return (
            format_class,
            byte_order,
            image_kind,
            "elf_interpreter_declared",
            _BUILTIN_LOADER_PATH_REF(
                runtime_file_ref=runtime_file.runtime_file_ref,
                format_class=format_class,
                declaration_kind="elf_pt_interp",
                path=path,
            ),
            len(path),
            True,
            True,
        )
    except _UnsupportedNativeLayout:
        return (
            format_class,
            byte_order,
            None,
            "unsupported_native_layout",
            None,
            0,
            None,
            False,
        )


_BUILTIN_ELF_REQUIREMENT_FIELDS = _elf_requirement_fields


def _mach_o_requirement_fields(
    runtime_file: Any,
    *,
    descriptor: int,
    header: bytes,
) -> tuple[str, str, str | None, str, str | None, int, bool | None, bool]:
    magic = header[:4]
    if magic in _FAT_MACH_O:
        format_class, byte_order = _FAT_MACH_O[magic]
        return (
            format_class,
            byte_order,
            None,
            "unsupported_native_layout",
            None,
            0,
            None,
            False,
        )
    thin = _THIN_MACH_O.get(magic)
    if thin is None:
        raise _InvalidNativeLoaderRequirements
    format_class, byte_order, header_size = thin
    try:
        if len(header) < header_size:
            raise _UnsupportedNativeLayout
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
        if (
            command_count > _MAX_LOAD_COMMANDS
            or command_bytes > _MAX_TABLE_BYTES
        ):
            raise _UnsupportedNativeLayout
        table = _BUILTIN_READ_EXACT_RANGE(
            descriptor,
            offset=header_size,
            size=command_bytes,
            content_bytes=runtime_file.content_bytes,
            maximum_bytes=_MAX_TABLE_BYTES,
        )
        cursor = 0
        declared_paths: list[bytes] = []
        for _ in range(command_count):
            if cursor + 8 > len(table):
                raise _UnsupportedNativeLayout
            command = _BUILTIN_INTEGER(table, cursor, 4, byte_order)
            command_size = _BUILTIN_INTEGER(
                table,
                cursor + 4,
                4,
                byte_order,
            )
            if (
                command_size < 8
                or command_size % 4 != 0
                or command_size > len(table) - cursor
            ):
                raise _UnsupportedNativeLayout
            if command == _LC_LOAD_DYLINKER:
                if command_size < 12:
                    raise _UnsupportedNativeLayout
                name_offset = _BUILTIN_INTEGER(
                    table,
                    cursor + 8,
                    4,
                    byte_order,
                )
                if name_offset < 12 or name_offset >= command_size:
                    raise _UnsupportedNativeLayout
                command_data = table[cursor : cursor + command_size]
                raw_tail = command_data[name_offset:]
                terminator = raw_tail.find(b"\x00")
                if terminator < 0:
                    raise _UnsupportedNativeLayout
                path = _BUILTIN_TERMINATED_LOADER_PATH(
                    raw_tail[: terminator + 1]
                )
                if any(raw_tail[terminator + 1 :]):
                    raise _UnsupportedNativeLayout
                declared_paths.append(path)
            cursor += command_size
        if cursor != len(table) or len(declared_paths) > 1:
            raise _UnsupportedNativeLayout
        if not declared_paths:
            return (
                format_class,
                byte_order,
                image_kind,
                "mach_o_dylinker_absent",
                None,
                0,
                None,
                True,
            )
        path = declared_paths[0]
        return (
            format_class,
            byte_order,
            image_kind,
            "mach_o_dylinker_declared",
            _BUILTIN_LOADER_PATH_REF(
                runtime_file_ref=runtime_file.runtime_file_ref,
                format_class=format_class,
                declaration_kind="mach_o_lc_load_dylinker",
                path=path,
            ),
            len(path),
            True,
            True,
        )
    except _UnsupportedNativeLayout:
        return (
            format_class,
            byte_order,
            None,
            "unsupported_native_layout",
            None,
            0,
            None,
            False,
        )


_BUILTIN_MACH_O_REQUIREMENT_FIELDS = _mach_o_requirement_fields


def _build_requirement(
    runtime_file: Any,
    *,
    descriptor: int,
    header: bytes,
) -> RepositoryExecutableNativeLoaderRequirement:
    if (
        runtime_file.header_bytes != len(header)
        or runtime_file.header_digest
        != _BUILTIN_HEADER_DIGEST(runtime_file.staged_file_ref, header)
    ):
        raise _InvalidNativeLoaderRequirements
    classification = runtime_file.classification
    if classification == "elf":
        fields = _BUILTIN_ELF_REQUIREMENT_FIELDS(
            runtime_file,
            descriptor=descriptor,
            header=header,
        )
    elif classification == "mach_o":
        fields = _BUILTIN_MACH_O_REQUIREMENT_FIELDS(
            runtime_file,
            descriptor=descriptor,
            header=header,
        )
    elif classification in {
        "posix_shebang",
        "unsupported_shebang",
        "unknown",
    }:
        fields = (None, None, None, "non_native_not_applicable", None, 0, None, False)
    else:
        raise _InvalidNativeLoaderRequirements
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
        staged_file_ref=runtime_file.staged_file_ref,
        runtime_file_ref=runtime_file.runtime_file_ref,
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
    requirement = _FIXED_REQUIREMENT_TYPE(
        kind=_FIXED_REQUIREMENT_KIND,
        staged_file_ref=runtime_file.staged_file_ref,
        runtime_file_ref=runtime_file.runtime_file_ref,
        runtime_classification=classification,
        format_class=format_class,
        byte_order=byte_order,
        image_kind=image_kind,
        disposition=disposition,
        loader_path_ref=loader_path_ref,
        loader_path_bytes=loader_path_bytes,
        loader_path_absolute=loader_path_absolute,
        layout_supported=layout_supported,
        requirement_ref=_BUILTIN_CANONICAL_DIGEST(reference),
    )
    _BUILTIN_REQUIREMENT_PROJECTION(requirement)
    return requirement


_BUILTIN_BUILD_REQUIREMENT = _build_requirement


def _remeasure_requirements(
    expected_runtime: RepositoryExecutableRuntimeManifestReceipt,
    expected_staging: RepositoryExecutableStagingReceipt,
    retained_files: tuple[Any, ...],
) -> tuple[RepositoryExecutableNativeLoaderRequirement, ...]:
    requirements: list[RepositoryExecutableNativeLoaderRequirement] = []
    for retained, staged_file, runtime_file in zip(
        retained_files,
        expected_staging.staged_files,
        expected_runtime.files,
        strict=True,
    ):
        if (
            runtime_file.staged_file_ref != staged_file.staged_file_ref
            or runtime_file.staged_filesystem_identity_ref
            != staged_file.staged_filesystem_identity_ref
            or runtime_file.content_digest != staged_file.content_digest
            or runtime_file.content_bytes != staged_file.content_bytes
        ):
            raise _InvalidNativeLoaderRequirements
        before_header = _BUILTIN_DESCRIPTOR_REMEASUREMENT(
            retained,
            staged_file,
        )
        requirement = _BUILTIN_BUILD_REQUIREMENT(
            runtime_file,
            descriptor=retained.descriptor,
            header=before_header,
        )
        after_header = _BUILTIN_DESCRIPTOR_REMEASUREMENT(
            retained,
            staged_file,
        )
        if after_header != before_header:
            raise _InvalidNativeLoaderRequirements
        requirements.append(requirement)
    return tuple(requirements)


_BUILTIN_REMEASURE_REQUIREMENTS = _remeasure_requirements


_BUILTIN_STAGED_FILE_PROJECTION = _staged_file_projection
_BUILTIN_STAGING_RECEIPT_PROJECTION = _staging_receipt_projection
_BUILTIN_RUNTIME_MANIFEST_PROJECTION = _runtime_manifest_projection
_BUILTIN_ACTIVE_STAGE_SNAPSHOT = _active_stage_snapshot
_BUILTIN_INSPECT_RUNTIME_MANIFEST = inspect_staged_executable_runtime_manifest


def inspect_staged_executable_native_loader_requirements(
    expected_runtime: RepositoryExecutableRuntimeManifestReceipt,
    *,
    expected_staging: RepositoryExecutableStagingReceipt,
    lease: RepositoryExecutableStageLease,
) -> RepositoryExecutableNativeLoaderRequirementsReceipt:
    """Inspect direct native loader declarations from one active stage."""

    try:
        if (
            type(expected_runtime) is not _FIXED_RUNTIME_RECEIPT_TYPE
            or type(expected_staging) is not _FIXED_STAGING_RECEIPT_TYPE
            or type(lease) is not _FIXED_STAGE_LEASE_TYPE
        ):
            raise _InvalidNativeLoaderRequirements
        runtime_canonical = _BUILTIN_RUNTIME_MANIFEST_PROJECTION(
            expected_runtime
        )
        staging_canonical = _BUILTIN_STAGING_RECEIPT_PROJECTION(
            expected_staging
        )
        runtime_digest = _BUILTIN_CANONICAL_DIGEST(runtime_canonical)
        staging_digest = _BUILTIN_CANONICAL_DIGEST(staging_canonical)
        if (
            expected_runtime.staging_receipt_digest != staging_digest
            or expected_runtime.registration_digest
            != expected_staging.registration_digest
            or expected_runtime.repository_ref != expected_staging.repository_ref
            or expected_runtime.verification_commands_digest
            != expected_staging.verification_commands_digest
            or expected_runtime.resolution_context_digest
            != expected_staging.resolution_context_digest
            or expected_runtime.staging_context_digest
            != expected_staging.staging_context_digest
        ):
            raise _InvalidNativeLoaderRequirements

        fresh_runtime = _BUILTIN_INSPECT_RUNTIME_MANIFEST(
            expected_staging,
            lease=lease,
        )
        if (
            _BUILTIN_RUNTIME_MANIFEST_PROJECTION(fresh_runtime)
            != runtime_canonical
        ):
            raise _InvalidNativeLoaderRequirements
        active_canonical, retained_files = _BUILTIN_ACTIVE_STAGE_SNAPSHOT(
            expected_staging,
            lease,
        )
        if active_canonical != staging_canonical:
            raise _InvalidNativeLoaderRequirements
        requirements = _BUILTIN_REMEASURE_REQUIREMENTS(
            expected_runtime,
            expected_staging,
            retained_files,
        )

        final_runtime = _BUILTIN_INSPECT_RUNTIME_MANIFEST(
            expected_staging,
            lease=lease,
        )
        final_canonical, final_retained_files = (
            _BUILTIN_ACTIVE_STAGE_SNAPSHOT(expected_staging, lease)
        )
        if (
            _BUILTIN_RUNTIME_MANIFEST_PROJECTION(final_runtime)
            != runtime_canonical
            or final_canonical != staging_canonical
            or final_retained_files is not retained_files
            or _BUILTIN_REMEASURE_REQUIREMENTS(
                expected_runtime,
                expected_staging,
                retained_files,
            )
            != requirements
        ):
            raise _InvalidNativeLoaderRequirements
        closing_canonical, closing_retained_files = (
            _BUILTIN_ACTIVE_STAGE_SNAPSHOT(expected_staging, lease)
        )
        if (
            closing_canonical != staging_canonical
            or closing_retained_files is not retained_files
        ):
            raise _InvalidNativeLoaderRequirements

        by_runtime_ref = {
            item.runtime_file_ref: item for item in requirements
        }
        bindings: list[
            RepositoryExecutableNativeLoaderRequirementBinding
        ] = []
        for runtime_projection, staging_projection in zip(
            runtime_canonical["bindings"],
            staging_canonical["bindings"],
            strict=True,
        ):
            if (
                runtime_projection["command_kind"]
                != staging_projection["command_kind"]
                or runtime_projection["command_id"]
                != staging_projection["command_id"]
                or runtime_projection["command_digest"]
                != staging_projection["command_digest"]
                or runtime_projection["staged_file_ref"]
                != staging_projection["staged_file_ref"]
            ):
                raise _InvalidNativeLoaderRequirements
            requirement = by_runtime_ref.get(
                runtime_projection["runtime_file_ref"]
            )
            if (
                requirement is None
                or requirement.staged_file_ref
                != runtime_projection["staged_file_ref"]
            ):
                raise _InvalidNativeLoaderRequirements
            bindings.append(
                _FIXED_BINDING_TYPE(
                    kind=_FIXED_BINDING_KIND,
                    command_kind=runtime_projection["command_kind"],
                    command_id=runtime_projection["command_id"],
                    command_digest=runtime_projection["command_digest"],
                    staged_file_ref=runtime_projection["staged_file_ref"],
                    runtime_file_ref=runtime_projection["runtime_file_ref"],
                    requirement_ref=requirement.requirement_ref,
                )
            )

        receipt = _FIXED_RECEIPT_TYPE(
            kind=_FIXED_RECEIPT_KIND,
            schema_version=_FIXED_SCHEMA_VERSION,
            requirements_source=_FIXED_REQUIREMENTS_SOURCE,
            requirements_scope=_FIXED_REQUIREMENTS_SCOPE,
            runtime_manifest_receipt_digest=runtime_digest,
            staging_receipt_digest=staging_digest,
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
            loader_declared_count=sum(
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
            total_loader_path_bytes=sum(
                item.loader_path_bytes for item in requirements
            ),
        )
        _BUILTIN_RECEIPT_PROJECTION(receipt)
        return receipt
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise _FIXED_VALIDATION_ERROR(_INVALID_MESSAGE) from None


__all__ = [
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_REQUIREMENT_BINDING_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_REQUIREMENT_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_REQUIREMENTS_EVIDENCE_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_REQUIREMENTS_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_REQUIREMENTS_SCHEMA_VERSION",
    "REQUIREMENTS_SCOPE",
    "REQUIREMENTS_SOURCE",
    "RepositoryExecutableNativeLoaderRequirement",
    "RepositoryExecutableNativeLoaderRequirementBinding",
    "RepositoryExecutableNativeLoaderRequirementsReceipt",
    "inspect_staged_executable_native_loader_requirements",
]
