"""Read-only runtime-header evidence for one active nested-target stage.

This library-only Class 0 primitive validates one exact active depth-two
native-loader target staging receipt and lease, fully remeasures each retained
anonymous file, and classifies a bounded header.  It opens no path, mutates no
lease, follows no further loader declaration, and executes nothing.
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
from .repository_executable_native_loader_nested_target_staging import (
    STAGING_SCOPE as NESTED_TARGET_STAGING_SCOPE,
    RepositoryExecutableNativeLoaderNestedTargetStageLease,
    RepositoryExecutableNativeLoaderNestedTargetStagingReceipt,
    _BUILTIN_STAGING_RECEIPT_PROJECTION as _nested_target_staging_projection_v1,
    _RetainedStagedNestedTarget,
)


REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RUNTIME_MANIFEST_SCHEMA_VERSION = 1
REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RUNTIME_MANIFEST_KIND = (
    "repository_executable_native_loader_nested_target_runtime_manifest"
)
REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RUNTIME_MANIFEST_EVIDENCE_KIND = (
    "repository_executable_native_loader_nested_target_runtime_manifest_validation"
)
REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RUNTIME_FILE_KIND = (
    "repository_executable_native_loader_nested_target_runtime_file"
)
REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RUNTIME_REQUIREMENT_KIND = (
    "repository_executable_native_loader_nested_target_runtime_requirement"
)
REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RUNTIME_LINEAGE_KIND = (
    "repository_executable_native_loader_nested_target_runtime_lineage"
)
REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RUNTIME_BINDING_KIND = (
    "repository_executable_native_loader_nested_target_runtime_binding"
)
MANIFEST_SOURCE = "controller_inspected"
MANIFEST_SCOPE = "staged_native_loader_nested_target_runtime_header_v1"

_SCHEMA_VERSION = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RUNTIME_MANIFEST_SCHEMA_VERSION
)
_MANIFEST_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RUNTIME_MANIFEST_KIND
)
_EVIDENCE_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RUNTIME_MANIFEST_EVIDENCE_KIND
)
_FILE_KIND = REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RUNTIME_FILE_KIND
_REQUIREMENT_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RUNTIME_REQUIREMENT_KIND
)
_LINEAGE_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RUNTIME_LINEAGE_KIND
)
_BINDING_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RUNTIME_BINDING_KIND
)
_STAGED_FILE_KIND = (
    "repository_executable_native_loader_nested_target_staged_file"
)
_STAGE_REQUIREMENT_KIND = (
    "repository_executable_native_loader_nested_target_stage_requirement"
)
_STAGE_LINEAGE_KIND = (
    "repository_executable_native_loader_nested_target_stage_lineage"
)
_STAGE_BINDING_KIND = (
    "repository_executable_native_loader_nested_target_stage_binding"
)
_INVALID_MESSAGE = (
    "repository executable native loader nested target runtime manifest is invalid"
)
_DIGEST_PREFIX = "sha256:"
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER_PATTERN = re.compile(r"[a-z][a-z0-9_.-]{0,119}\Z")
_COMMAND_KINDS = ("format", "lint", "type_check", "test", "build")
_CLASSIFICATIONS = (
    "elf",
    "mach_o",
    "posix_shebang",
    "unsupported_shebang",
    "unknown",
)
_STAGE_DISPOSITIONS = (
    "known_chain_guard_staged",
    "loader_declaration_absent",
    "unsupported_native_layout",
    "non_native_not_applicable",
)
_RUNTIME_DISPOSITIONS = (
    "known_chain_guard_runtime_inspected",
    "loader_declaration_absent",
    "unsupported_native_layout",
    "non_native_not_applicable",
)
_STAGE_LINEAGE_DISPOSITIONS = (
    "stage_requirement_bound",
    "loader_declaration_absent",
    "unsupported_native_layout",
    "non_native_not_applicable",
)
_RUNTIME_LINEAGE_DISPOSITIONS = (
    "runtime_requirement_bound",
    "loader_declaration_absent",
    "unsupported_native_layout",
    "non_native_not_applicable",
)
_MAX_FILES = 80
_MAX_REQUIREMENTS = 80
_MAX_LINEAGES = 80
_MAX_COMMANDS = 80
_MAX_FILE_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_BYTES = 256 * 1024 * 1024
_MAX_HEADER_BYTES = 4_096
_MAX_SHEBANG_DIRECTIVE_BYTES = 255
_FULL_REMEASUREMENT_CHUNK_BYTES = 1024 * 1024
_STAGED_FILE_MODE = 0o400
_STAGING_ROOT_MODE = 0o700
_MACH_O_MINIMUM_BYTES = {
    b"\xfe\xed\xfa\xce": 28,
    b"\xce\xfa\xed\xfe": 28,
    b"\xfe\xed\xfa\xcf": 32,
    b"\xcf\xfa\xed\xfe": 32,
    b"\xca\xfe\xba\xbe": 28,
    b"\xbe\xba\xfe\xca": 28,
    b"\xca\xfe\xba\xbf": 40,
    b"\xbf\xba\xfe\xca": 40,
}

# Freeze shipped proof primitives before public attributes can be patched.
_BUILTIN_CANONICAL_JSON = canonical_json
_BUILTIN_SHA256 = hashlib.sha256
_BUILTIN_PREAD = os.pread
_BUILTIN_FSTAT = os.fstat
_BUILTIN_GETPID = os.getpid
_BUILTIN_GETEUID = os.geteuid
_BUILTIN_GET_INHERITABLE = os.get_inheritable
_BUILTIN_FCNTL = fcntl.fcntl
_BUILTIN_F_GETFL = fcntl.F_GETFL
_BUILTIN_O_ACCMODE = os.O_ACCMODE
_BUILTIN_O_RDONLY = os.O_RDONLY
_BUILTIN_S_ISDIR = stat.S_ISDIR
_BUILTIN_S_ISREG = stat.S_ISREG
_BUILTIN_S_IMODE = stat.S_IMODE
_BUILTIN_NESTED_TARGET_STAGING_PROJECTION = (
    _nested_target_staging_projection_v1
)
_FIXED_VALIDATION_ERROR = ValidationError
_FIXED_STAGING_RECEIPT_TYPE = (
    RepositoryExecutableNativeLoaderNestedTargetStagingReceipt
)
_FIXED_STAGE_LEASE_TYPE = RepositoryExecutableNativeLoaderNestedTargetStageLease
_FIXED_RETAINED_TYPE = _RetainedStagedNestedTarget


def _canonical_digest(value: Any) -> str:
    encoded = _BUILTIN_CANONICAL_JSON(value).encode("utf-8")
    return _DIGEST_PREFIX + _BUILTIN_SHA256(encoded).hexdigest()


_BUILTIN_CANONICAL_DIGEST = _canonical_digest


class _InvalidNestedTargetRuntimeManifest(ValueError):
    """Internal invalid-input sentinel with no public details."""


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeLoaderNestedTargetRuntimeFile:
    """One detached nested target and its bounded header classification."""

    kind: str
    nested_target_staged_file_ref: str = field(repr=False)
    staged_filesystem_identity_ref: str = field(repr=False)
    content_digest: str = field(repr=False)
    content_bytes: int
    nested_target_runtime_file_ref: str = field(repr=False)
    header_digest: str = field(repr=False)
    header_bytes: int
    classification: str
    shebang_directive_ref: str | None = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _runtime_file_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeLoaderNestedTargetRuntimeRequirement:
    """One nested-target stage requirement's runtime disposition."""

    kind: str
    target_staged_file_ref: str = field(repr=False)
    target_runtime_file_ref: str = field(repr=False)
    target_loader_requirement_ref: str = field(repr=False)
    nested_target_requirement_ref: str = field(repr=False)
    chain_guard_requirement_ref: str = field(repr=False)
    nested_target_stage_requirement_ref: str = field(repr=False)
    disposition: str
    nested_target_measurement_ref: str | None = field(repr=False)
    guarded_measurement_ref: str | None = field(repr=False)
    nested_target_staged_file_ref: str | None = field(repr=False)
    nested_target_runtime_file_ref: str | None = field(repr=False)
    nested_target_runtime_requirement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _runtime_requirement_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeLoaderNestedTargetRuntimeLineage:
    """One source lineage bound through nested-target runtime evidence."""

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
    nested_target_runtime_requirement_ref: str | None = field(repr=False)
    disposition: str
    nested_target_runtime_lineage_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _runtime_lineage_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeLoaderNestedTargetRuntimeBinding:
    """One command bound through one nested-target runtime lineage."""

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

    def to_canonical(self) -> dict[str, Any]:
        return _runtime_binding_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeLoaderNestedTargetRuntimeManifestReceipt:
    """Historical evidence from one active nested-target descriptor inspection."""

    kind: str
    schema_version: int
    manifest_source: str
    manifest_scope: str
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
    files: tuple[
        RepositoryExecutableNativeLoaderNestedTargetRuntimeFile, ...
    ] = field(repr=False)
    requirements: tuple[
        RepositoryExecutableNativeLoaderNestedTargetRuntimeRequirement, ...
    ] = field(repr=False)
    lineages: tuple[
        RepositoryExecutableNativeLoaderNestedTargetRuntimeLineage, ...
    ] = field(repr=False)
    bindings: tuple[
        RepositoryExecutableNativeLoaderNestedTargetRuntimeBinding, ...
    ] = field(repr=False)
    file_count: int
    requirement_count: int
    lineage_count: int
    command_count: int
    known_chain_guard_runtime_inspected_count: int
    loader_declaration_absent_count: int
    unsupported_native_layout_count: int
    non_native_not_applicable_count: int
    total_content_bytes: int
    total_header_bytes: int

    def to_canonical(self) -> dict[str, Any]:
        return _runtime_manifest_projection(self)

    @property
    def receipt_digest(self) -> str:
        return _BUILTIN_CANONICAL_DIGEST(_runtime_manifest_projection(self))

    def to_evidence(self) -> dict[str, Any]:
        return _runtime_manifest_evidence_projection(self)


_FIXED_RUNTIME_FILE_TYPE = RepositoryExecutableNativeLoaderNestedTargetRuntimeFile
_FIXED_RUNTIME_REQUIREMENT_TYPE = (
    RepositoryExecutableNativeLoaderNestedTargetRuntimeRequirement
)
_FIXED_RUNTIME_LINEAGE_TYPE = (
    RepositoryExecutableNativeLoaderNestedTargetRuntimeLineage
)
_FIXED_RUNTIME_BINDING_TYPE = (
    RepositoryExecutableNativeLoaderNestedTargetRuntimeBinding
)
_FIXED_RUNTIME_RECEIPT_TYPE = (
    RepositoryExecutableNativeLoaderNestedTargetRuntimeManifestReceipt
)


def _is_digest(value: Any) -> bool:
    return type(value) is str and _DIGEST_PATTERN.fullmatch(value) is not None


_BUILTIN_IS_DIGEST = _is_digest


def _runtime_file_ref_projection(
    *,
    nested_target_staged_file_ref: str,
    staged_filesystem_identity_ref: str,
    content_digest: str,
    content_bytes: int,
    header_digest: str,
    header_bytes: int,
    classification: str,
    shebang_directive_ref: str | None,
) -> dict[str, Any]:
    if (
        not all(
            _BUILTIN_IS_DIGEST(item)
            for item in (
                nested_target_staged_file_ref,
                staged_filesystem_identity_ref,
                content_digest,
                header_digest,
            )
        )
        or type(content_bytes) is not int
        or not 0 <= content_bytes <= _MAX_FILE_BYTES
        or type(header_bytes) is not int
        or header_bytes != min(content_bytes, _MAX_HEADER_BYTES)
        or type(classification) is not str
        or classification not in _CLASSIFICATIONS
        or (classification == "elf" and header_bytes < 16)
        or (classification == "mach_o" and header_bytes < 28)
        or (classification == "posix_shebang" and header_bytes < 4)
        or (classification == "unsupported_shebang" and header_bytes < 2)
        or (
            shebang_directive_ref is not None
            and not _BUILTIN_IS_DIGEST(shebang_directive_ref)
        )
        or (classification == "posix_shebang")
        != (shebang_directive_ref is not None)
    ):
        raise _InvalidNestedTargetRuntimeManifest
    return {
        "classification": classification,
        "content_bytes": content_bytes,
        "content_digest": content_digest,
        "header_bytes": header_bytes,
        "header_digest": header_digest,
        "kind": (
            "repository_executable_native_loader_nested_target_runtime_file_ref"
        ),
        "manifest_scope": MANIFEST_SCOPE,
        "nested_target_staged_file_ref": nested_target_staged_file_ref,
        "schema_version": _SCHEMA_VERSION,
        "shebang_directive_ref": shebang_directive_ref,
        "staged_filesystem_identity_ref": staged_filesystem_identity_ref,
    }


def _runtime_file_projection(
    value: RepositoryExecutableNativeLoaderNestedTargetRuntimeFile,
) -> dict[str, Any]:
    if type(value) is not _FIXED_RUNTIME_FILE_TYPE or value.kind != _FILE_KIND:
        raise _InvalidNestedTargetRuntimeManifest
    reference = _BUILTIN_RUNTIME_FILE_REF_PROJECTION(
        nested_target_staged_file_ref=value.nested_target_staged_file_ref,
        staged_filesystem_identity_ref=value.staged_filesystem_identity_ref,
        content_digest=value.content_digest,
        content_bytes=value.content_bytes,
        header_digest=value.header_digest,
        header_bytes=value.header_bytes,
        classification=value.classification,
        shebang_directive_ref=value.shebang_directive_ref,
    )
    if value.nested_target_runtime_file_ref != _BUILTIN_CANONICAL_DIGEST(
        reference
    ):
        raise _InvalidNestedTargetRuntimeManifest
    return {
        **reference,
        "kind": value.kind,
        "nested_target_runtime_file_ref": value.nested_target_runtime_file_ref,
    }


def _runtime_requirement_ref_projection(
    *,
    chain_guard_requirement_ref: str,
    nested_target_stage_requirement_ref: str,
    disposition: str,
    nested_target_measurement_ref: str | None,
    guarded_measurement_ref: str | None,
    nested_target_staged_file_ref: str | None,
    nested_target_runtime_file_ref: str | None,
) -> dict[str, Any]:
    optional = (
        nested_target_measurement_ref,
        guarded_measurement_ref,
        nested_target_staged_file_ref,
        nested_target_runtime_file_ref,
    )
    inspected = disposition == "known_chain_guard_runtime_inspected"
    if (
        not _BUILTIN_IS_DIGEST(chain_guard_requirement_ref)
        or not _BUILTIN_IS_DIGEST(nested_target_stage_requirement_ref)
        or disposition not in _RUNTIME_DISPOSITIONS
        or any(
            item is not None and not _BUILTIN_IS_DIGEST(item)
            for item in optional
        )
        or inspected != all(item is not None for item in optional)
        or (not inspected and any(item is not None for item in optional))
    ):
        raise _InvalidNestedTargetRuntimeManifest
    return {
        "chain_guard_requirement_ref": chain_guard_requirement_ref,
        "disposition": disposition,
        "guarded_measurement_ref": guarded_measurement_ref,
        "kind": (
            "repository_executable_native_loader_nested_target_"
            "runtime_requirement_ref"
        ),
        "manifest_scope": MANIFEST_SCOPE,
        "nested_target_measurement_ref": nested_target_measurement_ref,
        "nested_target_runtime_file_ref": nested_target_runtime_file_ref,
        "nested_target_stage_requirement_ref": (
            nested_target_stage_requirement_ref
        ),
        "nested_target_staged_file_ref": nested_target_staged_file_ref,
        "schema_version": _SCHEMA_VERSION,
    }


def _runtime_requirement_projection(
    value: RepositoryExecutableNativeLoaderNestedTargetRuntimeRequirement,
) -> dict[str, Any]:
    required = (
        value.target_staged_file_ref,
        value.target_runtime_file_ref,
        value.target_loader_requirement_ref,
        value.nested_target_requirement_ref,
        value.chain_guard_requirement_ref,
        value.nested_target_stage_requirement_ref,
        value.nested_target_runtime_requirement_ref,
    )
    if (
        type(value) is not _FIXED_RUNTIME_REQUIREMENT_TYPE
        or value.kind != _REQUIREMENT_KIND
        or not all(_BUILTIN_IS_DIGEST(item) for item in required)
    ):
        raise _InvalidNestedTargetRuntimeManifest
    reference = _BUILTIN_RUNTIME_REQUIREMENT_REF_PROJECTION(
        chain_guard_requirement_ref=value.chain_guard_requirement_ref,
        nested_target_stage_requirement_ref=(
            value.nested_target_stage_requirement_ref
        ),
        disposition=value.disposition,
        nested_target_measurement_ref=value.nested_target_measurement_ref,
        guarded_measurement_ref=value.guarded_measurement_ref,
        nested_target_staged_file_ref=value.nested_target_staged_file_ref,
        nested_target_runtime_file_ref=value.nested_target_runtime_file_ref,
    )
    if value.nested_target_runtime_requirement_ref != _BUILTIN_CANONICAL_DIGEST(
        reference
    ):
        raise _InvalidNestedTargetRuntimeManifest
    return {
        **reference,
        "kind": value.kind,
        "nested_target_requirement_ref": value.nested_target_requirement_ref,
        "nested_target_runtime_requirement_ref": (
            value.nested_target_runtime_requirement_ref
        ),
        "target_loader_requirement_ref": value.target_loader_requirement_ref,
        "target_runtime_file_ref": value.target_runtime_file_ref,
        "target_staged_file_ref": value.target_staged_file_ref,
    }


def _runtime_lineage_ref_projection(
    *,
    nested_target_stage_lineage_ref: str,
    nested_target_runtime_requirement_ref: str | None,
    disposition: str,
) -> dict[str, Any]:
    bound = disposition == "runtime_requirement_bound"
    if (
        not _BUILTIN_IS_DIGEST(nested_target_stage_lineage_ref)
        or disposition not in _RUNTIME_LINEAGE_DISPOSITIONS
        or (
            nested_target_runtime_requirement_ref is not None
            and not _BUILTIN_IS_DIGEST(
                nested_target_runtime_requirement_ref
            )
        )
        or bound != (nested_target_runtime_requirement_ref is not None)
    ):
        raise _InvalidNestedTargetRuntimeManifest
    return {
        "disposition": disposition,
        "kind": (
            "repository_executable_native_loader_nested_target_"
            "runtime_lineage_ref"
        ),
        "manifest_scope": MANIFEST_SCOPE,
        "nested_target_runtime_requirement_ref": (
            nested_target_runtime_requirement_ref
        ),
        "nested_target_stage_lineage_ref": nested_target_stage_lineage_ref,
        "schema_version": _SCHEMA_VERSION,
    }


def _runtime_lineage_projection(
    value: RepositoryExecutableNativeLoaderNestedTargetRuntimeLineage,
) -> dict[str, Any]:
    required = (
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
    if (
        type(value) is not _FIXED_RUNTIME_LINEAGE_TYPE
        or value.kind != _LINEAGE_KIND
        or not all(_BUILTIN_IS_DIGEST(item) for item in required)
    ):
        raise _InvalidNestedTargetRuntimeManifest
    reference = _BUILTIN_RUNTIME_LINEAGE_REF_PROJECTION(
        nested_target_stage_lineage_ref=value.nested_target_stage_lineage_ref,
        nested_target_runtime_requirement_ref=(
            value.nested_target_runtime_requirement_ref
        ),
        disposition=value.disposition,
    )
    if value.nested_target_runtime_lineage_ref != _BUILTIN_CANONICAL_DIGEST(
        reference
    ):
        raise _InvalidNestedTargetRuntimeManifest
    return {
        **reference,
        "chain_guard_lineage_ref": value.chain_guard_lineage_ref,
        "kind": value.kind,
        "nested_target_lineage_ref": value.nested_target_lineage_ref,
        "nested_target_runtime_lineage_ref": (
            value.nested_target_runtime_lineage_ref
        ),
        "requirement_ref": value.requirement_ref,
        "runtime_file_ref": value.runtime_file_ref,
        "staged_file_ref": value.staged_file_ref,
        "target_loader_lineage_ref": value.target_loader_lineage_ref,
        "target_requirement_ref": value.target_requirement_ref,
        "target_runtime_requirement_ref": value.target_runtime_requirement_ref,
        "target_stage_requirement_ref": value.target_stage_requirement_ref,
    }


def _runtime_binding_projection(
    value: RepositoryExecutableNativeLoaderNestedTargetRuntimeBinding,
) -> dict[str, Any]:
    required = (
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
    )
    if (
        type(value) is not _FIXED_RUNTIME_BINDING_TYPE
        or value.kind != _BINDING_KIND
        or value.command_kind not in _COMMAND_KINDS
        or type(value.command_id) is not str
        or _IDENTIFIER_PATTERN.fullmatch(value.command_id) is None
        or not all(_BUILTIN_IS_DIGEST(item) for item in required)
    ):
        raise _InvalidNestedTargetRuntimeManifest
    return {
        "chain_guard_lineage_ref": value.chain_guard_lineage_ref,
        "command_digest": value.command_digest,
        "command_id": value.command_id,
        "command_kind": value.command_kind,
        "kind": value.kind,
        "nested_target_lineage_ref": value.nested_target_lineage_ref,
        "nested_target_runtime_lineage_ref": (
            value.nested_target_runtime_lineage_ref
        ),
        "nested_target_stage_lineage_ref": (
            value.nested_target_stage_lineage_ref
        ),
        "requirement_ref": value.requirement_ref,
        "runtime_file_ref": value.runtime_file_ref,
        "staged_file_ref": value.staged_file_ref,
        "target_loader_lineage_ref": value.target_loader_lineage_ref,
        "target_requirement_ref": value.target_requirement_ref,
        "target_runtime_requirement_ref": value.target_runtime_requirement_ref,
        "target_stage_requirement_ref": value.target_stage_requirement_ref,
    }


def _runtime_manifest_projection(
    value: RepositoryExecutableNativeLoaderNestedTargetRuntimeManifestReceipt,
) -> dict[str, Any]:
    digest_fields = (
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
    counts = (
        value.file_count,
        value.requirement_count,
        value.lineage_count,
        value.command_count,
        value.known_chain_guard_runtime_inspected_count,
        value.loader_declaration_absent_count,
        value.unsupported_native_layout_count,
        value.non_native_not_applicable_count,
        value.total_content_bytes,
        value.total_header_bytes,
    )
    if (
        type(value) is not _FIXED_RUNTIME_RECEIPT_TYPE
        or value.kind != _MANIFEST_KIND
        or value.schema_version != _SCHEMA_VERSION
        or value.manifest_source != MANIFEST_SOURCE
        or value.manifest_scope != MANIFEST_SCOPE
        or not all(_BUILTIN_IS_DIGEST(item) for item in digest_fields)
        or value.expected_chain_guard_receipt_digest
        != value.action_chain_guard_receipt_digest
        or value.expected_chain_guard_receipt_digest
        != value.post_stage_chain_guard_receipt_digest
        or type(value.files) is not tuple
        or len(value.files) > _MAX_FILES
        or type(value.requirements) is not tuple
        or len(value.requirements) > _MAX_REQUIREMENTS
        or type(value.lineages) is not tuple
        or len(value.lineages) > _MAX_LINEAGES
        or type(value.bindings) is not tuple
        or len(value.bindings) > _MAX_COMMANDS
        or any(type(item) is not int or item < 0 for item in counts)
        or value.file_count != len(value.files)
        or value.requirement_count != len(value.requirements)
        or value.lineage_count != len(value.lineages)
        or value.command_count != len(value.bindings)
        or value.total_content_bytes > _MAX_TOTAL_BYTES
        or value.total_header_bytes > value.total_content_bytes
    ):
        raise _InvalidNestedTargetRuntimeManifest

    files = [_BUILTIN_RUNTIME_FILE_PROJECTION(item) for item in value.files]
    requirements = [
        _BUILTIN_RUNTIME_REQUIREMENT_PROJECTION(item)
        for item in value.requirements
    ]
    lineages = [
        _BUILTIN_RUNTIME_LINEAGE_PROJECTION(item) for item in value.lineages
    ]
    bindings = [
        _BUILTIN_RUNTIME_BINDING_PROJECTION(item) for item in value.bindings
    ]

    file_by_stage: dict[
        str, RepositoryExecutableNativeLoaderNestedTargetRuntimeFile
    ] = {}
    runtime_file_refs: set[str] = set()
    identities: set[str] = set()
    total_content = 0
    total_header = 0
    for item in value.files:
        if (
            item.nested_target_staged_file_ref in file_by_stage
            or item.nested_target_runtime_file_ref in runtime_file_refs
            or item.staged_filesystem_identity_ref in identities
        ):
            raise _InvalidNestedTargetRuntimeManifest
        file_by_stage[item.nested_target_staged_file_ref] = item
        runtime_file_refs.add(item.nested_target_runtime_file_ref)
        identities.add(item.staged_filesystem_identity_ref)
        total_content += item.content_bytes
        total_header += item.header_bytes

    requirement_by_stage: dict[
        str, RepositoryExecutableNativeLoaderNestedTargetRuntimeRequirement
    ] = {}
    runtime_requirement_refs: set[str] = set()
    used_files: list[str] = []
    seen_files: set[str] = set()
    disposition_counts = {item: 0 for item in _RUNTIME_DISPOSITIONS}
    for item in value.requirements:
        if (
            item.nested_target_stage_requirement_ref in requirement_by_stage
            or item.nested_target_runtime_requirement_ref
            in runtime_requirement_refs
        ):
            raise _InvalidNestedTargetRuntimeManifest
        if item.disposition == "known_chain_guard_runtime_inspected":
            if item.nested_target_staged_file_ref is None:
                raise _InvalidNestedTargetRuntimeManifest
            runtime_file = file_by_stage.get(item.nested_target_staged_file_ref)
            if (
                runtime_file is None
                or item.nested_target_runtime_file_ref
                != runtime_file.nested_target_runtime_file_ref
            ):
                raise _InvalidNestedTargetRuntimeManifest
            if item.nested_target_staged_file_ref not in seen_files:
                used_files.append(item.nested_target_staged_file_ref)
                seen_files.add(item.nested_target_staged_file_ref)
        requirement_by_stage[item.nested_target_stage_requirement_ref] = item
        runtime_requirement_refs.add(item.nested_target_runtime_requirement_ref)
        disposition_counts[item.disposition] += 1
    if tuple(used_files) != tuple(file_by_stage):
        raise _InvalidNestedTargetRuntimeManifest

    lineage_by_stage: dict[
        str, RepositoryExecutableNativeLoaderNestedTargetRuntimeLineage
    ] = {}
    runtime_lineage_refs: set[str] = set()
    bound_requirements: set[str] = set()
    for item in value.lineages:
        if (
            item.nested_target_stage_lineage_ref in lineage_by_stage
            or item.nested_target_runtime_lineage_ref in runtime_lineage_refs
        ):
            raise _InvalidNestedTargetRuntimeManifest
        if item.disposition == "runtime_requirement_bound":
            if item.nested_target_runtime_requirement_ref is None:
                raise _InvalidNestedTargetRuntimeManifest
            requirement = next(
                (
                    candidate
                    for candidate in value.requirements
                    if candidate.nested_target_runtime_requirement_ref
                    == item.nested_target_runtime_requirement_ref
                ),
                None,
            )
            if requirement is None:
                raise _InvalidNestedTargetRuntimeManifest
            bound_requirements.add(requirement.nested_target_stage_requirement_ref)
        lineage_by_stage[item.nested_target_stage_lineage_ref] = item
        runtime_lineage_refs.add(item.nested_target_runtime_lineage_ref)
    if bound_requirements != set(requirement_by_stage):
        raise _InvalidNestedTargetRuntimeManifest

    command_ids: set[str] = set()
    bound_lineages: set[str] = set()
    prior_kind_index = -1
    for item in value.bindings:
        lineage = lineage_by_stage.get(item.nested_target_stage_lineage_ref)
        kind_index = _COMMAND_KINDS.index(item.command_kind)
        if (
            lineage is None
            or item.command_id in command_ids
            or item.nested_target_stage_lineage_ref in bound_lineages
            or kind_index < prior_kind_index
            or item.nested_target_runtime_lineage_ref
            != lineage.nested_target_runtime_lineage_ref
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
        ):
            raise _InvalidNestedTargetRuntimeManifest
        command_ids.add(item.command_id)
        bound_lineages.add(item.nested_target_stage_lineage_ref)
        prior_kind_index = kind_index
    if (
        bound_lineages != set(lineage_by_stage)
        or total_content != value.total_content_bytes
        or total_header != value.total_header_bytes
        or disposition_counts["known_chain_guard_runtime_inspected"]
        != value.known_chain_guard_runtime_inspected_count
        or disposition_counts["loader_declaration_absent"]
        != value.loader_declaration_absent_count
        or disposition_counts["unsupported_native_layout"]
        != value.unsupported_native_layout_count
        or disposition_counts["non_native_not_applicable"]
        != value.non_native_not_applicable_count
    ):
        raise _InvalidNestedTargetRuntimeManifest

    return {
        "bindings": bindings,
        "action_chain_guard_receipt_digest": (
            value.action_chain_guard_receipt_digest
        ),
        "command_count": value.command_count,
        "file_count": value.file_count,
        "files": files,
        "first_loader_path_context_digest": (
            value.first_loader_path_context_digest
        ),
        "guard_summary_ref": value.guard_summary_ref,
        "expected_chain_guard_receipt_digest": (
            value.expected_chain_guard_receipt_digest
        ),
        "kind": value.kind,
        "known_chain_guard_runtime_inspected_count": (
            value.known_chain_guard_runtime_inspected_count
        ),
        "lineage_count": value.lineage_count,
        "lineages": lineages,
        "loader_declaration_absent_count": (
            value.loader_declaration_absent_count
        ),
        "manifest_scope": value.manifest_scope,
        "manifest_source": value.manifest_source,
        "nested_loader_path_context_digest": (
            value.nested_loader_path_context_digest
        ),
        "nested_target_resolution_receipt_digest": (
            value.nested_target_resolution_receipt_digest
        ),
        "nested_target_staging_context_digest": (
            value.nested_target_staging_context_digest
        ),
        "nested_target_staging_receipt_digest": (
            value.nested_target_staging_receipt_digest
        ),
        "known_source_identity_set_digest": (
            value.known_source_identity_set_digest
        ),
        "known_target_identity_set_digest": (
            value.known_target_identity_set_digest
        ),
        "non_native_not_applicable_count": (
            value.non_native_not_applicable_count
        ),
        "registration_digest": value.registration_digest,
        "repository_ref": value.repository_ref,
        "requirement_count": value.requirement_count,
        "requirements": requirements,
        "resolution_context_digest": value.resolution_context_digest,
        "schema_version": value.schema_version,
        "native_loader_requirements_receipt_digest": (
            value.native_loader_requirements_receipt_digest
        ),
        "post_stage_chain_guard_receipt_digest": (
            value.post_stage_chain_guard_receipt_digest
        ),
        "protected_staging_root_identity_set_digest": (
            value.protected_staging_root_identity_set_digest
        ),
        "runtime_manifest_receipt_digest": (
            value.runtime_manifest_receipt_digest
        ),
        "source_staging_context_digest": (
            value.source_staging_context_digest
        ),
        "source_staging_receipt_digest": value.source_staging_receipt_digest,
        "target_loader_requirements_receipt_digest": (
            value.target_loader_requirements_receipt_digest
        ),
        "target_runtime_manifest_receipt_digest": (
            value.target_runtime_manifest_receipt_digest
        ),
        "target_resolution_receipt_digest": (
            value.target_resolution_receipt_digest
        ),
        "target_staging_context_digest": value.target_staging_context_digest,
        "target_staging_receipt_digest": value.target_staging_receipt_digest,
        "total_content_bytes": value.total_content_bytes,
        "total_header_bytes": value.total_header_bytes,
        "unsupported_native_layout_count": (
            value.unsupported_native_layout_count
        ),
        "verification_commands_digest": value.verification_commands_digest,
    }


def _runtime_manifest_evidence_projection(
    value: RepositoryExecutableNativeLoaderNestedTargetRuntimeManifestReceipt,
) -> dict[str, Any]:
    canonical = _BUILTIN_RUNTIME_MANIFEST_PROJECTION(value)
    classification_counts = {item: 0 for item in _CLASSIFICATIONS}
    for item in value.files:
        classification_counts[item.classification] += 1
    return {
        "action_receipt_issued": False,
        "active_nested_target_stage_lease_verified_at_measurement": True,
        "authority_granted": False,
        "authorization_verified": False,
        "billing_eligible": False,
        "bounded_runtime_header_inspection_complete": True,
        "bounded_shebang_syntax_classification_complete": True,
        "broader_protected_root_exclusion_verified": False,
        "capacity_eligible": False,
        "circuit_eligible": False,
        "command_count": canonical["command_count"],
        "current_freshness_verified": False,
        "dependency_environment_coverage_verified": False,
        "dispatch_enabled": False,
        "durable_control_plane_persistence_enabled": False,
        "dynamic_loader_identity_verified": False,
        "effect_class": 0,
        "effective_interpreter_resolution_verified": False,
        "effective_invocability_verified": False,
        "elf_file_count": classification_counts["elf"],
        "execution_enabled": False,
        "exact_nested_target_staging_correspondence_verified": True,
        "external_writable_descriptor_absence_verified": False,
        "file_count": canonical["file_count"],
        "filesystem_immutability_verified": False,
        "future_execution_correspondence_verified": False,
        "generic_cycle_closure_verified": False,
        "harness_invocation_performed": False,
        "kind": _EVIDENCE_KIND,
        "known_chain_guard_runtime_inspected_count": canonical[
            "known_chain_guard_runtime_inspected_count"
        ],
        "lineage_count": canonical["lineage_count"],
        "loader_invocation_performed": False,
        "mach_o_file_count": classification_counts["mach_o"],
        "manifest_scope": canonical["manifest_scope"],
        "manifest_source": canonical["manifest_source"],
        "model_invocation_performed": False,
        "nested_target_paths_exposed": False,
        "network_access_performed": False,
        "path_open_performed": False,
        "permission_widening_performed": False,
        "posix_shebang_file_count": classification_counts["posix_shebang"],
        "read_only_descriptor_inspection": True,
        "raw_headers_exposed": False,
        "receipt_authenticity_verified": False,
        "receipt_digest": _BUILTIN_CANONICAL_DIGEST(canonical),
        "recursive_resolution_performed": False,
        "registration_digest": canonical["registration_digest"],
        "repository_ref": canonical["repository_ref"],
        "requirement_count": canonical["requirement_count"],
        "requirement_lineage_binding_correspondence_verified": True,
        "resolution_context_digest": canonical["resolution_context_digest"],
        "route_eligible": False,
        "schema_version": canonical["schema_version"],
        "staged_descriptor_full_remeasurement_complete": True,
        "staging_cleanup_performed": False,
        "staging_lease_mutated": False,
        "nested_target_staging_receipt_digest": canonical[
            "nested_target_staging_receipt_digest"
        ],
        "subprocess_invocation_performed": False,
        "total_content_bytes": canonical["total_content_bytes"],
        "total_header_bytes": canonical["total_header_bytes"],
        "unknown_file_count": classification_counts["unknown"],
        "unsupported_shebang_file_count": classification_counts[
            "unsupported_shebang"
        ],
        "validation_mode": "read_only",
    }


# Freeze the complete output proof graph.
_BUILTIN_RUNTIME_FILE_REF_PROJECTION = _runtime_file_ref_projection
_BUILTIN_RUNTIME_FILE_PROJECTION = _runtime_file_projection
_BUILTIN_RUNTIME_REQUIREMENT_REF_PROJECTION = (
    _runtime_requirement_ref_projection
)
_BUILTIN_RUNTIME_REQUIREMENT_PROJECTION = _runtime_requirement_projection
_BUILTIN_RUNTIME_LINEAGE_REF_PROJECTION = _runtime_lineage_ref_projection
_BUILTIN_RUNTIME_LINEAGE_PROJECTION = _runtime_lineage_projection
_BUILTIN_RUNTIME_BINDING_PROJECTION = _runtime_binding_projection
_BUILTIN_RUNTIME_MANIFEST_PROJECTION = _runtime_manifest_projection


def _read_exact_header(descriptor: int, content_bytes: int) -> bytes:
    expected = min(content_bytes, _MAX_HEADER_BYTES)
    chunks: list[bytes] = []
    offset = 0
    while offset < expected:
        try:
            chunk = _BUILTIN_PREAD(descriptor, expected - offset, offset)
        except (BlockingIOError, InterruptedError, OSError):
            raise _InvalidNestedTargetRuntimeManifest from None
        if not chunk or len(chunk) > expected - offset:
            raise _InvalidNestedTargetRuntimeManifest
        chunks.append(chunk)
        offset += len(chunk)
    header = b"".join(chunks)
    try:
        boundary = _BUILTIN_PREAD(descriptor, 1, expected)
    except (BlockingIOError, InterruptedError, OSError):
        raise _InvalidNestedTargetRuntimeManifest from None
    if (
        len(header) != expected
        or (content_bytes > expected and len(boundary) != 1)
        or (content_bytes <= expected and boundary != b"")
    ):
        raise _InvalidNestedTargetRuntimeManifest
    return header


def _header_digest(nested_target_staged_file_ref: str, header: bytes) -> str:
    return _DIGEST_PREFIX + _BUILTIN_SHA256(
        nested_target_staged_file_ref.encode("ascii") + b"\x00" + header
    ).hexdigest()


def _bounded_shebang_directive(header: bytes) -> bytes | None:
    if not header.startswith(b"#!"):
        return None
    newline = header.find(b"\n", 2)
    if newline < 0:
        return None
    directive = header[2:newline]
    if (
        not 1 <= len(directive) <= _MAX_SHEBANG_DIRECTIVE_BYTES
        or directive[:1] in {b" ", b"\t"}
        or directive[-1:] in {b" ", b"\t"}
        or not any(value not in {0x20, 0x09} for value in directive)
        or any(
            value != 0x09 and not 0x20 <= value <= 0x7E
            for value in directive
        )
    ):
        return None
    return directive


def _classify_header(
    nested_target_staged_file_ref: str,
    header: bytes,
) -> tuple[str, str | None]:
    if header.startswith(b"#!"):
        directive = _BUILTIN_BOUNDED_SHEBANG_DIRECTIVE(header)
        if directive is None:
            return "unsupported_shebang", None
        return "posix_shebang", _BUILTIN_CANONICAL_DIGEST(
            {
                "directive_hex": directive.hex(),
                "kind": (
                    "repository_executable_native_loader_nested_target_"
                    "runtime_shebang_directive_ref"
                ),
                "nested_target_staged_file_ref": (
                    nested_target_staged_file_ref
                ),
                "schema_version": _SCHEMA_VERSION,
            }
        )
    if header.startswith(b"\x7fELF"):
        if (
            len(header) >= 16
            and header[4] in {1, 2}
            and header[5] in {1, 2}
            and header[6] == 1
        ):
            return "elf", None
        return "unknown", None
    magic = header[:4]
    if magic in _MACH_O_MINIMUM_BYTES and len(header) >= _MACH_O_MINIMUM_BYTES[
        magic
    ]:
        return "mach_o", None
    return "unknown", None


def _noop_staging_context_digest() -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "kind": (
                "repository_executable_native_loader_nested_target_"
                "staging_context"
            ),
            "schema_version": 1,
            "staging_root_used": False,
            "staging_scope": NESTED_TARGET_STAGING_SCOPE,
        }
    )


def _root_context_matches(
    expected: RepositoryExecutableNativeLoaderNestedTargetStagingReceipt,
    lease: RepositoryExecutableNativeLoaderNestedTargetStageLease,
) -> bool:
    metadata = lease._root_metadata
    if not expected.staging_root_used:
        return (
            metadata is None
            and expected.nested_target_staging_context_digest
            == _BUILTIN_NOOP_STAGING_CONTEXT_DIGEST()
        )
    if (
        type(metadata) is not tuple
        or len(metadata) != 9
        or any(type(item) is not int for item in metadata)
        or not _BUILTIN_S_ISDIR(metadata[2])
        or _BUILTIN_S_IMODE(metadata[2]) != _STAGING_ROOT_MODE
        or metadata[3] <= 0
        or metadata[4] != _BUILTIN_GETEUID()
    ):
        return False
    context_digest = _BUILTIN_CANONICAL_DIGEST(
        {
            "directory_device": metadata[0],
            "directory_inode": metadata[1],
            "directory_mode": _BUILTIN_S_IMODE(metadata[2]),
            "directory_owner": metadata[4],
            "kind": (
                "repository_executable_native_loader_nested_target_"
                "staging_context"
            ),
            "schema_version": 1,
            "staging_root_used": True,
            "staging_scope": NESTED_TARGET_STAGING_SCOPE,
        }
    )
    return context_digest == expected.nested_target_staging_context_digest


_BUILTIN_BOUNDED_SHEBANG_DIRECTIVE = _bounded_shebang_directive
_BUILTIN_CLASSIFY_HEADER = _classify_header
_BUILTIN_HEADER_DIGEST = _header_digest
_BUILTIN_NOOP_STAGING_CONTEXT_DIGEST = _noop_staging_context_digest
_BUILTIN_ROOT_CONTEXT_MATCHES = _root_context_matches


def _active_nested_target_stage_snapshot(
    expected_staging: Any,
    lease: Any,
) -> tuple[dict[str, Any], tuple[_RetainedStagedNestedTarget, ...]]:
    if (
        type(expected_staging) is not _FIXED_STAGING_RECEIPT_TYPE
        or type(lease) is not _FIXED_STAGE_LEASE_TYPE
        or type(lease._owner_pid) is not int
        or lease._owner_pid <= 0
        or lease._owner_pid != _BUILTIN_GETPID()
        or lease._state != "active"
        or lease._receipt is not expected_staging
        or lease._receipt is not lease._receipt_object_anchor
        or lease._cleanup_receipt is not None
        or lease._cleanup_receipt_digest_anchor is not None
        or lease._cleanup_receipt_object_anchor is not None
        or type(lease._receipt_digest_anchor) is not str
        or type(lease._receipt_file_refs_anchor) is not tuple
        or lease._root_descriptor is not None
        or lease._pending_name is not None
        or lease._pending_identity is not None
        or lease._pending_descriptors != ()
        or lease._descriptor_release_unverifiable is not False
        or type(lease._files) is not tuple
        or lease._files is not lease._files_object_anchor
    ):
        raise _InvalidNestedTargetRuntimeManifest
    canonical = _BUILTIN_NESTED_TARGET_STAGING_PROJECTION(expected_staging)
    expected_refs = tuple(
        item.nested_target_staged_file_ref
        for item in expected_staging.staged_files
    )
    if (
        lease._receipt_digest_anchor != _BUILTIN_CANONICAL_DIGEST(canonical)
        or lease._receipt_file_refs_anchor != expected_refs
        or len(lease._files) != expected_staging.unique_nested_target_count
        or not _BUILTIN_ROOT_CONTEXT_MATCHES(expected_staging, lease)
        or any(
            type(item) is not _FIXED_RETAINED_TYPE
            or type(item.descriptor) is not int
            or item.descriptor < 0
            or type(item.metadata) is not tuple
            or len(item.metadata) != 9
            or any(type(part) is not int for part in item.metadata)
            for item in lease._files
        )
        or any(
            retained.staged_file is not anchored
            for retained, anchored in zip(
                lease._files,
                expected_staging.staged_files,
                strict=True,
            )
        )
    ):
        raise _InvalidNestedTargetRuntimeManifest
    return canonical, lease._files


def _verify_anchored_retained_nested_target(
    retained: _RetainedStagedNestedTarget,
    anchored: dict[str, Any],
) -> bytes:
    if (
        type(retained) is not _FIXED_RETAINED_TYPE
        or type(anchored) is not dict
        or anchored.get("kind") != _STAGED_FILE_KIND
        or retained.staged_file.nested_target_staged_file_ref
        != anchored.get("nested_target_staged_file_ref")
    ):
        raise _InvalidNestedTargetRuntimeManifest
    try:
        before = _BUILTIN_FSTAT(retained.descriptor)
        before_flags = _BUILTIN_FCNTL(retained.descriptor, _BUILTIN_F_GETFL)
        before_inheritable = _BUILTIN_GET_INHERITABLE(retained.descriptor)
    except (OSError, ValueError):
        raise _InvalidNestedTargetRuntimeManifest from None
    before_signature = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_nlink,
        before.st_uid,
        before.st_gid,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    if (
        before_signature != retained.metadata
        or not _BUILTIN_S_ISREG(before.st_mode)
        or before.st_uid != _BUILTIN_GETEUID()
        or _BUILTIN_S_IMODE(before.st_mode) != _STAGED_FILE_MODE
        or before.st_nlink != 0
        or before.st_size != anchored.get("content_bytes")
        or before_flags & _BUILTIN_O_ACCMODE != _BUILTIN_O_RDONLY
        or before_inheritable
    ):
        raise _InvalidNestedTargetRuntimeManifest
    identity_ref = _BUILTIN_CANONICAL_DIGEST(
        {
            "device": before.st_dev,
            "inode": before.st_ino,
            "kind": (
                "repository_executable_native_loader_nested_target_"
                "staged_file_identity"
            ),
            "schema_version": 1,
        }
    )
    metadata_digest = _BUILTIN_CANONICAL_DIGEST(
        {
            "change_time_ns": before.st_ctime_ns,
            "filesystem_identity_ref": identity_ref,
            "group_id": before.st_gid,
            "kind": (
                "repository_executable_native_loader_nested_target_"
                "staged_file_metadata"
            ),
            "link_count": before.st_nlink,
            "mode": before.st_mode,
            "modified_time_ns": before.st_mtime_ns,
            "owner_id": before.st_uid,
            "schema_version": 1,
            "size_bytes": before.st_size,
        }
    )
    if (
        identity_ref != anchored.get("staged_filesystem_identity_ref")
        or metadata_digest != anchored.get("staged_metadata_digest")
    ):
        raise _InvalidNestedTargetRuntimeManifest

    digest = _BUILTIN_SHA256()
    header_parts: list[bytes] = []
    header_remaining = min(before.st_size, _MAX_HEADER_BYTES)
    offset = 0
    while offset < before.st_size:
        requested = min(
            _FULL_REMEASUREMENT_CHUNK_BYTES,
            before.st_size - offset,
        )
        try:
            chunk = _BUILTIN_PREAD(retained.descriptor, requested, offset)
        except (BlockingIOError, InterruptedError, OSError):
            raise _InvalidNestedTargetRuntimeManifest from None
        if not chunk or len(chunk) > requested:
            raise _InvalidNestedTargetRuntimeManifest
        digest.update(chunk)
        if header_remaining:
            captured = chunk[:header_remaining]
            header_parts.append(captured)
            header_remaining -= len(captured)
        offset += len(chunk)
    try:
        boundary = _BUILTIN_PREAD(retained.descriptor, 1, before.st_size)
        after = _BUILTIN_FSTAT(retained.descriptor)
        after_flags = _BUILTIN_FCNTL(retained.descriptor, _BUILTIN_F_GETFL)
        after_inheritable = _BUILTIN_GET_INHERITABLE(retained.descriptor)
    except (OSError, ValueError):
        raise _InvalidNestedTargetRuntimeManifest from None
    after_signature = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_nlink,
        after.st_uid,
        after.st_gid,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    header = b"".join(header_parts)
    if (
        boundary != b""
        or after_signature != before_signature
        or after_flags != before_flags
        or after_inheritable != before_inheritable
        or header_remaining != 0
        or _DIGEST_PREFIX + digest.hexdigest() != anchored.get("content_digest")
    ):
        raise _InvalidNestedTargetRuntimeManifest
    return header


def _build_runtime_file(
    staged_file: dict[str, Any],
    header: bytes,
) -> RepositoryExecutableNativeLoaderNestedTargetRuntimeFile:
    staged_ref = staged_file["nested_target_staged_file_ref"]
    classification, directive_ref = _BUILTIN_CLASSIFY_HEADER(staged_ref, header)
    header_digest = _BUILTIN_HEADER_DIGEST(staged_ref, header)
    reference = _BUILTIN_RUNTIME_FILE_REF_PROJECTION(
        nested_target_staged_file_ref=staged_ref,
        staged_filesystem_identity_ref=(
            staged_file["staged_filesystem_identity_ref"]
        ),
        content_digest=staged_file["content_digest"],
        content_bytes=staged_file["content_bytes"],
        header_digest=header_digest,
        header_bytes=len(header),
        classification=classification,
        shebang_directive_ref=directive_ref,
    )
    value = _FIXED_RUNTIME_FILE_TYPE(
        kind=_FILE_KIND,
        nested_target_staged_file_ref=staged_ref,
        staged_filesystem_identity_ref=(
            staged_file["staged_filesystem_identity_ref"]
        ),
        content_digest=staged_file["content_digest"],
        content_bytes=staged_file["content_bytes"],
        nested_target_runtime_file_ref=_BUILTIN_CANONICAL_DIGEST(reference),
        header_digest=header_digest,
        header_bytes=len(header),
        classification=classification,
        shebang_directive_ref=directive_ref,
    )
    _BUILTIN_RUNTIME_FILE_PROJECTION(value)
    return value


def _build_runtime_requirement(
    staged: dict[str, Any],
    *,
    runtime_file_by_stage_ref: dict[
        str, RepositoryExecutableNativeLoaderNestedTargetRuntimeFile
    ],
) -> RepositoryExecutableNativeLoaderNestedTargetRuntimeRequirement:
    if staged["kind"] != _STAGE_REQUIREMENT_KIND:
        raise _InvalidNestedTargetRuntimeManifest
    if staged["disposition"] == "known_chain_guard_staged":
        staged_ref = staged["nested_target_staged_file_ref"]
        runtime_file = runtime_file_by_stage_ref.get(staged_ref)
        if runtime_file is None:
            raise _InvalidNestedTargetRuntimeManifest
        disposition = "known_chain_guard_runtime_inspected"
        runtime_file_ref = runtime_file.nested_target_runtime_file_ref
    elif staged["disposition"] in _STAGE_DISPOSITIONS[1:]:
        disposition = staged["disposition"]
        runtime_file_ref = None
    else:
        raise _InvalidNestedTargetRuntimeManifest
    reference = _BUILTIN_RUNTIME_REQUIREMENT_REF_PROJECTION(
        chain_guard_requirement_ref=staged["chain_guard_requirement_ref"],
        nested_target_stage_requirement_ref=(
            staged["nested_target_stage_requirement_ref"]
        ),
        disposition=disposition,
        nested_target_measurement_ref=staged["nested_target_measurement_ref"],
        guarded_measurement_ref=staged["guarded_measurement_ref"],
        nested_target_staged_file_ref=staged["nested_target_staged_file_ref"],
        nested_target_runtime_file_ref=runtime_file_ref,
    )
    value = _FIXED_RUNTIME_REQUIREMENT_TYPE(
        kind=_REQUIREMENT_KIND,
        target_staged_file_ref=staged["target_staged_file_ref"],
        target_runtime_file_ref=staged["target_runtime_file_ref"],
        target_loader_requirement_ref=staged["target_loader_requirement_ref"],
        nested_target_requirement_ref=staged["nested_target_requirement_ref"],
        chain_guard_requirement_ref=staged["chain_guard_requirement_ref"],
        nested_target_stage_requirement_ref=(
            staged["nested_target_stage_requirement_ref"]
        ),
        disposition=disposition,
        nested_target_measurement_ref=staged["nested_target_measurement_ref"],
        guarded_measurement_ref=staged["guarded_measurement_ref"],
        nested_target_staged_file_ref=staged["nested_target_staged_file_ref"],
        nested_target_runtime_file_ref=runtime_file_ref,
        nested_target_runtime_requirement_ref=(
            _BUILTIN_CANONICAL_DIGEST(reference)
        ),
    )
    _BUILTIN_RUNTIME_REQUIREMENT_PROJECTION(value)
    return value


_BUILTIN_READ_EXACT_HEADER = _read_exact_header
_BUILTIN_ACTIVE_STAGE_SNAPSHOT = _active_nested_target_stage_snapshot
_BUILTIN_VERIFY_RETAINED_TARGET = _verify_anchored_retained_nested_target
_BUILTIN_BUILD_RUNTIME_FILE = _build_runtime_file
_BUILTIN_BUILD_RUNTIME_REQUIREMENT = _build_runtime_requirement


def inspect_staged_executable_native_loader_nested_target_runtime_manifest(
    expected_nested_target_staging: (
        RepositoryExecutableNativeLoaderNestedTargetStagingReceipt
    ),
    *,
    lease: RepositoryExecutableNativeLoaderNestedTargetStageLease,
) -> RepositoryExecutableNativeLoaderNestedTargetRuntimeManifestReceipt:
    """Inspect one exact active nested-target stage without mutating it."""

    try:
        staging_canonical, retained_files = _BUILTIN_ACTIVE_STAGE_SNAPSHOT(
            expected_nested_target_staging,
            lease,
        )
        staged_files = tuple(
            dict(item) for item in staging_canonical["staged_files"]
        )
        staged_requirements = tuple(
            dict(item) for item in staging_canonical["requirements"]
        )
        staged_lineages = tuple(
            dict(item) for item in staging_canonical["lineages"]
        )
        staged_bindings = tuple(
            dict(item) for item in staging_canonical["bindings"]
        )

        runtime_files: list[
            RepositoryExecutableNativeLoaderNestedTargetRuntimeFile
        ] = []
        for retained, anchored in zip(
            retained_files,
            staged_files,
            strict=True,
        ):
            remeasured_header = _BUILTIN_VERIFY_RETAINED_TARGET(
                retained,
                anchored,
            )
            header = _BUILTIN_READ_EXACT_HEADER(
                retained.descriptor,
                anchored["content_bytes"],
            )
            if header != remeasured_header:
                raise _InvalidNestedTargetRuntimeManifest
            runtime_files.append(_BUILTIN_BUILD_RUNTIME_FILE(anchored, header))

        final_canonical, final_retained = _BUILTIN_ACTIVE_STAGE_SNAPSHOT(
            expected_nested_target_staging,
            lease,
        )
        if final_canonical != staging_canonical or final_retained is not retained_files:
            raise _InvalidNestedTargetRuntimeManifest
        for retained, anchored in zip(final_retained, staged_files, strict=True):
            _BUILTIN_VERIFY_RETAINED_TARGET(retained, anchored)

        runtime_file_by_stage_ref = {
            item.nested_target_staged_file_ref: item for item in runtime_files
        }
        runtime_requirements = tuple(
            _BUILTIN_BUILD_RUNTIME_REQUIREMENT(
                item,
                runtime_file_by_stage_ref=runtime_file_by_stage_ref,
            )
            for item in staged_requirements
        )
        requirement_by_stage_ref = {
            item.nested_target_stage_requirement_ref: item
            for item in runtime_requirements
        }

        runtime_lineages: list[
            RepositoryExecutableNativeLoaderNestedTargetRuntimeLineage
        ] = []
        for staged in staged_lineages:
            if staged["kind"] != _STAGE_LINEAGE_KIND:
                raise _InvalidNestedTargetRuntimeManifest
            if staged["disposition"] == "stage_requirement_bound":
                stage_requirement_ref = staged[
                    "nested_target_stage_requirement_ref"
                ]
                requirement = requirement_by_stage_ref.get(stage_requirement_ref)
                if requirement is None:
                    raise _InvalidNestedTargetRuntimeManifest
                disposition = "runtime_requirement_bound"
                runtime_requirement_ref = (
                    requirement.nested_target_runtime_requirement_ref
                )
            elif staged["disposition"] in _STAGE_LINEAGE_DISPOSITIONS[1:]:
                disposition = staged["disposition"]
                runtime_requirement_ref = None
            else:
                raise _InvalidNestedTargetRuntimeManifest
            reference = _BUILTIN_RUNTIME_LINEAGE_REF_PROJECTION(
                nested_target_stage_lineage_ref=(
                    staged["nested_target_stage_lineage_ref"]
                ),
                nested_target_runtime_requirement_ref=runtime_requirement_ref,
                disposition=disposition,
            )
            runtime_lineages.append(
                _FIXED_RUNTIME_LINEAGE_TYPE(
                    kind=_LINEAGE_KIND,
                    staged_file_ref=staged["staged_file_ref"],
                    runtime_file_ref=staged["runtime_file_ref"],
                    requirement_ref=staged["requirement_ref"],
                    target_requirement_ref=staged["target_requirement_ref"],
                    target_stage_requirement_ref=(
                        staged["target_stage_requirement_ref"]
                    ),
                    target_runtime_requirement_ref=(
                        staged["target_runtime_requirement_ref"]
                    ),
                    target_loader_lineage_ref=(
                        staged["target_loader_lineage_ref"]
                    ),
                    nested_target_lineage_ref=(
                        staged["nested_target_lineage_ref"]
                    ),
                    chain_guard_lineage_ref=staged["chain_guard_lineage_ref"],
                    nested_target_stage_lineage_ref=(
                        staged["nested_target_stage_lineage_ref"]
                    ),
                    nested_target_runtime_requirement_ref=(
                        runtime_requirement_ref
                    ),
                    disposition=disposition,
                    nested_target_runtime_lineage_ref=(
                        _BUILTIN_CANONICAL_DIGEST(reference)
                    ),
                )
            )

        lineage_by_stage_ref = {
            item.nested_target_stage_lineage_ref: item
            for item in runtime_lineages
        }
        runtime_bindings: list[
            RepositoryExecutableNativeLoaderNestedTargetRuntimeBinding
        ] = []
        for staged in staged_bindings:
            if staged["kind"] != _STAGE_BINDING_KIND:
                raise _InvalidNestedTargetRuntimeManifest
            lineage = lineage_by_stage_ref.get(
                staged["nested_target_stage_lineage_ref"]
            )
            if lineage is None:
                raise _InvalidNestedTargetRuntimeManifest
            runtime_bindings.append(
                _FIXED_RUNTIME_BINDING_TYPE(
                    kind=_BINDING_KIND,
                    command_kind=staged["command_kind"],
                    command_id=staged["command_id"],
                    command_digest=staged["command_digest"],
                    staged_file_ref=staged["staged_file_ref"],
                    runtime_file_ref=staged["runtime_file_ref"],
                    requirement_ref=staged["requirement_ref"],
                    target_requirement_ref=staged["target_requirement_ref"],
                    target_stage_requirement_ref=(
                        staged["target_stage_requirement_ref"]
                    ),
                    target_runtime_requirement_ref=(
                        staged["target_runtime_requirement_ref"]
                    ),
                    target_loader_lineage_ref=(
                        staged["target_loader_lineage_ref"]
                    ),
                    nested_target_lineage_ref=(
                        staged["nested_target_lineage_ref"]
                    ),
                    chain_guard_lineage_ref=staged["chain_guard_lineage_ref"],
                    nested_target_stage_lineage_ref=(
                        staged["nested_target_stage_lineage_ref"]
                    ),
                    nested_target_runtime_lineage_ref=(
                        lineage.nested_target_runtime_lineage_ref
                    ),
                )
            )

        receipt = _FIXED_RUNTIME_RECEIPT_TYPE(
            kind=_MANIFEST_KIND,
            schema_version=_SCHEMA_VERSION,
            manifest_source=MANIFEST_SOURCE,
            manifest_scope=MANIFEST_SCOPE,
            nested_target_staging_receipt_digest=(
                _BUILTIN_CANONICAL_DIGEST(staging_canonical)
            ),
            nested_target_resolution_receipt_digest=(
                staging_canonical["nested_target_resolution_receipt_digest"]
            ),
            expected_chain_guard_receipt_digest=(
                staging_canonical["expected_chain_guard_receipt_digest"]
            ),
            action_chain_guard_receipt_digest=(
                staging_canonical["action_chain_guard_receipt_digest"]
            ),
            post_stage_chain_guard_receipt_digest=(
                staging_canonical["post_stage_chain_guard_receipt_digest"]
            ),
            target_loader_requirements_receipt_digest=(
                staging_canonical[
                    "target_loader_requirements_receipt_digest"
                ]
            ),
            target_runtime_manifest_receipt_digest=(
                staging_canonical["target_runtime_manifest_receipt_digest"]
            ),
            target_staging_receipt_digest=(
                staging_canonical["target_staging_receipt_digest"]
            ),
            target_resolution_receipt_digest=(
                staging_canonical["target_resolution_receipt_digest"]
            ),
            native_loader_requirements_receipt_digest=(
                staging_canonical[
                    "native_loader_requirements_receipt_digest"
                ]
            ),
            runtime_manifest_receipt_digest=(
                staging_canonical["runtime_manifest_receipt_digest"]
            ),
            source_staging_receipt_digest=(
                staging_canonical["source_staging_receipt_digest"]
            ),
            registration_digest=staging_canonical["registration_digest"],
            repository_ref=staging_canonical["repository_ref"],
            verification_commands_digest=(
                staging_canonical["verification_commands_digest"]
            ),
            resolution_context_digest=(
                staging_canonical["resolution_context_digest"]
            ),
            source_staging_context_digest=(
                staging_canonical["source_staging_context_digest"]
            ),
            first_loader_path_context_digest=(
                staging_canonical["first_loader_path_context_digest"]
            ),
            target_staging_context_digest=(
                staging_canonical["target_staging_context_digest"]
            ),
            nested_loader_path_context_digest=(
                staging_canonical["nested_loader_path_context_digest"]
            ),
            nested_target_staging_context_digest=(
                staging_canonical["nested_target_staging_context_digest"]
            ),
            known_source_identity_set_digest=(
                staging_canonical["known_source_identity_set_digest"]
            ),
            known_target_identity_set_digest=(
                staging_canonical["known_target_identity_set_digest"]
            ),
            protected_staging_root_identity_set_digest=(
                staging_canonical[
                    "protected_staging_root_identity_set_digest"
                ]
            ),
            guard_summary_ref=staging_canonical["guard_summary_ref"],
            files=tuple(runtime_files),
            requirements=runtime_requirements,
            lineages=tuple(runtime_lineages),
            bindings=tuple(runtime_bindings),
            file_count=len(runtime_files),
            requirement_count=len(runtime_requirements),
            lineage_count=len(runtime_lineages),
            command_count=len(runtime_bindings),
            known_chain_guard_runtime_inspected_count=(
                staging_canonical["known_chain_guard_staged_count"]
            ),
            loader_declaration_absent_count=(
                staging_canonical["loader_declaration_absent_count"]
            ),
            unsupported_native_layout_count=(
                staging_canonical["unsupported_native_layout_count"]
            ),
            non_native_not_applicable_count=(
                staging_canonical["non_native_not_applicable_count"]
            ),
            total_content_bytes=sum(item.content_bytes for item in runtime_files),
            total_header_bytes=sum(item.header_bytes for item in runtime_files),
        )
        _BUILTIN_RUNTIME_MANIFEST_PROJECTION(receipt)
        closing_canonical, closing_retained = _BUILTIN_ACTIVE_STAGE_SNAPSHOT(
            expected_nested_target_staging,
            lease,
        )
        if closing_canonical != staging_canonical or closing_retained is not retained_files:
            raise _InvalidNestedTargetRuntimeManifest
        return receipt
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise _FIXED_VALIDATION_ERROR(_INVALID_MESSAGE) from None


__all__ = [
    "MANIFEST_SCOPE",
    "MANIFEST_SOURCE",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RUNTIME_BINDING_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RUNTIME_FILE_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RUNTIME_LINEAGE_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RUNTIME_MANIFEST_EVIDENCE_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RUNTIME_MANIFEST_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RUNTIME_MANIFEST_SCHEMA_VERSION",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RUNTIME_REQUIREMENT_KIND",
    "RepositoryExecutableNativeLoaderNestedTargetRuntimeBinding",
    "RepositoryExecutableNativeLoaderNestedTargetRuntimeFile",
    "RepositoryExecutableNativeLoaderNestedTargetRuntimeLineage",
    "RepositoryExecutableNativeLoaderNestedTargetRuntimeManifestReceipt",
    "RepositoryExecutableNativeLoaderNestedTargetRuntimeRequirement",
    "inspect_staged_executable_native_loader_nested_target_runtime_manifest",
]
