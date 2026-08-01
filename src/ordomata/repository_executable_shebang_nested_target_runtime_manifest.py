"""Read-only runtime-header evidence for one active shebang-nested-target stage.

This module deliberately stops before recursive interpreter resolution or
dependency closure.  It independently validates one exact nested-target-staging
receipt and lease, fully remeasures the anonymous target files, reads bounded
headers with ``pread``, and applies a fixed byte-level classification.  It
opens no path, mutates no lease, and executes nothing.
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
from .repository_executable_shebang_nested_target_staging import (
    RepositoryExecutableShebangNestedTargetStageLease,
    RepositoryExecutableShebangNestedTargetStagingReceipt,
    _RetainedStagedNestedTarget,
    _noop_staging_context_digest as _nested_target_noop_context_digest_v1,
    _staged_file_projection as _nested_target_staged_file_projection_v1,
    _staging_receipt_projection as _nested_target_staging_projection_v1,
)


REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RUNTIME_MANIFEST_SCHEMA_VERSION = 1
REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RUNTIME_MANIFEST_KIND = (
    "repository_executable_shebang_nested_target_runtime_manifest"
)
REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RUNTIME_MANIFEST_EVIDENCE_KIND = (
    "repository_executable_shebang_nested_target_runtime_manifest_validation"
)
REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RUNTIME_FILE_KIND = (
    "repository_executable_shebang_nested_target_runtime_file"
)
REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RUNTIME_REQUIREMENT_KIND = (
    "repository_executable_shebang_nested_target_runtime_requirement"
)
REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RUNTIME_BINDING_KIND = (
    "repository_executable_shebang_nested_target_runtime_binding"
)
MANIFEST_SOURCE = "controller_inspected"
MANIFEST_SCOPE = "posix_staged_shebang_nested_target_runtime_header_v1"

_FIXED_SCHEMA_VERSION = (
    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RUNTIME_MANIFEST_SCHEMA_VERSION
)
_FIXED_MANIFEST_KIND = (
    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RUNTIME_MANIFEST_KIND
)
_FIXED_EVIDENCE_KIND = (
    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RUNTIME_MANIFEST_EVIDENCE_KIND
)
_FIXED_FILE_KIND = REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RUNTIME_FILE_KIND
_FIXED_REQUIREMENT_KIND = (
    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RUNTIME_REQUIREMENT_KIND
)
_FIXED_BINDING_KIND = (
    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RUNTIME_BINDING_KIND
)
_FIXED_MANIFEST_SOURCE = MANIFEST_SOURCE
_FIXED_MANIFEST_SCOPE = MANIFEST_SCOPE

_TARGET_STAGE_BINDING_KIND = (
    "repository_executable_shebang_nested_target_stage_binding"
)
_TARGET_STAGING_SCOPE = "posix_shebang_nested_target_unlinked_readonly_v1"

_INVALID_MESSAGE = (
    "repository executable shebang nested target runtime manifest is invalid"
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
    "not_applicable",
)
_RUNTIME_DISPOSITIONS = (
    "known_chain_guard_runtime_inspected",
    "source_native_not_applicable",
    "target_native_not_applicable",
)
_MAX_FILES = 80
_MAX_REQUIREMENTS = 80
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

# Hold the shipped proof primitives.  Public dataclass methods and module
# attributes remain patchable and are not accepted as canonical input here.
_BUILTIN_SHA256 = hashlib.sha256
_BUILTIN_CANONICAL_JSON = canonical_json


def _captured_canonical_digest(value: Any) -> str:
    encoded = _BUILTIN_CANONICAL_JSON(value).encode("utf-8")
    return _DIGEST_PREFIX + _BUILTIN_SHA256(encoded).hexdigest()


_BUILTIN_CANONICAL_DIGEST = _captured_canonical_digest
_BUILTIN_NESTED_TARGET_STAGING_PROJECTION = (
    _nested_target_staging_projection_v1
)
_BUILTIN_NESTED_TARGET_STAGED_FILE_PROJECTION = (
    _nested_target_staged_file_projection_v1
)
_BUILTIN_NESTED_TARGET_NOOP_CONTEXT_DIGEST = (
    _nested_target_noop_context_digest_v1
)
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
_FIXED_VALIDATION_ERROR = ValidationError
_FIXED_TARGET_STAGING_RECEIPT_TYPE = (
    RepositoryExecutableShebangNestedTargetStagingReceipt
)
_FIXED_TARGET_STAGE_LEASE_TYPE = RepositoryExecutableShebangNestedTargetStageLease
_FIXED_RETAINED_TARGET_TYPE = _RetainedStagedNestedTarget


class _InvalidNestedTargetRuntimeManifest(ValueError):
    """Internal invalid-input sentinel with no public details."""


@dataclass(frozen=True, slots=True)
class RepositoryExecutableShebangNestedTargetRuntimeFile:
    """One staged target and its bounded runtime-header classification."""

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
class RepositoryExecutableShebangNestedTargetRuntimeRequirement:
    """One upstream nested-target-stage requirement's runtime disposition."""

    kind: str
    staged_file_ref: str = field(repr=False)
    runtime_file_ref: str = field(repr=False)
    requirement_ref: str = field(repr=False)
    target_requirement_ref: str = field(repr=False)
    target_stage_requirement_ref: str = field(repr=False)
    target_runtime_requirement_ref: str = field(repr=False)
    target_shebang_requirement_ref: str = field(repr=False)
    nested_target_requirement_ref: str = field(repr=False)
    chain_guard_requirement_ref: str = field(repr=False)
    nested_target_stage_requirement_ref: str = field(repr=False)
    runtime_classification: str
    disposition: str
    nested_target_measurement_ref: str | None = field(repr=False)
    guarded_measurement_ref: str | None = field(repr=False)
    nested_target_staged_file_ref: str | None = field(repr=False)
    nested_target_runtime_file_ref: str | None = field(repr=False)
    nested_target_runtime_requirement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _runtime_requirement_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableShebangNestedTargetRuntimeBinding:
    """One registered command bound to one nested-target-runtime requirement."""

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
    target_shebang_requirement_ref: str = field(repr=False)
    nested_target_requirement_ref: str = field(repr=False)
    chain_guard_requirement_ref: str = field(repr=False)
    nested_target_stage_requirement_ref: str = field(repr=False)
    nested_target_runtime_requirement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _runtime_binding_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableShebangNestedTargetRuntimeManifestReceipt:
    """Historical evidence from one active nested-target-descriptor inspection."""

    kind: str
    schema_version: int
    manifest_source: str
    manifest_scope: str
    nested_target_staging_receipt_digest: str = field(repr=False)
    nested_target_resolution_receipt_digest: str = field(repr=False)
    expected_chain_guard_receipt_digest: str = field(repr=False)
    action_chain_guard_receipt_digest: str = field(repr=False)
    post_stage_chain_guard_receipt_digest: str = field(repr=False)
    target_shebang_requirements_receipt_digest: str = field(repr=False)
    target_runtime_manifest_receipt_digest: str = field(repr=False)
    target_staging_receipt_digest: str = field(repr=False)
    target_resolution_receipt_digest: str = field(repr=False)
    shebang_requirements_receipt_digest: str = field(repr=False)
    runtime_manifest_receipt_digest: str = field(repr=False)
    source_staging_receipt_digest: str = field(repr=False)
    registration_digest: str = field(repr=False)
    repository_ref: str = field(repr=False)
    verification_commands_digest: str = field(repr=False)
    resolution_context_digest: str = field(repr=False)
    source_staging_context_digest: str = field(repr=False)
    target_path_context_digest: str = field(repr=False)
    target_staging_context_digest: str = field(repr=False)
    nested_target_path_context_digest: str = field(repr=False)
    known_source_identity_set_digest: str = field(repr=False)
    known_target_identity_set_digest: str = field(repr=False)
    protected_staging_root_identity_set_digest: str = field(repr=False)
    guard_summary_ref: str = field(repr=False)
    nested_target_staging_context_digest: str = field(repr=False)
    files: tuple[RepositoryExecutableShebangNestedTargetRuntimeFile, ...] = field(
        repr=False
    )
    requirements: tuple[
        RepositoryExecutableShebangNestedTargetRuntimeRequirement, ...
    ] = field(repr=False)
    bindings: tuple[
        RepositoryExecutableShebangNestedTargetRuntimeBinding, ...
    ] = field(repr=False)
    file_count: int
    requirement_count: int
    command_count: int
    known_chain_guard_runtime_inspected_count: int
    source_native_not_applicable_count: int
    target_native_not_applicable_count: int
    total_content_bytes: int
    total_header_bytes: int

    def to_canonical(self) -> dict[str, Any]:
        return _runtime_manifest_projection(self)

    @property
    def receipt_digest(self) -> str:
        return _BUILTIN_CANONICAL_DIGEST(
            _runtime_manifest_projection(self)
        )

    def to_evidence(self) -> dict[str, Any]:
        return _runtime_manifest_evidence_projection(self)


_FIXED_RUNTIME_FILE_TYPE = RepositoryExecutableShebangNestedTargetRuntimeFile
_FIXED_RUNTIME_REQUIREMENT_TYPE = (
    RepositoryExecutableShebangNestedTargetRuntimeRequirement
)
_FIXED_RUNTIME_BINDING_TYPE = RepositoryExecutableShebangNestedTargetRuntimeBinding
_FIXED_RUNTIME_MANIFEST_RECEIPT_TYPE = (
    RepositoryExecutableShebangNestedTargetRuntimeManifestReceipt
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
    return {
        "classification": classification,
        "content_bytes": content_bytes,
        "content_digest": content_digest,
        "header_bytes": header_bytes,
        "header_digest": header_digest,
        "kind": "repository_executable_shebang_nested_target_runtime_file_ref",
        "manifest_scope": _FIXED_MANIFEST_SCOPE,
        "schema_version": _FIXED_SCHEMA_VERSION,
        "shebang_directive_ref": shebang_directive_ref,
        "staged_filesystem_identity_ref": staged_filesystem_identity_ref,
        "nested_target_staged_file_ref": nested_target_staged_file_ref,
    }


def _runtime_file_projection(
    value: RepositoryExecutableShebangNestedTargetRuntimeFile,
) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_RUNTIME_FILE_TYPE
        or type(value.kind) is not str
        or value.kind
        != _FIXED_FILE_KIND
        or not _BUILTIN_IS_DIGEST(value.nested_target_staged_file_ref)
        or not _BUILTIN_IS_DIGEST(value.staged_filesystem_identity_ref)
        or not _BUILTIN_IS_DIGEST(value.content_digest)
        or type(value.content_bytes) is not int
        or not 0 <= value.content_bytes <= _MAX_FILE_BYTES
        or not _BUILTIN_IS_DIGEST(value.nested_target_runtime_file_ref)
        or not _BUILTIN_IS_DIGEST(value.header_digest)
        or type(value.header_bytes) is not int
        or not 0 <= value.header_bytes <= _MAX_HEADER_BYTES
        or value.header_bytes != min(value.content_bytes, _MAX_HEADER_BYTES)
        or type(value.classification) is not str
        or value.classification not in _CLASSIFICATIONS[:-1]
        or (value.classification == "elf" and value.header_bytes < 16)
        or (value.classification == "mach_o" and value.header_bytes < 28)
        or (
            value.classification == "posix_shebang"
            and value.header_bytes < 4
        )
        or (
            value.classification == "unsupported_shebang"
            and value.header_bytes < 2
        )
        or (
            value.shebang_directive_ref is not None
            and not _BUILTIN_IS_DIGEST(value.shebang_directive_ref)
        )
        or (
            value.classification == "posix_shebang"
            and value.shebang_directive_ref is None
        )
        or (
            value.classification != "posix_shebang"
            and value.shebang_directive_ref is not None
        )
    ):
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
    if value.nested_target_runtime_file_ref != _BUILTIN_CANONICAL_DIGEST(reference):
        raise _InvalidNestedTargetRuntimeManifest
    return {
        "classification": value.classification,
        "content_bytes": value.content_bytes,
        "content_digest": value.content_digest,
        "header_bytes": value.header_bytes,
        "header_digest": value.header_digest,
        "kind": value.kind,
        "shebang_directive_ref": value.shebang_directive_ref,
        "staged_filesystem_identity_ref": (
            value.staged_filesystem_identity_ref
        ),
        "nested_target_runtime_file_ref": value.nested_target_runtime_file_ref,
        "nested_target_staged_file_ref": value.nested_target_staged_file_ref,
    }


def _runtime_requirement_ref_projection(
    *,
    staged_file_ref: str,
    runtime_file_ref: str,
    requirement_ref: str,
    target_requirement_ref: str,
    target_stage_requirement_ref: str,
    target_runtime_requirement_ref: str,
    target_shebang_requirement_ref: str,
    nested_target_requirement_ref: str,
    chain_guard_requirement_ref: str,
    nested_target_stage_requirement_ref: str,
    runtime_classification: str,
    disposition: str,
    nested_target_measurement_ref: str | None,
    guarded_measurement_ref: str | None,
    nested_target_staged_file_ref: str | None,
    nested_target_runtime_file_ref: str | None,
) -> dict[str, Any]:
    return {
        "disposition": disposition,
        "kind": (
            "repository_executable_shebang_nested_target_runtime_requirement_ref"
        ),
        "requirement_ref": requirement_ref,
        "runtime_classification": runtime_classification,
        "runtime_file_ref": runtime_file_ref,
        "schema_version": _FIXED_SCHEMA_VERSION,
        "staged_file_ref": staged_file_ref,
        "guarded_measurement_ref": guarded_measurement_ref,
        "nested_target_measurement_ref": nested_target_measurement_ref,
        "chain_guard_requirement_ref": chain_guard_requirement_ref,
        "nested_target_requirement_ref": nested_target_requirement_ref,
        "target_requirement_ref": target_requirement_ref,
        "target_runtime_requirement_ref": target_runtime_requirement_ref,
        "target_shebang_requirement_ref": target_shebang_requirement_ref,
        "target_stage_requirement_ref": target_stage_requirement_ref,
        "nested_target_runtime_file_ref": nested_target_runtime_file_ref,
        "nested_target_stage_requirement_ref": nested_target_stage_requirement_ref,
        "nested_target_staged_file_ref": nested_target_staged_file_ref,
    }


def _runtime_requirement_projection(
    value: RepositoryExecutableShebangNestedTargetRuntimeRequirement,
) -> dict[str, Any]:
    if (
        type(value)
        is not _FIXED_RUNTIME_REQUIREMENT_TYPE
        or type(value.kind) is not str
        or value.kind
        != _FIXED_REQUIREMENT_KIND
        or not all(
            _BUILTIN_IS_DIGEST(item)
            for item in (
                value.staged_file_ref,
                value.runtime_file_ref,
                value.requirement_ref,
                value.target_requirement_ref,
                value.target_stage_requirement_ref,
                value.target_runtime_requirement_ref,
                value.target_shebang_requirement_ref,
                value.nested_target_requirement_ref,
                value.chain_guard_requirement_ref,
                value.nested_target_stage_requirement_ref,
                value.nested_target_runtime_requirement_ref,
            )
        )
        or type(value.runtime_classification) is not str
        or value.runtime_classification not in _CLASSIFICATIONS
        or type(value.disposition) is not str
        or value.disposition not in _RUNTIME_DISPOSITIONS
        or (
            value.nested_target_measurement_ref is not None
            and not _BUILTIN_IS_DIGEST(value.nested_target_measurement_ref)
        )
        or (
            value.nested_target_staged_file_ref is not None
            and not _BUILTIN_IS_DIGEST(value.nested_target_staged_file_ref)
        )
        or (
            value.guarded_measurement_ref is not None
            and not _BUILTIN_IS_DIGEST(value.guarded_measurement_ref)
        )
        or (
            value.nested_target_runtime_file_ref is not None
            and not _BUILTIN_IS_DIGEST(value.nested_target_runtime_file_ref)
        )
        or (
            value.disposition == "known_chain_guard_runtime_inspected"
            and (
                value.runtime_classification == "not_applicable"
                or value.nested_target_measurement_ref is None
                or value.guarded_measurement_ref is None
                or value.nested_target_staged_file_ref is None
                or value.nested_target_runtime_file_ref is None
            )
        )
        or (
            value.disposition
            in {
                "source_native_not_applicable",
                "target_native_not_applicable",
            }
            and (
                value.runtime_classification != "not_applicable"
                or value.nested_target_measurement_ref is not None
                or value.guarded_measurement_ref is not None
                or value.nested_target_staged_file_ref is not None
                or value.nested_target_runtime_file_ref is not None
            )
        )
    ):
        raise _InvalidNestedTargetRuntimeManifest
    reference = _BUILTIN_RUNTIME_REQUIREMENT_REF_PROJECTION(
        staged_file_ref=value.staged_file_ref,
        runtime_file_ref=value.runtime_file_ref,
        requirement_ref=value.requirement_ref,
        target_requirement_ref=value.target_requirement_ref,
        target_stage_requirement_ref=value.target_stage_requirement_ref,
        target_runtime_requirement_ref=value.target_runtime_requirement_ref,
        target_shebang_requirement_ref=value.target_shebang_requirement_ref,
        nested_target_requirement_ref=value.nested_target_requirement_ref,
        chain_guard_requirement_ref=value.chain_guard_requirement_ref,
        nested_target_stage_requirement_ref=value.nested_target_stage_requirement_ref,
        runtime_classification=value.runtime_classification,
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
        "nested_target_runtime_requirement_ref": (
            value.nested_target_runtime_requirement_ref
        ),
    }


def _runtime_binding_projection(
    value: RepositoryExecutableShebangNestedTargetRuntimeBinding,
) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_RUNTIME_BINDING_TYPE
        or type(value.kind) is not str
        or value.kind
        != _FIXED_BINDING_KIND
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
                value.target_shebang_requirement_ref,
                value.nested_target_requirement_ref,
                value.chain_guard_requirement_ref,
                value.nested_target_stage_requirement_ref,
                value.nested_target_runtime_requirement_ref,
            )
        )
    ):
        raise _InvalidNestedTargetRuntimeManifest
    return {
        "command_digest": value.command_digest,
        "command_id": value.command_id,
        "command_kind": value.command_kind,
        "kind": value.kind,
        "requirement_ref": value.requirement_ref,
        "runtime_file_ref": value.runtime_file_ref,
        "staged_file_ref": value.staged_file_ref,
        "chain_guard_requirement_ref": value.chain_guard_requirement_ref,
        "nested_target_requirement_ref": value.nested_target_requirement_ref,
        "target_requirement_ref": value.target_requirement_ref,
        "target_runtime_requirement_ref": value.target_runtime_requirement_ref,
        "target_shebang_requirement_ref": value.target_shebang_requirement_ref,
        "target_stage_requirement_ref": value.target_stage_requirement_ref,
        "nested_target_runtime_requirement_ref": (
            value.nested_target_runtime_requirement_ref
        ),
        "nested_target_stage_requirement_ref": (
            value.nested_target_stage_requirement_ref
        ),
    }


def _target_staging_receipt_projection(
    value: RepositoryExecutableShebangNestedTargetStagingReceipt,
) -> dict[str, Any]:
    return _BUILTIN_NESTED_TARGET_STAGING_PROJECTION(value)


def _runtime_manifest_projection(
    value: RepositoryExecutableShebangNestedTargetRuntimeManifestReceipt,
) -> dict[str, Any]:
    digest_fields = (
        value.nested_target_staging_receipt_digest,
        value.nested_target_resolution_receipt_digest,
        value.expected_chain_guard_receipt_digest,
        value.action_chain_guard_receipt_digest,
        value.post_stage_chain_guard_receipt_digest,
        value.target_shebang_requirements_receipt_digest,
        value.target_runtime_manifest_receipt_digest,
        value.target_staging_receipt_digest,
        value.target_resolution_receipt_digest,
        value.shebang_requirements_receipt_digest,
        value.runtime_manifest_receipt_digest,
        value.source_staging_receipt_digest,
        value.registration_digest,
        value.repository_ref,
        value.verification_commands_digest,
        value.resolution_context_digest,
        value.source_staging_context_digest,
        value.target_path_context_digest,
        value.target_staging_context_digest,
        value.nested_target_path_context_digest,
        value.known_source_identity_set_digest,
        value.known_target_identity_set_digest,
        value.protected_staging_root_identity_set_digest,
        value.guard_summary_ref,
        value.nested_target_staging_context_digest,
    )
    if (
        type(value)
        is not _FIXED_RUNTIME_MANIFEST_RECEIPT_TYPE
        or type(value.kind) is not str
        or value.kind
        != _FIXED_MANIFEST_KIND
        or type(value.schema_version) is not int
        or value.schema_version
        != _FIXED_SCHEMA_VERSION
        or type(value.manifest_source) is not str
        or value.manifest_source != _FIXED_MANIFEST_SOURCE
        or type(value.manifest_scope) is not str
        or value.manifest_scope != _FIXED_MANIFEST_SCOPE
        or not all(_BUILTIN_IS_DIGEST(item) for item in digest_fields)
        or value.expected_chain_guard_receipt_digest
        != value.action_chain_guard_receipt_digest
        or value.expected_chain_guard_receipt_digest
        != value.post_stage_chain_guard_receipt_digest
        or type(value.files) is not tuple
        or not 0 <= len(value.files) <= _MAX_FILES
        or type(value.requirements) is not tuple
        or not 1 <= len(value.requirements) <= _MAX_REQUIREMENTS
        or type(value.bindings) is not tuple
        or not 1 <= len(value.bindings) <= _MAX_COMMANDS
        or type(value.file_count) is not int
        or value.file_count != len(value.files)
        or type(value.requirement_count) is not int
        or value.requirement_count != len(value.requirements)
        or type(value.command_count) is not int
        or value.command_count != len(value.bindings)
        or type(value.known_chain_guard_runtime_inspected_count) is not int
        or type(value.source_native_not_applicable_count) is not int
        or type(value.target_native_not_applicable_count) is not int
        or any(
            item < 0
            for item in (
                value.known_chain_guard_runtime_inspected_count,
                value.source_native_not_applicable_count,
                value.target_native_not_applicable_count,
            )
        )
        or type(value.total_content_bytes) is not int
        or not 0 <= value.total_content_bytes <= _MAX_TOTAL_BYTES
        or type(value.total_header_bytes) is not int
        or not 0
        <= value.total_header_bytes
        <= _MAX_FILES * _MAX_HEADER_BYTES
    ):
        raise _InvalidNestedTargetRuntimeManifest

    files = [_BUILTIN_RUNTIME_FILE_PROJECTION(item) for item in value.files]
    requirements = [
        _BUILTIN_RUNTIME_REQUIREMENT_PROJECTION(item)
        for item in value.requirements
    ]
    bindings = [
        _BUILTIN_RUNTIME_BINDING_PROJECTION(item) for item in value.bindings
    ]

    file_by_staged_ref: dict[
        str, RepositoryExecutableShebangNestedTargetRuntimeFile
    ] = {}
    runtime_file_refs: set[str] = set()
    staged_identity_refs: set[str] = set()
    total_content_bytes = 0
    total_header_bytes = 0
    for item in value.files:
        if (
            item.nested_target_staged_file_ref in file_by_staged_ref
            or item.nested_target_runtime_file_ref in runtime_file_refs
            or item.staged_filesystem_identity_ref in staged_identity_refs
        ):
            raise _InvalidNestedTargetRuntimeManifest
        file_by_staged_ref[item.nested_target_staged_file_ref] = item
        runtime_file_refs.add(item.nested_target_runtime_file_ref)
        staged_identity_refs.add(item.staged_filesystem_identity_ref)
        total_content_bytes += item.content_bytes
        total_header_bytes += item.header_bytes

    requirement_by_ref: dict[
        str, RepositoryExecutableShebangNestedTargetRuntimeRequirement
    ] = {}
    runtime_requirement_refs: set[str] = set()
    stage_requirement_refs: set[str] = set()
    first_use_file_refs: list[str] = []
    used_file_refs: set[str] = set()
    inspected_count = 0
    source_native_count = 0
    target_native_count = 0
    for item in value.requirements:
        if (
            item.requirement_ref in requirement_by_ref
            or item.nested_target_runtime_requirement_ref in runtime_requirement_refs
            or item.nested_target_stage_requirement_ref in stage_requirement_refs
        ):
            raise _InvalidNestedTargetRuntimeManifest
        requirement_by_ref[item.requirement_ref] = item
        runtime_requirement_refs.add(item.nested_target_runtime_requirement_ref)
        stage_requirement_refs.add(item.nested_target_stage_requirement_ref)
        if item.disposition == "known_chain_guard_runtime_inspected":
            inspected_count += 1
            if (
                item.nested_target_staged_file_ref is None
                or item.nested_target_runtime_file_ref is None
            ):
                raise _InvalidNestedTargetRuntimeManifest
            runtime_file = file_by_staged_ref.get(
                item.nested_target_staged_file_ref
            )
            if (
                runtime_file is None
                or runtime_file.nested_target_runtime_file_ref
                != item.nested_target_runtime_file_ref
                or runtime_file.classification
                != item.runtime_classification
            ):
                raise _InvalidNestedTargetRuntimeManifest
            if item.nested_target_staged_file_ref not in first_use_file_refs:
                first_use_file_refs.append(item.nested_target_staged_file_ref)
            used_file_refs.add(item.nested_target_staged_file_ref)
        elif item.disposition == "source_native_not_applicable":
            source_native_count += 1
        elif item.disposition == "target_native_not_applicable":
            target_native_count += 1
        else:
            raise _InvalidNestedTargetRuntimeManifest
    if (
        tuple(first_use_file_refs)
        != tuple(item.nested_target_staged_file_ref for item in value.files)
        or used_file_refs != set(file_by_staged_ref)
    ):
        raise _InvalidNestedTargetRuntimeManifest

    command_ids: set[str] = set()
    bound_runtime_requirement_refs: set[str] = set()
    ordered_runtime_requirement_refs: list[str] = []
    prior_kind_index = -1
    for binding in value.bindings:
        requirement = requirement_by_ref.get(binding.requirement_ref)
        kind_index = _COMMAND_KINDS.index(binding.command_kind)
        if (
            requirement is None
            or binding.staged_file_ref != requirement.staged_file_ref
            or binding.runtime_file_ref != requirement.runtime_file_ref
            or binding.target_requirement_ref
            != requirement.target_requirement_ref
            or binding.target_stage_requirement_ref
            != requirement.target_stage_requirement_ref
            or binding.target_runtime_requirement_ref
            != requirement.target_runtime_requirement_ref
            or binding.target_shebang_requirement_ref
            != requirement.target_shebang_requirement_ref
            or binding.nested_target_requirement_ref
            != requirement.nested_target_requirement_ref
            or binding.chain_guard_requirement_ref
            != requirement.chain_guard_requirement_ref
            or binding.nested_target_stage_requirement_ref
            != requirement.nested_target_stage_requirement_ref
            or binding.nested_target_runtime_requirement_ref
            != requirement.nested_target_runtime_requirement_ref
            or binding.command_id in command_ids
            or kind_index < prior_kind_index
        ):
            raise _InvalidNestedTargetRuntimeManifest
        command_ids.add(binding.command_id)
        if (
            binding.nested_target_runtime_requirement_ref
            not in bound_runtime_requirement_refs
        ):
            ordered_runtime_requirement_refs.append(
                binding.nested_target_runtime_requirement_ref
            )
        bound_runtime_requirement_refs.add(
            binding.nested_target_runtime_requirement_ref
        )
        prior_kind_index = kind_index

    if (
        bound_runtime_requirement_refs != runtime_requirement_refs
        or tuple(ordered_runtime_requirement_refs)
        != tuple(
            item.nested_target_runtime_requirement_ref
            for item in value.requirements
        )
        or inspected_count
        != value.known_chain_guard_runtime_inspected_count
        or source_native_count != value.source_native_not_applicable_count
        or target_native_count != value.target_native_not_applicable_count
        or inspected_count + source_native_count + target_native_count
        != value.requirement_count
        or total_content_bytes != value.total_content_bytes
        or total_header_bytes != value.total_header_bytes
        or (value.file_count == 0 and inspected_count != 0)
        or (value.file_count > 0 and inspected_count == 0)
    ):
        raise _InvalidNestedTargetRuntimeManifest

    return {
        "bindings": bindings,
        "command_count": value.command_count,
        "known_chain_guard_runtime_inspected_count": (
            value.known_chain_guard_runtime_inspected_count
        ),
        "file_count": value.file_count,
        "files": files,
        "kind": value.kind,
        "manifest_scope": value.manifest_scope,
        "manifest_source": value.manifest_source,
        "source_native_not_applicable_count": (
            value.source_native_not_applicable_count
        ),
        "target_native_not_applicable_count": (
            value.target_native_not_applicable_count
        ),
        "registration_digest": value.registration_digest,
        "repository_ref": value.repository_ref,
        "requirement_count": value.requirement_count,
        "requirements": requirements,
        "resolution_context_digest": value.resolution_context_digest,
        "runtime_manifest_receipt_digest": (
            value.runtime_manifest_receipt_digest
        ),
        "schema_version": value.schema_version,
        "shebang_requirements_receipt_digest": (
            value.shebang_requirements_receipt_digest
        ),
        "source_staging_context_digest": (
            value.source_staging_context_digest
        ),
        "source_staging_receipt_digest": value.source_staging_receipt_digest,
        "target_path_context_digest": value.target_path_context_digest,
        "target_staging_context_digest": (
            value.target_staging_context_digest
        ),
        "nested_target_path_context_digest": value.nested_target_path_context_digest,
        "known_source_identity_set_digest": (
            value.known_source_identity_set_digest
        ),
        "known_target_identity_set_digest": (
            value.known_target_identity_set_digest
        ),
        "protected_staging_root_identity_set_digest": (
            value.protected_staging_root_identity_set_digest
        ),
        "guard_summary_ref": value.guard_summary_ref,
        "expected_chain_guard_receipt_digest": (
            value.expected_chain_guard_receipt_digest
        ),
        "action_chain_guard_receipt_digest": (
            value.action_chain_guard_receipt_digest
        ),
        "post_stage_chain_guard_receipt_digest": (
            value.post_stage_chain_guard_receipt_digest
        ),
        "nested_target_resolution_receipt_digest": (
            value.nested_target_resolution_receipt_digest
        ),
        "target_shebang_requirements_receipt_digest": (
            value.target_shebang_requirements_receipt_digest
        ),
        "target_runtime_manifest_receipt_digest": (
            value.target_runtime_manifest_receipt_digest
        ),
        "target_staging_receipt_digest": (
            value.target_staging_receipt_digest
        ),
        "target_resolution_receipt_digest": (
            value.target_resolution_receipt_digest
        ),
        "nested_target_staging_context_digest": (
            value.nested_target_staging_context_digest
        ),
        "nested_target_staging_receipt_digest": (
            value.nested_target_staging_receipt_digest
        ),
        "total_content_bytes": value.total_content_bytes,
        "total_header_bytes": value.total_header_bytes,
        "verification_commands_digest": (
            value.verification_commands_digest
        ),
    }


def _runtime_manifest_evidence_projection(
    value: RepositoryExecutableShebangNestedTargetRuntimeManifestReceipt,
) -> dict[str, Any]:
    canonical = _BUILTIN_RUNTIME_MANIFEST_PROJECTION(value)
    counts = {
        classification: sum(
            item.classification == classification for item in value.files
        )
        for classification in _CLASSIFICATIONS
    }
    return {
        "action_receipt_issued": False,
        "active_nested_target_stage_lease_verified_at_measurement": True,
        "atomic_snapshot_verified": False,
        "authority_granted": False,
        "authorization_verified": False,
        "billing_eligible": False,
        "bounded_header_measurement_complete": True,
        "bounded_shebang_syntax_classification_complete": True,
        "capacity_eligible": False,
        "circuit_eligible": False,
        "command_count": value.command_count,
        "current_lease_activity_verified": False,
        "current_source_freshness_verified": False,
        "dependency_environment_coverage_verified": False,
        "known_chain_guard_runtime_inspected_count": (
            value.known_chain_guard_runtime_inspected_count
        ),
        "dispatch_enabled": False,
        "durable_control_plane_persistence_enabled": False,
        "dynamic_loader_identity_verified": False,
        "effect_class": 0,
        "effective_interpreter_resolution_verified": False,
        "effective_invocability_verified": False,
        "elf_file_count": counts["elf"],
        "environment_coverage_verified": False,
        "exact_nested_target_staging_correspondence_verified": True,
        "execution_enabled": False,
        "external_hardlink_alias_excluded": False,
        "external_writable_descriptor_absence_verified": False,
        "file_count": value.file_count,
        "filesystem_immutability_verified": False,
        "fixed_runtime_format_classification_complete": True,
        "fork_descriptor_inheritance_excluded": False,
        "future_execution_correspondence_verified": False,
        "hardlink_alias_exclusion_verified": False,
        "harness_invocation_performed": False,
        "interpreter_argument_semantics_verified": False,
        "interpreter_authenticity_verified": False,
        "interpreter_compatibility_verified": False,
        "interpreter_identity_verified": False,
        "interpreter_provenance_verified": False,
        "kind": _FIXED_EVIDENCE_KIND,
        "lease_cleanup_performed": False,
        "lease_mutated": False,
        "live_execution_eligible": False,
        "mach_o_file_count": counts["mach_o"],
        "manifest_scope": value.manifest_scope,
        "manifest_source": value.manifest_source,
        "model_invocation_performed": False,
        "mount_alias_exclusion_verified": False,
        "nested_target_paths_exposed": False,
        "network_access_performed": False,
        "source_native_not_applicable_count": (
            value.source_native_not_applicable_count
        ),
        "target_native_not_applicable_count": (
            value.target_native_not_applicable_count
        ),
        "posix_shebang_file_count": counts["posix_shebang"],
        "proposal_lineage_extended": False,
        "receipt_authenticity_verified": False,
        "raw_headers_exposed": False,
        "receipt_digest": _BUILTIN_CANONICAL_DIGEST(canonical),
        "recursive_shebang_resolution_verified": False,
        "registration_digest": value.registration_digest,
        "repository_ref": value.repository_ref,
        "requirement_binding_correspondence_verified": True,
        "requirement_count": value.requirement_count,
        "resolution_context_digest": value.resolution_context_digest,
        "route_eligible": False,
        "runtime_manifest_complete": False,
        "same_uid_tamper_exclusion_verified": False,
        "schema_version": value.schema_version,
        "shared_library_identity_verified": False,
        "source_path_reopen_performed": False,
        "staged_byte_correspondence_verified": True,
        "staged_descriptor_full_remeasurement_complete": True,
        "staging_root_path_reopen_performed": False,
        "subprocess_invocation_performed": False,
        "target_path_reopen_performed": False,
        "target_resolution_receipt_digest": (
            value.target_resolution_receipt_digest
        ),
        "target_semantics_verified": False,
        "nested_target_staging_receipt_digest": (
            value.nested_target_staging_receipt_digest
        ),
        "toolchain_completeness_verified": False,
        "total_content_bytes": value.total_content_bytes,
        "total_header_bytes": value.total_header_bytes,
        "unknown_file_count": counts["unknown"],
        "unsupported_shebang_file_count": counts[
            "unsupported_shebang"
        ],
        "validation_mode": "read_only",
        "worktree_integration_enabled": False,
        "worker_enabled": False,
    }


# Freeze the complete canonical proof graph after every component exists.
# Callers may patch the public helper names for diagnostics, but the public
# inspection boundary below uses only these captured shipped implementations.
_BUILTIN_RUNTIME_FILE_REF_PROJECTION = _runtime_file_ref_projection
_BUILTIN_RUNTIME_FILE_PROJECTION = _runtime_file_projection
_BUILTIN_RUNTIME_REQUIREMENT_REF_PROJECTION = (
    _runtime_requirement_ref_projection
)
_BUILTIN_RUNTIME_REQUIREMENT_PROJECTION = _runtime_requirement_projection
_BUILTIN_RUNTIME_BINDING_PROJECTION = _runtime_binding_projection
_BUILTIN_TARGET_STAGED_FILE_PROJECTION = (
    _BUILTIN_NESTED_TARGET_STAGED_FILE_PROJECTION
)
_BUILTIN_TARGET_NOOP_STAGING_CONTEXT_DIGEST = (
    _BUILTIN_NESTED_TARGET_NOOP_CONTEXT_DIGEST
)
_BUILTIN_TARGET_STAGING_RECEIPT_PROJECTION = (
    _target_staging_receipt_projection
)
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
        if not chunk:
            raise _InvalidNestedTargetRuntimeManifest
        chunks.append(chunk)
        offset += len(chunk)
    header = b"".join(chunks)
    if len(header) != expected:
        raise _InvalidNestedTargetRuntimeManifest
    try:
        boundary_probe = _BUILTIN_PREAD(descriptor, 1, expected)
    except (BlockingIOError, InterruptedError, OSError):
        raise _InvalidNestedTargetRuntimeManifest from None
    if (
        content_bytes > expected
        and len(boundary_probe) != 1
    ) or (
        content_bytes <= expected
        and boundary_probe != b""
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
        directive_ref = _BUILTIN_CANONICAL_DIGEST(
            {
                "directive_hex": directive.hex(),
                "kind": (
                    "repository_executable_shebang_nested_target_"
                    "runtime_shebang_directive_ref"
                ),
                "schema_version": _FIXED_SCHEMA_VERSION,
                "nested_target_staged_file_ref": nested_target_staged_file_ref,
            }
        )
        return "posix_shebang", directive_ref
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
    if (
        magic in _MACH_O_MINIMUM_BYTES
        and len(header) >= _MACH_O_MINIMUM_BYTES[magic]
    ):
        return "mach_o", None
    return "unknown", None


def _root_context_matches(
    expected: RepositoryExecutableShebangNestedTargetStagingReceipt,
    lease: RepositoryExecutableShebangNestedTargetStageLease,
) -> bool:
    metadata = lease._root_metadata
    if not expected.staging_root_used:
        return (
            metadata is None
            and expected.nested_target_staging_context_digest
            == _BUILTIN_TARGET_NOOP_STAGING_CONTEXT_DIGEST()
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
                "repository_executable_shebang_nested_target_staging_context"
            ),
            "schema_version": 1,
            "staging_root_used": True,
            "staging_scope": _TARGET_STAGING_SCOPE,
        }
    )
    return context_digest == expected.nested_target_staging_context_digest


_BUILTIN_BOUNDED_SHEBANG_DIRECTIVE = _bounded_shebang_directive
_BUILTIN_CLASSIFY_HEADER = _classify_header
_BUILTIN_HEADER_DIGEST = _header_digest
_BUILTIN_ROOT_CONTEXT_MATCHES = _root_context_matches


def _active_target_stage_snapshot(
    expected_target_staging: Any,
    lease: Any,
) -> tuple[
    dict[str, Any],
    tuple[_RetainedStagedNestedTarget, ...],
]:
    if (
        type(expected_target_staging)
        is not _FIXED_TARGET_STAGING_RECEIPT_TYPE
        or type(lease) is not _FIXED_TARGET_STAGE_LEASE_TYPE
        or type(lease._owner_pid) is not int
        or lease._owner_pid <= 0
        or lease._owner_pid != _BUILTIN_GETPID()
        or type(lease._state) is not str
        or lease._state != "active"
        or lease._receipt is not expected_target_staging
        or lease._receipt is not lease._receipt_object_anchor
        or lease._cleanup_receipt is not None
        or lease._cleanup_receipt_digest_anchor is not None
        or lease._cleanup_receipt_object_anchor is not None
        or type(lease._receipt_digest_anchor) is not str
        or type(lease._receipt_file_refs_anchor) is not tuple
        or lease._root_descriptor is not None
        or lease._pending_name is not None
        or lease._pending_identity is not None
        or type(lease._pending_descriptors) is not tuple
        or lease._pending_descriptors != ()
        or lease._descriptor_release_unverifiable is not False
        or type(lease._files) is not tuple
        or lease._files is not lease._files_object_anchor
    ):
        raise _InvalidNestedTargetRuntimeManifest
    canonical = _BUILTIN_TARGET_STAGING_RECEIPT_PROJECTION(
        expected_target_staging
    )
    receipt_digest = _BUILTIN_CANONICAL_DIGEST(canonical)
    expected_refs = tuple(
        item.nested_target_staged_file_ref
        for item in expected_target_staging.staged_files
    )
    if (
        lease._receipt_digest_anchor != receipt_digest
        or lease._receipt_file_refs_anchor != expected_refs
        or len(lease._files) != expected_target_staging.unique_nested_target_count
        or not _BUILTIN_ROOT_CONTEXT_MATCHES(
            expected_target_staging,
            lease,
        )
        or any(
            type(item) is not _FIXED_RETAINED_TARGET_TYPE
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
                expected_target_staging.staged_files,
                strict=True,
            )
        )
    ):
        raise _InvalidNestedTargetRuntimeManifest
    return canonical, lease._files


def _verify_anchored_retained_target(
    retained: _RetainedStagedNestedTarget,
    anchored: dict[str, Any],
    *,
    nested_target_staging_context_digest: str,
) -> bytes:
    """Remeasure one descriptor and return its digest-corresponding header."""

    if (
        type(retained) is not _FIXED_RETAINED_TARGET_TYPE
        or type(anchored) is not dict
        or _BUILTIN_TARGET_STAGED_FILE_PROJECTION(
            retained.staged_file,
            staging_context_digest=(
                nested_target_staging_context_digest
            ),
        )
        != anchored
    ):
        raise _InvalidNestedTargetRuntimeManifest
    try:
        before = _BUILTIN_FSTAT(retained.descriptor)
        before_flags = _BUILTIN_FCNTL(
            retained.descriptor,
            _BUILTIN_F_GETFL,
        )
        before_inheritable = _BUILTIN_GET_INHERITABLE(
            retained.descriptor
        )
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
        or before.st_size != anchored["content_bytes"]
        or before_flags & _BUILTIN_O_ACCMODE != _BUILTIN_O_RDONLY
        or before_inheritable
    ):
        raise _InvalidNestedTargetRuntimeManifest

    staged_identity_ref = _BUILTIN_CANONICAL_DIGEST(
        {
            "device": before.st_dev,
            "inode": before.st_ino,
            "kind": (
                "repository_executable_shebang_nested_target_"
                "staged_file_identity"
            ),
            "schema_version": 1,
        }
    )
    staged_metadata_digest = _BUILTIN_CANONICAL_DIGEST(
        {
            "change_time_ns": before.st_ctime_ns,
            "filesystem_identity_ref": staged_identity_ref,
            "group_id": before.st_gid,
            "kind": (
                "repository_executable_shebang_nested_target_"
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
        staged_identity_ref != anchored["staged_filesystem_identity_ref"]
        or staged_metadata_digest != anchored["staged_metadata_digest"]
    ):
        raise _InvalidNestedTargetRuntimeManifest

    digest = _BUILTIN_SHA256()
    header_parts: list[bytes] = []
    header_remaining = min(anchored["content_bytes"], _MAX_HEADER_BYTES)
    offset = 0
    while offset < anchored["content_bytes"]:
        requested = min(
            _FULL_REMEASUREMENT_CHUNK_BYTES,
            anchored["content_bytes"] - offset,
        )
        try:
            chunk = _BUILTIN_PREAD(
                retained.descriptor,
                requested,
                offset,
            )
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
        if (
            _BUILTIN_PREAD(
                retained.descriptor,
                1,
                anchored["content_bytes"],
            )
            != b""
        ):
            raise _InvalidNestedTargetRuntimeManifest
        after = _BUILTIN_FSTAT(retained.descriptor)
        after_flags = _BUILTIN_FCNTL(
            retained.descriptor,
            _BUILTIN_F_GETFL,
        )
        after_inheritable = _BUILTIN_GET_INHERITABLE(
            retained.descriptor
        )
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
    content_digest = _DIGEST_PREFIX + digest.hexdigest()
    if (
        after_signature != before_signature
        or after_flags != before_flags
        or after_inheritable != before_inheritable
        or header_remaining != 0
        or len(header)
        != min(anchored["content_bytes"], _MAX_HEADER_BYTES)
        or content_digest != anchored["content_digest"]
    ):
        raise _InvalidNestedTargetRuntimeManifest
    return header


def _build_runtime_file(
    staged_file: dict[str, Any],
    header: bytes,
) -> RepositoryExecutableShebangNestedTargetRuntimeFile:
    classification, directive_ref = _BUILTIN_CLASSIFY_HEADER(
        staged_file["nested_target_staged_file_ref"],
        header,
    )
    header_digest = _BUILTIN_HEADER_DIGEST(
        staged_file["nested_target_staged_file_ref"],
        header,
    )
    reference = _BUILTIN_RUNTIME_FILE_REF_PROJECTION(
        nested_target_staged_file_ref=staged_file["nested_target_staged_file_ref"],
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
        kind=_FIXED_FILE_KIND,
        nested_target_staged_file_ref=staged_file["nested_target_staged_file_ref"],
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
    runtime_file_by_staged_ref: dict[
        str, RepositoryExecutableShebangNestedTargetRuntimeFile
    ],
) -> RepositoryExecutableShebangNestedTargetRuntimeRequirement:
    if staged["disposition"] == "known_chain_guard_staged":
        if staged["nested_target_staged_file_ref"] is None:
            raise _InvalidNestedTargetRuntimeManifest
        runtime_file = runtime_file_by_staged_ref.get(
            staged["nested_target_staged_file_ref"]
        )
        if runtime_file is None:
            raise _InvalidNestedTargetRuntimeManifest
        disposition = "known_chain_guard_runtime_inspected"
        runtime_classification = runtime_file.classification
        nested_target_runtime_file_ref = runtime_file.nested_target_runtime_file_ref
    elif staged["disposition"] in {
        "source_native_not_applicable",
        "target_native_not_applicable",
    }:
        disposition = staged["disposition"]
        runtime_classification = "not_applicable"
        nested_target_runtime_file_ref = None
    else:
        raise _InvalidNestedTargetRuntimeManifest
    reference = _BUILTIN_RUNTIME_REQUIREMENT_REF_PROJECTION(
        staged_file_ref=staged["staged_file_ref"],
        runtime_file_ref=staged["runtime_file_ref"],
        requirement_ref=staged["requirement_ref"],
        target_requirement_ref=staged["target_requirement_ref"],
        target_stage_requirement_ref=staged[
            "target_stage_requirement_ref"
        ],
        target_runtime_requirement_ref=staged[
            "target_runtime_requirement_ref"
        ],
        target_shebang_requirement_ref=staged[
            "target_shebang_requirement_ref"
        ],
        nested_target_requirement_ref=staged[
            "nested_target_requirement_ref"
        ],
        chain_guard_requirement_ref=staged[
            "chain_guard_requirement_ref"
        ],
        nested_target_stage_requirement_ref=staged[
            "nested_target_stage_requirement_ref"
        ],
        runtime_classification=runtime_classification,
        disposition=disposition,
        nested_target_measurement_ref=staged["nested_target_measurement_ref"],
        guarded_measurement_ref=staged["guarded_measurement_ref"],
        nested_target_staged_file_ref=staged["nested_target_staged_file_ref"],
        nested_target_runtime_file_ref=nested_target_runtime_file_ref,
    )
    value = _FIXED_RUNTIME_REQUIREMENT_TYPE(
        kind=_FIXED_REQUIREMENT_KIND,
        staged_file_ref=staged["staged_file_ref"],
        runtime_file_ref=staged["runtime_file_ref"],
        requirement_ref=staged["requirement_ref"],
        target_requirement_ref=staged["target_requirement_ref"],
        target_stage_requirement_ref=staged[
            "target_stage_requirement_ref"
        ],
        target_runtime_requirement_ref=staged[
            "target_runtime_requirement_ref"
        ],
        target_shebang_requirement_ref=staged[
            "target_shebang_requirement_ref"
        ],
        nested_target_requirement_ref=staged[
            "nested_target_requirement_ref"
        ],
        chain_guard_requirement_ref=staged[
            "chain_guard_requirement_ref"
        ],
        nested_target_stage_requirement_ref=staged[
            "nested_target_stage_requirement_ref"
        ],
        runtime_classification=runtime_classification,
        disposition=disposition,
        nested_target_measurement_ref=staged["nested_target_measurement_ref"],
        guarded_measurement_ref=staged["guarded_measurement_ref"],
        nested_target_staged_file_ref=staged["nested_target_staged_file_ref"],
        nested_target_runtime_file_ref=nested_target_runtime_file_ref,
        nested_target_runtime_requirement_ref=_BUILTIN_CANONICAL_DIGEST(reference),
    )
    _BUILTIN_RUNTIME_REQUIREMENT_PROJECTION(value)
    return value


_BUILTIN_ACTIVE_TARGET_STAGE_SNAPSHOT = _active_target_stage_snapshot
_BUILTIN_VERIFY_ANCHORED_RETAINED_TARGET = (
    _verify_anchored_retained_target
)
_BUILTIN_READ_EXACT_HEADER = _read_exact_header
_BUILTIN_BUILD_RUNTIME_FILE = _build_runtime_file
_BUILTIN_BUILD_RUNTIME_REQUIREMENT = _build_runtime_requirement


def inspect_staged_executable_shebang_nested_target_runtime_manifest(
    expected_nested_target_staging: (
        RepositoryExecutableShebangNestedTargetStagingReceipt
    ),
    *,
    lease: RepositoryExecutableShebangNestedTargetStageLease,
) -> RepositoryExecutableShebangNestedTargetRuntimeManifestReceipt:
    """Inspect one exact active nested-target stage without mutating its lease."""

    try:
        staging_canonical, retained_files = (
            _BUILTIN_ACTIVE_TARGET_STAGE_SNAPSHOT(
                expected_nested_target_staging,
                lease,
            )
        )
        staged_files = tuple(
            dict(item) for item in staging_canonical["staged_files"]
        )
        staged_requirements = tuple(
            dict(item) for item in staging_canonical["requirements"]
        )
        staged_bindings = tuple(
            dict(item) for item in staging_canonical["bindings"]
        )
        nested_target_staging_context_digest = staging_canonical[
            "nested_target_staging_context_digest"
        ]
        runtime_files: list[
            RepositoryExecutableShebangNestedTargetRuntimeFile
        ] = []
        for retained, anchored in zip(
            retained_files,
            staged_files,
            strict=True,
        ):
            remeasured_header = _BUILTIN_VERIFY_ANCHORED_RETAINED_TARGET(
                retained,
                anchored,
                nested_target_staging_context_digest=(
                    nested_target_staging_context_digest
                ),
            )
            header = _BUILTIN_READ_EXACT_HEADER(
                retained.descriptor,
                anchored["content_bytes"],
            )
            if header != remeasured_header:
                raise _InvalidNestedTargetRuntimeManifest
            runtime_files.append(
                _BUILTIN_BUILD_RUNTIME_FILE(anchored, header)
            )

        final_canonical, final_retained_files = (
            _BUILTIN_ACTIVE_TARGET_STAGE_SNAPSHOT(
                expected_nested_target_staging,
                lease,
            )
        )
        if (
            final_canonical != staging_canonical
            or final_retained_files is not retained_files
        ):
            raise _InvalidNestedTargetRuntimeManifest
        for retained, anchored in zip(
            final_retained_files,
            staged_files,
            strict=True,
        ):
            _BUILTIN_VERIFY_ANCHORED_RETAINED_TARGET(
                retained,
                anchored,
                nested_target_staging_context_digest=(
                    nested_target_staging_context_digest
                ),
            )

        runtime_file_by_staged_ref = {
            item.nested_target_staged_file_ref: item for item in runtime_files
        }
        runtime_requirements = tuple(
            _BUILTIN_BUILD_RUNTIME_REQUIREMENT(
                item,
                runtime_file_by_staged_ref=runtime_file_by_staged_ref,
            )
            for item in staged_requirements
        )
        requirement_by_stage_ref = {
            item.nested_target_stage_requirement_ref: item
            for item in runtime_requirements
        }
        runtime_bindings: list[
            RepositoryExecutableShebangNestedTargetRuntimeBinding
        ] = []
        for staged_binding in staged_bindings:
            if staged_binding["kind"] != _TARGET_STAGE_BINDING_KIND:
                raise _InvalidNestedTargetRuntimeManifest
            requirement = requirement_by_stage_ref.get(
                staged_binding["nested_target_stage_requirement_ref"]
            )
            if requirement is None:
                raise _InvalidNestedTargetRuntimeManifest
            runtime_bindings.append(
                _FIXED_RUNTIME_BINDING_TYPE(
                    kind=_FIXED_BINDING_KIND,
                    command_kind=staged_binding["command_kind"],
                    command_id=staged_binding["command_id"],
                    command_digest=staged_binding["command_digest"],
                    staged_file_ref=staged_binding["staged_file_ref"],
                    runtime_file_ref=staged_binding["runtime_file_ref"],
                    requirement_ref=staged_binding["requirement_ref"],
                    target_requirement_ref=(
                        staged_binding["target_requirement_ref"]
                    ),
                    target_stage_requirement_ref=(
                        staged_binding["target_stage_requirement_ref"]
                    ),
                    target_runtime_requirement_ref=(
                        staged_binding["target_runtime_requirement_ref"]
                    ),
                    target_shebang_requirement_ref=(
                        staged_binding["target_shebang_requirement_ref"]
                    ),
                    nested_target_requirement_ref=(
                        staged_binding["nested_target_requirement_ref"]
                    ),
                    chain_guard_requirement_ref=(
                        staged_binding["chain_guard_requirement_ref"]
                    ),
                    nested_target_stage_requirement_ref=(
                        staged_binding["nested_target_stage_requirement_ref"]
                    ),
                    nested_target_runtime_requirement_ref=(
                        requirement.nested_target_runtime_requirement_ref
                    ),
                )
            )

        receipt = (
            _FIXED_RUNTIME_MANIFEST_RECEIPT_TYPE(
                kind=_FIXED_MANIFEST_KIND,
                schema_version=_FIXED_SCHEMA_VERSION,
                manifest_source=_FIXED_MANIFEST_SOURCE,
                manifest_scope=_FIXED_MANIFEST_SCOPE,
                nested_target_staging_receipt_digest=(
                    _BUILTIN_CANONICAL_DIGEST(staging_canonical)
                ),
                nested_target_resolution_receipt_digest=(
                    staging_canonical[
                        "nested_target_resolution_receipt_digest"
                    ]
                ),
                expected_chain_guard_receipt_digest=(
                    staging_canonical[
                        "expected_chain_guard_receipt_digest"
                    ]
                ),
                action_chain_guard_receipt_digest=(
                    staging_canonical[
                        "action_chain_guard_receipt_digest"
                    ]
                ),
                post_stage_chain_guard_receipt_digest=(
                    staging_canonical[
                        "post_stage_chain_guard_receipt_digest"
                    ]
                ),
                target_shebang_requirements_receipt_digest=(
                    staging_canonical[
                        "target_shebang_requirements_receipt_digest"
                    ]
                ),
                target_runtime_manifest_receipt_digest=(
                    staging_canonical[
                        "target_runtime_manifest_receipt_digest"
                    ]
                ),
                target_staging_receipt_digest=(
                    staging_canonical["target_staging_receipt_digest"]
                ),
                target_resolution_receipt_digest=(
                    staging_canonical["target_resolution_receipt_digest"]
                ),
                shebang_requirements_receipt_digest=(
                    staging_canonical[
                        "shebang_requirements_receipt_digest"
                    ]
                ),
                runtime_manifest_receipt_digest=(
                    staging_canonical["runtime_manifest_receipt_digest"]
                ),
                source_staging_receipt_digest=(
                    staging_canonical["source_staging_receipt_digest"]
                ),
                registration_digest=(
                    staging_canonical["registration_digest"]
                ),
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
                target_path_context_digest=(
                    staging_canonical["target_path_context_digest"]
                ),
                target_staging_context_digest=(
                    staging_canonical["target_staging_context_digest"]
                ),
                nested_target_path_context_digest=(
                    staging_canonical["nested_target_path_context_digest"]
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
                nested_target_staging_context_digest=(
                    staging_canonical["nested_target_staging_context_digest"]
                ),
                files=tuple(runtime_files),
                requirements=runtime_requirements,
                bindings=tuple(runtime_bindings),
                file_count=len(runtime_files),
                requirement_count=len(runtime_requirements),
                command_count=len(runtime_bindings),
                known_chain_guard_runtime_inspected_count=(
                    staging_canonical[
                        "known_chain_guard_staged_count"
                    ]
                ),
                source_native_not_applicable_count=(
                    staging_canonical[
                        "source_native_not_applicable_count"
                    ]
                ),
                target_native_not_applicable_count=(
                    staging_canonical[
                        "target_native_not_applicable_count"
                    ]
                ),
                total_content_bytes=sum(
                    item.content_bytes for item in runtime_files
                ),
                total_header_bytes=sum(
                    item.header_bytes for item in runtime_files
                ),
            )
        )
        _BUILTIN_RUNTIME_MANIFEST_PROJECTION(receipt)
        closing_canonical, closing_retained_files = (
            _BUILTIN_ACTIVE_TARGET_STAGE_SNAPSHOT(
                expected_nested_target_staging,
                lease,
            )
        )
        if (
            closing_canonical != staging_canonical
            or closing_retained_files is not retained_files
        ):
            raise _InvalidNestedTargetRuntimeManifest
        return receipt
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise _FIXED_VALIDATION_ERROR(_INVALID_MESSAGE) from None


__all__ = [
    "MANIFEST_SCOPE",
    "MANIFEST_SOURCE",
    "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RUNTIME_BINDING_KIND",
    "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RUNTIME_FILE_KIND",
    "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RUNTIME_MANIFEST_EVIDENCE_KIND",
    "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RUNTIME_MANIFEST_KIND",
    "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RUNTIME_MANIFEST_SCHEMA_VERSION",
    "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RUNTIME_REQUIREMENT_KIND",
    "RepositoryExecutableShebangNestedTargetRuntimeBinding",
    "RepositoryExecutableShebangNestedTargetRuntimeFile",
    "RepositoryExecutableShebangNestedTargetRuntimeManifestReceipt",
    "RepositoryExecutableShebangNestedTargetRuntimeRequirement",
    "inspect_staged_executable_shebang_nested_target_runtime_manifest",
]
