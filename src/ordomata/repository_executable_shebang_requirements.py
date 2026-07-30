"""Digest-only shebang requirements from one active executable stage.

This Class 0 boundary consumes the exact staged runtime-manifest receipt and
reproduces it from the same active process-local lease.  For each bounded
``posix_shebang`` directive it records only content-addressed references to the
interpreter token and opaque argument tail.  It deliberately does not resolve
paths, interpret launcher or kernel semantics, mutate the lease, or execute a
process.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
import re
from typing import Any

from .authorization import canonical_digest
from .errors import ValidationError
from .repository_executable_runtime_manifest import (
    MANIFEST_SCOPE as RUNTIME_MANIFEST_SCOPE,
    MANIFEST_SOURCE as RUNTIME_MANIFEST_SOURCE,
    REPOSITORY_EXECUTABLE_RUNTIME_BINDING_KIND,
    REPOSITORY_EXECUTABLE_RUNTIME_FILE_KIND,
    REPOSITORY_EXECUTABLE_RUNTIME_MANIFEST_KIND,
    REPOSITORY_EXECUTABLE_RUNTIME_MANIFEST_SCHEMA_VERSION,
    RepositoryExecutableRuntimeBinding,
    RepositoryExecutableRuntimeFile,
    RepositoryExecutableRuntimeManifestReceipt,
    _active_stage_snapshot,
    _verify_anchored_retained_file,
    inspect_staged_executable_runtime_manifest,
)
from .repository_executable_staging import (
    REPOSITORY_EXECUTABLE_STAGE_BINDING_KIND,
    REPOSITORY_EXECUTABLE_STAGED_FILE_KIND,
    REPOSITORY_EXECUTABLE_STAGING_KIND,
    REPOSITORY_EXECUTABLE_STAGING_SCHEMA_VERSION,
    STAGING_SCOPE,
    STAGING_SOURCE,
    RepositoryExecutableStageBinding,
    RepositoryExecutableStageLease,
    RepositoryExecutableStagedFile,
    RepositoryExecutableStagingReceipt,
)
from .repository_executable_resolution import (
    MEASUREMENT_SOURCE as STAGING_MEASUREMENT_SOURCE,
    REPOSITORY_EXECUTABLE_RESOLUTION_SCOPE as STAGING_RESOLUTION_SCOPE,
)


REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENTS_SCHEMA_VERSION = 1
REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENTS_KIND = (
    "repository_executable_shebang_requirements"
)
REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENTS_EVIDENCE_KIND = (
    "repository_executable_shebang_requirements_validation"
)
REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENT_KIND = (
    "repository_executable_shebang_requirement"
)
REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENT_BINDING_KIND = (
    "repository_executable_shebang_requirement_binding"
)
REQUIREMENTS_SOURCE = "controller_inspected"
REQUIREMENTS_SCOPE = "posix_staged_shebang_requirements_v1"

_INVALID_MESSAGE = "repository executable shebang requirements are invalid"
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
_DISPOSITIONS = (
    "native_binary_no_shebang",
    "absolute_interpreter_token",
    "non_absolute_interpreter_token",
    "unsupported_shebang",
    "unknown_runtime_format",
)
_MAX_FILES = 80
_MAX_COMMANDS = 80
_MAX_DIRECTIVE_BYTES = 255
_MAX_HEADER_BYTES = 4_096
_MAX_RUNTIME_FILE_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_RUNTIME_BYTES = 256 * 1024 * 1024
_MAX_TOTAL_REQUIREMENT_BYTES = _MAX_FILES * _MAX_DIRECTIVE_BYTES
_FULL_REMEASUREMENT_CHUNK_BYTES = 1024 * 1024
_MACH_O_MAGICS = frozenset(
    {
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf",
        b"\xbf\xba\xfe\xca",
    }
)
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

# Hold the shipped proof boundaries.  Public dataclass methods and module
# attributes remain patchable and are not accepted as canonical input here.
_BUILTIN_CANONICAL_DIGEST = canonical_digest
_BUILTIN_SHA256 = hashlib.sha256
_BUILTIN_PREAD = os.pread
_BUILTIN_GETPID = os.getpid
_BUILTIN_INSPECT_RUNTIME_MANIFEST = (
    inspect_staged_executable_runtime_manifest
)
_BUILTIN_ACTIVE_STAGE_SNAPSHOT = _active_stage_snapshot
_BUILTIN_VERIFY_RETAINED_FILE = _verify_anchored_retained_file


class _InvalidShebangRequirements(ValueError):
    """Internal invalid-input sentinel with no public details."""


@dataclass(frozen=True, slots=True)
class RepositoryExecutableShebangRequirement:
    """One runtime file's bounded, non-resolving shebang requirement."""

    kind: str
    staged_file_ref: str = field(repr=False)
    runtime_file_ref: str = field(repr=False)
    runtime_classification: str
    disposition: str
    shebang_directive_ref: str | None = field(repr=False)
    interpreter_token_ref: str | None = field(repr=False)
    interpreter_token_bytes: int
    argument_separator_kind: str | None
    argument_tail_ref: str | None = field(repr=False)
    argument_tail_bytes: int
    requirement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _requirement_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableShebangRequirementBinding:
    """One registered command bound to one shebang requirement record."""

    kind: str
    command_kind: str
    command_id: str = field(repr=False)
    command_digest: str = field(repr=False)
    staged_file_ref: str = field(repr=False)
    runtime_file_ref: str = field(repr=False)
    requirement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _binding_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableShebangRequirementsReceipt:
    """Historical evidence from one active-lease shebang inspection."""

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
    requirements: tuple[RepositoryExecutableShebangRequirement, ...] = field(
        repr=False
    )
    bindings: tuple[
        RepositoryExecutableShebangRequirementBinding, ...
    ] = field(repr=False)
    requirement_count: int
    command_count: int
    posix_shebang_requirement_count: int
    argument_tail_requirement_count: int
    total_interpreter_token_bytes: int
    total_argument_tail_bytes: int

    def to_canonical(self) -> dict[str, Any]:
        return _receipt_projection(self)

    @property
    def receipt_digest(self) -> str:
        return _BUILTIN_CANONICAL_DIGEST(_receipt_projection(self))

    def to_evidence(self) -> dict[str, Any]:
        return _evidence_projection(self)


def _is_digest(value: Any) -> bool:
    return type(value) is str and _DIGEST_PATTERN.fullmatch(value) is not None


def _independent_staged_file_projection(
    value: RepositoryExecutableStagedFile,
) -> dict[str, Any]:
    if (
        type(value) is not RepositoryExecutableStagedFile
        or type(value.kind) is not str
        or value.kind != REPOSITORY_EXECUTABLE_STAGED_FILE_KIND
        or not _is_digest(value.source_filesystem_identity_ref)
        or not _is_digest(value.source_metadata_digest)
        or not _is_digest(value.staged_file_ref)
        or not _is_digest(value.staged_filesystem_identity_ref)
        or not _is_digest(value.staged_metadata_digest)
        or not _is_digest(value.content_digest)
        or type(value.content_bytes) is not int
        or not 0 <= value.content_bytes <= _MAX_RUNTIME_FILE_BYTES
    ):
        raise _InvalidShebangRequirements
    return {
        "content_bytes": value.content_bytes,
        "content_digest": value.content_digest,
        "kind": value.kind,
        "source_filesystem_identity_ref": (
            value.source_filesystem_identity_ref
        ),
        "source_metadata_digest": value.source_metadata_digest,
        "staged_file_ref": value.staged_file_ref,
        "staged_filesystem_identity_ref": (
            value.staged_filesystem_identity_ref
        ),
        "staged_metadata_digest": value.staged_metadata_digest,
    }


def _independent_stage_binding_projection(
    value: RepositoryExecutableStageBinding,
) -> dict[str, Any]:
    if (
        type(value) is not RepositoryExecutableStageBinding
        or type(value.kind) is not str
        or value.kind != REPOSITORY_EXECUTABLE_STAGE_BINDING_KIND
        or type(value.command_kind) is not str
        or value.command_kind not in _COMMAND_KINDS
        or type(value.command_id) is not str
        or _IDENTIFIER_PATTERN.fullmatch(value.command_id) is None
        or not _is_digest(value.command_digest)
        or not _is_digest(value.declared_executable_ref)
        or not _is_digest(value.resolved_executable_ref)
        or not _is_digest(value.staged_file_ref)
    ):
        raise _InvalidShebangRequirements
    return {
        "command_digest": value.command_digest,
        "command_id": value.command_id,
        "command_kind": value.command_kind,
        "declared_executable_ref": value.declared_executable_ref,
        "kind": value.kind,
        "resolved_executable_ref": value.resolved_executable_ref,
        "staged_file_ref": value.staged_file_ref,
    }


def _independent_staging_receipt_projection(
    value: RepositoryExecutableStagingReceipt,
) -> dict[str, Any]:
    digest_fields = (
        value.registration_digest,
        value.repository_ref,
        value.verification_commands_digest,
        value.baseline_command_results_digest,
        value.executable_toolchain_identities_digest,
        value.resolution_context_digest,
        value.expected_resolution_receipt_digest,
        value.action_resolution_receipt_digest,
        value.post_stage_resolution_receipt_digest,
        value.staging_context_digest,
    )
    if (
        type(value) is not RepositoryExecutableStagingReceipt
        or type(value.kind) is not str
        or value.kind != REPOSITORY_EXECUTABLE_STAGING_KIND
        or type(value.schema_version) is not int
        or value.schema_version
        != REPOSITORY_EXECUTABLE_STAGING_SCHEMA_VERSION
        or type(value.measurement_source) is not str
        or value.measurement_source != STAGING_MEASUREMENT_SOURCE
        or type(value.resolution_scope) is not str
        or value.resolution_scope != STAGING_RESOLUTION_SCOPE
        or type(value.staging_source) is not str
        or value.staging_source != STAGING_SOURCE
        or type(value.staging_scope) is not str
        or value.staging_scope != STAGING_SCOPE
        or not all(_is_digest(item) for item in digest_fields)
        or value.expected_resolution_receipt_digest
        != value.action_resolution_receipt_digest
        or value.action_resolution_receipt_digest
        != value.post_stage_resolution_receipt_digest
        or type(value.staged_files) is not tuple
        or not 1 <= len(value.staged_files) <= _MAX_FILES
        or type(value.bindings) is not tuple
        or not 1 <= len(value.bindings) <= _MAX_COMMANDS
        or type(value.unique_file_count) is not int
        or value.unique_file_count != len(value.staged_files)
        or type(value.total_staged_bytes) is not int
        or not 0
        <= value.total_staged_bytes
        <= _MAX_TOTAL_RUNTIME_BYTES
    ):
        raise _InvalidShebangRequirements

    staged_files = [
        _independent_staged_file_projection(item)
        for item in value.staged_files
    ]
    bindings = [
        _independent_stage_binding_projection(item)
        for item in value.bindings
    ]
    file_by_ref: dict[str, RepositoryExecutableStagedFile] = {}
    source_refs: set[str] = set()
    total_staged_bytes = 0
    for staged_file in value.staged_files:
        if (
            staged_file.staged_file_ref in file_by_ref
            or staged_file.source_filesystem_identity_ref in source_refs
        ):
            raise _InvalidShebangRequirements
        file_by_ref[staged_file.staged_file_ref] = staged_file
        source_refs.add(staged_file.source_filesystem_identity_ref)
        total_staged_bytes += staged_file.content_bytes

    command_ids: set[str] = set()
    bound_refs: set[str] = set()
    ordered_bound_refs: list[str] = []
    prior_kind_index = -1
    for binding in value.bindings:
        kind_index = _COMMAND_KINDS.index(binding.command_kind)
        if (
            kind_index < prior_kind_index
            or binding.command_id in command_ids
            or binding.staged_file_ref not in file_by_ref
        ):
            raise _InvalidShebangRequirements
        command_ids.add(binding.command_id)
        if binding.staged_file_ref not in bound_refs:
            ordered_bound_refs.append(binding.staged_file_ref)
        bound_refs.add(binding.staged_file_ref)
        prior_kind_index = kind_index
    if (
        total_staged_bytes != value.total_staged_bytes
        or bound_refs != set(file_by_ref)
        or tuple(ordered_bound_refs)
        != tuple(item.staged_file_ref for item in value.staged_files)
    ):
        raise _InvalidShebangRequirements
    return {
        "action_resolution_receipt_digest": (
            value.action_resolution_receipt_digest
        ),
        "baseline_command_results_digest": (
            value.baseline_command_results_digest
        ),
        "bindings": bindings,
        "executable_toolchain_identities_digest": (
            value.executable_toolchain_identities_digest
        ),
        "expected_resolution_receipt_digest": (
            value.expected_resolution_receipt_digest
        ),
        "kind": value.kind,
        "measurement_source": value.measurement_source,
        "post_stage_resolution_receipt_digest": (
            value.post_stage_resolution_receipt_digest
        ),
        "registration_digest": value.registration_digest,
        "repository_ref": value.repository_ref,
        "resolution_context_digest": value.resolution_context_digest,
        "resolution_scope": value.resolution_scope,
        "schema_version": value.schema_version,
        "staged_files": staged_files,
        "staging_context_digest": value.staging_context_digest,
        "staging_scope": value.staging_scope,
        "staging_source": value.staging_source,
        "total_staged_bytes": value.total_staged_bytes,
        "unique_file_count": value.unique_file_count,
        "verification_commands_digest": value.verification_commands_digest,
    }


def _verify_independent_lease_anchor(
    expected_staging: RepositoryExecutableStagingReceipt,
    lease: RepositoryExecutableStageLease,
    *,
    staging_canonical: dict[str, Any],
    staging_digest: str,
) -> None:
    if (
        type(lease) is not RepositoryExecutableStageLease
        or type(lease._owner_pid) is not int
        or lease._owner_pid != _BUILTIN_GETPID()
        or lease._state != "active"
        or type(lease._receipt) is not RepositoryExecutableStagingReceipt
        or lease._cleanup_receipt is not None
        or lease._cleanup_receipt_digest_anchor is not None
        or type(lease._receipt_digest_anchor) is not str
        or lease._receipt_digest_anchor != staging_digest
        or type(lease._receipt_staged_file_refs_anchor) is not tuple
        or lease._receipt_staged_file_refs_anchor
        != tuple(item.staged_file_ref for item in expected_staging.staged_files)
        or lease._root_descriptor is not None
        or lease._pending_name is not None
        or lease._pending_identity is not None
        or type(lease._pending_descriptors) is not tuple
        or lease._pending_descriptors != ()
        or lease._descriptor_release_unverifiable is not False
        or type(lease._files) is not tuple
        or _independent_staging_receipt_projection(lease._receipt)
        != staging_canonical
    ):
        raise _InvalidShebangRequirements


def _independent_runtime_file_ref_projection(
    value: RepositoryExecutableRuntimeFile,
) -> dict[str, Any]:
    return {
        "classification": value.classification,
        "content_bytes": value.content_bytes,
        "content_digest": value.content_digest,
        "header_bytes": value.header_bytes,
        "header_digest": value.header_digest,
        "kind": "repository_executable_runtime_file_ref",
        "manifest_scope": RUNTIME_MANIFEST_SCOPE,
        "schema_version": (
            REPOSITORY_EXECUTABLE_RUNTIME_MANIFEST_SCHEMA_VERSION
        ),
        "shebang_directive_ref": value.shebang_directive_ref,
        "staged_file_ref": value.staged_file_ref,
        "staged_filesystem_identity_ref": (
            value.staged_filesystem_identity_ref
        ),
    }


def _independent_runtime_file_projection(
    value: RepositoryExecutableRuntimeFile,
) -> dict[str, Any]:
    if (
        type(value) is not RepositoryExecutableRuntimeFile
        or type(value.kind) is not str
        or value.kind != REPOSITORY_EXECUTABLE_RUNTIME_FILE_KIND
        or not _is_digest(value.staged_file_ref)
        or not _is_digest(value.staged_filesystem_identity_ref)
        or not _is_digest(value.content_digest)
        or type(value.content_bytes) is not int
        or not 0 <= value.content_bytes <= _MAX_RUNTIME_FILE_BYTES
        or not _is_digest(value.runtime_file_ref)
        or not _is_digest(value.header_digest)
        or type(value.header_bytes) is not int
        or not 0 <= value.header_bytes <= _MAX_HEADER_BYTES
        or value.header_bytes != min(value.content_bytes, _MAX_HEADER_BYTES)
        or type(value.classification) is not str
        or value.classification not in _RUNTIME_CLASSIFICATIONS
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
            and not _is_digest(value.shebang_directive_ref)
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
        raise _InvalidShebangRequirements
    reference = _independent_runtime_file_ref_projection(value)
    if value.runtime_file_ref != _BUILTIN_CANONICAL_DIGEST(reference):
        raise _InvalidShebangRequirements
    return {
        "classification": value.classification,
        "content_bytes": value.content_bytes,
        "content_digest": value.content_digest,
        "header_bytes": value.header_bytes,
        "header_digest": value.header_digest,
        "kind": value.kind,
        "runtime_file_ref": value.runtime_file_ref,
        "shebang_directive_ref": value.shebang_directive_ref,
        "staged_file_ref": value.staged_file_ref,
        "staged_filesystem_identity_ref": (
            value.staged_filesystem_identity_ref
        ),
    }


def _independent_runtime_binding_projection(
    value: RepositoryExecutableRuntimeBinding,
) -> dict[str, Any]:
    if (
        type(value) is not RepositoryExecutableRuntimeBinding
        or type(value.kind) is not str
        or value.kind != REPOSITORY_EXECUTABLE_RUNTIME_BINDING_KIND
        or type(value.command_kind) is not str
        or value.command_kind not in _COMMAND_KINDS
        or type(value.command_id) is not str
        or _IDENTIFIER_PATTERN.fullmatch(value.command_id) is None
        or not _is_digest(value.command_digest)
        or not _is_digest(value.staged_file_ref)
        or not _is_digest(value.runtime_file_ref)
    ):
        raise _InvalidShebangRequirements
    return {
        "command_digest": value.command_digest,
        "command_id": value.command_id,
        "command_kind": value.command_kind,
        "kind": value.kind,
        "runtime_file_ref": value.runtime_file_ref,
        "staged_file_ref": value.staged_file_ref,
    }


def _independent_runtime_manifest_projection(
    value: RepositoryExecutableRuntimeManifestReceipt,
) -> dict[str, Any]:
    digest_fields = (
        value.staging_receipt_digest,
        value.registration_digest,
        value.repository_ref,
        value.verification_commands_digest,
        value.resolution_context_digest,
        value.staging_context_digest,
    )
    if (
        type(value) is not RepositoryExecutableRuntimeManifestReceipt
        or type(value.kind) is not str
        or value.kind != REPOSITORY_EXECUTABLE_RUNTIME_MANIFEST_KIND
        or type(value.schema_version) is not int
        or value.schema_version
        != REPOSITORY_EXECUTABLE_RUNTIME_MANIFEST_SCHEMA_VERSION
        or type(value.manifest_source) is not str
        or value.manifest_source != RUNTIME_MANIFEST_SOURCE
        or type(value.manifest_scope) is not str
        or value.manifest_scope != RUNTIME_MANIFEST_SCOPE
        or not all(_is_digest(item) for item in digest_fields)
        or type(value.files) is not tuple
        or not 1 <= len(value.files) <= _MAX_FILES
        or type(value.bindings) is not tuple
        or not 1 <= len(value.bindings) <= _MAX_COMMANDS
        or type(value.file_count) is not int
        or value.file_count != len(value.files)
        or type(value.command_count) is not int
        or value.command_count != len(value.bindings)
        or type(value.total_content_bytes) is not int
        or not 0
        <= value.total_content_bytes
        <= _MAX_TOTAL_RUNTIME_BYTES
        or type(value.total_header_bytes) is not int
        or not 0
        <= value.total_header_bytes
        <= _MAX_FILES * _MAX_HEADER_BYTES
    ):
        raise _InvalidShebangRequirements

    files = [
        _independent_runtime_file_projection(item) for item in value.files
    ]
    bindings = [
        _independent_runtime_binding_projection(item)
        for item in value.bindings
    ]
    file_by_staged_ref: dict[str, RepositoryExecutableRuntimeFile] = {}
    runtime_refs: set[str] = set()
    total_content_bytes = 0
    total_header_bytes = 0
    for runtime_file in value.files:
        if (
            runtime_file.staged_file_ref in file_by_staged_ref
            or runtime_file.runtime_file_ref in runtime_refs
        ):
            raise _InvalidShebangRequirements
        file_by_staged_ref[runtime_file.staged_file_ref] = runtime_file
        runtime_refs.add(runtime_file.runtime_file_ref)
        total_content_bytes += runtime_file.content_bytes
        total_header_bytes += runtime_file.header_bytes

    command_ids: set[str] = set()
    bound_staged_refs: set[str] = set()
    ordered_staged_refs: list[str] = []
    prior_kind_index = -1
    for binding in value.bindings:
        runtime_file = file_by_staged_ref.get(binding.staged_file_ref)
        kind_index = _COMMAND_KINDS.index(binding.command_kind)
        if (
            runtime_file is None
            or binding.runtime_file_ref != runtime_file.runtime_file_ref
            or binding.command_id in command_ids
            or kind_index < prior_kind_index
        ):
            raise _InvalidShebangRequirements
        command_ids.add(binding.command_id)
        if binding.staged_file_ref not in bound_staged_refs:
            ordered_staged_refs.append(binding.staged_file_ref)
        bound_staged_refs.add(binding.staged_file_ref)
        prior_kind_index = kind_index
    if (
        bound_staged_refs != set(file_by_staged_ref)
        or tuple(ordered_staged_refs)
        != tuple(item.staged_file_ref for item in value.files)
        or total_content_bytes != value.total_content_bytes
        or total_header_bytes != value.total_header_bytes
    ):
        raise _InvalidShebangRequirements
    return {
        "bindings": bindings,
        "command_count": value.command_count,
        "file_count": value.file_count,
        "files": files,
        "kind": value.kind,
        "manifest_scope": value.manifest_scope,
        "manifest_source": value.manifest_source,
        "registration_digest": value.registration_digest,
        "repository_ref": value.repository_ref,
        "resolution_context_digest": value.resolution_context_digest,
        "schema_version": value.schema_version,
        "staging_context_digest": value.staging_context_digest,
        "staging_receipt_digest": value.staging_receipt_digest,
        "total_content_bytes": value.total_content_bytes,
        "total_header_bytes": value.total_header_bytes,
        "verification_commands_digest": value.verification_commands_digest,
    }


def _expected_dispositions(runtime_classification: str) -> frozenset[str]:
    if runtime_classification in {"elf", "mach_o"}:
        return frozenset({"native_binary_no_shebang"})
    if runtime_classification == "posix_shebang":
        return frozenset(
            {
                "absolute_interpreter_token",
                "non_absolute_interpreter_token",
            }
        )
    if runtime_classification == "unsupported_shebang":
        return frozenset({"unsupported_shebang"})
    if runtime_classification == "unknown":
        return frozenset({"unknown_runtime_format"})
    return frozenset()


def _requirement_ref_projection(
    *,
    staged_file_ref: str,
    runtime_file_ref: str,
    runtime_classification: str,
    disposition: str,
    shebang_directive_ref: str | None,
    interpreter_token_ref: str | None,
    interpreter_token_bytes: int,
    argument_separator_kind: str | None,
    argument_tail_ref: str | None,
    argument_tail_bytes: int,
) -> dict[str, Any]:
    return {
        "argument_separator_kind": argument_separator_kind,
        "argument_tail_bytes": argument_tail_bytes,
        "argument_tail_ref": argument_tail_ref,
        "disposition": disposition,
        "interpreter_token_bytes": interpreter_token_bytes,
        "interpreter_token_ref": interpreter_token_ref,
        "kind": "repository_executable_shebang_requirement_ref",
        "requirements_scope": REQUIREMENTS_SCOPE,
        "runtime_classification": runtime_classification,
        "runtime_file_ref": runtime_file_ref,
        "schema_version": (
            REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENTS_SCHEMA_VERSION
        ),
        "shebang_directive_ref": shebang_directive_ref,
        "staged_file_ref": staged_file_ref,
    }


def _requirement_projection(
    requirement: RepositoryExecutableShebangRequirement,
) -> dict[str, Any]:
    if (
        type(requirement) is not RepositoryExecutableShebangRequirement
        or type(requirement.kind) is not str
        or requirement.kind
        != REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENT_KIND
        or not _is_digest(requirement.staged_file_ref)
        or not _is_digest(requirement.runtime_file_ref)
        or type(requirement.runtime_classification) is not str
        or requirement.runtime_classification not in _RUNTIME_CLASSIFICATIONS
        or type(requirement.disposition) is not str
        or requirement.disposition not in _DISPOSITIONS
        or requirement.disposition
        not in _expected_dispositions(requirement.runtime_classification)
        or type(requirement.interpreter_token_bytes) is not int
        or not 0
        <= requirement.interpreter_token_bytes
        <= _MAX_DIRECTIVE_BYTES
        or type(requirement.argument_tail_bytes) is not int
        or not 0 <= requirement.argument_tail_bytes <= _MAX_DIRECTIVE_BYTES
        or not _is_digest(requirement.requirement_ref)
    ):
        raise _InvalidShebangRequirements

    is_posix = requirement.runtime_classification == "posix_shebang"
    has_tail = requirement.argument_tail_bytes > 0
    if is_posix:
        if (
            not _is_digest(requirement.shebang_directive_ref)
            or not _is_digest(requirement.interpreter_token_ref)
            or not 1
            <= requirement.interpreter_token_bytes
            <= _MAX_DIRECTIVE_BYTES
            or (
                has_tail
                and (
                    type(requirement.argument_separator_kind) is not str
                    or requirement.argument_separator_kind
                    not in {"space", "horizontal_tab"}
                    or not _is_digest(requirement.argument_tail_ref)
                    or requirement.interpreter_token_bytes
                    + 1
                    + requirement.argument_tail_bytes
                    > _MAX_DIRECTIVE_BYTES
                )
            )
            or (
                not has_tail
                and (
                    requirement.argument_separator_kind is not None
                    or requirement.argument_tail_ref is not None
                )
            )
        ):
            raise _InvalidShebangRequirements
    elif (
        requirement.shebang_directive_ref is not None
        or requirement.interpreter_token_ref is not None
        or requirement.interpreter_token_bytes != 0
        or requirement.argument_separator_kind is not None
        or requirement.argument_tail_ref is not None
        or requirement.argument_tail_bytes != 0
    ):
        raise _InvalidShebangRequirements

    reference = _requirement_ref_projection(
        staged_file_ref=requirement.staged_file_ref,
        runtime_file_ref=requirement.runtime_file_ref,
        runtime_classification=requirement.runtime_classification,
        disposition=requirement.disposition,
        shebang_directive_ref=requirement.shebang_directive_ref,
        interpreter_token_ref=requirement.interpreter_token_ref,
        interpreter_token_bytes=requirement.interpreter_token_bytes,
        argument_separator_kind=requirement.argument_separator_kind,
        argument_tail_ref=requirement.argument_tail_ref,
        argument_tail_bytes=requirement.argument_tail_bytes,
    )
    if requirement.requirement_ref != _BUILTIN_CANONICAL_DIGEST(reference):
        raise _InvalidShebangRequirements
    return {
        "argument_separator_kind": requirement.argument_separator_kind,
        "argument_tail_bytes": requirement.argument_tail_bytes,
        "argument_tail_ref": requirement.argument_tail_ref,
        "disposition": requirement.disposition,
        "interpreter_token_bytes": requirement.interpreter_token_bytes,
        "interpreter_token_ref": requirement.interpreter_token_ref,
        "kind": requirement.kind,
        "requirement_ref": requirement.requirement_ref,
        "runtime_classification": requirement.runtime_classification,
        "runtime_file_ref": requirement.runtime_file_ref,
        "shebang_directive_ref": requirement.shebang_directive_ref,
        "staged_file_ref": requirement.staged_file_ref,
    }


def _binding_projection(
    binding: RepositoryExecutableShebangRequirementBinding,
) -> dict[str, Any]:
    if (
        type(binding)
        is not RepositoryExecutableShebangRequirementBinding
        or type(binding.kind) is not str
        or binding.kind
        != REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENT_BINDING_KIND
        or type(binding.command_kind) is not str
        or binding.command_kind not in _COMMAND_KINDS
        or type(binding.command_id) is not str
        or _IDENTIFIER_PATTERN.fullmatch(binding.command_id) is None
        or not _is_digest(binding.command_digest)
        or not _is_digest(binding.staged_file_ref)
        or not _is_digest(binding.runtime_file_ref)
        or not _is_digest(binding.requirement_ref)
    ):
        raise _InvalidShebangRequirements
    return {
        "command_digest": binding.command_digest,
        "command_id": binding.command_id,
        "command_kind": binding.command_kind,
        "kind": binding.kind,
        "requirement_ref": binding.requirement_ref,
        "runtime_file_ref": binding.runtime_file_ref,
        "staged_file_ref": binding.staged_file_ref,
    }


def _receipt_projection(
    receipt: RepositoryExecutableShebangRequirementsReceipt,
) -> dict[str, Any]:
    digest_fields = (
        receipt.runtime_manifest_receipt_digest,
        receipt.staging_receipt_digest,
        receipt.registration_digest,
        receipt.repository_ref,
        receipt.verification_commands_digest,
        receipt.resolution_context_digest,
        receipt.staging_context_digest,
    )
    if (
        type(receipt) is not RepositoryExecutableShebangRequirementsReceipt
        or type(receipt.kind) is not str
        or receipt.kind != REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENTS_KIND
        or type(receipt.schema_version) is not int
        or receipt.schema_version
        != REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENTS_SCHEMA_VERSION
        or type(receipt.requirements_source) is not str
        or receipt.requirements_source != REQUIREMENTS_SOURCE
        or type(receipt.requirements_scope) is not str
        or receipt.requirements_scope != REQUIREMENTS_SCOPE
        or not all(_is_digest(value) for value in digest_fields)
        or type(receipt.requirements) is not tuple
        or not 1 <= len(receipt.requirements) <= _MAX_FILES
        or type(receipt.bindings) is not tuple
        or not 1 <= len(receipt.bindings) <= _MAX_COMMANDS
        or type(receipt.requirement_count) is not int
        or receipt.requirement_count != len(receipt.requirements)
        or type(receipt.command_count) is not int
        or receipt.command_count != len(receipt.bindings)
        or type(receipt.posix_shebang_requirement_count) is not int
        or type(receipt.argument_tail_requirement_count) is not int
        or type(receipt.total_interpreter_token_bytes) is not int
        or not 0
        <= receipt.total_interpreter_token_bytes
        <= _MAX_TOTAL_REQUIREMENT_BYTES
        or type(receipt.total_argument_tail_bytes) is not int
        or not 0
        <= receipt.total_argument_tail_bytes
        <= _MAX_TOTAL_REQUIREMENT_BYTES
    ):
        raise _InvalidShebangRequirements

    requirements = [
        _requirement_projection(value) for value in receipt.requirements
    ]
    bindings = [_binding_projection(value) for value in receipt.bindings]
    by_runtime_ref: dict[str, RepositoryExecutableShebangRequirement] = {}
    staged_refs: set[str] = set()
    requirement_refs: set[str] = set()
    for requirement in receipt.requirements:
        if (
            requirement.runtime_file_ref in by_runtime_ref
            or requirement.staged_file_ref in staged_refs
            or requirement.requirement_ref in requirement_refs
        ):
            raise _InvalidShebangRequirements
        by_runtime_ref[requirement.runtime_file_ref] = requirement
        staged_refs.add(requirement.staged_file_ref)
        requirement_refs.add(requirement.requirement_ref)

    command_ids: set[str] = set()
    bound_requirement_refs: set[str] = set()
    ordered_bound_requirement_refs: list[str] = []
    prior_kind_index = -1
    for binding in receipt.bindings:
        requirement = by_runtime_ref.get(binding.runtime_file_ref)
        kind_index = _COMMAND_KINDS.index(binding.command_kind)
        if (
            requirement is None
            or binding.staged_file_ref != requirement.staged_file_ref
            or binding.requirement_ref != requirement.requirement_ref
            or binding.command_id in command_ids
            or kind_index < prior_kind_index
        ):
            raise _InvalidShebangRequirements
        command_ids.add(binding.command_id)
        if binding.requirement_ref not in bound_requirement_refs:
            ordered_bound_requirement_refs.append(binding.requirement_ref)
        bound_requirement_refs.add(binding.requirement_ref)
        prior_kind_index = kind_index

    posix_count = sum(
        value.runtime_classification == "posix_shebang"
        for value in receipt.requirements
    )
    argument_tail_count = sum(
        value.argument_tail_ref is not None for value in receipt.requirements
    )
    total_token_bytes = sum(
        value.interpreter_token_bytes for value in receipt.requirements
    )
    total_tail_bytes = sum(
        value.argument_tail_bytes for value in receipt.requirements
    )
    if (
        bound_requirement_refs != requirement_refs
        or tuple(ordered_bound_requirement_refs)
        != tuple(value.requirement_ref for value in receipt.requirements)
        or receipt.posix_shebang_requirement_count != posix_count
        or receipt.argument_tail_requirement_count != argument_tail_count
        or receipt.total_interpreter_token_bytes != total_token_bytes
        or receipt.total_argument_tail_bytes != total_tail_bytes
    ):
        raise _InvalidShebangRequirements
    return {
        "argument_tail_requirement_count": (
            receipt.argument_tail_requirement_count
        ),
        "bindings": bindings,
        "command_count": receipt.command_count,
        "kind": receipt.kind,
        "posix_shebang_requirement_count": (
            receipt.posix_shebang_requirement_count
        ),
        "registration_digest": receipt.registration_digest,
        "repository_ref": receipt.repository_ref,
        "requirement_count": receipt.requirement_count,
        "requirements": requirements,
        "requirements_scope": receipt.requirements_scope,
        "requirements_source": receipt.requirements_source,
        "resolution_context_digest": receipt.resolution_context_digest,
        "runtime_manifest_receipt_digest": (
            receipt.runtime_manifest_receipt_digest
        ),
        "schema_version": receipt.schema_version,
        "staging_context_digest": receipt.staging_context_digest,
        "staging_receipt_digest": receipt.staging_receipt_digest,
        "total_argument_tail_bytes": receipt.total_argument_tail_bytes,
        "total_interpreter_token_bytes": (
            receipt.total_interpreter_token_bytes
        ),
        "verification_commands_digest": (
            receipt.verification_commands_digest
        ),
    }


def _evidence_projection(
    receipt: RepositoryExecutableShebangRequirementsReceipt,
) -> dict[str, Any]:
    canonical = _receipt_projection(receipt)
    dispositions = {
        disposition: sum(
            value.disposition == disposition
            for value in receipt.requirements
        )
        for disposition in _DISPOSITIONS
    }
    return {
        "absolute_interpreter_token_count": dispositions[
            "absolute_interpreter_token"
        ],
        "action_receipt_issued": False,
        "active_lease_verified_at_measurement": True,
        "argument_tail_requirement_count": (
            receipt.argument_tail_requirement_count
        ),
        "authority_granted": False,
        "authorization_verified": False,
        "billing_eligible": False,
        "bounded_shebang_requirement_extraction_complete": True,
        "capacity_eligible": False,
        "circuit_eligible": False,
        "command_count": receipt.command_count,
        "current_lease_activity_verified": False,
        "current_source_freshness_verified": False,
        "dependency_environment_coverage_verified": False,
        "dispatch_enabled": False,
        "durable_control_plane_persistence_enabled": False,
        "dynamic_loader_identity_verified": False,
        "effect_class": 0,
        "effective_invocability_verified": False,
        "environment_coverage_verified": False,
        "execution_enabled": False,
        "future_execution_correspondence_verified": False,
        "interpreter_argument_semantics_verified": False,
        "interpreter_authenticity_verified": False,
        "interpreter_compatibility_verified": False,
        "interpreter_identity_verified": False,
        "interpreter_resolution_verified": False,
        "interpreter_token_syntax_classification_complete": True,
        "kind": REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENTS_EVIDENCE_KIND,
        "launcher_semantics_verified": False,
        "lease_cleanup_performed": False,
        "lease_mutated": False,
        "live_execution_eligible": False,
        "native_binary_no_shebang_count": dispositions[
            "native_binary_no_shebang"
        ],
        "native_runtime_dependency_coverage_verified": False,
        "non_absolute_interpreter_token_count": dispositions[
            "non_absolute_interpreter_token"
        ],
        "path_lookup_performed": False,
        "posix_shebang_requirement_count": (
            receipt.posix_shebang_requirement_count
        ),
        "proposal_lineage_extended": False,
        "receipt_authenticity_verified": False,
        "receipt_digest": _BUILTIN_CANONICAL_DIGEST(canonical),
        "registration_digest": receipt.registration_digest,
        "repository_ref": receipt.repository_ref,
        "requirement_count": receipt.requirement_count,
        "requirements_scope": receipt.requirements_scope,
        "requirements_source": receipt.requirements_source,
        "resolution_context_digest": receipt.resolution_context_digest,
        "route_eligible": False,
        "runtime_manifest_complete": False,
        "runtime_manifest_receipt_digest": (
            receipt.runtime_manifest_receipt_digest
        ),
        "schema_version": receipt.schema_version,
        "shared_library_identity_verified": False,
        "source_path_reopen_performed": False,
        "staged_byte_correspondence_verified": True,
        "staging_receipt_digest": receipt.staging_receipt_digest,
        "subprocess_invocation_performed": False,
        "toolchain_completeness_verified": False,
        "total_argument_tail_bytes": receipt.total_argument_tail_bytes,
        "total_interpreter_token_bytes": (
            receipt.total_interpreter_token_bytes
        ),
        "unknown_runtime_format_count": dispositions[
            "unknown_runtime_format"
        ],
        "unsupported_shebang_count": dispositions[
            "unsupported_shebang"
        ],
        "validation_mode": "read_only",
        "worktree_integration_enabled": False,
    }


def _split_directive(
    directive: bytes,
) -> tuple[bytes, str | None, bytes | None]:
    boundary = next(
        (
            index
            for index, value in enumerate(directive)
            if value in {0x20, 0x09}
        ),
        None,
    )
    if boundary is None:
        return directive, None, None
    token = directive[:boundary]
    tail_start = boundary + 1
    while (
        tail_start < len(directive)
        and directive[tail_start] in {0x20, 0x09}
    ):
        tail_start += 1
    tail = directive[tail_start:]
    if not token or not tail:
        raise _InvalidShebangRequirements
    separator = "space" if directive[boundary] == 0x20 else "horizontal_tab"
    return token, separator, tail


def _is_syntactically_absolute_token(token: bytes) -> bool:
    return token.startswith(b"/")


def _token_ref(
    *,
    runtime_file_ref: str,
    shebang_directive_ref: str,
    token: bytes,
) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "interpreter_token_hex": token.hex(),
            "kind": "repository_executable_shebang_interpreter_token_ref",
            "runtime_file_ref": runtime_file_ref,
            "schema_version": (
                REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENTS_SCHEMA_VERSION
            ),
            "shebang_directive_ref": shebang_directive_ref,
        }
    )


def _tail_ref(
    *,
    runtime_file_ref: str,
    shebang_directive_ref: str,
    interpreter_token_ref: str,
    separator_kind: str,
    tail: bytes,
) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "argument_separator_kind": separator_kind,
            "argument_tail_hex": tail.hex(),
            "interpreter_token_ref": interpreter_token_ref,
            "kind": "repository_executable_shebang_argument_tail_ref",
            "runtime_file_ref": runtime_file_ref,
            "schema_version": (
                REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENTS_SCHEMA_VERSION
            ),
            "shebang_directive_ref": shebang_directive_ref,
        }
    )


def _independent_header_digest(staged_file_ref: str, header: bytes) -> str:
    return "sha256:" + _BUILTIN_SHA256(
        staged_file_ref.encode("ascii") + b"\x00" + header
    ).hexdigest()


def _independent_descriptor_remeasurement(
    descriptor: int,
    *,
    content_bytes: int,
    expected_content_digest: str,
) -> bytes:
    digest = _BUILTIN_SHA256()
    header_parts: list[bytes] = []
    header_remaining = min(content_bytes, _MAX_HEADER_BYTES)
    offset = 0
    while offset < content_bytes:
        requested = min(
            _FULL_REMEASUREMENT_CHUNK_BYTES,
            content_bytes - offset,
        )
        try:
            chunk = _BUILTIN_PREAD(descriptor, requested, offset)
        except (BlockingIOError, InterruptedError, OSError):
            raise _InvalidShebangRequirements from None
        if not chunk or len(chunk) > requested:
            raise _InvalidShebangRequirements
        digest.update(chunk)
        if header_remaining:
            captured = chunk[:header_remaining]
            header_parts.append(captured)
            header_remaining -= len(captured)
        offset += len(chunk)
    try:
        boundary = _BUILTIN_PREAD(descriptor, 1, content_bytes)
    except (BlockingIOError, InterruptedError, OSError):
        raise _InvalidShebangRequirements from None
    header = b"".join(header_parts)
    if (
        boundary != b""
        or header_remaining != 0
        or len(header) != min(content_bytes, _MAX_HEADER_BYTES)
        or "sha256:" + digest.hexdigest() != expected_content_digest
    ):
        raise _InvalidShebangRequirements
    return header


def _independent_bounded_shebang_directive(header: bytes) -> bytes | None:
    if not header.startswith(b"#!"):
        return None
    newline = header.find(b"\n", 2)
    if newline < 0:
        return None
    directive = header[2:newline]
    if (
        not 1 <= len(directive) <= _MAX_DIRECTIVE_BYTES
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


def _independent_header_classification(
    staged_file_ref: str,
    header: bytes,
) -> tuple[str, str | None, bytes | None]:
    if header.startswith(b"#!"):
        directive = _independent_bounded_shebang_directive(header)
        if directive is None:
            return "unsupported_shebang", None, None
        directive_ref = _BUILTIN_CANONICAL_DIGEST(
            {
                "directive_hex": directive.hex(),
                "kind": "repository_executable_shebang_directive_ref",
                "schema_version": (
                    REPOSITORY_EXECUTABLE_RUNTIME_MANIFEST_SCHEMA_VERSION
                ),
                "staged_file_ref": staged_file_ref,
            }
        )
        return "posix_shebang", directive_ref, directive
    if header.startswith(b"\x7fELF"):
        if (
            len(header) >= 16
            and header[4] in {1, 2}
            and header[5] in {1, 2}
            and header[6] == 1
        ):
            return "elf", None, None
        return "unknown", None, None
    magic = header[:4]
    if (
        magic in _MACH_O_MAGICS
        and len(header) >= _MACH_O_MINIMUM_BYTES[magic]
    ):
        return "mach_o", None, None
    return "unknown", None, None


def _build_requirement(
    runtime_file: Any,
    *,
    header: bytes,
) -> RepositoryExecutableShebangRequirement:
    classification, directive_ref, directive = (
        _independent_header_classification(
        runtime_file.staged_file_ref,
        header,
    )
    )
    if (
        classification != runtime_file.classification
        or directive_ref != runtime_file.shebang_directive_ref
        or runtime_file.header_bytes != len(header)
        or runtime_file.header_digest
        != _independent_header_digest(runtime_file.staged_file_ref, header)
    ):
        raise _InvalidShebangRequirements

    interpreter_token_ref: str | None = None
    interpreter_token_bytes = 0
    separator_kind: str | None = None
    argument_tail_ref: str | None = None
    argument_tail_bytes = 0
    if classification == "posix_shebang":
        if directive_ref is None or directive is None:
            raise _InvalidShebangRequirements
        token, separator_kind, tail = _split_directive(directive)
        interpreter_token_ref = _token_ref(
            runtime_file_ref=runtime_file.runtime_file_ref,
            shebang_directive_ref=directive_ref,
            token=token,
        )
        interpreter_token_bytes = len(token)
        if tail is not None:
            if separator_kind is None:
                raise _InvalidShebangRequirements
            argument_tail_ref = _tail_ref(
                runtime_file_ref=runtime_file.runtime_file_ref,
                shebang_directive_ref=directive_ref,
                interpreter_token_ref=interpreter_token_ref,
                separator_kind=separator_kind,
                tail=tail,
            )
            argument_tail_bytes = len(tail)
        disposition = (
            "absolute_interpreter_token"
            if _is_syntactically_absolute_token(token)
            else "non_absolute_interpreter_token"
        )
    elif classification in {"elf", "mach_o"}:
        disposition = "native_binary_no_shebang"
    elif classification == "unsupported_shebang":
        disposition = "unsupported_shebang"
    elif classification == "unknown":
        disposition = "unknown_runtime_format"
    else:
        raise _InvalidShebangRequirements

    reference = _requirement_ref_projection(
        staged_file_ref=runtime_file.staged_file_ref,
        runtime_file_ref=runtime_file.runtime_file_ref,
        runtime_classification=classification,
        disposition=disposition,
        shebang_directive_ref=directive_ref,
        interpreter_token_ref=interpreter_token_ref,
        interpreter_token_bytes=interpreter_token_bytes,
        argument_separator_kind=separator_kind,
        argument_tail_ref=argument_tail_ref,
        argument_tail_bytes=argument_tail_bytes,
    )
    requirement = RepositoryExecutableShebangRequirement(
        kind=REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENT_KIND,
        staged_file_ref=runtime_file.staged_file_ref,
        runtime_file_ref=runtime_file.runtime_file_ref,
        runtime_classification=classification,
        disposition=disposition,
        shebang_directive_ref=directive_ref,
        interpreter_token_ref=interpreter_token_ref,
        interpreter_token_bytes=interpreter_token_bytes,
        argument_separator_kind=separator_kind,
        argument_tail_ref=argument_tail_ref,
        argument_tail_bytes=argument_tail_bytes,
        requirement_ref=_BUILTIN_CANONICAL_DIGEST(reference),
    )
    _requirement_projection(requirement)
    return requirement


def _remeasure_runtime_requirements(
    expected_runtime: RepositoryExecutableRuntimeManifestReceipt,
    expected_staging: RepositoryExecutableStagingReceipt,
    retained_files: tuple[Any, ...],
) -> tuple[RepositoryExecutableShebangRequirement, ...]:
    requirements: list[RepositoryExecutableShebangRequirement] = []
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
            raise _InvalidShebangRequirements
        header = _BUILTIN_VERIFY_RETAINED_FILE(retained, staged_file)
        independent_header = _independent_descriptor_remeasurement(
            retained.descriptor,
            content_bytes=staged_file.content_bytes,
            expected_content_digest=staged_file.content_digest,
        )
        if independent_header != header:
            raise _InvalidShebangRequirements
        requirements.append(_build_requirement(runtime_file, header=header))
    return tuple(requirements)


def inspect_staged_executable_shebang_requirements(
    expected_runtime: RepositoryExecutableRuntimeManifestReceipt,
    *,
    expected_staging: RepositoryExecutableStagingReceipt,
    lease: RepositoryExecutableStageLease,
) -> RepositoryExecutableShebangRequirementsReceipt:
    """Extract bounded digest-only shebang requirements from one active lease."""

    try:
        if (
            type(expected_runtime)
            is not RepositoryExecutableRuntimeManifestReceipt
            or type(expected_staging)
            is not RepositoryExecutableStagingReceipt
            or type(lease) is not RepositoryExecutableStageLease
        ):
            raise _InvalidShebangRequirements
        staging_canonical = _independent_staging_receipt_projection(
            expected_staging
        )
        runtime_canonical = _independent_runtime_manifest_projection(
            expected_runtime
        )
        staging_digest = _BUILTIN_CANONICAL_DIGEST(staging_canonical)
        runtime_digest = _BUILTIN_CANONICAL_DIGEST(runtime_canonical)
        _verify_independent_lease_anchor(
            expected_staging,
            lease,
            staging_canonical=staging_canonical,
            staging_digest=staging_digest,
        )
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
            raise _InvalidShebangRequirements

        fresh_runtime = _BUILTIN_INSPECT_RUNTIME_MANIFEST(
            expected_staging,
            lease=lease,
        )
        if (
            _independent_runtime_manifest_projection(fresh_runtime)
            != runtime_canonical
        ):
            raise _InvalidShebangRequirements
        active_canonical, retained_files = _BUILTIN_ACTIVE_STAGE_SNAPSHOT(
            expected_staging,
            lease,
        )
        if active_canonical != staging_canonical:
            raise _InvalidShebangRequirements
        _verify_independent_lease_anchor(
            expected_staging,
            lease,
            staging_canonical=staging_canonical,
            staging_digest=staging_digest,
        )

        requirements = list(
            _remeasure_runtime_requirements(
                expected_runtime,
                expected_staging,
                retained_files,
            )
        )

        final_canonical, final_retained_files = (
            _BUILTIN_ACTIVE_STAGE_SNAPSHOT(expected_staging, lease)
        )
        if (
            final_canonical != staging_canonical
            or final_retained_files is not retained_files
        ):
            raise _InvalidShebangRequirements
        _verify_independent_lease_anchor(
            expected_staging,
            lease,
            staging_canonical=staging_canonical,
            staging_digest=staging_digest,
        )
        final_runtime = _BUILTIN_INSPECT_RUNTIME_MANIFEST(
            expected_staging,
            lease=lease,
        )
        if (
            _independent_runtime_manifest_projection(final_runtime)
            != runtime_canonical
        ):
            raise _InvalidShebangRequirements
        final_canonical, final_retained_files = (
            _BUILTIN_ACTIVE_STAGE_SNAPSHOT(expected_staging, lease)
        )
        if (
            final_canonical != staging_canonical
            or final_retained_files is not retained_files
        ):
            raise _InvalidShebangRequirements
        _verify_independent_lease_anchor(
            expected_staging,
            lease,
            staging_canonical=staging_canonical,
            staging_digest=staging_digest,
        )
        if _remeasure_runtime_requirements(
            expected_runtime,
            expected_staging,
            retained_files,
        ) != tuple(requirements):
            raise _InvalidShebangRequirements
        final_canonical, final_retained_files = (
            _BUILTIN_ACTIVE_STAGE_SNAPSHOT(expected_staging, lease)
        )
        if (
            final_canonical != staging_canonical
            or final_retained_files is not retained_files
        ):
            raise _InvalidShebangRequirements
        _verify_independent_lease_anchor(
            expected_staging,
            lease,
            staging_canonical=staging_canonical,
            staging_digest=staging_digest,
        )

        by_runtime_ref = {
            value.runtime_file_ref: value for value in requirements
        }
        bindings: list[RepositoryExecutableShebangRequirementBinding] = []
        for runtime_binding, staging_binding in zip(
            expected_runtime.bindings,
            expected_staging.bindings,
            strict=True,
        ):
            if (
                runtime_binding.kind
                != REPOSITORY_EXECUTABLE_RUNTIME_BINDING_KIND
                or type(staging_binding)
                is not RepositoryExecutableStageBinding
                or staging_binding.kind
                != REPOSITORY_EXECUTABLE_STAGE_BINDING_KIND
                or runtime_binding.command_kind
                != staging_binding.command_kind
                or runtime_binding.command_id != staging_binding.command_id
                or runtime_binding.command_digest
                != staging_binding.command_digest
                or runtime_binding.staged_file_ref
                != staging_binding.staged_file_ref
            ):
                raise _InvalidShebangRequirements
            requirement = by_runtime_ref.get(runtime_binding.runtime_file_ref)
            if (
                requirement is None
                or requirement.staged_file_ref
                != runtime_binding.staged_file_ref
            ):
                raise _InvalidShebangRequirements
            bindings.append(
                RepositoryExecutableShebangRequirementBinding(
                    kind=(
                        REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENT_BINDING_KIND
                    ),
                    command_kind=runtime_binding.command_kind,
                    command_id=runtime_binding.command_id,
                    command_digest=runtime_binding.command_digest,
                    staged_file_ref=runtime_binding.staged_file_ref,
                    runtime_file_ref=runtime_binding.runtime_file_ref,
                    requirement_ref=requirement.requirement_ref,
                )
            )

        receipt = RepositoryExecutableShebangRequirementsReceipt(
            kind=REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENTS_KIND,
            schema_version=(
                REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENTS_SCHEMA_VERSION
            ),
            requirements_source=REQUIREMENTS_SOURCE,
            requirements_scope=REQUIREMENTS_SCOPE,
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
            requirements=tuple(requirements),
            bindings=tuple(bindings),
            requirement_count=len(requirements),
            command_count=len(bindings),
            posix_shebang_requirement_count=sum(
                value.runtime_classification == "posix_shebang"
                for value in requirements
            ),
            argument_tail_requirement_count=sum(
                value.argument_tail_ref is not None for value in requirements
            ),
            total_interpreter_token_bytes=sum(
                value.interpreter_token_bytes for value in requirements
            ),
            total_argument_tail_bytes=sum(
                value.argument_tail_bytes for value in requirements
            ),
        )
        _receipt_projection(receipt)
        return receipt
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise ValidationError(_INVALID_MESSAGE) from None
