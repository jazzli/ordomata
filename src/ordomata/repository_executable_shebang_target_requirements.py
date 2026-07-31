"""Digest-only one-hop requirements from an active shebang-target stage.

This Class 0 boundary consumes one exact staged-target runtime manifest and
reproduces it from the same active process-local target-stage lease.  It
extracts only bounded syntax references from a target's shebang.  It never
resolves the extracted token, interprets launcher semantics, opens a path,
mutates the lease, or executes a process.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import fcntl
import hashlib
import os
import re
import stat
from typing import Any

from .authorization import canonical_digest, canonical_json
from .errors import ValidationError
from .repository_executable_shebang_target_runtime_manifest import (
    RepositoryExecutableShebangTargetRuntimeBinding,
    RepositoryExecutableShebangTargetRuntimeFile,
    RepositoryExecutableShebangTargetRuntimeManifestReceipt,
    RepositoryExecutableShebangTargetRuntimeRequirement,
    _active_target_stage_snapshot,
    _verify_anchored_retained_target,
    inspect_staged_executable_shebang_target_runtime_manifest,
)
from .repository_executable_shebang_target_staging import (
    RepositoryExecutableShebangTargetStagedFile,
    RepositoryExecutableShebangTargetStageBinding,
    RepositoryExecutableShebangTargetStageLease,
    RepositoryExecutableShebangTargetStageRequirement,
    RepositoryExecutableShebangTargetStagingReceipt,
    _RetainedStagedTarget,
)


REPOSITORY_EXECUTABLE_SHEBANG_TARGET_REQUIREMENTS_SCHEMA_VERSION = 1
REPOSITORY_EXECUTABLE_SHEBANG_TARGET_REQUIREMENTS_KIND = (
    "repository_executable_shebang_target_requirements"
)
REPOSITORY_EXECUTABLE_SHEBANG_TARGET_REQUIREMENTS_EVIDENCE_KIND = (
    "repository_executable_shebang_target_requirements_validation"
)
REPOSITORY_EXECUTABLE_SHEBANG_TARGET_SHEBANG_REQUIREMENT_KIND = (
    "repository_executable_shebang_target_shebang_requirement"
)
REPOSITORY_EXECUTABLE_SHEBANG_TARGET_SHEBANG_REQUIREMENT_BINDING_KIND = (
    "repository_executable_shebang_target_shebang_requirement_binding"
)
REQUIREMENTS_SOURCE = "controller_inspected"
REQUIREMENTS_SCOPE = "posix_staged_shebang_target_requirements_v1"

_FIXED_SCHEMA_VERSION = (
    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_REQUIREMENTS_SCHEMA_VERSION
)
_FIXED_RECEIPT_KIND = (
    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_REQUIREMENTS_KIND
)
_FIXED_EVIDENCE_KIND = (
    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_REQUIREMENTS_EVIDENCE_KIND
)
_FIXED_REQUIREMENT_KIND = (
    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_SHEBANG_REQUIREMENT_KIND
)
_FIXED_BINDING_KIND = (
    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_SHEBANG_REQUIREMENT_BINDING_KIND
)
_FIXED_REQUIREMENTS_SOURCE = REQUIREMENTS_SOURCE
_FIXED_REQUIREMENTS_SCOPE = REQUIREMENTS_SCOPE

_TARGET_STAGING_KIND = "repository_executable_shebang_target_staging"
_TARGET_STAGED_FILE_KIND = (
    "repository_executable_shebang_target_staged_file"
)
_TARGET_STAGE_REQUIREMENT_KIND = (
    "repository_executable_shebang_target_stage_requirement"
)
_TARGET_STAGE_BINDING_KIND = (
    "repository_executable_shebang_target_stage_binding"
)
_TARGET_STAGING_SOURCE = "controller_copied"
_TARGET_STAGING_SCOPE = "posix_shebang_target_unlinked_readonly_v1"
_TARGET_MEASUREMENT_SOURCE = "controller_measured"
_TARGET_RESOLUTION_SCOPE = "posix_absolute_shebang_target_nofollow_v1"

_TARGET_RUNTIME_MANIFEST_KIND = (
    "repository_executable_shebang_target_runtime_manifest"
)
_TARGET_RUNTIME_FILE_KIND = (
    "repository_executable_shebang_target_runtime_file"
)
_TARGET_RUNTIME_REQUIREMENT_KIND = (
    "repository_executable_shebang_target_runtime_requirement"
)
_TARGET_RUNTIME_BINDING_KIND = (
    "repository_executable_shebang_target_runtime_binding"
)
_TARGET_RUNTIME_MANIFEST_SOURCE = "controller_inspected"
_TARGET_RUNTIME_MANIFEST_SCOPE = (
    "posix_staged_shebang_target_runtime_header_v1"
)

_INVALID_MESSAGE = (
    "repository executable shebang target requirements are invalid"
)
_DIGEST_PREFIX = "sha256:"
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER_PATTERN = re.compile(r"[a-z][a-z0-9_.-]{0,119}\Z")
_COMMAND_KINDS = ("format", "lint", "type_check", "test", "build")
_SOURCE_RUNTIME_CLASSIFICATIONS = ("elf", "mach_o", "posix_shebang")
_TARGET_RUNTIME_CLASSIFICATIONS = (
    "elf",
    "mach_o",
    "posix_shebang",
    "unsupported_shebang",
    "unknown",
)
_TARGET_RUNTIME_DISPOSITIONS = (
    "direct_absolute_target_runtime_inspected",
    "native_not_applicable",
)
_TARGET_STAGE_DISPOSITIONS = (
    "direct_absolute_target_staged",
    "native_not_applicable",
)
_DISPOSITIONS = (
    "native_not_applicable",
    "native_binary_no_shebang",
    "absolute_interpreter_token",
    "non_absolute_interpreter_token",
    "unsupported_shebang",
    "unknown_runtime_format",
)
_MAX_FILES = 80
_MAX_REQUIREMENTS = 80
_MAX_COMMANDS = 80
_MAX_FILE_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_BYTES = 256 * 1024 * 1024
_MAX_HEADER_BYTES = 4_096
_MAX_DIRECTIVE_BYTES = 255
_MAX_TOTAL_REQUIREMENT_BYTES = _MAX_FILES * _MAX_DIRECTIVE_BYTES
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

# Hold the shipped proof primitives.  Public module attributes and dataclass
# methods remain patchable and are never accepted as canonical proof input.
_BUILTIN_SHA256 = hashlib.sha256
_BUILTIN_CANONICAL_JSON = canonical_json


def _captured_canonical_digest(value: Any) -> str:
    encoded = _BUILTIN_CANONICAL_JSON(value).encode("utf-8")
    return _DIGEST_PREFIX + _BUILTIN_SHA256(encoded).hexdigest()


_BUILTIN_CANONICAL_DIGEST = _captured_canonical_digest
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

_FIXED_TARGET_STAGED_FILE_TYPE = RepositoryExecutableShebangTargetStagedFile
_FIXED_TARGET_STAGE_REQUIREMENT_TYPE = (
    RepositoryExecutableShebangTargetStageRequirement
)
_FIXED_TARGET_STAGE_BINDING_TYPE = (
    RepositoryExecutableShebangTargetStageBinding
)
_FIXED_TARGET_STAGING_RECEIPT_TYPE = (
    RepositoryExecutableShebangTargetStagingReceipt
)
_FIXED_TARGET_STAGE_LEASE_TYPE = RepositoryExecutableShebangTargetStageLease
_FIXED_RETAINED_TARGET_TYPE = _RetainedStagedTarget
_FIXED_TARGET_RUNTIME_FILE_TYPE = (
    RepositoryExecutableShebangTargetRuntimeFile
)
_FIXED_TARGET_RUNTIME_REQUIREMENT_TYPE = (
    RepositoryExecutableShebangTargetRuntimeRequirement
)
_FIXED_TARGET_RUNTIME_BINDING_TYPE = (
    RepositoryExecutableShebangTargetRuntimeBinding
)
_FIXED_TARGET_RUNTIME_RECEIPT_TYPE = (
    RepositoryExecutableShebangTargetRuntimeManifestReceipt
)


class _InvalidTargetRequirements(ValueError):
    """Private fail-closed sentinel whose details never cross the API."""


@dataclass(frozen=True, slots=True)
class RepositoryExecutableShebangTargetShebangRequirement:
    """One upstream target-runtime requirement's bounded syntax result."""

    kind: str
    staged_file_ref: str = field(repr=False)
    runtime_file_ref: str = field(repr=False)
    requirement_ref: str = field(repr=False)
    target_requirement_ref: str = field(repr=False)
    target_stage_requirement_ref: str = field(repr=False)
    target_runtime_requirement_ref: str = field(repr=False)
    runtime_classification: str
    target_measurement_ref: str | None = field(repr=False)
    target_staged_file_ref: str | None = field(repr=False)
    target_runtime_file_ref: str | None = field(repr=False)
    target_runtime_classification: str | None
    disposition: str
    target_shebang_directive_ref: str | None = field(repr=False)
    interpreter_token_ref: str | None = field(repr=False)
    interpreter_token_bytes: int
    argument_separator_kind: str | None
    argument_tail_ref: str | None = field(repr=False)
    argument_tail_bytes: int
    target_shebang_requirement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _requirement_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableShebangTargetShebangRequirementBinding:
    """One registered command bound to one target-shebang requirement."""

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

    def to_canonical(self) -> dict[str, Any]:
        return _binding_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableShebangTargetRequirementsReceipt:
    """Historical one-hop syntax evidence from one active target stage."""

    kind: str
    schema_version: int
    requirements_source: str
    requirements_scope: str
    target_runtime_manifest_receipt_digest: str = field(repr=False)
    target_staging_receipt_digest: str = field(repr=False)
    target_resolution_receipt_digest: str = field(repr=False)
    shebang_requirements_receipt_digest: str = field(repr=False)
    runtime_manifest_receipt_digest: str = field(repr=False)
    staging_receipt_digest: str = field(repr=False)
    registration_digest: str = field(repr=False)
    repository_ref: str = field(repr=False)
    verification_commands_digest: str = field(repr=False)
    resolution_context_digest: str = field(repr=False)
    source_staging_context_digest: str = field(repr=False)
    target_path_context_digest: str = field(repr=False)
    target_staging_context_digest: str = field(repr=False)
    requirements: tuple[
        RepositoryExecutableShebangTargetShebangRequirement, ...
    ] = field(repr=False)
    bindings: tuple[
        RepositoryExecutableShebangTargetShebangRequirementBinding, ...
    ] = field(repr=False)
    requirement_count: int
    command_count: int
    direct_target_requirement_count: int
    native_not_applicable_count: int
    unique_target_count: int
    target_posix_shebang_requirement_count: int
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


_FIXED_REQUIREMENT_TYPE = RepositoryExecutableShebangTargetShebangRequirement
_FIXED_BINDING_TYPE = (
    RepositoryExecutableShebangTargetShebangRequirementBinding
)
_FIXED_RECEIPT_TYPE = RepositoryExecutableShebangTargetRequirementsReceipt


def _is_digest(value: Any) -> bool:
    return type(value) is str and _DIGEST_PATTERN.fullmatch(value) is not None


_BUILTIN_IS_DIGEST = _is_digest


def _requirement_ref_projection(
    *,
    staged_file_ref: str,
    runtime_file_ref: str,
    requirement_ref: str,
    target_requirement_ref: str,
    target_stage_requirement_ref: str,
    target_runtime_requirement_ref: str,
    runtime_classification: str,
    target_measurement_ref: str | None,
    target_staged_file_ref: str | None,
    target_runtime_file_ref: str | None,
    target_runtime_classification: str | None,
    disposition: str,
    target_shebang_directive_ref: str | None,
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
        "kind": (
            "repository_executable_shebang_target_"
            "shebang_requirement_ref"
        ),
        "requirement_ref": requirement_ref,
        "requirements_scope": _FIXED_REQUIREMENTS_SCOPE,
        "runtime_classification": runtime_classification,
        "runtime_file_ref": runtime_file_ref,
        "schema_version": _FIXED_SCHEMA_VERSION,
        "staged_file_ref": staged_file_ref,
        "target_measurement_ref": target_measurement_ref,
        "target_requirement_ref": target_requirement_ref,
        "target_runtime_classification": target_runtime_classification,
        "target_runtime_file_ref": target_runtime_file_ref,
        "target_runtime_requirement_ref": target_runtime_requirement_ref,
        "target_shebang_directive_ref": target_shebang_directive_ref,
        "target_stage_requirement_ref": target_stage_requirement_ref,
        "target_staged_file_ref": target_staged_file_ref,
    }


def _expected_disposition(
    runtime_classification: str,
    target_runtime_classification: str | None,
) -> frozenset[str]:
    if runtime_classification in {"elf", "mach_o"}:
        return frozenset({"native_not_applicable"})
    if runtime_classification != "posix_shebang":
        return frozenset()
    if target_runtime_classification in {"elf", "mach_o"}:
        return frozenset({"native_binary_no_shebang"})
    if target_runtime_classification == "posix_shebang":
        return frozenset(
            {"absolute_interpreter_token", "non_absolute_interpreter_token"}
        )
    if target_runtime_classification == "unsupported_shebang":
        return frozenset({"unsupported_shebang"})
    if target_runtime_classification == "unknown":
        return frozenset({"unknown_runtime_format"})
    return frozenset()


_BUILTIN_EXPECTED_DISPOSITION = _expected_disposition


def _requirement_projection(
    value: RepositoryExecutableShebangTargetShebangRequirement,
) -> dict[str, Any]:
    required_digests = (
        value.staged_file_ref,
        value.runtime_file_ref,
        value.requirement_ref,
        value.target_requirement_ref,
        value.target_stage_requirement_ref,
        value.target_runtime_requirement_ref,
        value.target_shebang_requirement_ref,
    )
    optional_digests = (
        value.target_measurement_ref,
        value.target_staged_file_ref,
        value.target_runtime_file_ref,
        value.target_shebang_directive_ref,
        value.interpreter_token_ref,
        value.argument_tail_ref,
    )
    if (
        type(value) is not _FIXED_REQUIREMENT_TYPE
        or type(value.kind) is not str
        or value.kind != _FIXED_REQUIREMENT_KIND
        or not all(_BUILTIN_IS_DIGEST(item) for item in required_digests)
        or any(
            item is not None and not _BUILTIN_IS_DIGEST(item)
            for item in optional_digests
        )
        or type(value.runtime_classification) is not str
        or value.runtime_classification not in _SOURCE_RUNTIME_CLASSIFICATIONS
        or (
            value.target_runtime_classification is not None
            and (
                type(value.target_runtime_classification) is not str
                or value.target_runtime_classification
                not in _TARGET_RUNTIME_CLASSIFICATIONS
            )
        )
        or type(value.disposition) is not str
        or value.disposition not in _DISPOSITIONS
        or value.disposition
        not in _BUILTIN_EXPECTED_DISPOSITION(
            value.runtime_classification,
            value.target_runtime_classification,
        )
        or type(value.interpreter_token_bytes) is not int
        or not 0 <= value.interpreter_token_bytes <= _MAX_DIRECTIVE_BYTES
        or type(value.argument_tail_bytes) is not int
        or not 0 <= value.argument_tail_bytes <= _MAX_DIRECTIVE_BYTES
    ):
        raise _InvalidTargetRequirements

    source_native = value.disposition == "native_not_applicable"
    target_posix = value.target_runtime_classification == "posix_shebang"
    has_tail = value.argument_tail_bytes > 0
    if source_native:
        if (
            value.target_measurement_ref is not None
            or value.target_staged_file_ref is not None
            or value.target_runtime_file_ref is not None
            or value.target_runtime_classification is not None
            or value.target_shebang_directive_ref is not None
            or value.interpreter_token_ref is not None
            or value.interpreter_token_bytes != 0
            or value.argument_separator_kind is not None
            or value.argument_tail_ref is not None
            or value.argument_tail_bytes != 0
        ):
            raise _InvalidTargetRequirements
    else:
        if (
            value.runtime_classification != "posix_shebang"
            or value.target_measurement_ref is None
            or value.target_staged_file_ref is None
            or value.target_runtime_file_ref is None
            or value.target_runtime_classification is None
        ):
            raise _InvalidTargetRequirements
        if target_posix:
            if (
                value.target_shebang_directive_ref is None
                or value.interpreter_token_ref is None
                or not 1
                <= value.interpreter_token_bytes
                <= _MAX_DIRECTIVE_BYTES
                or (
                    has_tail
                    and (
                        type(value.argument_separator_kind) is not str
                        or value.argument_separator_kind
                        not in {"space", "horizontal_tab"}
                        or value.argument_tail_ref is None
                        or value.interpreter_token_bytes
                        + 1
                        + value.argument_tail_bytes
                        > _MAX_DIRECTIVE_BYTES
                    )
                )
                or (
                    not has_tail
                    and (
                        value.argument_separator_kind is not None
                        or value.argument_tail_ref is not None
                    )
                )
            ):
                raise _InvalidTargetRequirements
        elif (
            value.target_shebang_directive_ref is not None
            or value.interpreter_token_ref is not None
            or value.interpreter_token_bytes != 0
            or value.argument_separator_kind is not None
            or value.argument_tail_ref is not None
            or value.argument_tail_bytes != 0
        ):
            raise _InvalidTargetRequirements

    reference = _BUILTIN_REQUIREMENT_REF_PROJECTION(
        staged_file_ref=value.staged_file_ref,
        runtime_file_ref=value.runtime_file_ref,
        requirement_ref=value.requirement_ref,
        target_requirement_ref=value.target_requirement_ref,
        target_stage_requirement_ref=value.target_stage_requirement_ref,
        target_runtime_requirement_ref=value.target_runtime_requirement_ref,
        runtime_classification=value.runtime_classification,
        target_measurement_ref=value.target_measurement_ref,
        target_staged_file_ref=value.target_staged_file_ref,
        target_runtime_file_ref=value.target_runtime_file_ref,
        target_runtime_classification=value.target_runtime_classification,
        disposition=value.disposition,
        target_shebang_directive_ref=value.target_shebang_directive_ref,
        interpreter_token_ref=value.interpreter_token_ref,
        interpreter_token_bytes=value.interpreter_token_bytes,
        argument_separator_kind=value.argument_separator_kind,
        argument_tail_ref=value.argument_tail_ref,
        argument_tail_bytes=value.argument_tail_bytes,
    )
    if value.target_shebang_requirement_ref != _BUILTIN_CANONICAL_DIGEST(
        reference
    ):
        raise _InvalidTargetRequirements
    return {
        "argument_separator_kind": value.argument_separator_kind,
        "argument_tail_bytes": value.argument_tail_bytes,
        "argument_tail_ref": value.argument_tail_ref,
        "disposition": value.disposition,
        "interpreter_token_bytes": value.interpreter_token_bytes,
        "interpreter_token_ref": value.interpreter_token_ref,
        "kind": value.kind,
        "requirement_ref": value.requirement_ref,
        "runtime_classification": value.runtime_classification,
        "runtime_file_ref": value.runtime_file_ref,
        "staged_file_ref": value.staged_file_ref,
        "target_measurement_ref": value.target_measurement_ref,
        "target_requirement_ref": value.target_requirement_ref,
        "target_runtime_classification": (
            value.target_runtime_classification
        ),
        "target_runtime_file_ref": value.target_runtime_file_ref,
        "target_runtime_requirement_ref": (
            value.target_runtime_requirement_ref
        ),
        "target_shebang_directive_ref": (
            value.target_shebang_directive_ref
        ),
        "target_shebang_requirement_ref": (
            value.target_shebang_requirement_ref
        ),
        "target_stage_requirement_ref": value.target_stage_requirement_ref,
        "target_staged_file_ref": value.target_staged_file_ref,
    }


def _binding_projection(
    value: RepositoryExecutableShebangTargetShebangRequirementBinding,
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
                value.target_shebang_requirement_ref,
            )
        )
    ):
        raise _InvalidTargetRequirements
    return {
        "command_digest": value.command_digest,
        "command_id": value.command_id,
        "command_kind": value.command_kind,
        "kind": value.kind,
        "requirement_ref": value.requirement_ref,
        "runtime_file_ref": value.runtime_file_ref,
        "staged_file_ref": value.staged_file_ref,
        "target_requirement_ref": value.target_requirement_ref,
        "target_runtime_requirement_ref": (
            value.target_runtime_requirement_ref
        ),
        "target_shebang_requirement_ref": (
            value.target_shebang_requirement_ref
        ),
        "target_stage_requirement_ref": value.target_stage_requirement_ref,
    }


def _receipt_projection(
    value: RepositoryExecutableShebangTargetRequirementsReceipt,
) -> dict[str, Any]:
    digest_fields = (
        value.target_runtime_manifest_receipt_digest,
        value.target_staging_receipt_digest,
        value.target_resolution_receipt_digest,
        value.shebang_requirements_receipt_digest,
        value.runtime_manifest_receipt_digest,
        value.staging_receipt_digest,
        value.registration_digest,
        value.repository_ref,
        value.verification_commands_digest,
        value.resolution_context_digest,
        value.source_staging_context_digest,
        value.target_path_context_digest,
        value.target_staging_context_digest,
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
        or not 1 <= len(value.requirements) <= _MAX_REQUIREMENTS
        or type(value.bindings) is not tuple
        or not 1 <= len(value.bindings) <= _MAX_COMMANDS
        or type(value.requirement_count) is not int
        or value.requirement_count != len(value.requirements)
        or type(value.command_count) is not int
        or value.command_count != len(value.bindings)
        or type(value.direct_target_requirement_count) is not int
        or type(value.native_not_applicable_count) is not int
        or type(value.unique_target_count) is not int
        or not 0 <= value.unique_target_count <= _MAX_FILES
        or type(value.target_posix_shebang_requirement_count) is not int
        or not 0
        <= value.target_posix_shebang_requirement_count
        <= _MAX_FILES
        or type(value.argument_tail_requirement_count) is not int
        or not 0 <= value.argument_tail_requirement_count <= _MAX_FILES
        or type(value.total_interpreter_token_bytes) is not int
        or not 0
        <= value.total_interpreter_token_bytes
        <= _MAX_TOTAL_REQUIREMENT_BYTES
        or type(value.total_argument_tail_bytes) is not int
        or not 0
        <= value.total_argument_tail_bytes
        <= _MAX_TOTAL_REQUIREMENT_BYTES
    ):
        raise _InvalidTargetRequirements

    requirements = [
        _BUILTIN_REQUIREMENT_PROJECTION(item) for item in value.requirements
    ]
    bindings = [
        _BUILTIN_BINDING_PROJECTION(item) for item in value.bindings
    ]

    by_runtime_requirement_ref: dict[
        str, RepositoryExecutableShebangTargetShebangRequirement
    ] = {}
    source_requirement_refs: set[str] = set()
    stage_requirement_refs: set[str] = set()
    terminal_refs: set[str] = set()
    unique_target_rows: dict[
        str, RepositoryExecutableShebangTargetShebangRequirement
    ] = {}
    direct_count = 0
    native_count = 0
    for item in value.requirements:
        if (
            item.target_runtime_requirement_ref
            in by_runtime_requirement_ref
            or item.requirement_ref in source_requirement_refs
            or item.target_stage_requirement_ref in stage_requirement_refs
            or item.target_shebang_requirement_ref in terminal_refs
        ):
            raise _InvalidTargetRequirements
        by_runtime_requirement_ref[item.target_runtime_requirement_ref] = item
        source_requirement_refs.add(item.requirement_ref)
        stage_requirement_refs.add(item.target_stage_requirement_ref)
        terminal_refs.add(item.target_shebang_requirement_ref)
        if item.disposition == "native_not_applicable":
            native_count += 1
            continue
        direct_count += 1
        if item.target_runtime_file_ref is None:
            raise _InvalidTargetRequirements
        prior = unique_target_rows.get(item.target_runtime_file_ref)
        if prior is None:
            unique_target_rows[item.target_runtime_file_ref] = item
        elif (
            item.target_measurement_ref != prior.target_measurement_ref
            or item.target_staged_file_ref != prior.target_staged_file_ref
            or item.target_runtime_classification
            != prior.target_runtime_classification
            or item.disposition != prior.disposition
            or item.target_shebang_directive_ref
            != prior.target_shebang_directive_ref
            or item.interpreter_token_ref != prior.interpreter_token_ref
            or item.interpreter_token_bytes != prior.interpreter_token_bytes
            or item.argument_separator_kind
            != prior.argument_separator_kind
            or item.argument_tail_ref != prior.argument_tail_ref
            or item.argument_tail_bytes != prior.argument_tail_bytes
        ):
            raise _InvalidTargetRequirements

    command_ids: set[str] = set()
    bound_terminal_refs: set[str] = set()
    ordered_terminal_refs: list[str] = []
    prior_kind_index = -1
    for binding in value.bindings:
        requirement = by_runtime_requirement_ref.get(
            binding.target_runtime_requirement_ref
        )
        kind_index = _COMMAND_KINDS.index(binding.command_kind)
        if (
            requirement is None
            or binding.staged_file_ref != requirement.staged_file_ref
            or binding.runtime_file_ref != requirement.runtime_file_ref
            or binding.requirement_ref != requirement.requirement_ref
            or binding.target_requirement_ref
            != requirement.target_requirement_ref
            or binding.target_stage_requirement_ref
            != requirement.target_stage_requirement_ref
            or binding.target_shebang_requirement_ref
            != requirement.target_shebang_requirement_ref
            or binding.command_id in command_ids
            or kind_index < prior_kind_index
        ):
            raise _InvalidTargetRequirements
        command_ids.add(binding.command_id)
        if binding.target_shebang_requirement_ref not in bound_terminal_refs:
            ordered_terminal_refs.append(
                binding.target_shebang_requirement_ref
            )
        bound_terminal_refs.add(binding.target_shebang_requirement_ref)
        prior_kind_index = kind_index

    unique_rows = tuple(unique_target_rows.values())
    posix_count = sum(
        item.target_runtime_classification == "posix_shebang"
        for item in unique_rows
    )
    tail_count = sum(item.argument_tail_ref is not None for item in unique_rows)
    total_token_bytes = sum(
        item.interpreter_token_bytes for item in unique_rows
    )
    total_tail_bytes = sum(item.argument_tail_bytes for item in unique_rows)
    if (
        bound_terminal_refs != terminal_refs
        or tuple(ordered_terminal_refs)
        != tuple(
            item.target_shebang_requirement_ref
            for item in value.requirements
        )
        or direct_count != value.direct_target_requirement_count
        or native_count != value.native_not_applicable_count
        or direct_count + native_count != value.requirement_count
        or len(unique_rows) != value.unique_target_count
        or posix_count != value.target_posix_shebang_requirement_count
        or tail_count != value.argument_tail_requirement_count
        or total_token_bytes != value.total_interpreter_token_bytes
        or total_tail_bytes != value.total_argument_tail_bytes
        or (value.unique_target_count == 0 and direct_count != 0)
        or (value.unique_target_count > 0 and direct_count == 0)
    ):
        raise _InvalidTargetRequirements

    return {
        "argument_tail_requirement_count": (
            value.argument_tail_requirement_count
        ),
        "bindings": bindings,
        "command_count": value.command_count,
        "direct_target_requirement_count": (
            value.direct_target_requirement_count
        ),
        "kind": value.kind,
        "native_not_applicable_count": value.native_not_applicable_count,
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
        "shebang_requirements_receipt_digest": (
            value.shebang_requirements_receipt_digest
        ),
        "source_staging_context_digest": (
            value.source_staging_context_digest
        ),
        "staging_receipt_digest": value.staging_receipt_digest,
        "target_path_context_digest": value.target_path_context_digest,
        "target_posix_shebang_requirement_count": (
            value.target_posix_shebang_requirement_count
        ),
        "target_resolution_receipt_digest": (
            value.target_resolution_receipt_digest
        ),
        "target_runtime_manifest_receipt_digest": (
            value.target_runtime_manifest_receipt_digest
        ),
        "target_staging_context_digest": (
            value.target_staging_context_digest
        ),
        "target_staging_receipt_digest": (
            value.target_staging_receipt_digest
        ),
        "total_argument_tail_bytes": value.total_argument_tail_bytes,
        "total_interpreter_token_bytes": (
            value.total_interpreter_token_bytes
        ),
        "unique_target_count": value.unique_target_count,
        "verification_commands_digest": (
            value.verification_commands_digest
        ),
    }


def _evidence_projection(
    value: RepositoryExecutableShebangTargetRequirementsReceipt,
) -> dict[str, Any]:
    canonical = _BUILTIN_RECEIPT_PROJECTION(value)
    unique_rows: dict[
        str, RepositoryExecutableShebangTargetShebangRequirement
    ] = {}
    for item in value.requirements:
        if item.target_runtime_file_ref is not None:
            unique_rows.setdefault(item.target_runtime_file_ref, item)
    dispositions = {
        disposition: sum(
            item.disposition == disposition
            for item in unique_rows.values()
        )
        for disposition in _DISPOSITIONS
        if disposition != "native_not_applicable"
    }
    return {
        "absolute_interpreter_token_count": dispositions[
            "absolute_interpreter_token"
        ],
        "action_receipt_issued": False,
        "active_target_stage_lease_verified_at_measurement": True,
        "argument_tail_requirement_count": (
            value.argument_tail_requirement_count
        ),
        "atomic_snapshot_verified": False,
        "authority_granted": False,
        "authorization_verified": False,
        "billing_eligible": False,
        "bounded_target_shebang_requirement_extraction_complete": True,
        "capacity_eligible": False,
        "circuit_eligible": False,
        "command_count": value.command_count,
        "current_lease_activity_verified": False,
        "current_source_freshness_verified": False,
        "dependency_environment_coverage_verified": False,
        "direct_target_requirement_count": (
            value.direct_target_requirement_count
        ),
        "dispatch_enabled": False,
        "durable_control_plane_persistence_enabled": False,
        "dynamic_loader_identity_verified": False,
        "effect_class": 0,
        "effective_interpreter_resolution_verified": False,
        "effective_invocability_verified": False,
        "environment_coverage_verified": False,
        "exact_target_runtime_manifest_correspondence_verified": True,
        "execution_enabled": False,
        "external_hardlink_alias_excluded": False,
        "external_writable_descriptor_absence_verified": False,
        "filesystem_immutability_verified": False,
        "fork_descriptor_inheritance_excluded": False,
        "future_execution_correspondence_verified": False,
        "hardlink_alias_exclusion_verified": False,
        "harness_invocation_performed": False,
        "interpreter_argument_semantics_verified": False,
        "interpreter_authenticity_verified": False,
        "interpreter_compatibility_verified": False,
        "interpreter_identity_verified": False,
        "interpreter_provenance_verified": False,
        "interpreter_token_syntax_classification_complete": True,
        "kind": _FIXED_EVIDENCE_KIND,
        "launcher_semantics_verified": False,
        "lease_cleanup_performed": False,
        "lease_mutated": False,
        "live_execution_eligible": False,
        "mount_alias_exclusion_verified": False,
        "native_binary_no_shebang_count": dispositions[
            "native_binary_no_shebang"
        ],
        "native_not_applicable_count": value.native_not_applicable_count,
        "native_runtime_dependency_coverage_verified": False,
        "non_absolute_interpreter_token_count": dispositions[
            "non_absolute_interpreter_token"
        ],
        "path_lookup_performed": False,
        "proposal_lineage_extended": False,
        "receipt_authenticity_verified": False,
        "receipt_digest": _BUILTIN_CANONICAL_DIGEST(canonical),
        "recursive_shebang_resolution_verified": False,
        "registration_digest": value.registration_digest,
        "repository_ref": value.repository_ref,
        "requirement_binding_correspondence_verified": True,
        "requirement_count": value.requirement_count,
        "requirements_scope": value.requirements_scope,
        "requirements_source": value.requirements_source,
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
        "target_posix_shebang_requirement_count": (
            value.target_posix_shebang_requirement_count
        ),
        "target_resolution_receipt_digest": (
            value.target_resolution_receipt_digest
        ),
        "target_runtime_manifest_receipt_digest": (
            value.target_runtime_manifest_receipt_digest
        ),
        "target_semantics_verified": False,
        "target_staging_receipt_digest": (
            value.target_staging_receipt_digest
        ),
        "toolchain_completeness_verified": False,
        "total_argument_tail_bytes": value.total_argument_tail_bytes,
        "total_interpreter_token_bytes": (
            value.total_interpreter_token_bytes
        ),
        "unique_target_count": value.unique_target_count,
        "unknown_runtime_format_count": dispositions[
            "unknown_runtime_format"
        ],
        "unsupported_shebang_count": dispositions[
            "unsupported_shebang"
        ],
        "validation_mode": "read_only",
        "worktree_integration_enabled": False,
    }


def _target_staged_file_projection(
    value: RepositoryExecutableShebangTargetStagedFile,
    *,
    target_staging_context_digest: str,
) -> dict[str, Any]:
    digest_fields = (
        value.target_path_ref,
        value.source_filesystem_identity_ref,
        value.source_metadata_digest,
        value.target_measurement_ref,
        value.target_staged_file_ref,
        value.staged_filesystem_identity_ref,
        value.staged_metadata_digest,
        value.content_digest,
    )
    if (
        type(value) is not _FIXED_TARGET_STAGED_FILE_TYPE
        or type(value.kind) is not str
        or value.kind != _TARGET_STAGED_FILE_KIND
        or not all(_BUILTIN_IS_DIGEST(item) for item in digest_fields)
        or type(value.content_bytes) is not int
        or not 0 <= value.content_bytes <= _MAX_FILE_BYTES
    ):
        raise _InvalidTargetRequirements
    expected_ref = _BUILTIN_CANONICAL_DIGEST(
        {
            "content_digest": value.content_digest,
            "kind": (
                "repository_executable_shebang_target_staged_file_ref"
            ),
            "schema_version": 1,
            "source_filesystem_identity_ref": (
                value.source_filesystem_identity_ref
            ),
            "source_metadata_digest": value.source_metadata_digest,
            "staged_filesystem_identity_ref": (
                value.staged_filesystem_identity_ref
            ),
            "staged_metadata_digest": value.staged_metadata_digest,
            "target_measurement_ref": value.target_measurement_ref,
            "target_path_ref": value.target_path_ref,
            "target_staging_context_digest": target_staging_context_digest,
        }
    )
    if value.target_staged_file_ref != expected_ref:
        raise _InvalidTargetRequirements
    return {
        "content_bytes": value.content_bytes,
        "content_digest": value.content_digest,
        "kind": value.kind,
        "source_filesystem_identity_ref": value.source_filesystem_identity_ref,
        "source_metadata_digest": value.source_metadata_digest,
        "staged_filesystem_identity_ref": value.staged_filesystem_identity_ref,
        "staged_metadata_digest": value.staged_metadata_digest,
        "target_measurement_ref": value.target_measurement_ref,
        "target_path_ref": value.target_path_ref,
        "target_staged_file_ref": value.target_staged_file_ref,
    }


def _target_stage_requirement_ref_projection(
    *,
    staged_file_ref: str,
    runtime_file_ref: str,
    requirement_ref: str,
    target_requirement_ref: str,
    runtime_classification: str,
    disposition: str,
    target_measurement_ref: str | None,
    target_staged_file_ref: str | None,
) -> dict[str, Any]:
    return {
        "disposition": disposition,
        "kind": (
            "repository_executable_shebang_target_stage_requirement_ref"
        ),
        "requirement_ref": requirement_ref,
        "runtime_classification": runtime_classification,
        "runtime_file_ref": runtime_file_ref,
        "schema_version": 1,
        "staged_file_ref": staged_file_ref,
        "target_measurement_ref": target_measurement_ref,
        "target_requirement_ref": target_requirement_ref,
        "target_staged_file_ref": target_staged_file_ref,
    }


def _target_stage_requirement_projection(
    value: RepositoryExecutableShebangTargetStageRequirement,
) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_TARGET_STAGE_REQUIREMENT_TYPE
        or type(value.kind) is not str
        or value.kind != _TARGET_STAGE_REQUIREMENT_KIND
        or not all(
            _BUILTIN_IS_DIGEST(item)
            for item in (
                value.staged_file_ref,
                value.runtime_file_ref,
                value.requirement_ref,
                value.target_requirement_ref,
                value.target_stage_requirement_ref,
            )
        )
        or type(value.runtime_classification) is not str
        or value.runtime_classification not in _SOURCE_RUNTIME_CLASSIFICATIONS
        or type(value.disposition) is not str
        or value.disposition not in _TARGET_STAGE_DISPOSITIONS
        or (
            value.target_measurement_ref is not None
            and not _BUILTIN_IS_DIGEST(value.target_measurement_ref)
        )
        or (
            value.target_staged_file_ref is not None
            and not _BUILTIN_IS_DIGEST(value.target_staged_file_ref)
        )
        or (
            value.disposition == "direct_absolute_target_staged"
            and (
                value.runtime_classification != "posix_shebang"
                or value.target_measurement_ref is None
                or value.target_staged_file_ref is None
            )
        )
        or (
            value.disposition == "native_not_applicable"
            and (
                value.runtime_classification not in {"elf", "mach_o"}
                or value.target_measurement_ref is not None
                or value.target_staged_file_ref is not None
            )
        )
    ):
        raise _InvalidTargetRequirements
    reference = _BUILTIN_TARGET_STAGE_REQUIREMENT_REF_PROJECTION(
        staged_file_ref=value.staged_file_ref,
        runtime_file_ref=value.runtime_file_ref,
        requirement_ref=value.requirement_ref,
        target_requirement_ref=value.target_requirement_ref,
        runtime_classification=value.runtime_classification,
        disposition=value.disposition,
        target_measurement_ref=value.target_measurement_ref,
        target_staged_file_ref=value.target_staged_file_ref,
    )
    if value.target_stage_requirement_ref != _BUILTIN_CANONICAL_DIGEST(
        reference
    ):
        raise _InvalidTargetRequirements
    return {
        **reference,
        "kind": value.kind,
        "target_stage_requirement_ref": value.target_stage_requirement_ref,
    }


def _target_stage_binding_projection(
    value: RepositoryExecutableShebangTargetStageBinding,
) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_TARGET_STAGE_BINDING_TYPE
        or type(value.kind) is not str
        or value.kind != _TARGET_STAGE_BINDING_KIND
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
            )
        )
    ):
        raise _InvalidTargetRequirements
    return {
        "command_digest": value.command_digest,
        "command_id": value.command_id,
        "command_kind": value.command_kind,
        "kind": value.kind,
        "requirement_ref": value.requirement_ref,
        "runtime_file_ref": value.runtime_file_ref,
        "staged_file_ref": value.staged_file_ref,
        "target_requirement_ref": value.target_requirement_ref,
        "target_stage_requirement_ref": value.target_stage_requirement_ref,
    }


def _target_noop_staging_context_digest() -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "kind": "repository_executable_shebang_target_staging_context",
            "schema_version": 1,
            "staging_root_used": False,
            "staging_scope": _TARGET_STAGING_SCOPE,
        }
    )


def _target_staging_receipt_projection(
    value: RepositoryExecutableShebangTargetStagingReceipt,
) -> dict[str, Any]:
    digest_fields = (
        value.shebang_requirements_receipt_digest,
        value.runtime_manifest_receipt_digest,
        value.staging_receipt_digest,
        value.registration_digest,
        value.repository_ref,
        value.verification_commands_digest,
        value.resolution_context_digest,
        value.source_staging_context_digest,
        value.target_path_context_digest,
        value.expected_target_resolution_receipt_digest,
        value.action_target_resolution_receipt_digest,
        value.post_stage_target_resolution_receipt_digest,
        value.target_staging_context_digest,
    )
    if (
        type(value) is not _FIXED_TARGET_STAGING_RECEIPT_TYPE
        or type(value.kind) is not str
        or value.kind != _TARGET_STAGING_KIND
        or type(value.schema_version) is not int
        or value.schema_version != 1
        or type(value.measurement_source) is not str
        or value.measurement_source != _TARGET_MEASUREMENT_SOURCE
        or type(value.resolution_scope) is not str
        or value.resolution_scope != _TARGET_RESOLUTION_SCOPE
        or type(value.staging_source) is not str
        or value.staging_source != _TARGET_STAGING_SOURCE
        or type(value.staging_scope) is not str
        or value.staging_scope != _TARGET_STAGING_SCOPE
        or not all(_BUILTIN_IS_DIGEST(item) for item in digest_fields)
        or value.expected_target_resolution_receipt_digest
        != value.action_target_resolution_receipt_digest
        or value.action_target_resolution_receipt_digest
        != value.post_stage_target_resolution_receipt_digest
        or type(value.staging_root_used) is not bool
        or type(value.staged_files) is not tuple
        or not 0 <= len(value.staged_files) <= _MAX_FILES
        or type(value.requirements) is not tuple
        or not 1 <= len(value.requirements) <= _MAX_REQUIREMENTS
        or type(value.bindings) is not tuple
        or not 1 <= len(value.bindings) <= _MAX_COMMANDS
        or type(value.requirement_count) is not int
        or value.requirement_count != len(value.requirements)
        or type(value.command_count) is not int
        or value.command_count != len(value.bindings)
        or type(value.direct_target_requirement_count) is not int
        or type(value.native_not_applicable_count) is not int
        or type(value.unique_target_count) is not int
        or value.unique_target_count != len(value.staged_files)
        or type(value.total_staged_bytes) is not int
        or not 0 <= value.total_staged_bytes <= _MAX_TOTAL_BYTES
        or value.staging_root_used != bool(value.unique_target_count)
        or (
            not value.staging_root_used
            and value.target_staging_context_digest
            != _BUILTIN_TARGET_NOOP_STAGING_CONTEXT_DIGEST()
        )
    ):
        raise _InvalidTargetRequirements

    staged_files = [
        _BUILTIN_TARGET_STAGED_FILE_PROJECTION(
            item,
            target_staging_context_digest=value.target_staging_context_digest,
        )
        for item in value.staged_files
    ]
    requirements = [
        _BUILTIN_TARGET_STAGE_REQUIREMENT_PROJECTION(item)
        for item in value.requirements
    ]
    bindings = [
        _BUILTIN_TARGET_STAGE_BINDING_PROJECTION(item)
        for item in value.bindings
    ]

    file_by_ref: dict[str, RepositoryExecutableShebangTargetStagedFile] = {}
    file_by_measurement: dict[
        str, RepositoryExecutableShebangTargetStagedFile
    ] = {}
    path_refs: set[str] = set()
    source_refs: set[str] = set()
    staged_identity_refs: set[str] = set()
    total_bytes = 0
    for item in value.staged_files:
        if (
            item.target_staged_file_ref in file_by_ref
            or item.target_measurement_ref in file_by_measurement
            or item.target_path_ref in path_refs
            or item.source_filesystem_identity_ref in source_refs
            or item.staged_filesystem_identity_ref in staged_identity_refs
        ):
            raise _InvalidTargetRequirements
        file_by_ref[item.target_staged_file_ref] = item
        file_by_measurement[item.target_measurement_ref] = item
        path_refs.add(item.target_path_ref)
        source_refs.add(item.source_filesystem_identity_ref)
        staged_identity_refs.add(item.staged_filesystem_identity_ref)
        total_bytes += item.content_bytes

    requirement_by_ref: dict[
        str, RepositoryExecutableShebangTargetStageRequirement
    ] = {}
    stage_requirement_refs: set[str] = set()
    first_use_measurements: list[str] = []
    used_file_refs: set[str] = set()
    direct_count = 0
    native_count = 0
    for item in value.requirements:
        if (
            item.requirement_ref in requirement_by_ref
            or item.target_stage_requirement_ref in stage_requirement_refs
        ):
            raise _InvalidTargetRequirements
        requirement_by_ref[item.requirement_ref] = item
        stage_requirement_refs.add(item.target_stage_requirement_ref)
        if item.disposition == "direct_absolute_target_staged":
            direct_count += 1
            if (
                item.target_measurement_ref is None
                or item.target_staged_file_ref is None
            ):
                raise _InvalidTargetRequirements
            staged = file_by_measurement.get(item.target_measurement_ref)
            if (
                staged is None
                or staged.target_staged_file_ref != item.target_staged_file_ref
            ):
                raise _InvalidTargetRequirements
            if item.target_measurement_ref not in first_use_measurements:
                first_use_measurements.append(item.target_measurement_ref)
            used_file_refs.add(item.target_staged_file_ref)
        else:
            native_count += 1
    if (
        tuple(first_use_measurements)
        != tuple(item.target_measurement_ref for item in value.staged_files)
        or used_file_refs != set(file_by_ref)
    ):
        raise _InvalidTargetRequirements

    command_ids: set[str] = set()
    bound_refs: set[str] = set()
    ordered_refs: list[str] = []
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
            or binding.command_id in command_ids
            or kind_index < prior_kind_index
        ):
            raise _InvalidTargetRequirements
        command_ids.add(binding.command_id)
        if binding.target_stage_requirement_ref not in bound_refs:
            ordered_refs.append(binding.target_stage_requirement_ref)
        bound_refs.add(binding.target_stage_requirement_ref)
        prior_kind_index = kind_index

    if (
        bound_refs != stage_requirement_refs
        or tuple(ordered_refs)
        != tuple(item.target_stage_requirement_ref for item in value.requirements)
        or direct_count != value.direct_target_requirement_count
        or native_count != value.native_not_applicable_count
        or direct_count + native_count != value.requirement_count
        or total_bytes != value.total_staged_bytes
        or (value.unique_target_count == 0 and direct_count != 0)
        or (value.unique_target_count > 0 and direct_count == 0)
    ):
        raise _InvalidTargetRequirements

    return {
        "action_target_resolution_receipt_digest": value.action_target_resolution_receipt_digest,
        "bindings": bindings,
        "command_count": value.command_count,
        "direct_target_requirement_count": value.direct_target_requirement_count,
        "expected_target_resolution_receipt_digest": value.expected_target_resolution_receipt_digest,
        "kind": value.kind,
        "measurement_source": value.measurement_source,
        "native_not_applicable_count": value.native_not_applicable_count,
        "post_stage_target_resolution_receipt_digest": value.post_stage_target_resolution_receipt_digest,
        "registration_digest": value.registration_digest,
        "repository_ref": value.repository_ref,
        "requirement_count": value.requirement_count,
        "requirements": requirements,
        "resolution_context_digest": value.resolution_context_digest,
        "resolution_scope": value.resolution_scope,
        "runtime_manifest_receipt_digest": value.runtime_manifest_receipt_digest,
        "schema_version": value.schema_version,
        "shebang_requirements_receipt_digest": value.shebang_requirements_receipt_digest,
        "source_staging_context_digest": value.source_staging_context_digest,
        "staged_files": staged_files,
        "staging_receipt_digest": value.staging_receipt_digest,
        "staging_root_used": value.staging_root_used,
        "staging_scope": value.staging_scope,
        "staging_source": value.staging_source,
        "target_path_context_digest": value.target_path_context_digest,
        "target_staging_context_digest": value.target_staging_context_digest,
        "total_staged_bytes": value.total_staged_bytes,
        "unique_target_count": value.unique_target_count,
        "verification_commands_digest": value.verification_commands_digest,
    }


def _target_runtime_file_ref_projection(
    *,
    target_staged_file_ref: str,
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
        "kind": "repository_executable_shebang_target_runtime_file_ref",
        "manifest_scope": _TARGET_RUNTIME_MANIFEST_SCOPE,
        "schema_version": 1,
        "shebang_directive_ref": shebang_directive_ref,
        "staged_filesystem_identity_ref": staged_filesystem_identity_ref,
        "target_staged_file_ref": target_staged_file_ref,
    }


def _target_runtime_file_projection(
    value: RepositoryExecutableShebangTargetRuntimeFile,
) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_TARGET_RUNTIME_FILE_TYPE
        or type(value.kind) is not str
        or value.kind != _TARGET_RUNTIME_FILE_KIND
        or not _BUILTIN_IS_DIGEST(value.target_staged_file_ref)
        or not _BUILTIN_IS_DIGEST(value.staged_filesystem_identity_ref)
        or not _BUILTIN_IS_DIGEST(value.content_digest)
        or type(value.content_bytes) is not int
        or not 0 <= value.content_bytes <= _MAX_FILE_BYTES
        or not _BUILTIN_IS_DIGEST(value.target_runtime_file_ref)
        or not _BUILTIN_IS_DIGEST(value.header_digest)
        or type(value.header_bytes) is not int
        or not 0 <= value.header_bytes <= _MAX_HEADER_BYTES
        or value.header_bytes != min(value.content_bytes, _MAX_HEADER_BYTES)
        or type(value.classification) is not str
        or value.classification not in _TARGET_RUNTIME_CLASSIFICATIONS
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
        raise _InvalidTargetRequirements
    reference = _BUILTIN_TARGET_RUNTIME_FILE_REF_PROJECTION(
        target_staged_file_ref=value.target_staged_file_ref,
        staged_filesystem_identity_ref=value.staged_filesystem_identity_ref,
        content_digest=value.content_digest,
        content_bytes=value.content_bytes,
        header_digest=value.header_digest,
        header_bytes=value.header_bytes,
        classification=value.classification,
        shebang_directive_ref=value.shebang_directive_ref,
    )
    if value.target_runtime_file_ref != _BUILTIN_CANONICAL_DIGEST(reference):
        raise _InvalidTargetRequirements
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
        "target_runtime_file_ref": value.target_runtime_file_ref,
        "target_staged_file_ref": value.target_staged_file_ref,
    }


def _target_runtime_requirement_ref_projection(
    *,
    staged_file_ref: str,
    runtime_file_ref: str,
    requirement_ref: str,
    target_requirement_ref: str,
    target_stage_requirement_ref: str,
    runtime_classification: str,
    disposition: str,
    target_measurement_ref: str | None,
    target_staged_file_ref: str | None,
    target_runtime_file_ref: str | None,
) -> dict[str, Any]:
    return {
        "disposition": disposition,
        "kind": (
            "repository_executable_shebang_target_runtime_requirement_ref"
        ),
        "requirement_ref": requirement_ref,
        "runtime_classification": runtime_classification,
        "runtime_file_ref": runtime_file_ref,
        "schema_version": 1,
        "staged_file_ref": staged_file_ref,
        "target_measurement_ref": target_measurement_ref,
        "target_requirement_ref": target_requirement_ref,
        "target_runtime_file_ref": target_runtime_file_ref,
        "target_stage_requirement_ref": target_stage_requirement_ref,
        "target_staged_file_ref": target_staged_file_ref,
    }


def _target_runtime_requirement_projection(
    value: RepositoryExecutableShebangTargetRuntimeRequirement,
) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_TARGET_RUNTIME_REQUIREMENT_TYPE
        or type(value.kind) is not str
        or value.kind != _TARGET_RUNTIME_REQUIREMENT_KIND
        or not all(
            _BUILTIN_IS_DIGEST(item)
            for item in (
                value.staged_file_ref,
                value.runtime_file_ref,
                value.requirement_ref,
                value.target_requirement_ref,
                value.target_stage_requirement_ref,
                value.target_runtime_requirement_ref,
            )
        )
        or type(value.runtime_classification) is not str
        or value.runtime_classification
        not in _SOURCE_RUNTIME_CLASSIFICATIONS
        or type(value.disposition) is not str
        or value.disposition not in _TARGET_RUNTIME_DISPOSITIONS
        or (
            value.target_measurement_ref is not None
            and not _BUILTIN_IS_DIGEST(value.target_measurement_ref)
        )
        or (
            value.target_staged_file_ref is not None
            and not _BUILTIN_IS_DIGEST(value.target_staged_file_ref)
        )
        or (
            value.target_runtime_file_ref is not None
            and not _BUILTIN_IS_DIGEST(value.target_runtime_file_ref)
        )
        or (
            value.disposition
            == "direct_absolute_target_runtime_inspected"
            and (
                value.runtime_classification != "posix_shebang"
                or value.target_measurement_ref is None
                or value.target_staged_file_ref is None
                or value.target_runtime_file_ref is None
            )
        )
        or (
            value.disposition == "native_not_applicable"
            and (
                value.runtime_classification not in {"elf", "mach_o"}
                or value.target_measurement_ref is not None
                or value.target_staged_file_ref is not None
                or value.target_runtime_file_ref is not None
            )
        )
    ):
        raise _InvalidTargetRequirements
    reference = _BUILTIN_TARGET_RUNTIME_REQUIREMENT_REF_PROJECTION(
        staged_file_ref=value.staged_file_ref,
        runtime_file_ref=value.runtime_file_ref,
        requirement_ref=value.requirement_ref,
        target_requirement_ref=value.target_requirement_ref,
        target_stage_requirement_ref=value.target_stage_requirement_ref,
        runtime_classification=value.runtime_classification,
        disposition=value.disposition,
        target_measurement_ref=value.target_measurement_ref,
        target_staged_file_ref=value.target_staged_file_ref,
        target_runtime_file_ref=value.target_runtime_file_ref,
    )
    if value.target_runtime_requirement_ref != _BUILTIN_CANONICAL_DIGEST(
        reference
    ):
        raise _InvalidTargetRequirements
    return {
        "disposition": value.disposition,
        "kind": value.kind,
        "requirement_ref": value.requirement_ref,
        "runtime_classification": value.runtime_classification,
        "runtime_file_ref": value.runtime_file_ref,
        "schema_version": 1,
        "staged_file_ref": value.staged_file_ref,
        "target_measurement_ref": value.target_measurement_ref,
        "target_requirement_ref": value.target_requirement_ref,
        "target_runtime_file_ref": value.target_runtime_file_ref,
        "target_runtime_requirement_ref": (
            value.target_runtime_requirement_ref
        ),
        "target_stage_requirement_ref": value.target_stage_requirement_ref,
        "target_staged_file_ref": value.target_staged_file_ref,
    }


def _target_runtime_binding_projection(
    value: RepositoryExecutableShebangTargetRuntimeBinding,
) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_TARGET_RUNTIME_BINDING_TYPE
        or type(value.kind) is not str
        or value.kind != _TARGET_RUNTIME_BINDING_KIND
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
            )
        )
    ):
        raise _InvalidTargetRequirements
    return {
        "command_digest": value.command_digest,
        "command_id": value.command_id,
        "command_kind": value.command_kind,
        "kind": value.kind,
        "requirement_ref": value.requirement_ref,
        "runtime_file_ref": value.runtime_file_ref,
        "staged_file_ref": value.staged_file_ref,
        "target_requirement_ref": value.target_requirement_ref,
        "target_runtime_requirement_ref": (
            value.target_runtime_requirement_ref
        ),
        "target_stage_requirement_ref": value.target_stage_requirement_ref,
    }


def _target_runtime_manifest_projection(
    value: RepositoryExecutableShebangTargetRuntimeManifestReceipt,
) -> dict[str, Any]:
    digest_fields = (
        value.target_staging_receipt_digest,
        value.target_resolution_receipt_digest,
        value.shebang_requirements_receipt_digest,
        value.runtime_manifest_receipt_digest,
        value.staging_receipt_digest,
        value.registration_digest,
        value.repository_ref,
        value.verification_commands_digest,
        value.resolution_context_digest,
        value.source_staging_context_digest,
        value.target_path_context_digest,
        value.target_staging_context_digest,
    )
    if (
        type(value) is not _FIXED_TARGET_RUNTIME_RECEIPT_TYPE
        or type(value.kind) is not str
        or value.kind != _TARGET_RUNTIME_MANIFEST_KIND
        or type(value.schema_version) is not int
        or value.schema_version != 1
        or type(value.manifest_source) is not str
        or value.manifest_source != _TARGET_RUNTIME_MANIFEST_SOURCE
        or type(value.manifest_scope) is not str
        or value.manifest_scope != _TARGET_RUNTIME_MANIFEST_SCOPE
        or not all(_BUILTIN_IS_DIGEST(item) for item in digest_fields)
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
        or type(value.direct_target_requirement_count) is not int
        or type(value.native_not_applicable_count) is not int
        or type(value.total_content_bytes) is not int
        or not 0 <= value.total_content_bytes <= _MAX_TOTAL_BYTES
        or type(value.total_header_bytes) is not int
        or not 0
        <= value.total_header_bytes
        <= _MAX_FILES * _MAX_HEADER_BYTES
    ):
        raise _InvalidTargetRequirements

    files = [
        _BUILTIN_TARGET_RUNTIME_FILE_PROJECTION(item) for item in value.files
    ]
    requirements = [
        _BUILTIN_TARGET_RUNTIME_REQUIREMENT_PROJECTION(item)
        for item in value.requirements
    ]
    bindings = [
        _BUILTIN_TARGET_RUNTIME_BINDING_PROJECTION(item)
        for item in value.bindings
    ]

    file_by_staged_ref: dict[
        str, RepositoryExecutableShebangTargetRuntimeFile
    ] = {}
    runtime_file_refs: set[str] = set()
    staged_identity_refs: set[str] = set()
    total_content_bytes = 0
    total_header_bytes = 0
    for item in value.files:
        if (
            item.target_staged_file_ref in file_by_staged_ref
            or item.target_runtime_file_ref in runtime_file_refs
            or item.staged_filesystem_identity_ref in staged_identity_refs
        ):
            raise _InvalidTargetRequirements
        file_by_staged_ref[item.target_staged_file_ref] = item
        runtime_file_refs.add(item.target_runtime_file_ref)
        staged_identity_refs.add(item.staged_filesystem_identity_ref)
        total_content_bytes += item.content_bytes
        total_header_bytes += item.header_bytes

    requirement_by_source_ref: dict[
        str, RepositoryExecutableShebangTargetRuntimeRequirement
    ] = {}
    runtime_requirement_refs: set[str] = set()
    stage_requirement_refs: set[str] = set()
    first_use_file_refs: list[str] = []
    used_file_refs: set[str] = set()
    direct_count = 0
    native_count = 0
    for item in value.requirements:
        if (
            item.requirement_ref in requirement_by_source_ref
            or item.target_runtime_requirement_ref in runtime_requirement_refs
            or item.target_stage_requirement_ref in stage_requirement_refs
        ):
            raise _InvalidTargetRequirements
        requirement_by_source_ref[item.requirement_ref] = item
        runtime_requirement_refs.add(item.target_runtime_requirement_ref)
        stage_requirement_refs.add(item.target_stage_requirement_ref)
        if item.disposition == "direct_absolute_target_runtime_inspected":
            direct_count += 1
            if (
                item.target_staged_file_ref is None
                or item.target_runtime_file_ref is None
            ):
                raise _InvalidTargetRequirements
            runtime_file = file_by_staged_ref.get(item.target_staged_file_ref)
            if (
                runtime_file is None
                or runtime_file.target_runtime_file_ref
                != item.target_runtime_file_ref
            ):
                raise _InvalidTargetRequirements
            if item.target_staged_file_ref not in first_use_file_refs:
                first_use_file_refs.append(item.target_staged_file_ref)
            used_file_refs.add(item.target_staged_file_ref)
        else:
            native_count += 1
    if (
        tuple(first_use_file_refs)
        != tuple(item.target_staged_file_ref for item in value.files)
        or used_file_refs != set(file_by_staged_ref)
    ):
        raise _InvalidTargetRequirements

    command_ids: set[str] = set()
    bound_runtime_requirement_refs: set[str] = set()
    ordered_runtime_requirement_refs: list[str] = []
    prior_kind_index = -1
    for binding in value.bindings:
        requirement = requirement_by_source_ref.get(binding.requirement_ref)
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
            or binding.command_id in command_ids
            or kind_index < prior_kind_index
        ):
            raise _InvalidTargetRequirements
        command_ids.add(binding.command_id)
        if (
            binding.target_runtime_requirement_ref
            not in bound_runtime_requirement_refs
        ):
            ordered_runtime_requirement_refs.append(
                binding.target_runtime_requirement_ref
            )
        bound_runtime_requirement_refs.add(
            binding.target_runtime_requirement_ref
        )
        prior_kind_index = kind_index

    if (
        bound_runtime_requirement_refs != runtime_requirement_refs
        or tuple(ordered_runtime_requirement_refs)
        != tuple(
            item.target_runtime_requirement_ref
            for item in value.requirements
        )
        or direct_count != value.direct_target_requirement_count
        or native_count != value.native_not_applicable_count
        or direct_count + native_count != value.requirement_count
        or total_content_bytes != value.total_content_bytes
        or total_header_bytes != value.total_header_bytes
        or (value.file_count == 0 and direct_count != 0)
        or (value.file_count > 0 and direct_count == 0)
    ):
        raise _InvalidTargetRequirements

    return {
        "bindings": bindings,
        "command_count": value.command_count,
        "direct_target_requirement_count": (
            value.direct_target_requirement_count
        ),
        "file_count": value.file_count,
        "files": files,
        "kind": value.kind,
        "manifest_scope": value.manifest_scope,
        "manifest_source": value.manifest_source,
        "native_not_applicable_count": value.native_not_applicable_count,
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
        "staging_receipt_digest": value.staging_receipt_digest,
        "target_path_context_digest": value.target_path_context_digest,
        "target_resolution_receipt_digest": (
            value.target_resolution_receipt_digest
        ),
        "target_staging_context_digest": (
            value.target_staging_context_digest
        ),
        "target_staging_receipt_digest": (
            value.target_staging_receipt_digest
        ),
        "total_content_bytes": value.total_content_bytes,
        "total_header_bytes": value.total_header_bytes,
        "verification_commands_digest": (
            value.verification_commands_digest
        ),
    }


# Freeze the complete local canonical proof graph before the public boundary.
_BUILTIN_REQUIREMENT_REF_PROJECTION = _requirement_ref_projection
_BUILTIN_REQUIREMENT_PROJECTION = _requirement_projection
_BUILTIN_BINDING_PROJECTION = _binding_projection
_BUILTIN_RECEIPT_PROJECTION = _receipt_projection
_BUILTIN_TARGET_STAGED_FILE_PROJECTION = _target_staged_file_projection
_BUILTIN_TARGET_STAGE_REQUIREMENT_REF_PROJECTION = (
    _target_stage_requirement_ref_projection
)
_BUILTIN_TARGET_STAGE_REQUIREMENT_PROJECTION = (
    _target_stage_requirement_projection
)
_BUILTIN_TARGET_STAGE_BINDING_PROJECTION = (
    _target_stage_binding_projection
)
_BUILTIN_TARGET_NOOP_STAGING_CONTEXT_DIGEST = (
    _target_noop_staging_context_digest
)
_BUILTIN_TARGET_STAGING_RECEIPT_PROJECTION = (
    _target_staging_receipt_projection
)
_BUILTIN_TARGET_RUNTIME_FILE_REF_PROJECTION = (
    _target_runtime_file_ref_projection
)
_BUILTIN_TARGET_RUNTIME_FILE_PROJECTION = (
    _target_runtime_file_projection
)
_BUILTIN_TARGET_RUNTIME_REQUIREMENT_REF_PROJECTION = (
    _target_runtime_requirement_ref_projection
)
_BUILTIN_TARGET_RUNTIME_REQUIREMENT_PROJECTION = (
    _target_runtime_requirement_projection
)
_BUILTIN_TARGET_RUNTIME_BINDING_PROJECTION = (
    _target_runtime_binding_projection
)
_BUILTIN_TARGET_RUNTIME_MANIFEST_PROJECTION = (
    _target_runtime_manifest_projection
)
_BUILTIN_ACTIVE_TARGET_STAGE_SNAPSHOT = _active_target_stage_snapshot
_BUILTIN_VERIFY_ANCHORED_RETAINED_TARGET = (
    _verify_anchored_retained_target
)
_BUILTIN_INSPECT_TARGET_RUNTIME_MANIFEST = (
    inspect_staged_executable_shebang_target_runtime_manifest
)


@dataclass(frozen=True, slots=True)
class _TargetShebangExtraction:
    """Private detached syntax result for one unique staged target."""

    target_staged_file_ref: str = field(repr=False)
    target_runtime_file_ref: str = field(repr=False)
    target_runtime_classification: str
    disposition: str
    target_shebang_directive_ref: str | None = field(repr=False)
    interpreter_token_ref: str | None = field(repr=False)
    interpreter_token_bytes: int
    argument_separator_kind: str | None
    argument_tail_ref: str | None = field(repr=False)
    argument_tail_bytes: int


_FIXED_EXTRACTION_TYPE = _TargetShebangExtraction


def _header_digest(target_staged_file_ref: str, header: bytes) -> str:
    return _DIGEST_PREFIX + _BUILTIN_SHA256(
        target_staged_file_ref.encode("ascii") + b"\x00" + header
    ).hexdigest()


def _bounded_shebang_directive(header: bytes) -> bytes | None:
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


def _classify_header(
    target_staged_file_ref: str,
    header: bytes,
) -> tuple[str, str | None, bytes | None]:
    if header.startswith(b"#!"):
        directive = _BUILTIN_BOUNDED_SHEBANG_DIRECTIVE(header)
        if directive is None:
            return "unsupported_shebang", None, None
        directive_ref = _BUILTIN_CANONICAL_DIGEST(
            {
                "directive_hex": directive.hex(),
                "kind": (
                    "repository_executable_shebang_target_"
                    "runtime_shebang_directive_ref"
                ),
                "schema_version": 1,
                "target_staged_file_ref": target_staged_file_ref,
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
        magic in _MACH_O_MINIMUM_BYTES
        and len(header) >= _MACH_O_MINIMUM_BYTES[magic]
    ):
        return "mach_o", None, None
    return "unknown", None, None


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
        raise _InvalidTargetRequirements
    separator = "space" if directive[boundary] == 0x20 else "horizontal_tab"
    return token, separator, tail


def _interpreter_token_ref(
    *,
    target_runtime_file_ref: str,
    target_shebang_directive_ref: str,
    token: bytes,
) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "interpreter_token_hex": token.hex(),
            "kind": (
                "repository_executable_shebang_target_"
                "interpreter_token_ref"
            ),
            "schema_version": _FIXED_SCHEMA_VERSION,
            "target_runtime_file_ref": target_runtime_file_ref,
            "target_shebang_directive_ref": (
                target_shebang_directive_ref
            ),
        }
    )


def _argument_tail_ref(
    *,
    target_runtime_file_ref: str,
    target_shebang_directive_ref: str,
    interpreter_token_ref: str,
    separator_kind: str,
    tail: bytes,
) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "argument_separator_kind": separator_kind,
            "argument_tail_hex": tail.hex(),
            "interpreter_token_ref": interpreter_token_ref,
            "kind": (
                "repository_executable_shebang_target_argument_tail_ref"
            ),
            "schema_version": _FIXED_SCHEMA_VERSION,
            "target_runtime_file_ref": target_runtime_file_ref,
            "target_shebang_directive_ref": (
                target_shebang_directive_ref
            ),
        }
    )


def _independent_descriptor_remeasurement(
    retained: _RetainedStagedTarget,
    staged_file: dict[str, Any],
    *,
    target_staging_context_digest: str,
) -> bytes:
    if (
        type(retained) is not _FIXED_RETAINED_TARGET_TYPE
        or type(staged_file) is not dict
        or _BUILTIN_TARGET_STAGED_FILE_PROJECTION(
            retained.staged_file,
            target_staging_context_digest=target_staging_context_digest,
        )
        != staged_file
    ):
        raise _InvalidTargetRequirements
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
        raise _InvalidTargetRequirements from None
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
        or before.st_size != staged_file["content_bytes"]
        or before_flags & _BUILTIN_O_ACCMODE != _BUILTIN_O_RDONLY
        or before_inheritable
    ):
        raise _InvalidTargetRequirements

    staged_identity_ref = _BUILTIN_CANONICAL_DIGEST(
        {
            "device": before.st_dev,
            "inode": before.st_ino,
            "kind": (
                "repository_executable_shebang_target_"
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
                "repository_executable_shebang_target_"
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
        staged_identity_ref != staged_file["staged_filesystem_identity_ref"]
        or staged_metadata_digest != staged_file["staged_metadata_digest"]
    ):
        raise _InvalidTargetRequirements

    digest = _BUILTIN_SHA256()
    header_parts: list[bytes] = []
    header_remaining = min(staged_file["content_bytes"], _MAX_HEADER_BYTES)
    offset = 0
    while offset < staged_file["content_bytes"]:
        requested = min(
            _FULL_REMEASUREMENT_CHUNK_BYTES,
            staged_file["content_bytes"] - offset,
        )
        try:
            chunk = _BUILTIN_PREAD(
                retained.descriptor,
                requested,
                offset,
            )
        except (BlockingIOError, InterruptedError, OSError):
            raise _InvalidTargetRequirements from None
        if not chunk or len(chunk) > requested:
            raise _InvalidTargetRequirements
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
            staged_file["content_bytes"],
        )
        after = _BUILTIN_FSTAT(retained.descriptor)
        after_flags = _BUILTIN_FCNTL(
            retained.descriptor,
            _BUILTIN_F_GETFL,
        )
        after_inheritable = _BUILTIN_GET_INHERITABLE(
            retained.descriptor
        )
    except (OSError, ValueError):
        raise _InvalidTargetRequirements from None
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
        or len(header)
        != min(staged_file["content_bytes"], _MAX_HEADER_BYTES)
        or _DIGEST_PREFIX + digest.hexdigest()
        != staged_file["content_digest"]
    ):
        raise _InvalidTargetRequirements
    return header


def _closing_descriptor_anchor(
    retained: _RetainedStagedTarget,
    staged_file: dict[str, Any],
    *,
    target_staging_context_digest: str,
) -> None:
    """Validate one retained descriptor without reading its content again."""

    if (
        type(retained) is not _FIXED_RETAINED_TARGET_TYPE
        or type(staged_file) is not dict
        or _BUILTIN_TARGET_STAGED_FILE_PROJECTION(
            retained.staged_file,
            target_staging_context_digest=target_staging_context_digest,
        )
        != staged_file
    ):
        raise _InvalidTargetRequirements
    try:
        current = _BUILTIN_FSTAT(retained.descriptor)
        current_flags = _BUILTIN_FCNTL(
            retained.descriptor,
            _BUILTIN_F_GETFL,
        )
        current_inheritable = _BUILTIN_GET_INHERITABLE(
            retained.descriptor
        )
    except (OSError, ValueError):
        raise _InvalidTargetRequirements from None
    current_signature = (
        current.st_dev,
        current.st_ino,
        current.st_mode,
        current.st_nlink,
        current.st_uid,
        current.st_gid,
        current.st_size,
        current.st_mtime_ns,
        current.st_ctime_ns,
    )
    if (
        current_signature != retained.metadata
        or not _BUILTIN_S_ISREG(current.st_mode)
        or current.st_uid != _BUILTIN_GETEUID()
        or _BUILTIN_S_IMODE(current.st_mode) != _STAGED_FILE_MODE
        or current.st_nlink != 0
        or current.st_size != staged_file["content_bytes"]
        or current_flags & _BUILTIN_O_ACCMODE != _BUILTIN_O_RDONLY
        or current_inheritable
    ):
        raise _InvalidTargetRequirements

    staged_identity_ref = _BUILTIN_CANONICAL_DIGEST(
        {
            "device": current.st_dev,
            "inode": current.st_ino,
            "kind": (
                "repository_executable_shebang_target_"
                "staged_file_identity"
            ),
            "schema_version": 1,
        }
    )
    staged_metadata_digest = _BUILTIN_CANONICAL_DIGEST(
        {
            "change_time_ns": current.st_ctime_ns,
            "filesystem_identity_ref": staged_identity_ref,
            "group_id": current.st_gid,
            "kind": (
                "repository_executable_shebang_target_"
                "staged_file_metadata"
            ),
            "link_count": current.st_nlink,
            "mode": current.st_mode,
            "modified_time_ns": current.st_mtime_ns,
            "owner_id": current.st_uid,
            "schema_version": 1,
            "size_bytes": current.st_size,
        }
    )
    if (
        staged_identity_ref != staged_file["staged_filesystem_identity_ref"]
        or staged_metadata_digest != staged_file["staged_metadata_digest"]
    ):
        raise _InvalidTargetRequirements


def _build_extraction(
    runtime_file: dict[str, Any],
    staged_file: dict[str, Any],
    *,
    header: bytes,
) -> _TargetShebangExtraction:
    if (
        runtime_file["target_staged_file_ref"]
        != staged_file["target_staged_file_ref"]
        or runtime_file["staged_filesystem_identity_ref"]
        != staged_file["staged_filesystem_identity_ref"]
        or runtime_file["content_digest"] != staged_file["content_digest"]
        or runtime_file["content_bytes"] != staged_file["content_bytes"]
    ):
        raise _InvalidTargetRequirements
    classification, directive_ref, directive = _BUILTIN_CLASSIFY_HEADER(
        staged_file["target_staged_file_ref"],
        header,
    )
    if (
        classification != runtime_file["classification"]
        or directive_ref != runtime_file["shebang_directive_ref"]
        or len(header) != runtime_file["header_bytes"]
        or _BUILTIN_HEADER_DIGEST(
            staged_file["target_staged_file_ref"],
            header,
        )
        != runtime_file["header_digest"]
    ):
        raise _InvalidTargetRequirements

    interpreter_ref: str | None = None
    interpreter_bytes = 0
    separator_kind: str | None = None
    tail_ref: str | None = None
    tail_bytes = 0
    if classification == "posix_shebang":
        if directive_ref is None or directive is None:
            raise _InvalidTargetRequirements
        token, separator_kind, tail = _BUILTIN_SPLIT_DIRECTIVE(directive)
        interpreter_ref = _BUILTIN_INTERPRETER_TOKEN_REF(
            target_runtime_file_ref=runtime_file[
                "target_runtime_file_ref"
            ],
            target_shebang_directive_ref=directive_ref,
            token=token,
        )
        interpreter_bytes = len(token)
        if tail is not None:
            if separator_kind is None:
                raise _InvalidTargetRequirements
            tail_ref = _BUILTIN_ARGUMENT_TAIL_REF(
                target_runtime_file_ref=runtime_file[
                    "target_runtime_file_ref"
                ],
                target_shebang_directive_ref=directive_ref,
                interpreter_token_ref=interpreter_ref,
                separator_kind=separator_kind,
                tail=tail,
            )
            tail_bytes = len(tail)
        disposition = (
            "absolute_interpreter_token"
            if token.startswith(b"/")
            else "non_absolute_interpreter_token"
        )
    elif classification in {"elf", "mach_o"}:
        disposition = "native_binary_no_shebang"
    elif classification == "unsupported_shebang":
        disposition = "unsupported_shebang"
    elif classification == "unknown":
        disposition = "unknown_runtime_format"
    else:
        raise _InvalidTargetRequirements
    return _FIXED_EXTRACTION_TYPE(
        target_staged_file_ref=runtime_file["target_staged_file_ref"],
        target_runtime_file_ref=runtime_file["target_runtime_file_ref"],
        target_runtime_classification=classification,
        disposition=disposition,
        target_shebang_directive_ref=directive_ref,
        interpreter_token_ref=interpreter_ref,
        interpreter_token_bytes=interpreter_bytes,
        argument_separator_kind=separator_kind,
        argument_tail_ref=tail_ref,
        argument_tail_bytes=tail_bytes,
    )


def _extract_unique_targets(
    *,
    runtime_files: tuple[dict[str, Any], ...],
    staged_files: tuple[dict[str, Any], ...],
    retained_files: tuple[_RetainedStagedTarget, ...],
    target_staging_context_digest: str,
) -> tuple[_TargetShebangExtraction, ...]:
    if not (
        len(runtime_files) == len(staged_files) == len(retained_files)
    ):
        raise _InvalidTargetRequirements
    values: list[_TargetShebangExtraction] = []
    for runtime_file, staged_file, retained in zip(
        runtime_files,
        staged_files,
        retained_files,
        strict=True,
    ):
        verified_header = _BUILTIN_VERIFY_ANCHORED_RETAINED_TARGET(
            retained,
            staged_file,
            target_staging_context_digest=target_staging_context_digest,
        )
        independent_header = _BUILTIN_DESCRIPTOR_REMEASUREMENT(
            retained,
            staged_file,
            target_staging_context_digest=target_staging_context_digest,
        )
        if independent_header != verified_header:
            raise _InvalidTargetRequirements
        values.append(
            _BUILTIN_BUILD_EXTRACTION(
                runtime_file,
                staged_file,
                header=independent_header,
            )
        )
    return tuple(values)


def _validate_runtime_staging_correspondence(
    runtime: dict[str, Any],
    staging: dict[str, Any],
) -> None:
    staging_digest = _BUILTIN_CANONICAL_DIGEST(staging)
    if (
        runtime["target_staging_receipt_digest"] != staging_digest
        or runtime["target_resolution_receipt_digest"]
        != staging["expected_target_resolution_receipt_digest"]
        or runtime["shebang_requirements_receipt_digest"]
        != staging["shebang_requirements_receipt_digest"]
        or runtime["runtime_manifest_receipt_digest"]
        != staging["runtime_manifest_receipt_digest"]
        or runtime["staging_receipt_digest"]
        != staging["staging_receipt_digest"]
        or runtime["registration_digest"] != staging["registration_digest"]
        or runtime["repository_ref"] != staging["repository_ref"]
        or runtime["verification_commands_digest"]
        != staging["verification_commands_digest"]
        or runtime["resolution_context_digest"]
        != staging["resolution_context_digest"]
        or runtime["source_staging_context_digest"]
        != staging["source_staging_context_digest"]
        or runtime["target_path_context_digest"]
        != staging["target_path_context_digest"]
        or runtime["target_staging_context_digest"]
        != staging["target_staging_context_digest"]
        or runtime["file_count"] != staging["unique_target_count"]
        or runtime["requirement_count"] != staging["requirement_count"]
        or runtime["command_count"] != staging["command_count"]
        or runtime["direct_target_requirement_count"]
        != staging["direct_target_requirement_count"]
        or runtime["native_not_applicable_count"]
        != staging["native_not_applicable_count"]
        or runtime["total_content_bytes"] != staging["total_staged_bytes"]
    ):
        raise _InvalidTargetRequirements

    for runtime_file, staged_file in zip(
        runtime["files"],
        staging["staged_files"],
        strict=True,
    ):
        if (
            runtime_file["target_staged_file_ref"]
            != staged_file["target_staged_file_ref"]
            or runtime_file["staged_filesystem_identity_ref"]
            != staged_file["staged_filesystem_identity_ref"]
            or runtime_file["content_digest"]
            != staged_file["content_digest"]
            or runtime_file["content_bytes"]
            != staged_file["content_bytes"]
        ):
            raise _InvalidTargetRequirements
    for runtime_requirement, stage_requirement in zip(
        runtime["requirements"],
        staging["requirements"],
        strict=True,
    ):
        for key in (
            "staged_file_ref",
            "runtime_file_ref",
            "requirement_ref",
            "target_requirement_ref",
            "target_stage_requirement_ref",
            "runtime_classification",
            "target_measurement_ref",
            "target_staged_file_ref",
        ):
            if runtime_requirement[key] != stage_requirement[key]:
                raise _InvalidTargetRequirements
        expected_disposition = (
            "direct_absolute_target_runtime_inspected"
            if stage_requirement["disposition"]
            == "direct_absolute_target_staged"
            else "native_not_applicable"
        )
        if runtime_requirement["disposition"] != expected_disposition:
            raise _InvalidTargetRequirements
    for runtime_binding, stage_binding in zip(
        runtime["bindings"],
        staging["bindings"],
        strict=True,
    ):
        for key in (
            "command_kind",
            "command_id",
            "command_digest",
            "staged_file_ref",
            "runtime_file_ref",
            "requirement_ref",
            "target_requirement_ref",
            "target_stage_requirement_ref",
        ):
            if runtime_binding[key] != stage_binding[key]:
                raise _InvalidTargetRequirements


def _build_requirement(
    source: dict[str, Any],
    *,
    extraction_by_runtime_ref: dict[str, _TargetShebangExtraction],
) -> RepositoryExecutableShebangTargetShebangRequirement:
    if source["disposition"] == "native_not_applicable":
        extraction = None
        target_runtime_classification = None
        disposition = "native_not_applicable"
        target_shebang_directive_ref = None
        interpreter_ref = None
        interpreter_bytes = 0
        separator_kind = None
        tail_ref = None
        tail_bytes = 0
    elif source["disposition"] == "direct_absolute_target_runtime_inspected":
        target_runtime_file_ref = source["target_runtime_file_ref"]
        if target_runtime_file_ref is None:
            raise _InvalidTargetRequirements
        extraction = extraction_by_runtime_ref.get(target_runtime_file_ref)
        if (
            extraction is None
            or extraction.target_staged_file_ref
            != source["target_staged_file_ref"]
        ):
            raise _InvalidTargetRequirements
        target_runtime_classification = (
            extraction.target_runtime_classification
        )
        disposition = extraction.disposition
        target_shebang_directive_ref = (
            extraction.target_shebang_directive_ref
        )
        interpreter_ref = extraction.interpreter_token_ref
        interpreter_bytes = extraction.interpreter_token_bytes
        separator_kind = extraction.argument_separator_kind
        tail_ref = extraction.argument_tail_ref
        tail_bytes = extraction.argument_tail_bytes
    else:
        raise _InvalidTargetRequirements

    reference = _BUILTIN_REQUIREMENT_REF_PROJECTION(
        staged_file_ref=source["staged_file_ref"],
        runtime_file_ref=source["runtime_file_ref"],
        requirement_ref=source["requirement_ref"],
        target_requirement_ref=source["target_requirement_ref"],
        target_stage_requirement_ref=source["target_stage_requirement_ref"],
        target_runtime_requirement_ref=source[
            "target_runtime_requirement_ref"
        ],
        runtime_classification=source["runtime_classification"],
        target_measurement_ref=source["target_measurement_ref"],
        target_staged_file_ref=source["target_staged_file_ref"],
        target_runtime_file_ref=source["target_runtime_file_ref"],
        target_runtime_classification=target_runtime_classification,
        disposition=disposition,
        target_shebang_directive_ref=target_shebang_directive_ref,
        interpreter_token_ref=interpreter_ref,
        interpreter_token_bytes=interpreter_bytes,
        argument_separator_kind=separator_kind,
        argument_tail_ref=tail_ref,
        argument_tail_bytes=tail_bytes,
    )
    value = _FIXED_REQUIREMENT_TYPE(
        kind=_FIXED_REQUIREMENT_KIND,
        staged_file_ref=source["staged_file_ref"],
        runtime_file_ref=source["runtime_file_ref"],
        requirement_ref=source["requirement_ref"],
        target_requirement_ref=source["target_requirement_ref"],
        target_stage_requirement_ref=source["target_stage_requirement_ref"],
        target_runtime_requirement_ref=source[
            "target_runtime_requirement_ref"
        ],
        runtime_classification=source["runtime_classification"],
        target_measurement_ref=source["target_measurement_ref"],
        target_staged_file_ref=source["target_staged_file_ref"],
        target_runtime_file_ref=source["target_runtime_file_ref"],
        target_runtime_classification=target_runtime_classification,
        disposition=disposition,
        target_shebang_directive_ref=target_shebang_directive_ref,
        interpreter_token_ref=interpreter_ref,
        interpreter_token_bytes=interpreter_bytes,
        argument_separator_kind=separator_kind,
        argument_tail_ref=tail_ref,
        argument_tail_bytes=tail_bytes,
        target_shebang_requirement_ref=(
            _BUILTIN_CANONICAL_DIGEST(reference)
        ),
    )
    _BUILTIN_REQUIREMENT_PROJECTION(value)
    return value


def _build_binding(
    source: dict[str, Any],
    requirement: RepositoryExecutableShebangTargetShebangRequirement,
) -> RepositoryExecutableShebangTargetShebangRequirementBinding:
    if (
        source["target_runtime_requirement_ref"]
        != requirement.target_runtime_requirement_ref
    ):
        raise _InvalidTargetRequirements
    value = _FIXED_BINDING_TYPE(
        kind=_FIXED_BINDING_KIND,
        command_kind=source["command_kind"],
        command_id=source["command_id"],
        command_digest=source["command_digest"],
        staged_file_ref=source["staged_file_ref"],
        runtime_file_ref=source["runtime_file_ref"],
        requirement_ref=source["requirement_ref"],
        target_requirement_ref=source["target_requirement_ref"],
        target_stage_requirement_ref=source["target_stage_requirement_ref"],
        target_runtime_requirement_ref=source[
            "target_runtime_requirement_ref"
        ],
        target_shebang_requirement_ref=(
            requirement.target_shebang_requirement_ref
        ),
    )
    _BUILTIN_BINDING_PROJECTION(value)
    return value


# Freeze the extraction and builder graph after every component exists.
_BUILTIN_HEADER_DIGEST = _header_digest
_BUILTIN_BOUNDED_SHEBANG_DIRECTIVE = _bounded_shebang_directive
_BUILTIN_CLASSIFY_HEADER = _classify_header
_BUILTIN_SPLIT_DIRECTIVE = _split_directive
_BUILTIN_INTERPRETER_TOKEN_REF = _interpreter_token_ref
_BUILTIN_ARGUMENT_TAIL_REF = _argument_tail_ref
_BUILTIN_DESCRIPTOR_REMEASUREMENT = _independent_descriptor_remeasurement
_BUILTIN_CLOSING_DESCRIPTOR_ANCHOR = _closing_descriptor_anchor
_BUILTIN_BUILD_EXTRACTION = _build_extraction
_BUILTIN_EXTRACT_UNIQUE_TARGETS = _extract_unique_targets
_BUILTIN_VALIDATE_RUNTIME_STAGING = (
    _validate_runtime_staging_correspondence
)
_BUILTIN_BUILD_REQUIREMENT = _build_requirement
_BUILTIN_BUILD_BINDING = _build_binding


def inspect_staged_executable_shebang_target_requirements(
    expected_target_runtime: (
        RepositoryExecutableShebangTargetRuntimeManifestReceipt
    ),
    *,
    expected_target_staging: RepositoryExecutableShebangTargetStagingReceipt,
    lease: RepositoryExecutableShebangTargetStageLease,
) -> RepositoryExecutableShebangTargetRequirementsReceipt:
    """Extract one bounded target-shebang layer without resolving it."""

    try:
        if (
            type(expected_target_runtime)
            is not _FIXED_TARGET_RUNTIME_RECEIPT_TYPE
            or type(expected_target_staging)
            is not _FIXED_TARGET_STAGING_RECEIPT_TYPE
            or type(lease) is not _FIXED_TARGET_STAGE_LEASE_TYPE
        ):
            raise _InvalidTargetRequirements

        staging_canonical = _BUILTIN_TARGET_STAGING_RECEIPT_PROJECTION(
            expected_target_staging
        )
        runtime_canonical = _BUILTIN_TARGET_RUNTIME_MANIFEST_PROJECTION(
            expected_target_runtime
        )
        _BUILTIN_VALIDATE_RUNTIME_STAGING(
            runtime_canonical,
            staging_canonical,
        )
        entry_canonical, retained_files = (
            _BUILTIN_ACTIVE_TARGET_STAGE_SNAPSHOT(
                expected_target_staging,
                lease,
            )
        )
        if entry_canonical != staging_canonical:
            raise _InvalidTargetRequirements

        runtime_files = tuple(
            dict(item) for item in runtime_canonical["files"]
        )
        runtime_requirements = tuple(
            dict(item) for item in runtime_canonical["requirements"]
        )
        runtime_bindings = tuple(
            dict(item) for item in runtime_canonical["bindings"]
        )
        staged_files = tuple(
            dict(item) for item in staging_canonical["staged_files"]
        )
        target_staging_context_digest = staging_canonical[
            "target_staging_context_digest"
        ]

        fresh_runtime = _BUILTIN_INSPECT_TARGET_RUNTIME_MANIFEST(
            expected_target_staging,
            lease=lease,
        )
        if (
            _BUILTIN_TARGET_RUNTIME_MANIFEST_PROJECTION(fresh_runtime)
            != runtime_canonical
        ):
            raise _InvalidTargetRequirements
        active_canonical, active_retained_files = (
            _BUILTIN_ACTIVE_TARGET_STAGE_SNAPSHOT(
                expected_target_staging,
                lease,
            )
        )
        if (
            active_canonical != staging_canonical
            or active_retained_files is not retained_files
        ):
            raise _InvalidTargetRequirements

        first_extractions = _BUILTIN_EXTRACT_UNIQUE_TARGETS(
            runtime_files=runtime_files,
            staged_files=staged_files,
            retained_files=retained_files,
            target_staging_context_digest=target_staging_context_digest,
        )
        pass_canonical, pass_retained_files = (
            _BUILTIN_ACTIVE_TARGET_STAGE_SNAPSHOT(
                expected_target_staging,
                lease,
            )
        )
        if (
            pass_canonical != staging_canonical
            or pass_retained_files is not retained_files
        ):
            raise _InvalidTargetRequirements

        second_extractions = _BUILTIN_EXTRACT_UNIQUE_TARGETS(
            runtime_files=runtime_files,
            staged_files=staged_files,
            retained_files=retained_files,
            target_staging_context_digest=target_staging_context_digest,
        )
        if second_extractions != first_extractions:
            raise _InvalidTargetRequirements

        final_runtime = _BUILTIN_INSPECT_TARGET_RUNTIME_MANIFEST(
            expected_target_staging,
            lease=lease,
        )
        if (
            _BUILTIN_TARGET_RUNTIME_MANIFEST_PROJECTION(final_runtime)
            != runtime_canonical
        ):
            raise _InvalidTargetRequirements
        final_canonical, final_retained_files = (
            _BUILTIN_ACTIVE_TARGET_STAGE_SNAPSHOT(
                expected_target_staging,
                lease,
            )
        )
        if (
            final_canonical != staging_canonical
            or final_retained_files is not retained_files
        ):
            raise _InvalidTargetRequirements

        extraction_by_runtime_ref = {
            value.target_runtime_file_ref: value
            for value in first_extractions
        }
        requirements = tuple(
            _BUILTIN_BUILD_REQUIREMENT(
                item,
                extraction_by_runtime_ref=extraction_by_runtime_ref,
            )
            for item in runtime_requirements
        )
        requirement_by_runtime_ref = {
            value.target_runtime_requirement_ref: value
            for value in requirements
        }
        bindings = tuple(
            _BUILTIN_BUILD_BINDING(
                item,
                requirement_by_runtime_ref[
                    item["target_runtime_requirement_ref"]
                ],
            )
            for item in runtime_bindings
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
                runtime_canonical["target_staging_receipt_digest"]
            ),
            target_resolution_receipt_digest=(
                runtime_canonical["target_resolution_receipt_digest"]
            ),
            shebang_requirements_receipt_digest=(
                runtime_canonical["shebang_requirements_receipt_digest"]
            ),
            runtime_manifest_receipt_digest=(
                runtime_canonical["runtime_manifest_receipt_digest"]
            ),
            staging_receipt_digest=(
                runtime_canonical["staging_receipt_digest"]
            ),
            registration_digest=runtime_canonical["registration_digest"],
            repository_ref=runtime_canonical["repository_ref"],
            verification_commands_digest=(
                runtime_canonical["verification_commands_digest"]
            ),
            resolution_context_digest=(
                runtime_canonical["resolution_context_digest"]
            ),
            source_staging_context_digest=(
                runtime_canonical["source_staging_context_digest"]
            ),
            target_path_context_digest=(
                runtime_canonical["target_path_context_digest"]
            ),
            target_staging_context_digest=(
                runtime_canonical["target_staging_context_digest"]
            ),
            requirements=requirements,
            bindings=bindings,
            requirement_count=len(requirements),
            command_count=len(bindings),
            direct_target_requirement_count=(
                runtime_canonical["direct_target_requirement_count"]
            ),
            native_not_applicable_count=(
                runtime_canonical["native_not_applicable_count"]
            ),
            unique_target_count=len(first_extractions),
            target_posix_shebang_requirement_count=sum(
                value.target_runtime_classification == "posix_shebang"
                for value in first_extractions
            ),
            argument_tail_requirement_count=sum(
                value.argument_tail_ref is not None
                for value in first_extractions
            ),
            total_interpreter_token_bytes=sum(
                value.interpreter_token_bytes
                for value in first_extractions
            ),
            total_argument_tail_bytes=sum(
                value.argument_tail_bytes for value in first_extractions
            ),
        )
        _BUILTIN_RECEIPT_PROJECTION(receipt)
        if (
            _BUILTIN_TARGET_RUNTIME_MANIFEST_PROJECTION(
                expected_target_runtime
            )
            != runtime_canonical
        ):
            raise _InvalidTargetRequirements
        closing_canonical, closing_retained_files = (
            _BUILTIN_ACTIVE_TARGET_STAGE_SNAPSHOT(
                expected_target_staging,
                lease,
            )
        )
        if (
            closing_canonical != staging_canonical
            or closing_retained_files is not retained_files
        ):
            raise _InvalidTargetRequirements
        for retained, staged_file in zip(
            closing_retained_files,
            staged_files,
            strict=True,
        ):
            _BUILTIN_CLOSING_DESCRIPTOR_ANCHOR(
                retained,
                staged_file,
                target_staging_context_digest=(
                    target_staging_context_digest
                ),
            )
        return receipt
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise _FIXED_VALIDATION_ERROR(_INVALID_MESSAGE) from None


__all__ = [
    "REQUIREMENTS_SCOPE",
    "REQUIREMENTS_SOURCE",
    "REPOSITORY_EXECUTABLE_SHEBANG_TARGET_SHEBANG_REQUIREMENT_BINDING_KIND",
    "REPOSITORY_EXECUTABLE_SHEBANG_TARGET_REQUIREMENTS_EVIDENCE_KIND",
    "REPOSITORY_EXECUTABLE_SHEBANG_TARGET_REQUIREMENTS_KIND",
    "REPOSITORY_EXECUTABLE_SHEBANG_TARGET_REQUIREMENTS_SCHEMA_VERSION",
    "REPOSITORY_EXECUTABLE_SHEBANG_TARGET_SHEBANG_REQUIREMENT_KIND",
    "RepositoryExecutableShebangTargetShebangRequirementBinding",
    "RepositoryExecutableShebangTargetRequirementsReceipt",
    "RepositoryExecutableShebangTargetShebangRequirement",
    "inspect_staged_executable_shebang_target_requirements",
]
