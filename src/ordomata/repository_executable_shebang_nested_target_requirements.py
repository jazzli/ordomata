"""Digest-only one-hop requirements from an active nested-target stage.

This Class 0 boundary consumes one exact nested-target runtime manifest and
reproduces it from the same active process-local nested-target-stage lease. It
extracts only bounded syntax references from retained shebang bytes. It never
resolves an extracted token, interprets launcher semantics, opens a path,
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

from .authorization import canonical_json
from .errors import ValidationError
from .repository_executable_shebang_nested_target_runtime_manifest import (
    RepositoryExecutableShebangNestedTargetRuntimeManifestReceipt,
    _active_target_stage_snapshot,
    _runtime_manifest_projection,
    _target_staging_receipt_projection,
    inspect_staged_executable_shebang_nested_target_runtime_manifest,
)
from .repository_executable_shebang_nested_target_staging import (
    RepositoryExecutableShebangNestedTargetStageLease,
    RepositoryExecutableShebangNestedTargetStagingReceipt,
    _RetainedStagedNestedTarget,
    _staged_file_projection,
)


REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_REQUIREMENTS_SCHEMA_VERSION = 1
REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_REQUIREMENTS_KIND = (
    "repository_executable_shebang_nested_target_requirements"
)
REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_REQUIREMENTS_EVIDENCE_KIND = (
    "repository_executable_shebang_nested_target_requirements_validation"
)
REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_SHEBANG_REQUIREMENT_KIND = (
    "repository_executable_shebang_nested_target_shebang_requirement"
)
REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_SHEBANG_REQUIREMENT_BINDING_KIND = (
    "repository_executable_shebang_nested_target_shebang_requirement_binding"
)
REQUIREMENTS_SOURCE = "controller_inspected"
REQUIREMENTS_SCOPE = "posix_staged_shebang_nested_target_requirements_v1"

_FIXED_SCHEMA_VERSION = (
    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_REQUIREMENTS_SCHEMA_VERSION
)
_FIXED_RECEIPT_KIND = (
    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_REQUIREMENTS_KIND
)
_FIXED_EVIDENCE_KIND = (
    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_REQUIREMENTS_EVIDENCE_KIND
)
_FIXED_REQUIREMENT_KIND = (
    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_SHEBANG_REQUIREMENT_KIND
)
_FIXED_BINDING_KIND = (
    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_SHEBANG_REQUIREMENT_BINDING_KIND
)
_FIXED_REQUIREMENTS_SOURCE = REQUIREMENTS_SOURCE
_FIXED_REQUIREMENTS_SCOPE = REQUIREMENTS_SCOPE

_INVALID_MESSAGE = (
    "repository executable shebang nested target requirements are invalid"
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
    "not_applicable",
)
_RUNTIME_DISPOSITIONS = (
    "known_chain_guard_runtime_inspected",
    "source_native_not_applicable",
    "target_native_not_applicable",
)
_DISPOSITIONS = (
    "source_native_not_applicable",
    "target_native_not_applicable",
    "native_binary_no_shebang",
    "absolute_interpreter_token",
    "non_absolute_interpreter_token",
    "unsupported_shebang",
    "unknown_runtime_format",
)
_MAX_FILES = 80
_MAX_REQUIREMENTS = 80
_MAX_COMMANDS = 80
_MAX_HEADER_BYTES = 4_096
_MAX_DIRECTIVE_BYTES = 255
_MAX_TOTAL_REQUIREMENT_BYTES = _MAX_FILES * _MAX_DIRECTIVE_BYTES
_FULL_REMEASUREMENT_CHUNK_BYTES = 1024 * 1024
_STAGED_FILE_MODE = 0o400
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
_FIXED_RUNTIME_RECEIPT_TYPE = (
    RepositoryExecutableShebangNestedTargetRuntimeManifestReceipt
)
_FIXED_STAGING_RECEIPT_TYPE = (
    RepositoryExecutableShebangNestedTargetStagingReceipt
)
_FIXED_STAGE_LEASE_TYPE = RepositoryExecutableShebangNestedTargetStageLease
_FIXED_RETAINED_TYPE = _RetainedStagedNestedTarget


class _InvalidNestedTargetRequirements(ValueError):
    """Private fail-closed sentinel whose details never cross the API."""


@dataclass(frozen=True, slots=True)
class RepositoryExecutableShebangNestedTargetShebangRequirement:
    """One nested-target-runtime requirement's bounded syntax result."""

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
    nested_target_runtime_requirement_ref: str = field(repr=False)
    runtime_classification: str
    runtime_disposition: str
    nested_target_measurement_ref: str | None = field(repr=False)
    guarded_measurement_ref: str | None = field(repr=False)
    nested_target_staged_file_ref: str | None = field(repr=False)
    nested_target_runtime_file_ref: str | None = field(repr=False)
    disposition: str
    nested_target_shebang_directive_ref: str | None = field(repr=False)
    interpreter_token_ref: str | None = field(repr=False)
    interpreter_token_bytes: int
    interpreter_token_absolute: bool | None
    argument_separator_kind: str | None
    argument_tail_ref: str | None = field(repr=False)
    argument_tail_bytes: int
    nested_target_shebang_requirement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _requirement_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableShebangNestedTargetShebangRequirementBinding:
    """One command bound to one nested-target shebang requirement."""

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
    nested_target_shebang_requirement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _binding_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableShebangNestedTargetRequirementsReceipt:
    """Historical one-hop syntax evidence from one active nested stage."""

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
    requirements: tuple[
        RepositoryExecutableShebangNestedTargetShebangRequirement, ...
    ] = field(repr=False)
    bindings: tuple[
        RepositoryExecutableShebangNestedTargetShebangRequirementBinding, ...
    ] = field(repr=False)
    requirement_count: int
    command_count: int
    known_chain_guard_requirement_count: int
    source_native_not_applicable_count: int
    target_native_not_applicable_count: int
    unique_nested_target_count: int
    nested_target_posix_shebang_requirement_count: int
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


_FIXED_REQUIREMENT_TYPE = (
    RepositoryExecutableShebangNestedTargetShebangRequirement
)
_FIXED_BINDING_TYPE = (
    RepositoryExecutableShebangNestedTargetShebangRequirementBinding
)
_FIXED_RECEIPT_TYPE = RepositoryExecutableShebangNestedTargetRequirementsReceipt


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
    target_shebang_requirement_ref: str,
    nested_target_requirement_ref: str,
    chain_guard_requirement_ref: str,
    nested_target_stage_requirement_ref: str,
    nested_target_runtime_requirement_ref: str,
    runtime_classification: str,
    runtime_disposition: str,
    nested_target_measurement_ref: str | None,
    guarded_measurement_ref: str | None,
    nested_target_staged_file_ref: str | None,
    nested_target_runtime_file_ref: str | None,
    disposition: str,
    nested_target_shebang_directive_ref: str | None,
    interpreter_token_ref: str | None,
    interpreter_token_bytes: int,
    interpreter_token_absolute: bool | None,
    argument_separator_kind: str | None,
    argument_tail_ref: str | None,
    argument_tail_bytes: int,
) -> dict[str, Any]:
    return {
        "argument_separator_kind": argument_separator_kind,
        "argument_tail_bytes": argument_tail_bytes,
        "argument_tail_ref": argument_tail_ref,
        "chain_guard_requirement_ref": chain_guard_requirement_ref,
        "disposition": disposition,
        "guarded_measurement_ref": guarded_measurement_ref,
        "interpreter_token_absolute": interpreter_token_absolute,
        "interpreter_token_bytes": interpreter_token_bytes,
        "interpreter_token_ref": interpreter_token_ref,
        "kind": (
            "repository_executable_shebang_nested_target_"
            "shebang_requirement_ref"
        ),
        "nested_target_measurement_ref": nested_target_measurement_ref,
        "nested_target_requirement_ref": nested_target_requirement_ref,
        "nested_target_runtime_file_ref": nested_target_runtime_file_ref,
        "nested_target_runtime_requirement_ref": (
            nested_target_runtime_requirement_ref
        ),
        "nested_target_shebang_directive_ref": (
            nested_target_shebang_directive_ref
        ),
        "nested_target_stage_requirement_ref": (
            nested_target_stage_requirement_ref
        ),
        "nested_target_staged_file_ref": nested_target_staged_file_ref,
        "requirement_ref": requirement_ref,
        "requirements_scope": _FIXED_REQUIREMENTS_SCOPE,
        "runtime_classification": runtime_classification,
        "runtime_disposition": runtime_disposition,
        "runtime_file_ref": runtime_file_ref,
        "schema_version": _FIXED_SCHEMA_VERSION,
        "staged_file_ref": staged_file_ref,
        "target_requirement_ref": target_requirement_ref,
        "target_runtime_requirement_ref": target_runtime_requirement_ref,
        "target_shebang_requirement_ref": target_shebang_requirement_ref,
        "target_stage_requirement_ref": target_stage_requirement_ref,
    }


def _expected_dispositions(
    runtime_disposition: str,
    runtime_classification: str,
) -> frozenset[str]:
    if runtime_disposition == "source_native_not_applicable":
        return frozenset({"source_native_not_applicable"})
    if runtime_disposition == "target_native_not_applicable":
        return frozenset({"target_native_not_applicable"})
    if runtime_disposition != "known_chain_guard_runtime_inspected":
        return frozenset()
    if runtime_classification in {"elf", "mach_o"}:
        return frozenset({"native_binary_no_shebang"})
    if runtime_classification == "posix_shebang":
        return frozenset(
            {"absolute_interpreter_token", "non_absolute_interpreter_token"}
        )
    if runtime_classification == "unsupported_shebang":
        return frozenset({"unsupported_shebang"})
    if runtime_classification == "unknown":
        return frozenset({"unknown_runtime_format"})
    return frozenset()


_BUILTIN_EXPECTED_DISPOSITIONS = _expected_dispositions


def _requirement_projection(
    value: RepositoryExecutableShebangNestedTargetShebangRequirement,
) -> dict[str, Any]:
    required_digests = (
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
        value.nested_target_shebang_requirement_ref,
    )
    optional_digests = (
        value.nested_target_measurement_ref,
        value.guarded_measurement_ref,
        value.nested_target_staged_file_ref,
        value.nested_target_runtime_file_ref,
        value.nested_target_shebang_directive_ref,
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
        or value.runtime_classification not in _RUNTIME_CLASSIFICATIONS
        or type(value.runtime_disposition) is not str
        or value.runtime_disposition not in _RUNTIME_DISPOSITIONS
        or type(value.disposition) is not str
        or value.disposition not in _DISPOSITIONS
        or value.disposition
        not in _BUILTIN_EXPECTED_DISPOSITIONS(
            value.runtime_disposition,
            value.runtime_classification,
        )
        or type(value.interpreter_token_bytes) is not int
        or not 0 <= value.interpreter_token_bytes <= _MAX_DIRECTIVE_BYTES
        or type(value.argument_tail_bytes) is not int
        or not 0 <= value.argument_tail_bytes <= _MAX_DIRECTIVE_BYTES
        or (
            value.interpreter_token_absolute is not None
            and type(value.interpreter_token_absolute) is not bool
        )
    ):
        raise _InvalidNestedTargetRequirements

    inspected = (
        value.runtime_disposition == "known_chain_guard_runtime_inspected"
    )
    posix = value.runtime_classification == "posix_shebang"
    has_tail = value.argument_tail_bytes > 0
    if not inspected:
        if (
            value.runtime_classification != "not_applicable"
            or value.nested_target_measurement_ref is not None
            or value.guarded_measurement_ref is not None
            or value.nested_target_staged_file_ref is not None
            or value.nested_target_runtime_file_ref is not None
            or value.nested_target_shebang_directive_ref is not None
            or value.interpreter_token_ref is not None
            or value.interpreter_token_bytes != 0
            or value.interpreter_token_absolute is not None
            or value.argument_separator_kind is not None
            or value.argument_tail_ref is not None
            or value.argument_tail_bytes != 0
        ):
            raise _InvalidNestedTargetRequirements
    else:
        if (
            value.runtime_classification == "not_applicable"
            or value.nested_target_measurement_ref is None
            or value.guarded_measurement_ref is None
            or value.nested_target_staged_file_ref is None
            or value.nested_target_runtime_file_ref is None
        ):
            raise _InvalidNestedTargetRequirements
        if posix:
            if (
                value.nested_target_shebang_directive_ref is None
                or value.interpreter_token_ref is None
                or not 1
                <= value.interpreter_token_bytes
                <= _MAX_DIRECTIVE_BYTES
                or value.interpreter_token_absolute
                != (value.disposition == "absolute_interpreter_token")
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
                raise _InvalidNestedTargetRequirements
        elif (
            value.nested_target_shebang_directive_ref is not None
            or value.interpreter_token_ref is not None
            or value.interpreter_token_bytes != 0
            or value.interpreter_token_absolute is not None
            or value.argument_separator_kind is not None
            or value.argument_tail_ref is not None
            or value.argument_tail_bytes != 0
        ):
            raise _InvalidNestedTargetRequirements

    reference = _BUILTIN_REQUIREMENT_REF_PROJECTION(
        staged_file_ref=value.staged_file_ref,
        runtime_file_ref=value.runtime_file_ref,
        requirement_ref=value.requirement_ref,
        target_requirement_ref=value.target_requirement_ref,
        target_stage_requirement_ref=value.target_stage_requirement_ref,
        target_runtime_requirement_ref=value.target_runtime_requirement_ref,
        target_shebang_requirement_ref=value.target_shebang_requirement_ref,
        nested_target_requirement_ref=value.nested_target_requirement_ref,
        chain_guard_requirement_ref=value.chain_guard_requirement_ref,
        nested_target_stage_requirement_ref=(
            value.nested_target_stage_requirement_ref
        ),
        nested_target_runtime_requirement_ref=(
            value.nested_target_runtime_requirement_ref
        ),
        runtime_classification=value.runtime_classification,
        runtime_disposition=value.runtime_disposition,
        nested_target_measurement_ref=value.nested_target_measurement_ref,
        guarded_measurement_ref=value.guarded_measurement_ref,
        nested_target_staged_file_ref=value.nested_target_staged_file_ref,
        nested_target_runtime_file_ref=value.nested_target_runtime_file_ref,
        disposition=value.disposition,
        nested_target_shebang_directive_ref=(
            value.nested_target_shebang_directive_ref
        ),
        interpreter_token_ref=value.interpreter_token_ref,
        interpreter_token_bytes=value.interpreter_token_bytes,
        interpreter_token_absolute=value.interpreter_token_absolute,
        argument_separator_kind=value.argument_separator_kind,
        argument_tail_ref=value.argument_tail_ref,
        argument_tail_bytes=value.argument_tail_bytes,
    )
    if (
        value.nested_target_shebang_requirement_ref
        != _BUILTIN_CANONICAL_DIGEST(reference)
    ):
        raise _InvalidNestedTargetRequirements
    return {
        **reference,
        "kind": value.kind,
        "nested_target_shebang_requirement_ref": (
            value.nested_target_shebang_requirement_ref
        ),
    }


def _binding_projection(
    value: RepositoryExecutableShebangNestedTargetShebangRequirementBinding,
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
                value.nested_target_requirement_ref,
                value.chain_guard_requirement_ref,
                value.nested_target_stage_requirement_ref,
                value.nested_target_runtime_requirement_ref,
                value.nested_target_shebang_requirement_ref,
            )
        )
    ):
        raise _InvalidNestedTargetRequirements
    return {
        "chain_guard_requirement_ref": value.chain_guard_requirement_ref,
        "command_digest": value.command_digest,
        "command_id": value.command_id,
        "command_kind": value.command_kind,
        "kind": value.kind,
        "nested_target_requirement_ref": value.nested_target_requirement_ref,
        "nested_target_runtime_requirement_ref": (
            value.nested_target_runtime_requirement_ref
        ),
        "nested_target_shebang_requirement_ref": (
            value.nested_target_shebang_requirement_ref
        ),
        "nested_target_stage_requirement_ref": (
            value.nested_target_stage_requirement_ref
        ),
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
    value: RepositoryExecutableShebangNestedTargetRequirementsReceipt,
) -> dict[str, Any]:
    digest_fields = (
        value.nested_target_runtime_manifest_receipt_digest,
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
    counts = (
        value.known_chain_guard_requirement_count,
        value.source_native_not_applicable_count,
        value.target_native_not_applicable_count,
        value.unique_nested_target_count,
        value.nested_target_posix_shebang_requirement_count,
        value.argument_tail_requirement_count,
        value.total_interpreter_token_bytes,
        value.total_argument_tail_bytes,
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
        or value.expected_chain_guard_receipt_digest
        != value.action_chain_guard_receipt_digest
        or value.expected_chain_guard_receipt_digest
        != value.post_stage_chain_guard_receipt_digest
        or type(value.requirements) is not tuple
        or not 1 <= len(value.requirements) <= _MAX_REQUIREMENTS
        or type(value.bindings) is not tuple
        or not 1 <= len(value.bindings) <= _MAX_COMMANDS
        or type(value.requirement_count) is not int
        or value.requirement_count != len(value.requirements)
        or type(value.command_count) is not int
        or value.command_count != len(value.bindings)
        or any(type(item) is not int or item < 0 for item in counts)
        or value.unique_nested_target_count > _MAX_FILES
        or value.nested_target_posix_shebang_requirement_count
        > value.unique_nested_target_count
        or value.argument_tail_requirement_count
        > value.nested_target_posix_shebang_requirement_count
        or value.total_interpreter_token_bytes
        > _MAX_TOTAL_REQUIREMENT_BYTES
        or value.total_argument_tail_bytes > _MAX_TOTAL_REQUIREMENT_BYTES
    ):
        raise _InvalidNestedTargetRequirements

    requirements = [
        _BUILTIN_REQUIREMENT_PROJECTION(item) for item in value.requirements
    ]
    bindings = [
        _BUILTIN_BINDING_PROJECTION(item) for item in value.bindings
    ]

    by_runtime_ref: dict[
        str, RepositoryExecutableShebangNestedTargetShebangRequirement
    ] = {}
    source_refs: set[str] = set()
    stage_refs: set[str] = set()
    terminal_refs: set[str] = set()
    unique_rows: dict[
        str, RepositoryExecutableShebangNestedTargetShebangRequirement
    ] = {}
    inspected_count = 0
    source_native_count = 0
    target_native_count = 0
    for item in value.requirements:
        if (
            item.nested_target_runtime_requirement_ref in by_runtime_ref
            or item.requirement_ref in source_refs
            or item.nested_target_stage_requirement_ref in stage_refs
            or item.nested_target_shebang_requirement_ref in terminal_refs
        ):
            raise _InvalidNestedTargetRequirements
        by_runtime_ref[item.nested_target_runtime_requirement_ref] = item
        source_refs.add(item.requirement_ref)
        stage_refs.add(item.nested_target_stage_requirement_ref)
        terminal_refs.add(item.nested_target_shebang_requirement_ref)
        if item.runtime_disposition == "source_native_not_applicable":
            source_native_count += 1
            continue
        if item.runtime_disposition == "target_native_not_applicable":
            target_native_count += 1
            continue
        inspected_count += 1
        if item.nested_target_runtime_file_ref is None:
            raise _InvalidNestedTargetRequirements
        prior = unique_rows.get(item.nested_target_runtime_file_ref)
        if prior is None:
            unique_rows[item.nested_target_runtime_file_ref] = item
        elif any(
            left != right
            for left, right in (
                (
                    item.nested_target_measurement_ref,
                    prior.nested_target_measurement_ref,
                ),
                (item.guarded_measurement_ref, prior.guarded_measurement_ref),
                (
                    item.nested_target_staged_file_ref,
                    prior.nested_target_staged_file_ref,
                ),
                (item.runtime_classification, prior.runtime_classification),
                (item.disposition, prior.disposition),
                (
                    item.nested_target_shebang_directive_ref,
                    prior.nested_target_shebang_directive_ref,
                ),
                (item.interpreter_token_ref, prior.interpreter_token_ref),
                (item.interpreter_token_bytes, prior.interpreter_token_bytes),
                (
                    item.interpreter_token_absolute,
                    prior.interpreter_token_absolute,
                ),
                (item.argument_separator_kind, prior.argument_separator_kind),
                (item.argument_tail_ref, prior.argument_tail_ref),
                (item.argument_tail_bytes, prior.argument_tail_bytes),
            )
        ):
            raise _InvalidNestedTargetRequirements

    command_ids: set[str] = set()
    bound_terminal_refs: set[str] = set()
    ordered_terminal_refs: list[str] = []
    prior_kind_index = -1
    lineage_fields = (
        "staged_file_ref",
        "runtime_file_ref",
        "requirement_ref",
        "target_requirement_ref",
        "target_stage_requirement_ref",
        "target_runtime_requirement_ref",
        "target_shebang_requirement_ref",
        "nested_target_requirement_ref",
        "chain_guard_requirement_ref",
        "nested_target_stage_requirement_ref",
        "nested_target_runtime_requirement_ref",
        "nested_target_shebang_requirement_ref",
    )
    for binding in value.bindings:
        requirement = by_runtime_ref.get(
            binding.nested_target_runtime_requirement_ref
        )
        kind_index = _COMMAND_KINDS.index(binding.command_kind)
        if (
            requirement is None
            or any(
                getattr(binding, name) != getattr(requirement, name)
                for name in lineage_fields
            )
            or binding.command_id in command_ids
            or kind_index < prior_kind_index
        ):
            raise _InvalidNestedTargetRequirements
        command_ids.add(binding.command_id)
        if (
            binding.nested_target_shebang_requirement_ref
            not in bound_terminal_refs
        ):
            ordered_terminal_refs.append(
                binding.nested_target_shebang_requirement_ref
            )
        bound_terminal_refs.add(
            binding.nested_target_shebang_requirement_ref
        )
        prior_kind_index = kind_index

    ordered_unique_rows = tuple(unique_rows.values())
    posix_count = sum(
        item.runtime_classification == "posix_shebang"
        for item in ordered_unique_rows
    )
    tail_count = sum(
        item.argument_tail_ref is not None for item in ordered_unique_rows
    )
    token_bytes = sum(
        item.interpreter_token_bytes for item in ordered_unique_rows
    )
    tail_bytes = sum(item.argument_tail_bytes for item in ordered_unique_rows)
    if (
        bound_terminal_refs != terminal_refs
        or tuple(ordered_terminal_refs)
        != tuple(
            item.nested_target_shebang_requirement_ref
            for item in value.requirements
        )
        or inspected_count != value.known_chain_guard_requirement_count
        or source_native_count != value.source_native_not_applicable_count
        or target_native_count != value.target_native_not_applicable_count
        or inspected_count + source_native_count + target_native_count
        != value.requirement_count
        or len(ordered_unique_rows) != value.unique_nested_target_count
        or posix_count
        != value.nested_target_posix_shebang_requirement_count
        or tail_count != value.argument_tail_requirement_count
        or token_bytes != value.total_interpreter_token_bytes
        or tail_bytes != value.total_argument_tail_bytes
        or (value.unique_nested_target_count == 0 and inspected_count != 0)
        or (value.unique_nested_target_count > 0 and inspected_count == 0)
    ):
        raise _InvalidNestedTargetRequirements

    return {
        "action_chain_guard_receipt_digest": (
            value.action_chain_guard_receipt_digest
        ),
        "argument_tail_requirement_count": (
            value.argument_tail_requirement_count
        ),
        "bindings": bindings,
        "command_count": value.command_count,
        "expected_chain_guard_receipt_digest": (
            value.expected_chain_guard_receipt_digest
        ),
        "guard_summary_ref": value.guard_summary_ref,
        "kind": value.kind,
        "known_chain_guard_requirement_count": (
            value.known_chain_guard_requirement_count
        ),
        "known_source_identity_set_digest": (
            value.known_source_identity_set_digest
        ),
        "known_target_identity_set_digest": (
            value.known_target_identity_set_digest
        ),
        "nested_target_path_context_digest": (
            value.nested_target_path_context_digest
        ),
        "nested_target_posix_shebang_requirement_count": (
            value.nested_target_posix_shebang_requirement_count
        ),
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
        "shebang_requirements_receipt_digest": (
            value.shebang_requirements_receipt_digest
        ),
        "source_native_not_applicable_count": (
            value.source_native_not_applicable_count
        ),
        "source_staging_context_digest": (
            value.source_staging_context_digest
        ),
        "source_staging_receipt_digest": value.source_staging_receipt_digest,
        "target_native_not_applicable_count": (
            value.target_native_not_applicable_count
        ),
        "target_path_context_digest": value.target_path_context_digest,
        "target_resolution_receipt_digest": (
            value.target_resolution_receipt_digest
        ),
        "target_runtime_manifest_receipt_digest": (
            value.target_runtime_manifest_receipt_digest
        ),
        "target_shebang_requirements_receipt_digest": (
            value.target_shebang_requirements_receipt_digest
        ),
        "target_staging_context_digest": (
            value.target_staging_context_digest
        ),
        "target_staging_receipt_digest": value.target_staging_receipt_digest,
        "total_argument_tail_bytes": value.total_argument_tail_bytes,
        "total_interpreter_token_bytes": (
            value.total_interpreter_token_bytes
        ),
        "unique_nested_target_count": value.unique_nested_target_count,
        "verification_commands_digest": value.verification_commands_digest,
    }


def _evidence_projection(
    value: RepositoryExecutableShebangNestedTargetRequirementsReceipt,
) -> dict[str, Any]:
    canonical = _BUILTIN_RECEIPT_PROJECTION(value)
    unique_rows: dict[
        str, RepositoryExecutableShebangNestedTargetShebangRequirement
    ] = {}
    for item in value.requirements:
        if item.nested_target_runtime_file_ref is not None:
            unique_rows.setdefault(item.nested_target_runtime_file_ref, item)
    disposition_counts = {
        disposition: sum(
            item.disposition == disposition for item in unique_rows.values()
        )
        for disposition in _DISPOSITIONS
    }
    return {
        "absolute_interpreter_token_count": disposition_counts[
            "absolute_interpreter_token"
        ],
        "action_receipt_issued": False,
        "active_nested_target_stage_lease_verified_at_measurement": True,
        "argument_tail_requirement_count": (
            value.argument_tail_requirement_count
        ),
        "atomic_snapshot_verified": False,
        "authority_granted": False,
        "authorization_verified": False,
        "billing_eligible": False,
        "bounded_nested_target_shebang_requirement_extraction_complete": True,
        "capacity_eligible": False,
        "circuit_eligible": False,
        "command_count": value.command_count,
        "current_lease_activity_verified": False,
        "current_source_freshness_verified": False,
        "dependency_environment_coverage_verified": False,
        "dispatch_enabled": False,
        "durable_control_plane_persistence_enabled": False,
        "dynamic_loader_identity_verified": False,
        "effect_class": 0,
        "effective_interpreter_resolution_verified": False,
        "effective_invocability_verified": False,
        "environment_coverage_verified": False,
        "exact_nested_target_runtime_manifest_correspondence_verified": True,
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
        "known_chain_guard_requirement_count": (
            value.known_chain_guard_requirement_count
        ),
        "launcher_semantics_verified": False,
        "lease_cleanup_performed": False,
        "lease_mutated": False,
        "live_execution_eligible": False,
        "model_invocation_performed": False,
        "mount_alias_exclusion_verified": False,
        "native_binary_no_shebang_count": disposition_counts[
            "native_binary_no_shebang"
        ],
        "network_access_performed": False,
        "non_absolute_interpreter_token_count": disposition_counts[
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
        "source_native_not_applicable_count": (
            value.source_native_not_applicable_count
        ),
        "source_path_reopen_performed": False,
        "staged_byte_correspondence_verified": True,
        "staged_descriptor_full_remeasurement_complete": True,
        "staging_root_path_reopen_performed": False,
        "subprocess_invocation_performed": False,
        "target_native_not_applicable_count": (
            value.target_native_not_applicable_count
        ),
        "target_path_reopen_performed": False,
        "target_semantics_verified": False,
        "toolchain_completeness_verified": False,
        "total_argument_tail_bytes": value.total_argument_tail_bytes,
        "total_interpreter_token_bytes": (
            value.total_interpreter_token_bytes
        ),
        "unique_nested_target_count": value.unique_nested_target_count,
        "unknown_runtime_format_count": disposition_counts[
            "unknown_runtime_format"
        ],
        "unsupported_shebang_count": disposition_counts[
            "unsupported_shebang"
        ],
        "validation_mode": "read_only",
        "worktree_integration_enabled": False,
        "worker_enabled": False,
    }


_BUILTIN_REQUIREMENT_REF_PROJECTION = _requirement_ref_projection
_BUILTIN_REQUIREMENT_PROJECTION = _requirement_projection
_BUILTIN_BINDING_PROJECTION = _binding_projection
_BUILTIN_RECEIPT_PROJECTION = _receipt_projection


@dataclass(frozen=True, slots=True)
class _NestedTargetShebangExtraction:
    """Private detached syntax result for one unique staged nested target."""

    nested_target_staged_file_ref: str = field(repr=False)
    nested_target_runtime_file_ref: str = field(repr=False)
    runtime_classification: str
    disposition: str
    nested_target_shebang_directive_ref: str | None = field(repr=False)
    interpreter_token_ref: str | None = field(repr=False)
    interpreter_token_bytes: int
    interpreter_token_absolute: bool | None
    argument_separator_kind: str | None
    argument_tail_ref: str | None = field(repr=False)
    argument_tail_bytes: int


_FIXED_EXTRACTION_TYPE = _NestedTargetShebangExtraction


def _header_digest(
    nested_target_staged_file_ref: str,
    header: bytes,
) -> str:
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
    nested_target_staged_file_ref: str,
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
                    "repository_executable_shebang_nested_target_"
                    "runtime_shebang_directive_ref"
                ),
                "nested_target_staged_file_ref": (
                    nested_target_staged_file_ref
                ),
                "schema_version": 1,
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
        raise _InvalidNestedTargetRequirements
    separator = "space" if directive[boundary] == 0x20 else "horizontal_tab"
    return token, separator, tail


def _interpreter_token_ref(
    *,
    nested_target_runtime_file_ref: str,
    nested_target_shebang_directive_ref: str,
    token: bytes,
) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "interpreter_token_hex": token.hex(),
            "kind": (
                "repository_executable_shebang_nested_target_"
                "interpreter_token_ref"
            ),
            "nested_target_runtime_file_ref": (
                nested_target_runtime_file_ref
            ),
            "nested_target_shebang_directive_ref": (
                nested_target_shebang_directive_ref
            ),
            "schema_version": _FIXED_SCHEMA_VERSION,
        }
    )


def _argument_tail_ref(
    *,
    nested_target_runtime_file_ref: str,
    nested_target_shebang_directive_ref: str,
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
                "repository_executable_shebang_nested_target_"
                "argument_tail_ref"
            ),
            "nested_target_runtime_file_ref": (
                nested_target_runtime_file_ref
            ),
            "nested_target_shebang_directive_ref": (
                nested_target_shebang_directive_ref
            ),
            "schema_version": _FIXED_SCHEMA_VERSION,
        }
    )


def _independent_descriptor_remeasurement(
    retained: _RetainedStagedNestedTarget,
    staged_file: dict[str, Any],
    *,
    staging_context_digest: str,
) -> bytes:
    if (
        type(retained) is not _FIXED_RETAINED_TYPE
        or type(staged_file) is not dict
        or _BUILTIN_STAGED_FILE_PROJECTION(
            retained.staged_file,
            staging_context_digest=staging_context_digest,
        )
        != staged_file
    ):
        raise _InvalidNestedTargetRequirements
    try:
        before = _BUILTIN_FSTAT(retained.descriptor)
        before_flags = _BUILTIN_FCNTL(
            retained.descriptor,
            _BUILTIN_F_GETFL,
        )
        before_inheritable = _BUILTIN_GET_INHERITABLE(retained.descriptor)
    except (OSError, ValueError):
        raise _InvalidNestedTargetRequirements from None
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
        raise _InvalidNestedTargetRequirements

    identity_ref = _BUILTIN_CANONICAL_DIGEST(
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
    metadata_digest = _BUILTIN_CANONICAL_DIGEST(
        {
            "change_time_ns": before.st_ctime_ns,
            "filesystem_identity_ref": identity_ref,
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
        identity_ref != staged_file["staged_filesystem_identity_ref"]
        or metadata_digest != staged_file["staged_metadata_digest"]
    ):
        raise _InvalidNestedTargetRequirements

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
            chunk = _BUILTIN_PREAD(retained.descriptor, requested, offset)
        except (BlockingIOError, InterruptedError, OSError):
            raise _InvalidNestedTargetRequirements from None
        if not chunk or len(chunk) > requested:
            raise _InvalidNestedTargetRequirements
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
        after_inheritable = _BUILTIN_GET_INHERITABLE(retained.descriptor)
    except (OSError, ValueError):
        raise _InvalidNestedTargetRequirements from None
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
        raise _InvalidNestedTargetRequirements
    return header


def _closing_descriptor_anchor(
    retained: _RetainedStagedNestedTarget,
    staged_file: dict[str, Any],
    *,
    staging_context_digest: str,
) -> None:
    if (
        type(retained) is not _FIXED_RETAINED_TYPE
        or _BUILTIN_STAGED_FILE_PROJECTION(
            retained.staged_file,
            staging_context_digest=staging_context_digest,
        )
        != staged_file
    ):
        raise _InvalidNestedTargetRequirements
    try:
        measured = _BUILTIN_FSTAT(retained.descriptor)
        flags = _BUILTIN_FCNTL(retained.descriptor, _BUILTIN_F_GETFL)
        inheritable = _BUILTIN_GET_INHERITABLE(retained.descriptor)
    except (OSError, ValueError):
        raise _InvalidNestedTargetRequirements from None
    signature = (
        measured.st_dev,
        measured.st_ino,
        measured.st_mode,
        measured.st_nlink,
        measured.st_uid,
        measured.st_gid,
        measured.st_size,
        measured.st_mtime_ns,
        measured.st_ctime_ns,
    )
    if (
        signature != retained.metadata
        or not _BUILTIN_S_ISREG(measured.st_mode)
        or measured.st_uid != _BUILTIN_GETEUID()
        or _BUILTIN_S_IMODE(measured.st_mode) != _STAGED_FILE_MODE
        or measured.st_nlink != 0
        or measured.st_size != staged_file["content_bytes"]
        or flags & _BUILTIN_O_ACCMODE != _BUILTIN_O_RDONLY
        or inheritable
    ):
        raise _InvalidNestedTargetRequirements


def _build_extraction(
    runtime_file: dict[str, Any],
    staged_file: dict[str, Any],
    header: bytes,
) -> _NestedTargetShebangExtraction:
    if (
        runtime_file["nested_target_staged_file_ref"]
        != staged_file["nested_target_staged_file_ref"]
        or runtime_file["staged_filesystem_identity_ref"]
        != staged_file["staged_filesystem_identity_ref"]
        or runtime_file["content_digest"] != staged_file["content_digest"]
        or runtime_file["content_bytes"] != staged_file["content_bytes"]
        or runtime_file["header_bytes"] != len(header)
        or runtime_file["header_digest"]
        != _BUILTIN_HEADER_DIGEST(
            staged_file["nested_target_staged_file_ref"],
            header,
        )
    ):
        raise _InvalidNestedTargetRequirements
    classification, directive_ref, directive = _BUILTIN_CLASSIFY_HEADER(
        staged_file["nested_target_staged_file_ref"],
        header,
    )
    if (
        classification != runtime_file["classification"]
        or directive_ref != runtime_file["shebang_directive_ref"]
    ):
        raise _InvalidNestedTargetRequirements

    token_ref: str | None = None
    token_bytes = 0
    token_absolute: bool | None = None
    separator: str | None = None
    tail_ref: str | None = None
    tail_bytes = 0
    if classification in {"elf", "mach_o"}:
        disposition = "native_binary_no_shebang"
    elif classification == "unsupported_shebang":
        disposition = "unsupported_shebang"
    elif classification == "unknown":
        disposition = "unknown_runtime_format"
    elif classification == "posix_shebang":
        if directive is None or directive_ref is None:
            raise _InvalidNestedTargetRequirements
        token, separator, tail = _BUILTIN_SPLIT_DIRECTIVE(directive)
        token_absolute = token.startswith(b"/")
        disposition = (
            "absolute_interpreter_token"
            if token_absolute
            else "non_absolute_interpreter_token"
        )
        token_ref = _BUILTIN_INTERPRETER_TOKEN_REF(
            nested_target_runtime_file_ref=(
                runtime_file["nested_target_runtime_file_ref"]
            ),
            nested_target_shebang_directive_ref=directive_ref,
            token=token,
        )
        token_bytes = len(token)
        if tail is not None:
            if separator is None:
                raise _InvalidNestedTargetRequirements
            tail_ref = _BUILTIN_ARGUMENT_TAIL_REF(
                nested_target_runtime_file_ref=(
                    runtime_file["nested_target_runtime_file_ref"]
                ),
                nested_target_shebang_directive_ref=directive_ref,
                interpreter_token_ref=token_ref,
                separator_kind=separator,
                tail=tail,
            )
            tail_bytes = len(tail)
    else:
        raise _InvalidNestedTargetRequirements
    return _FIXED_EXTRACTION_TYPE(
        nested_target_staged_file_ref=(
            staged_file["nested_target_staged_file_ref"]
        ),
        nested_target_runtime_file_ref=(
            runtime_file["nested_target_runtime_file_ref"]
        ),
        runtime_classification=classification,
        disposition=disposition,
        nested_target_shebang_directive_ref=directive_ref,
        interpreter_token_ref=token_ref,
        interpreter_token_bytes=token_bytes,
        interpreter_token_absolute=token_absolute,
        argument_separator_kind=separator,
        argument_tail_ref=tail_ref,
        argument_tail_bytes=tail_bytes,
    )


def _extract_unique_nested_targets(
    *,
    runtime_files: tuple[dict[str, Any], ...],
    staged_files: tuple[dict[str, Any], ...],
    retained_files: tuple[_RetainedStagedNestedTarget, ...],
    staging_context_digest: str,
) -> tuple[_NestedTargetShebangExtraction, ...]:
    if not (
        len(runtime_files) == len(staged_files) == len(retained_files)
    ):
        raise _InvalidNestedTargetRequirements
    result: list[_NestedTargetShebangExtraction] = []
    for runtime_file, staged_file, retained in zip(
        runtime_files,
        staged_files,
        retained_files,
        strict=True,
    ):
        header = _BUILTIN_DESCRIPTOR_REMEASUREMENT(
            retained,
            staged_file,
            staging_context_digest=staging_context_digest,
        )
        result.append(
            _BUILTIN_BUILD_EXTRACTION(runtime_file, staged_file, header)
        )
    return tuple(result)


def _validate_runtime_staging_correspondence(
    runtime: dict[str, Any],
    staging: dict[str, Any],
) -> None:
    common_fields = (
        "nested_target_resolution_receipt_digest",
        "expected_chain_guard_receipt_digest",
        "action_chain_guard_receipt_digest",
        "post_stage_chain_guard_receipt_digest",
        "target_shebang_requirements_receipt_digest",
        "target_runtime_manifest_receipt_digest",
        "target_staging_receipt_digest",
        "target_resolution_receipt_digest",
        "shebang_requirements_receipt_digest",
        "runtime_manifest_receipt_digest",
        "source_staging_receipt_digest",
        "registration_digest",
        "repository_ref",
        "verification_commands_digest",
        "resolution_context_digest",
        "source_staging_context_digest",
        "target_path_context_digest",
        "target_staging_context_digest",
        "nested_target_path_context_digest",
        "known_source_identity_set_digest",
        "known_target_identity_set_digest",
        "protected_staging_root_identity_set_digest",
        "guard_summary_ref",
        "nested_target_staging_context_digest",
        "source_native_not_applicable_count",
        "target_native_not_applicable_count",
        "requirement_count",
        "command_count",
    )
    if (
        runtime["nested_target_staging_receipt_digest"]
        != _BUILTIN_CANONICAL_DIGEST(staging)
        or any(runtime[field] != staging[field] for field in common_fields)
        or runtime["file_count"] != staging["unique_nested_target_count"]
        or runtime["known_chain_guard_runtime_inspected_count"]
        != staging["known_chain_guard_staged_count"]
        or runtime["total_content_bytes"] != staging["total_staged_bytes"]
        or len(runtime["files"]) != len(staging["staged_files"])
        or len(runtime["requirements"]) != len(staging["requirements"])
        or len(runtime["bindings"]) != len(staging["bindings"])
    ):
        raise _InvalidNestedTargetRequirements

    file_fields = (
        "nested_target_staged_file_ref",
        "staged_filesystem_identity_ref",
        "content_digest",
        "content_bytes",
    )
    for runtime_file, staged_file in zip(
        runtime["files"],
        staging["staged_files"],
        strict=True,
    ):
        if any(
            runtime_file[field] != staged_file[field]
            for field in file_fields
        ):
            raise _InvalidNestedTargetRequirements

    lineage = (
        "staged_file_ref",
        "runtime_file_ref",
        "requirement_ref",
        "target_requirement_ref",
        "target_stage_requirement_ref",
        "target_runtime_requirement_ref",
        "target_shebang_requirement_ref",
        "nested_target_requirement_ref",
        "chain_guard_requirement_ref",
        "nested_target_stage_requirement_ref",
        "nested_target_measurement_ref",
        "guarded_measurement_ref",
        "nested_target_staged_file_ref",
    )
    disposition_map = {
        "known_chain_guard_staged": (
            "known_chain_guard_runtime_inspected"
        ),
        "source_native_not_applicable": "source_native_not_applicable",
        "target_native_not_applicable": "target_native_not_applicable",
    }
    for runtime_requirement, staged_requirement in zip(
        runtime["requirements"],
        staging["requirements"],
        strict=True,
    ):
        if (
            any(
                runtime_requirement[field] != staged_requirement[field]
                for field in lineage
            )
            or runtime_requirement["disposition"]
            != disposition_map.get(staged_requirement["disposition"])
        ):
            raise _InvalidNestedTargetRequirements

    binding_lineage = (
        "command_kind",
        "command_id",
        "command_digest",
        "staged_file_ref",
        "runtime_file_ref",
        "requirement_ref",
        "target_requirement_ref",
        "target_stage_requirement_ref",
        "target_runtime_requirement_ref",
        "target_shebang_requirement_ref",
        "nested_target_requirement_ref",
        "chain_guard_requirement_ref",
        "nested_target_stage_requirement_ref",
    )
    for runtime_binding, staged_binding in zip(
        runtime["bindings"],
        staging["bindings"],
        strict=True,
    ):
        if any(
            runtime_binding[field] != staged_binding[field]
            for field in binding_lineage
        ):
            raise _InvalidNestedTargetRequirements


def _build_requirement(
    runtime_requirement: dict[str, Any],
    *,
    extraction_by_runtime_ref: dict[
        str, _NestedTargetShebangExtraction
    ],
) -> RepositoryExecutableShebangNestedTargetShebangRequirement:
    runtime_disposition = runtime_requirement["disposition"]
    if runtime_disposition == "known_chain_guard_runtime_inspected":
        runtime_file_ref = runtime_requirement[
            "nested_target_runtime_file_ref"
        ]
        if runtime_file_ref is None:
            raise _InvalidNestedTargetRequirements
        extraction = extraction_by_runtime_ref.get(runtime_file_ref)
        if (
            extraction is None
            or extraction.nested_target_staged_file_ref
            != runtime_requirement["nested_target_staged_file_ref"]
            or extraction.runtime_classification
            != runtime_requirement["runtime_classification"]
        ):
            raise _InvalidNestedTargetRequirements
        disposition = extraction.disposition
        directive_ref = extraction.nested_target_shebang_directive_ref
        token_ref = extraction.interpreter_token_ref
        token_bytes = extraction.interpreter_token_bytes
        token_absolute = extraction.interpreter_token_absolute
        separator = extraction.argument_separator_kind
        tail_ref = extraction.argument_tail_ref
        tail_bytes = extraction.argument_tail_bytes
    elif runtime_disposition in {
        "source_native_not_applicable",
        "target_native_not_applicable",
    }:
        disposition = runtime_disposition
        directive_ref = None
        token_ref = None
        token_bytes = 0
        token_absolute = None
        separator = None
        tail_ref = None
        tail_bytes = 0
    else:
        raise _InvalidNestedTargetRequirements

    reference = _BUILTIN_REQUIREMENT_REF_PROJECTION(
        staged_file_ref=runtime_requirement["staged_file_ref"],
        runtime_file_ref=runtime_requirement["runtime_file_ref"],
        requirement_ref=runtime_requirement["requirement_ref"],
        target_requirement_ref=runtime_requirement["target_requirement_ref"],
        target_stage_requirement_ref=(
            runtime_requirement["target_stage_requirement_ref"]
        ),
        target_runtime_requirement_ref=(
            runtime_requirement["target_runtime_requirement_ref"]
        ),
        target_shebang_requirement_ref=(
            runtime_requirement["target_shebang_requirement_ref"]
        ),
        nested_target_requirement_ref=(
            runtime_requirement["nested_target_requirement_ref"]
        ),
        chain_guard_requirement_ref=(
            runtime_requirement["chain_guard_requirement_ref"]
        ),
        nested_target_stage_requirement_ref=(
            runtime_requirement["nested_target_stage_requirement_ref"]
        ),
        nested_target_runtime_requirement_ref=(
            runtime_requirement["nested_target_runtime_requirement_ref"]
        ),
        runtime_classification=runtime_requirement["runtime_classification"],
        runtime_disposition=runtime_disposition,
        nested_target_measurement_ref=(
            runtime_requirement["nested_target_measurement_ref"]
        ),
        guarded_measurement_ref=runtime_requirement["guarded_measurement_ref"],
        nested_target_staged_file_ref=(
            runtime_requirement["nested_target_staged_file_ref"]
        ),
        nested_target_runtime_file_ref=(
            runtime_requirement["nested_target_runtime_file_ref"]
        ),
        disposition=disposition,
        nested_target_shebang_directive_ref=directive_ref,
        interpreter_token_ref=token_ref,
        interpreter_token_bytes=token_bytes,
        interpreter_token_absolute=token_absolute,
        argument_separator_kind=separator,
        argument_tail_ref=tail_ref,
        argument_tail_bytes=tail_bytes,
    )
    value = _FIXED_REQUIREMENT_TYPE(
        kind=_FIXED_REQUIREMENT_KIND,
        staged_file_ref=runtime_requirement["staged_file_ref"],
        runtime_file_ref=runtime_requirement["runtime_file_ref"],
        requirement_ref=runtime_requirement["requirement_ref"],
        target_requirement_ref=runtime_requirement["target_requirement_ref"],
        target_stage_requirement_ref=(
            runtime_requirement["target_stage_requirement_ref"]
        ),
        target_runtime_requirement_ref=(
            runtime_requirement["target_runtime_requirement_ref"]
        ),
        target_shebang_requirement_ref=(
            runtime_requirement["target_shebang_requirement_ref"]
        ),
        nested_target_requirement_ref=(
            runtime_requirement["nested_target_requirement_ref"]
        ),
        chain_guard_requirement_ref=(
            runtime_requirement["chain_guard_requirement_ref"]
        ),
        nested_target_stage_requirement_ref=(
            runtime_requirement["nested_target_stage_requirement_ref"]
        ),
        nested_target_runtime_requirement_ref=(
            runtime_requirement["nested_target_runtime_requirement_ref"]
        ),
        runtime_classification=runtime_requirement["runtime_classification"],
        runtime_disposition=runtime_disposition,
        nested_target_measurement_ref=(
            runtime_requirement["nested_target_measurement_ref"]
        ),
        guarded_measurement_ref=runtime_requirement["guarded_measurement_ref"],
        nested_target_staged_file_ref=(
            runtime_requirement["nested_target_staged_file_ref"]
        ),
        nested_target_runtime_file_ref=(
            runtime_requirement["nested_target_runtime_file_ref"]
        ),
        disposition=disposition,
        nested_target_shebang_directive_ref=directive_ref,
        interpreter_token_ref=token_ref,
        interpreter_token_bytes=token_bytes,
        interpreter_token_absolute=token_absolute,
        argument_separator_kind=separator,
        argument_tail_ref=tail_ref,
        argument_tail_bytes=tail_bytes,
        nested_target_shebang_requirement_ref=(
            _BUILTIN_CANONICAL_DIGEST(reference)
        ),
    )
    _BUILTIN_REQUIREMENT_PROJECTION(value)
    return value


def _build_binding(
    source: dict[str, Any],
    requirement: RepositoryExecutableShebangNestedTargetShebangRequirement,
) -> RepositoryExecutableShebangNestedTargetShebangRequirementBinding:
    lineage = (
        "staged_file_ref",
        "runtime_file_ref",
        "requirement_ref",
        "target_requirement_ref",
        "target_stage_requirement_ref",
        "target_runtime_requirement_ref",
        "target_shebang_requirement_ref",
        "nested_target_requirement_ref",
        "chain_guard_requirement_ref",
        "nested_target_stage_requirement_ref",
        "nested_target_runtime_requirement_ref",
    )
    if any(source[field] != getattr(requirement, field) for field in lineage):
        raise _InvalidNestedTargetRequirements
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
        target_runtime_requirement_ref=(
            source["target_runtime_requirement_ref"]
        ),
        target_shebang_requirement_ref=(
            source["target_shebang_requirement_ref"]
        ),
        nested_target_requirement_ref=(
            source["nested_target_requirement_ref"]
        ),
        chain_guard_requirement_ref=source["chain_guard_requirement_ref"],
        nested_target_stage_requirement_ref=(
            source["nested_target_stage_requirement_ref"]
        ),
        nested_target_runtime_requirement_ref=(
            source["nested_target_runtime_requirement_ref"]
        ),
        nested_target_shebang_requirement_ref=(
            requirement.nested_target_shebang_requirement_ref
        ),
    )
    _BUILTIN_BINDING_PROJECTION(value)
    return value


# Freeze the upstream proof entrypoints and the complete extraction graph.
_BUILTIN_STAGING_RECEIPT_PROJECTION = _target_staging_receipt_projection
_BUILTIN_RUNTIME_MANIFEST_PROJECTION = _runtime_manifest_projection
_BUILTIN_ACTIVE_STAGE_SNAPSHOT = _active_target_stage_snapshot
_BUILTIN_INSPECT_RUNTIME_MANIFEST = (
    inspect_staged_executable_shebang_nested_target_runtime_manifest
)
_BUILTIN_STAGED_FILE_PROJECTION = _staged_file_projection
_BUILTIN_HEADER_DIGEST = _header_digest
_BUILTIN_BOUNDED_SHEBANG_DIRECTIVE = _bounded_shebang_directive
_BUILTIN_CLASSIFY_HEADER = _classify_header
_BUILTIN_SPLIT_DIRECTIVE = _split_directive
_BUILTIN_INTERPRETER_TOKEN_REF = _interpreter_token_ref
_BUILTIN_ARGUMENT_TAIL_REF = _argument_tail_ref
_BUILTIN_DESCRIPTOR_REMEASUREMENT = _independent_descriptor_remeasurement
_BUILTIN_CLOSING_DESCRIPTOR_ANCHOR = _closing_descriptor_anchor
_BUILTIN_BUILD_EXTRACTION = _build_extraction
_BUILTIN_EXTRACT_UNIQUE_NESTED_TARGETS = _extract_unique_nested_targets
_BUILTIN_VALIDATE_RUNTIME_STAGING = _validate_runtime_staging_correspondence
_BUILTIN_BUILD_REQUIREMENT = _build_requirement
_BUILTIN_BUILD_BINDING = _build_binding


def inspect_staged_executable_shebang_nested_target_requirements(
    expected_nested_target_runtime: (
        RepositoryExecutableShebangNestedTargetRuntimeManifestReceipt
    ),
    *,
    expected_nested_target_staging: (
        RepositoryExecutableShebangNestedTargetStagingReceipt
    ),
    lease: RepositoryExecutableShebangNestedTargetStageLease,
) -> RepositoryExecutableShebangNestedTargetRequirementsReceipt:
    """Extract one bounded nested-target shebang layer without resolving it."""

    try:
        if (
            type(expected_nested_target_runtime)
            is not _FIXED_RUNTIME_RECEIPT_TYPE
            or type(expected_nested_target_staging)
            is not _FIXED_STAGING_RECEIPT_TYPE
            or type(lease) is not _FIXED_STAGE_LEASE_TYPE
        ):
            raise _InvalidNestedTargetRequirements

        staging_canonical = _BUILTIN_STAGING_RECEIPT_PROJECTION(
            expected_nested_target_staging
        )
        runtime_canonical = _BUILTIN_RUNTIME_MANIFEST_PROJECTION(
            expected_nested_target_runtime
        )
        _BUILTIN_VALIDATE_RUNTIME_STAGING(
            runtime_canonical,
            staging_canonical,
        )
        entry_canonical, retained_files = _BUILTIN_ACTIVE_STAGE_SNAPSHOT(
            expected_nested_target_staging,
            lease,
        )
        if entry_canonical != staging_canonical:
            raise _InvalidNestedTargetRequirements

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
        staging_context_digest = staging_canonical[
            "nested_target_staging_context_digest"
        ]

        fresh_runtime = _BUILTIN_INSPECT_RUNTIME_MANIFEST(
            expected_nested_target_staging,
            lease=lease,
        )
        if (
            _BUILTIN_RUNTIME_MANIFEST_PROJECTION(fresh_runtime)
            != runtime_canonical
        ):
            raise _InvalidNestedTargetRequirements
        active_canonical, active_retained_files = (
            _BUILTIN_ACTIVE_STAGE_SNAPSHOT(
                expected_nested_target_staging,
                lease,
            )
        )
        if (
            active_canonical != staging_canonical
            or active_retained_files is not retained_files
        ):
            raise _InvalidNestedTargetRequirements

        first_extractions = _BUILTIN_EXTRACT_UNIQUE_NESTED_TARGETS(
            runtime_files=runtime_files,
            staged_files=staged_files,
            retained_files=retained_files,
            staging_context_digest=staging_context_digest,
        )
        pass_canonical, pass_retained_files = _BUILTIN_ACTIVE_STAGE_SNAPSHOT(
            expected_nested_target_staging,
            lease,
        )
        if (
            pass_canonical != staging_canonical
            or pass_retained_files is not retained_files
        ):
            raise _InvalidNestedTargetRequirements

        second_extractions = _BUILTIN_EXTRACT_UNIQUE_NESTED_TARGETS(
            runtime_files=runtime_files,
            staged_files=staged_files,
            retained_files=retained_files,
            staging_context_digest=staging_context_digest,
        )
        if second_extractions != first_extractions:
            raise _InvalidNestedTargetRequirements

        final_runtime = _BUILTIN_INSPECT_RUNTIME_MANIFEST(
            expected_nested_target_staging,
            lease=lease,
        )
        if (
            _BUILTIN_RUNTIME_MANIFEST_PROJECTION(final_runtime)
            != runtime_canonical
        ):
            raise _InvalidNestedTargetRequirements
        final_canonical, final_retained_files = (
            _BUILTIN_ACTIVE_STAGE_SNAPSHOT(
                expected_nested_target_staging,
                lease,
            )
        )
        if (
            final_canonical != staging_canonical
            or final_retained_files is not retained_files
        ):
            raise _InvalidNestedTargetRequirements

        extraction_by_runtime_ref = {
            value.nested_target_runtime_file_ref: value
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
            value.nested_target_runtime_requirement_ref: value
            for value in requirements
        }
        bindings = tuple(
            _BUILTIN_BUILD_BINDING(
                item,
                requirement_by_runtime_ref[
                    item["nested_target_runtime_requirement_ref"]
                ],
            )
            for item in runtime_bindings
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
                runtime_canonical["nested_target_staging_receipt_digest"]
            ),
            nested_target_resolution_receipt_digest=(
                runtime_canonical[
                    "nested_target_resolution_receipt_digest"
                ]
            ),
            expected_chain_guard_receipt_digest=(
                runtime_canonical["expected_chain_guard_receipt_digest"]
            ),
            action_chain_guard_receipt_digest=(
                runtime_canonical["action_chain_guard_receipt_digest"]
            ),
            post_stage_chain_guard_receipt_digest=(
                runtime_canonical["post_stage_chain_guard_receipt_digest"]
            ),
            target_shebang_requirements_receipt_digest=(
                runtime_canonical[
                    "target_shebang_requirements_receipt_digest"
                ]
            ),
            target_runtime_manifest_receipt_digest=(
                runtime_canonical[
                    "target_runtime_manifest_receipt_digest"
                ]
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
            source_staging_receipt_digest=(
                runtime_canonical["source_staging_receipt_digest"]
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
            nested_target_path_context_digest=(
                runtime_canonical["nested_target_path_context_digest"]
            ),
            known_source_identity_set_digest=(
                runtime_canonical["known_source_identity_set_digest"]
            ),
            known_target_identity_set_digest=(
                runtime_canonical["known_target_identity_set_digest"]
            ),
            protected_staging_root_identity_set_digest=(
                runtime_canonical[
                    "protected_staging_root_identity_set_digest"
                ]
            ),
            guard_summary_ref=runtime_canonical["guard_summary_ref"],
            nested_target_staging_context_digest=(
                runtime_canonical[
                    "nested_target_staging_context_digest"
                ]
            ),
            requirements=requirements,
            bindings=bindings,
            requirement_count=len(requirements),
            command_count=len(bindings),
            known_chain_guard_requirement_count=(
                runtime_canonical[
                    "known_chain_guard_runtime_inspected_count"
                ]
            ),
            source_native_not_applicable_count=(
                runtime_canonical["source_native_not_applicable_count"]
            ),
            target_native_not_applicable_count=(
                runtime_canonical["target_native_not_applicable_count"]
            ),
            unique_nested_target_count=len(first_extractions),
            nested_target_posix_shebang_requirement_count=sum(
                value.runtime_classification == "posix_shebang"
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
            _BUILTIN_RUNTIME_MANIFEST_PROJECTION(
                expected_nested_target_runtime
            )
            != runtime_canonical
        ):
            raise _InvalidNestedTargetRequirements
        closing_canonical, closing_retained_files = (
            _BUILTIN_ACTIVE_STAGE_SNAPSHOT(
                expected_nested_target_staging,
                lease,
            )
        )
        if (
            closing_canonical != staging_canonical
            or closing_retained_files is not retained_files
        ):
            raise _InvalidNestedTargetRequirements
        for retained, staged_file in zip(
            closing_retained_files,
            staged_files,
            strict=True,
        ):
            _BUILTIN_CLOSING_DESCRIPTOR_ANCHOR(
                retained,
                staged_file,
                staging_context_digest=staging_context_digest,
            )
        return receipt
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise _FIXED_VALIDATION_ERROR(_INVALID_MESSAGE) from None


__all__ = [
    "REQUIREMENTS_SCOPE",
    "REQUIREMENTS_SOURCE",
    (
        "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_"
        "REQUIREMENTS_EVIDENCE_KIND"
    ),
    "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_REQUIREMENTS_KIND",
    "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_REQUIREMENTS_SCHEMA_VERSION",
    (
        "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_"
        "SHEBANG_REQUIREMENT_BINDING_KIND"
    ),
    (
        "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_"
        "SHEBANG_REQUIREMENT_KIND"
    ),
    "RepositoryExecutableShebangNestedTargetRequirementsReceipt",
    "RepositoryExecutableShebangNestedTargetShebangRequirement",
    "RepositoryExecutableShebangNestedTargetShebangRequirementBinding",
    "inspect_staged_executable_shebang_nested_target_requirements",
]
