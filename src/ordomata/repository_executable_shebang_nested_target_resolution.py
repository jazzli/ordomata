"""Measure one bounded nested absolute shebang-target hop.

This Class 0 boundary consumes the exact staged-target shebang-requirements
chain and measures only the concrete absolute file named by a supported
target shebang's first token.  Resolution terminates at depth two: measured
bytes are neither parsed nor staged, and no process is executed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
import unicodedata
from types import FunctionType
from typing import Any, Callable

from .authorization import canonical_json
from .errors import ValidationError
from .repository_executable_shebang_target_requirements import (
    RepositoryExecutableShebangTargetRequirementsReceipt,
    RepositoryExecutableShebangTargetShebangRequirement,
    RepositoryExecutableShebangTargetShebangRequirementBinding,
    _argument_tail_ref as _target_argument_tail_ref_v1,
    _classify_header as _target_classify_header_v1,
    _closing_descriptor_anchor as _target_closing_descriptor_anchor_v1,
    _independent_descriptor_remeasurement as _target_descriptor_remeasurement_v1,
    _interpreter_token_ref as _target_interpreter_token_ref_v1,
    _receipt_projection as _target_requirements_projection_v1,
    _split_directive as _target_split_directive_v1,
    _target_runtime_manifest_projection as _target_runtime_projection_v1,
    _target_staging_receipt_projection as _target_staging_projection_v1,
    inspect_staged_executable_shebang_target_requirements,
)
from .repository_executable_shebang_target_runtime_manifest import (
    RepositoryExecutableShebangTargetRuntimeManifestReceipt,
    _active_target_stage_snapshot,
    inspect_staged_executable_shebang_target_runtime_manifest,
)
from .repository_executable_shebang_target_staging import (
    RepositoryExecutableShebangTargetStageLease,
    RepositoryExecutableShebangTargetStagingReceipt,
)


REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RESOLUTION_SCHEMA_VERSION = 1
REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RESOLUTION_KIND = (
    "repository_executable_shebang_nested_target_resolution"
)
REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RESOLUTION_EVIDENCE_KIND = (
    "repository_executable_shebang_nested_target_resolution_validation"
)
REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_MEASUREMENT_KIND = (
    "repository_executable_shebang_nested_target_measurement"
)
REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_REQUIREMENT_KIND = (
    "repository_executable_shebang_nested_target_requirement"
)
REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_BINDING_KIND = (
    "repository_executable_shebang_nested_target_binding"
)
MEASUREMENT_SOURCE = "controller_measured"
RESOLUTION_SCOPE = "posix_absolute_shebang_nested_target_nofollow_v1"
RESOLUTION_DEPTH = 2
MAXIMUM_RESOLUTION_DEPTH = 2
CYCLE_SCOPE = "immediate_target_reentry_v1"

_FIXED_SCHEMA_VERSION = (
    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RESOLUTION_SCHEMA_VERSION
)
_FIXED_RECEIPT_KIND = (
    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RESOLUTION_KIND
)
_FIXED_EVIDENCE_KIND = (
    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RESOLUTION_EVIDENCE_KIND
)
_FIXED_MEASUREMENT_KIND = (
    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_MEASUREMENT_KIND
)
_FIXED_REQUIREMENT_KIND = (
    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_REQUIREMENT_KIND
)
_FIXED_BINDING_KIND = REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_BINDING_KIND
_FIXED_MEASUREMENT_SOURCE = MEASUREMENT_SOURCE
_FIXED_RESOLUTION_SCOPE = RESOLUTION_SCOPE
_FIXED_RESOLUTION_DEPTH = RESOLUTION_DEPTH
_FIXED_MAXIMUM_RESOLUTION_DEPTH = MAXIMUM_RESOLUTION_DEPTH
_FIXED_CYCLE_SCOPE = CYCLE_SCOPE

_INVALID_MESSAGE = (
    "repository executable shebang nested target resolution is invalid"
)
_DIRECT_TARGET_RESOLUTION_SCOPE = "posix_absolute_shebang_target_nofollow_v1"
_DIGEST_PREFIX = "sha256:"
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_BUILTIN_DIGEST_FULLMATCH = _DIGEST_PATTERN.fullmatch
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
_DISPOSITIONS = (
    "source_native_not_applicable",
    "target_native_not_applicable",
    "direct_absolute_nested_target_measured",
)
_MAX_REQUIREMENTS = 80
_MAX_COMMANDS = 80
_MAX_TARGET_PATHS = 80
_MAX_TARGET_PATH_BYTES = 4_096
_MAX_TOTAL_TARGET_PATH_BYTES = 16 * 1024
_MAX_TARGET_PATH_COMPONENTS = 64
_MAX_TARGET_PATH_COMPONENT_BYTES = 255
_MAX_DIRECTORY_ENTRIES = 16_384
_MAX_DIRECTORY_ENTRY_BYTES = 4 * 1024 * 1024
_MAX_TARGET_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_TARGET_BYTES = 256 * 1024 * 1024
_READ_CHUNK_BYTES = 1024 * 1024

# Capture the shipped proof graph.  Public module attributes and transparent
# dataclass methods remain patchable and are not accepted as proof inputs.
_BUILTIN_CANONICAL_JSON = canonical_json
_BUILTIN_SHA256 = hashlib.sha256
_BUILTIN_OPEN = os.open
_BUILTIN_CLOSE = os.close
_BUILTIN_READ = os.read
_BUILTIN_LSEEK = os.lseek
_BUILTIN_FSTAT = os.fstat
_BUILTIN_STAT = os.stat
_BUILTIN_SCANDIR = os.scandir
_BUILTIN_FSPATH = os.fspath
_BUILTIN_GETPID = os.getpid
_BUILTIN_GETEUID = os.geteuid
_BUILTIN_GET_INHERITABLE = os.get_inheritable
_BUILTIN_FCNTL = fcntl.fcntl
_BUILTIN_F_GETFL = fcntl.F_GETFL
_BUILTIN_F_GETFD = fcntl.F_GETFD
_BUILTIN_UNICODE_NORMALIZE = unicodedata.normalize
_BUILTIN_UNICODE_CATEGORY = unicodedata.category
_FIXED_CONCRETE_PATH_TYPE = type(Path())
_BUILTIN_CONCRETE_PATH = _FIXED_CONCRETE_PATH_TYPE
_FIXED_FUNCTION_TYPE = FunctionType
_FIXED_POSIX_ROOT = "/"
_FIXED_O_RDONLY = getattr(os, "O_RDONLY", None)
_FIXED_O_DIRECTORY = getattr(os, "O_DIRECTORY", None)
_FIXED_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", None)
_FIXED_O_CLOEXEC = getattr(os, "O_CLOEXEC", None)
_FIXED_O_NONBLOCK = getattr(os, "O_NONBLOCK", None)
_FIXED_O_ACCMODE = getattr(os, "O_ACCMODE", None)
_BUILTIN_S_ISDIR = stat.S_ISDIR
_BUILTIN_S_ISREG = stat.S_ISREG
_BUILTIN_S_ISLNK = stat.S_ISLNK
_FIXED_SUPPORTS_DIR_FD = frozenset(os.supports_dir_fd)
_FIXED_SUPPORTS_FOLLOW_SYMLINKS = frozenset(os.supports_follow_symlinks)
_FIXED_PLATFORM_SUPPORTED = (
    os.name == "posix"
    and all(
        type(value) is int and value >= 0
        for value in (
            _FIXED_O_RDONLY,
            _FIXED_O_DIRECTORY,
            _FIXED_O_NOFOLLOW,
            _FIXED_O_CLOEXEC,
            _FIXED_O_NONBLOCK,
            _FIXED_O_ACCMODE,
        )
    )
    and _BUILTIN_OPEN in _FIXED_SUPPORTS_DIR_FD
    and _BUILTIN_STAT in _FIXED_SUPPORTS_DIR_FD
    and _BUILTIN_STAT in _FIXED_SUPPORTS_FOLLOW_SYMLINKS
)
_FIXED_VALIDATION_ERROR = ValidationError
_FIXED_TARGET_REQUIREMENT_TYPE = (
    RepositoryExecutableShebangTargetShebangRequirement
)
_FIXED_TARGET_BINDING_TYPE = (
    RepositoryExecutableShebangTargetShebangRequirementBinding
)
_FIXED_TARGET_REQUIREMENTS_RECEIPT_TYPE = (
    RepositoryExecutableShebangTargetRequirementsReceipt
)
_FIXED_TARGET_RUNTIME_RECEIPT_TYPE = (
    RepositoryExecutableShebangTargetRuntimeManifestReceipt
)
_FIXED_TARGET_STAGING_RECEIPT_TYPE = (
    RepositoryExecutableShebangTargetStagingReceipt
)
_FIXED_TARGET_STAGE_LEASE_TYPE = RepositoryExecutableShebangTargetStageLease
_BUILTIN_TARGET_REQUIREMENTS_PROJECTION = _target_requirements_projection_v1
_BUILTIN_TARGET_RUNTIME_PROJECTION = _target_runtime_projection_v1
_BUILTIN_TARGET_STAGING_PROJECTION = _target_staging_projection_v1
_BUILTIN_ACTIVE_TARGET_STAGE_SNAPSHOT = _active_target_stage_snapshot
_BUILTIN_TARGET_DESCRIPTOR_REMEASUREMENT = (
    _target_descriptor_remeasurement_v1
)
_BUILTIN_TARGET_CLOSING_DESCRIPTOR_ANCHOR = (
    _target_closing_descriptor_anchor_v1
)
_BUILTIN_TARGET_CLASSIFY_HEADER = _target_classify_header_v1
_BUILTIN_TARGET_SPLIT_DIRECTIVE = _target_split_directive_v1
_BUILTIN_TARGET_INTERPRETER_TOKEN_REF = _target_interpreter_token_ref_v1
_BUILTIN_TARGET_ARGUMENT_TAIL_REF = _target_argument_tail_ref_v1
_BUILTIN_INSPECT_TARGET_RUNTIME = (
    inspect_staged_executable_shebang_target_runtime_manifest
)
_BUILTIN_INSPECT_TARGET_REQUIREMENTS = (
    inspect_staged_executable_shebang_target_requirements
)


def _captured_canonical_digest(value: Any) -> str:
    encoded = _BUILTIN_CANONICAL_JSON(value).encode("utf-8")
    return _DIGEST_PREFIX + _BUILTIN_SHA256(encoded).hexdigest()


_BUILTIN_CANONICAL_DIGEST = _captured_canonical_digest


class _InvalidNestedTargetResolution(ValueError):
    """Private invalid-input sentinel with no public detail."""


@dataclass(frozen=True, slots=True)
class RepositoryExecutableShebangNestedTargetMeasurement:
    """One exact depth-two target and its point-in-time measurement."""

    kind: str
    nested_target_path_ref: str = field(repr=False)
    filesystem_identity_ref: str = field(repr=False)
    metadata_digest: str = field(repr=False)
    content_digest: str = field(repr=False)
    content_bytes: int
    nested_target_measurement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _measurement_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableShebangNestedTargetRequirement:
    """One upstream row's bounded depth-two resolution disposition."""

    kind: str
    staged_file_ref: str = field(repr=False)
    runtime_file_ref: str = field(repr=False)
    requirement_ref: str = field(repr=False)
    target_requirement_ref: str = field(repr=False)
    target_stage_requirement_ref: str = field(repr=False)
    target_runtime_requirement_ref: str = field(repr=False)
    target_shebang_requirement_ref: str = field(repr=False)
    runtime_classification: str
    target_measurement_ref: str | None = field(repr=False)
    target_staged_file_ref: str | None = field(repr=False)
    target_runtime_file_ref: str | None = field(repr=False)
    target_runtime_classification: str | None
    target_shebang_directive_ref: str | None = field(repr=False)
    interpreter_token_ref: str | None = field(repr=False)
    argument_tail_ref: str | None = field(repr=False)
    disposition: str
    nested_target_measurement_ref: str | None = field(repr=False)
    nested_target_requirement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _requirement_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableShebangNestedTargetBinding:
    """One registered command bound to one nested-target requirement."""

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

    def to_canonical(self) -> dict[str, Any]:
        return _binding_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableShebangNestedTargetResolutionReceipt:
    """Immutable digest-only evidence for one bounded nested hop."""

    kind: str
    schema_version: int
    measurement_source: str
    resolution_scope: str
    resolution_depth: int
    maximum_resolution_depth: int
    cycle_scope: str
    target_shebang_requirements_receipt_digest: str = field(repr=False)
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
    nested_target_path_context_digest: str = field(repr=False)
    measurements: tuple[
        RepositoryExecutableShebangNestedTargetMeasurement, ...
    ] = field(repr=False)
    requirements: tuple[
        RepositoryExecutableShebangNestedTargetRequirement, ...
    ] = field(repr=False)
    bindings: tuple[
        RepositoryExecutableShebangNestedTargetBinding, ...
    ] = field(repr=False)
    requirement_count: int
    command_count: int
    nested_target_requirement_count: int
    target_native_not_applicable_count: int
    source_native_not_applicable_count: int
    unique_nested_target_count: int
    total_measured_bytes: int

    def to_canonical(self) -> dict[str, Any]:
        return _receipt_projection(self)

    @property
    def receipt_digest(self) -> str:
        return _BUILTIN_CANONICAL_DIGEST(_receipt_projection(self))

    def to_evidence(self) -> dict[str, Any]:
        return _evidence_projection(self)


_FIXED_MEASUREMENT_TYPE = RepositoryExecutableShebangNestedTargetMeasurement
_FIXED_REQUIREMENT_TYPE = RepositoryExecutableShebangNestedTargetRequirement
_FIXED_BINDING_TYPE = RepositoryExecutableShebangNestedTargetBinding
_FIXED_RECEIPT_TYPE = (
    RepositoryExecutableShebangNestedTargetResolutionReceipt
)


def _is_digest(value: Any) -> bool:
    return type(value) is str and _DIGEST_PATTERN.fullmatch(value) is not None


_BUILTIN_IS_DIGEST = _is_digest


def _measurement_ref_projection(
    *,
    nested_target_path_ref: str,
    filesystem_identity_ref: str,
    metadata_digest: str,
    content_digest: str,
    content_bytes: int,
) -> dict[str, Any]:
    return {
        "content_bytes": content_bytes,
        "content_digest": content_digest,
        "filesystem_identity_ref": filesystem_identity_ref,
        "kind": "repository_executable_shebang_nested_target_measurement_ref",
        "measurement_source": _FIXED_MEASUREMENT_SOURCE,
        "metadata_digest": metadata_digest,
        "nested_target_path_ref": nested_target_path_ref,
        "resolution_depth": _FIXED_RESOLUTION_DEPTH,
        "resolution_scope": _FIXED_RESOLUTION_SCOPE,
        "schema_version": _FIXED_SCHEMA_VERSION,
    }


def _measurement_projection(
    value: RepositoryExecutableShebangNestedTargetMeasurement,
) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_MEASUREMENT_TYPE
        or type(value.kind) is not str
        or value.kind
        != _FIXED_MEASUREMENT_KIND
        or not _BUILTIN_IS_DIGEST(value.nested_target_path_ref)
        or not _BUILTIN_IS_DIGEST(value.filesystem_identity_ref)
        or not _BUILTIN_IS_DIGEST(value.metadata_digest)
        or not _BUILTIN_IS_DIGEST(value.content_digest)
        or type(value.content_bytes) is not int
        or not 0 <= value.content_bytes <= _MAX_TARGET_BYTES
        or not _BUILTIN_IS_DIGEST(value.nested_target_measurement_ref)
    ):
        raise _InvalidNestedTargetResolution
    reference = _BUILTIN_MEASUREMENT_REF_PROJECTION(
        nested_target_path_ref=value.nested_target_path_ref,
        filesystem_identity_ref=value.filesystem_identity_ref,
        metadata_digest=value.metadata_digest,
        content_digest=value.content_digest,
        content_bytes=value.content_bytes,
    )
    if value.nested_target_measurement_ref != _BUILTIN_CANONICAL_DIGEST(
        reference
    ):
        raise _InvalidNestedTargetResolution
    return {
        "content_bytes": value.content_bytes,
        "content_digest": value.content_digest,
        "filesystem_identity_ref": value.filesystem_identity_ref,
        "kind": value.kind,
        "metadata_digest": value.metadata_digest,
        "nested_target_measurement_ref": (
            value.nested_target_measurement_ref
        ),
        "nested_target_path_ref": value.nested_target_path_ref,
    }


def _requirement_ref_projection(
    *,
    staged_file_ref: str,
    runtime_file_ref: str,
    requirement_ref: str,
    target_requirement_ref: str,
    target_stage_requirement_ref: str,
    target_runtime_requirement_ref: str,
    target_shebang_requirement_ref: str,
    runtime_classification: str,
    target_measurement_ref: str | None,
    target_staged_file_ref: str | None,
    target_runtime_file_ref: str | None,
    target_runtime_classification: str | None,
    target_shebang_directive_ref: str | None,
    interpreter_token_ref: str | None,
    argument_tail_ref: str | None,
    disposition: str,
    nested_target_measurement_ref: str | None,
) -> dict[str, Any]:
    return {
        "argument_tail_ref": argument_tail_ref,
        "disposition": disposition,
        "interpreter_token_ref": interpreter_token_ref,
        "kind": "repository_executable_shebang_nested_target_requirement_ref",
        "nested_target_measurement_ref": nested_target_measurement_ref,
        "requirement_ref": requirement_ref,
        "resolution_depth": _FIXED_RESOLUTION_DEPTH,
        "resolution_scope": _FIXED_RESOLUTION_SCOPE,
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
        "target_shebang_requirement_ref": target_shebang_requirement_ref,
        "target_stage_requirement_ref": target_stage_requirement_ref,
        "target_staged_file_ref": target_staged_file_ref,
    }


def _requirement_projection(
    value: RepositoryExecutableShebangNestedTargetRequirement,
) -> dict[str, Any]:
    required = (
        value.staged_file_ref,
        value.runtime_file_ref,
        value.requirement_ref,
        value.target_requirement_ref,
        value.target_stage_requirement_ref,
        value.target_runtime_requirement_ref,
        value.target_shebang_requirement_ref,
        value.nested_target_requirement_ref,
    )
    optional = (
        value.target_measurement_ref,
        value.target_staged_file_ref,
        value.target_runtime_file_ref,
        value.target_shebang_directive_ref,
        value.interpreter_token_ref,
        value.argument_tail_ref,
        value.nested_target_measurement_ref,
    )
    if (
        type(value) is not _FIXED_REQUIREMENT_TYPE
        or type(value.kind) is not str
        or value.kind
        != _FIXED_REQUIREMENT_KIND
        or not all(_BUILTIN_IS_DIGEST(item) for item in required)
        or any(
            item is not None and not _BUILTIN_IS_DIGEST(item)
            for item in optional
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
    ):
        raise _InvalidNestedTargetResolution

    target_fields = (
        value.target_measurement_ref,
        value.target_staged_file_ref,
        value.target_runtime_file_ref,
        value.target_runtime_classification,
    )
    syntax_fields = (
        value.target_shebang_directive_ref,
        value.interpreter_token_ref,
    )
    if value.disposition == "source_native_not_applicable":
        if (
            value.runtime_classification not in {"elf", "mach_o"}
            or any(item is not None for item in target_fields)
            or any(item is not None for item in syntax_fields)
            or value.argument_tail_ref is not None
            or value.nested_target_measurement_ref is not None
        ):
            raise _InvalidNestedTargetResolution
    elif value.disposition == "target_native_not_applicable":
        if (
            value.runtime_classification != "posix_shebang"
            or value.target_runtime_classification not in {"elf", "mach_o"}
            or any(item is None for item in target_fields)
            or any(item is not None for item in syntax_fields)
            or value.argument_tail_ref is not None
            or value.nested_target_measurement_ref is not None
        ):
            raise _InvalidNestedTargetResolution
    elif (
        value.runtime_classification != "posix_shebang"
        or value.target_runtime_classification != "posix_shebang"
        or any(item is None for item in target_fields)
        or any(item is None for item in syntax_fields)
        or value.nested_target_measurement_ref is None
    ):
        raise _InvalidNestedTargetResolution

    reference = _BUILTIN_REQUIREMENT_REF_PROJECTION(
        staged_file_ref=value.staged_file_ref,
        runtime_file_ref=value.runtime_file_ref,
        requirement_ref=value.requirement_ref,
        target_requirement_ref=value.target_requirement_ref,
        target_stage_requirement_ref=value.target_stage_requirement_ref,
        target_runtime_requirement_ref=value.target_runtime_requirement_ref,
        target_shebang_requirement_ref=value.target_shebang_requirement_ref,
        runtime_classification=value.runtime_classification,
        target_measurement_ref=value.target_measurement_ref,
        target_staged_file_ref=value.target_staged_file_ref,
        target_runtime_file_ref=value.target_runtime_file_ref,
        target_runtime_classification=value.target_runtime_classification,
        target_shebang_directive_ref=value.target_shebang_directive_ref,
        interpreter_token_ref=value.interpreter_token_ref,
        argument_tail_ref=value.argument_tail_ref,
        disposition=value.disposition,
        nested_target_measurement_ref=value.nested_target_measurement_ref,
    )
    if value.nested_target_requirement_ref != _BUILTIN_CANONICAL_DIGEST(
        reference
    ):
        raise _InvalidNestedTargetResolution
    return {
        "argument_tail_ref": value.argument_tail_ref,
        "disposition": value.disposition,
        "interpreter_token_ref": value.interpreter_token_ref,
        "kind": value.kind,
        "nested_target_measurement_ref": value.nested_target_measurement_ref,
        "nested_target_requirement_ref": value.nested_target_requirement_ref,
        "requirement_ref": value.requirement_ref,
        "runtime_classification": value.runtime_classification,
        "runtime_file_ref": value.runtime_file_ref,
        "staged_file_ref": value.staged_file_ref,
        "target_measurement_ref": value.target_measurement_ref,
        "target_requirement_ref": value.target_requirement_ref,
        "target_runtime_classification": value.target_runtime_classification,
        "target_runtime_file_ref": value.target_runtime_file_ref,
        "target_runtime_requirement_ref": value.target_runtime_requirement_ref,
        "target_shebang_directive_ref": value.target_shebang_directive_ref,
        "target_shebang_requirement_ref": value.target_shebang_requirement_ref,
        "target_stage_requirement_ref": value.target_stage_requirement_ref,
        "target_staged_file_ref": value.target_staged_file_ref,
    }


def _binding_projection(
    value: RepositoryExecutableShebangNestedTargetBinding,
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
            )
        )
    ):
        raise _InvalidNestedTargetResolution
    return {
        "command_digest": value.command_digest,
        "command_id": value.command_id,
        "command_kind": value.command_kind,
        "kind": value.kind,
        "nested_target_requirement_ref": value.nested_target_requirement_ref,
        "requirement_ref": value.requirement_ref,
        "runtime_file_ref": value.runtime_file_ref,
        "staged_file_ref": value.staged_file_ref,
        "target_requirement_ref": value.target_requirement_ref,
        "target_runtime_requirement_ref": value.target_runtime_requirement_ref,
        "target_shebang_requirement_ref": value.target_shebang_requirement_ref,
        "target_stage_requirement_ref": value.target_stage_requirement_ref,
    }


def _receipt_projection(
    value: RepositoryExecutableShebangNestedTargetResolutionReceipt,
) -> dict[str, Any]:
    digest_fields = (
        value.target_shebang_requirements_receipt_digest,
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
        value.nested_target_path_context_digest,
    )
    if (
        type(value) is not _FIXED_RECEIPT_TYPE
        or type(value.kind) is not str
        or value.kind
        != _FIXED_RECEIPT_KIND
        or type(value.schema_version) is not int
        or value.schema_version
        != _FIXED_SCHEMA_VERSION
        or type(value.measurement_source) is not str
        or value.measurement_source != _FIXED_MEASUREMENT_SOURCE
        or type(value.resolution_scope) is not str
        or value.resolution_scope != _FIXED_RESOLUTION_SCOPE
        or type(value.resolution_depth) is not int
        or value.resolution_depth != _FIXED_RESOLUTION_DEPTH
        or type(value.maximum_resolution_depth) is not int
        or value.maximum_resolution_depth
        != _FIXED_MAXIMUM_RESOLUTION_DEPTH
        or type(value.cycle_scope) is not str
        or value.cycle_scope != _FIXED_CYCLE_SCOPE
        or not all(_BUILTIN_IS_DIGEST(item) for item in digest_fields)
        or type(value.measurements) is not tuple
        or not 0 <= len(value.measurements) <= _MAX_TARGET_PATHS
        or type(value.requirements) is not tuple
        or not 1 <= len(value.requirements) <= _MAX_REQUIREMENTS
        or type(value.bindings) is not tuple
        or not 1 <= len(value.bindings) <= _MAX_COMMANDS
        or type(value.requirement_count) is not int
        or value.requirement_count != len(value.requirements)
        or type(value.command_count) is not int
        or value.command_count != len(value.bindings)
        or type(value.nested_target_requirement_count) is not int
        or type(value.target_native_not_applicable_count) is not int
        or type(value.source_native_not_applicable_count) is not int
        or type(value.unique_nested_target_count) is not int
        or value.unique_nested_target_count != len(value.measurements)
        or type(value.total_measured_bytes) is not int
        or not 0 <= value.total_measured_bytes <= _MAX_TOTAL_TARGET_BYTES
    ):
        raise _InvalidNestedTargetResolution

    measurements = [
        _BUILTIN_MEASUREMENT_PROJECTION(item) for item in value.measurements
    ]
    requirements = [
        _BUILTIN_REQUIREMENT_PROJECTION(item) for item in value.requirements
    ]
    bindings = [
        _BUILTIN_BINDING_PROJECTION(item) for item in value.bindings
    ]

    measurement_refs: set[str] = set()
    path_refs: set[str] = set()
    identity_refs: set[str] = set()
    total_bytes = 0
    for item in value.measurements:
        if (
            item.nested_target_measurement_ref in measurement_refs
            or item.nested_target_path_ref in path_refs
            or item.filesystem_identity_ref in identity_refs
        ):
            raise _InvalidNestedTargetResolution
        measurement_refs.add(item.nested_target_measurement_ref)
        path_refs.add(item.nested_target_path_ref)
        identity_refs.add(item.filesystem_identity_ref)
        total_bytes += item.content_bytes

    by_upstream_ref: dict[
        str, RepositoryExecutableShebangNestedTargetRequirement
    ] = {}
    source_requirement_refs: set[str] = set()
    target_requirement_refs: set[str] = set()
    target_stage_requirement_refs: set[str] = set()
    target_runtime_requirement_refs: set[str] = set()
    terminal_refs: set[str] = set()
    used_measurements: list[str] = []
    unique_target_rows: dict[
        str, RepositoryExecutableShebangNestedTargetRequirement
    ] = {}
    disposition_counts = {item: 0 for item in _DISPOSITIONS}
    for item in value.requirements:
        if (
            item.target_shebang_requirement_ref in by_upstream_ref
            or item.requirement_ref in source_requirement_refs
            or item.target_requirement_ref in target_requirement_refs
            or item.target_stage_requirement_ref
            in target_stage_requirement_refs
            or item.target_runtime_requirement_ref
            in target_runtime_requirement_refs
            or item.nested_target_requirement_ref in terminal_refs
        ):
            raise _InvalidNestedTargetResolution
        by_upstream_ref[item.target_shebang_requirement_ref] = item
        source_requirement_refs.add(item.requirement_ref)
        target_requirement_refs.add(item.target_requirement_ref)
        target_stage_requirement_refs.add(item.target_stage_requirement_ref)
        target_runtime_requirement_refs.add(
            item.target_runtime_requirement_ref
        )
        terminal_refs.add(item.nested_target_requirement_ref)
        disposition_counts[item.disposition] += 1
        if item.disposition != "source_native_not_applicable":
            if item.target_runtime_file_ref is None:
                raise _InvalidNestedTargetResolution
            prior = unique_target_rows.get(item.target_runtime_file_ref)
            if prior is None:
                unique_target_rows[item.target_runtime_file_ref] = item
            elif (
                item.target_measurement_ref != prior.target_measurement_ref
                or item.target_staged_file_ref
                != prior.target_staged_file_ref
                or item.target_runtime_classification
                != prior.target_runtime_classification
                or item.target_shebang_directive_ref
                != prior.target_shebang_directive_ref
                or item.interpreter_token_ref != prior.interpreter_token_ref
                or item.argument_tail_ref != prior.argument_tail_ref
                or item.disposition != prior.disposition
                or item.nested_target_measurement_ref
                != prior.nested_target_measurement_ref
            ):
                raise _InvalidNestedTargetResolution
        if (
            item.nested_target_measurement_ref is not None
            and item.nested_target_measurement_ref not in used_measurements
        ):
            used_measurements.append(item.nested_target_measurement_ref)
    if (
        set(used_measurements) != measurement_refs
        or tuple(used_measurements)
        != tuple(
            item.nested_target_measurement_ref for item in value.measurements
        )
    ):
        raise _InvalidNestedTargetResolution

    command_ids: set[str] = set()
    bound_refs: set[str] = set()
    ordered_refs: list[str] = []
    prior_kind_index = -1
    for binding in value.bindings:
        requirement = by_upstream_ref.get(
            binding.target_shebang_requirement_ref
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
            or binding.target_runtime_requirement_ref
            != requirement.target_runtime_requirement_ref
            or binding.nested_target_requirement_ref
            != requirement.nested_target_requirement_ref
            or binding.command_id in command_ids
            or kind_index < prior_kind_index
        ):
            raise _InvalidNestedTargetResolution
        command_ids.add(binding.command_id)
        if binding.nested_target_requirement_ref not in bound_refs:
            ordered_refs.append(binding.nested_target_requirement_ref)
        bound_refs.add(binding.nested_target_requirement_ref)
        prior_kind_index = kind_index

    if (
        bound_refs != terminal_refs
        or tuple(ordered_refs)
        != tuple(
            item.nested_target_requirement_ref
            for item in value.requirements
        )
        or disposition_counts["direct_absolute_nested_target_measured"]
        != value.nested_target_requirement_count
        or disposition_counts["target_native_not_applicable"]
        != value.target_native_not_applicable_count
        or disposition_counts["source_native_not_applicable"]
        != value.source_native_not_applicable_count
        or sum(disposition_counts.values()) != value.requirement_count
        or total_bytes != value.total_measured_bytes
        or (
            value.unique_nested_target_count == 0
            and value.nested_target_requirement_count != 0
        )
        or (
            value.unique_nested_target_count > 0
            and value.nested_target_requirement_count == 0
        )
    ):
        raise _InvalidNestedTargetResolution

    return {
        "bindings": bindings,
        "command_count": value.command_count,
        "cycle_scope": value.cycle_scope,
        "kind": value.kind,
        "maximum_resolution_depth": value.maximum_resolution_depth,
        "measurement_source": value.measurement_source,
        "measurements": measurements,
        "nested_target_path_context_digest": (
            value.nested_target_path_context_digest
        ),
        "nested_target_requirement_count": (
            value.nested_target_requirement_count
        ),
        "registration_digest": value.registration_digest,
        "repository_ref": value.repository_ref,
        "requirement_count": value.requirement_count,
        "requirements": requirements,
        "resolution_context_digest": value.resolution_context_digest,
        "resolution_depth": value.resolution_depth,
        "resolution_scope": value.resolution_scope,
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
        "staging_receipt_digest": value.staging_receipt_digest,
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
        "target_staging_receipt_digest": (
            value.target_staging_receipt_digest
        ),
        "total_measured_bytes": value.total_measured_bytes,
        "unique_nested_target_count": value.unique_nested_target_count,
        "verification_commands_digest": (
            value.verification_commands_digest
        ),
    }


def _evidence_projection(
    value: RepositoryExecutableShebangNestedTargetResolutionReceipt,
) -> dict[str, Any]:
    canonical = _BUILTIN_RECEIPT_PROJECTION(value)
    measured = bool(value.nested_target_requirement_count)
    return {
        "action_receipt_issued": False,
        "active_target_stage_lease_verified_at_measurement": True,
        "ambient_path_search_performed": False,
        "atomic_snapshot_verified": False,
        "authority_granted": False,
        "authorization_verified": False,
        "billing_eligible": False,
        "bounded_resolution_depth_enforced": True,
        "capacity_eligible": False,
        "circuit_eligible": False,
        "command_count": value.command_count,
        "current_lease_activity_verified": False,
        "current_source_freshness_verified": False,
        "cycle_scope": value.cycle_scope,
        "dependency_environment_coverage_verified": False,
        "dispatch_enabled": False,
        "durable_control_plane_persistence_enabled": False,
        "dynamic_loader_identity_verified": False,
        "effect_class": 0,
        "effective_interpreter_resolution_verified": False,
        "effective_invocability_verified": False,
        "environment_coverage_verified": False,
        "exact_nested_target_path_lookup_performed": measured,
        "exact_nested_target_path_set_verified": True,
        "exact_target_requirements_correspondence_verified": True,
        "execution_enabled": False,
        "external_hardlink_alias_excluded": False,
        "external_mount_alias_excluded": False,
        "external_writable_descriptor_absence_verified": False,
        "filesystem_immutability_verified": False,
        "first_hop_target_path_reopen_performed": False,
        "future_execution_correspondence_verified": False,
        "generic_cycle_exclusion_verified": False,
        "harness_invocation_performed": False,
        "immediate_target_identity_reentry_excluded": True,
        "immediate_target_path_reentry_excluded": True,
        "interpreter_argument_semantics_verified": False,
        "interpreter_authenticity_verified": False,
        "interpreter_compatibility_verified": False,
        "interpreter_identity_verified": False,
        "interpreter_provenance_verified": False,
        "kind": (
            _FIXED_EVIDENCE_KIND
        ),
        "launcher_semantics_verified": False,
        "lease_cleanup_performed": False,
        "lease_mutated": False,
        "live_execution_eligible": False,
        "maximum_resolution_depth": value.maximum_resolution_depth,
        "measurement_source": value.measurement_source,
        "nested_target_path_context_digest": (
            value.nested_target_path_context_digest
        ),
        "nested_target_namespace_reopen_verified": measured,
        "nested_target_path_reopen_performed": measured,
        "nested_target_requirement_count": (
            value.nested_target_requirement_count
        ),
        "nested_target_runtime_classification_verified": False,
        "path_lookup_performed": measured,
        "proposal_lineage_extended": False,
        "broader_protected_root_exclusion_verified": False,
        "receipt_authenticity_verified": False,
        "receipt_digest": _BUILTIN_CANONICAL_DIGEST(canonical),
        "recursive_shebang_resolution_verified": False,
        "registration_digest": value.registration_digest,
        "repository_ref": value.repository_ref,
        "requirement_binding_correspondence_verified": True,
        "requirement_count": value.requirement_count,
        "resolution_context_digest": value.resolution_context_digest,
        "resolution_depth": value.resolution_depth,
        "resolution_scope": value.resolution_scope,
        "route_eligible": False,
        "same_uid_tamper_exclusion_verified": False,
        "schema_version": value.schema_version,
        "sequential_nested_target_measurement_complete": True,
        "source_chain_cycle_exclusion_verified": False,
        "source_native_not_applicable_count": (
            value.source_native_not_applicable_count
        ),
        "source_path_reentry_exclusion_verified": False,
        "source_staging_root_reentry_exclusion_verified": False,
        "staged_byte_correspondence_verified": True,
        "subprocess_invocation_performed": False,
        "target_native_not_applicable_count": (
            value.target_native_not_applicable_count
        ),
        "target_shebang_requirements_receipt_digest": (
            value.target_shebang_requirements_receipt_digest
        ),
        "target_staging_root_path_reopen_performed": False,
        "target_staging_root_ancestor_excluded": True,
        "toolchain_completeness_verified": False,
        "total_measured_bytes": value.total_measured_bytes,
        "two_pass_nested_target_measurement_verified": True,
        "unique_nested_target_count": value.unique_nested_target_count,
        "validation_mode": "read_only",
        "worktree_integration_enabled": False,
    }


# Freeze public output validation only after its entire graph exists.
_BUILTIN_MEASUREMENT_REF_PROJECTION = _measurement_ref_projection
_BUILTIN_MEASUREMENT_PROJECTION = _measurement_projection
_BUILTIN_REQUIREMENT_REF_PROJECTION = _requirement_ref_projection
_BUILTIN_REQUIREMENT_PROJECTION = _requirement_projection
_BUILTIN_BINDING_PROJECTION = _binding_projection
_BUILTIN_RECEIPT_PROJECTION = _receipt_projection


@dataclass(frozen=True, slots=True)
class _DerivedNestedRequirement:
    upstream: dict[str, Any] = field(repr=False)
    nested_target_path: str | None = field(repr=False)


@dataclass(frozen=True, slots=True)
class _MeasuredNestedTarget:
    path: str = field(repr=False)
    path_ref: str = field(repr=False)
    identity: tuple[int, int] = field(repr=False)
    metadata: tuple[int, ...] = field(repr=False)
    directory_chain: tuple[tuple[int, ...], ...] = field(repr=False)
    filesystem_identity_ref: str = field(repr=False)
    metadata_digest: str = field(repr=False)
    content_digest: str = field(repr=False)
    content_bytes: int


_UniqueNestedTargetConsumer = Callable[
    [int, os.stat_result, _MeasuredNestedTarget],
    None,
]


@dataclass(frozen=True, slots=True)
class _NestedTargetGuardContext:
    """Private stronger exclusions for a separate proof boundary.

    The public schema-v1 resolver never supplies this context and therefore
    retains its frozen semantics and evidence.  A later controller inspection
    may supply exact identity-domain sets and staging-root identities so the
    same no-follow measurement engine rejects them before reading leaf bytes.
    """

    protected_root_identities: frozenset[tuple[int, int]] = field(
        repr=False
    )
    known_source_identity_refs: frozenset[str] = field(repr=False)
    known_target_identity_refs: frozenset[str] = field(repr=False)


_FIXED_DERIVED_NESTED_REQUIREMENT_TYPE = _DerivedNestedRequirement
_FIXED_MEASURED_NESTED_TARGET_TYPE = _MeasuredNestedTarget
_FIXED_NESTED_TARGET_GUARD_CONTEXT_TYPE = _NestedTargetGuardContext


def _derived_nested_requirement_projection(
    value: _DerivedNestedRequirement,
) -> tuple[str, str | None]:
    """Return only exact built-in primitives for private-state comparison."""

    if (
        type(value) is not _FIXED_DERIVED_NESTED_REQUIREMENT_TYPE
        or type(value.upstream) is not dict
        or (
            value.nested_target_path is not None
            and type(value.nested_target_path) is not str
        )
    ):
        raise _InvalidNestedTargetResolution
    upstream_json = _BUILTIN_CANONICAL_JSON(value.upstream)
    if type(upstream_json) is not str:
        raise _InvalidNestedTargetResolution
    return upstream_json, value.nested_target_path


def _measured_nested_target_projection(
    value: _MeasuredNestedTarget,
) -> tuple[
    str,
    str,
    tuple[int, int],
    tuple[int, ...],
    tuple[tuple[int, ...], ...],
    str,
    str,
    str,
    int,
]:
    """Project every measured security field without private ``__eq__``."""

    if (
        type(value) is not _FIXED_MEASURED_NESTED_TARGET_TYPE
        or type(value.path) is not str
        or type(value.path_ref) is not str
        or type(value.identity) is not tuple
        or len(value.identity) != 2
        or any(type(item) is not int for item in value.identity)
        or type(value.metadata) is not tuple
        or len(value.metadata) != 9
        or any(type(item) is not int for item in value.metadata)
        or type(value.directory_chain) is not tuple
        or not value.directory_chain
        or any(
            type(signature) is not tuple
            or len(signature) != 5
            or any(type(item) is not int for item in signature)
            for signature in value.directory_chain
        )
        or type(value.filesystem_identity_ref) is not str
        or type(value.metadata_digest) is not str
        or type(value.content_digest) is not str
        or type(value.content_bytes) is not int
        or value.content_bytes < 0
    ):
        raise _InvalidNestedTargetResolution
    return (
        value.path,
        value.path_ref,
        value.identity,
        value.metadata,
        value.directory_chain,
        value.filesystem_identity_ref,
        value.metadata_digest,
        value.content_digest,
        value.content_bytes,
    )


_BUILTIN_DERIVED_NESTED_REQUIREMENT_PROJECTION = (
    _derived_nested_requirement_projection
)
_BUILTIN_MEASURED_NESTED_TARGET_PROJECTION = (
    _measured_nested_target_projection
)


def _nested_target_guard_context_projection(
    value: _NestedTargetGuardContext,
) -> tuple[
    tuple[tuple[int, int], ...],
    tuple[str, ...],
    tuple[str, ...],
]:
    """Validate and detach every stronger private exclusion input."""

    if (
        type(value) is not _FIXED_NESTED_TARGET_GUARD_CONTEXT_TYPE
        or type(value.protected_root_identities) is not frozenset
        or type(value.known_source_identity_refs) is not frozenset
        or type(value.known_target_identity_refs) is not frozenset
        or any(
            type(identity) is not tuple
            or len(identity) != 2
            or any(type(part) is not int or part < 0 for part in identity)
            for identity in value.protected_root_identities
        )
        or any(
            type(reference) is not str
            or _BUILTIN_DIGEST_FULLMATCH(reference) is None
            for reference in value.known_source_identity_refs
        )
        or any(
            type(reference) is not str
            or _BUILTIN_DIGEST_FULLMATCH(reference) is None
            for reference in value.known_target_identity_refs
        )
    ):
        raise _InvalidNestedTargetResolution
    return (
        tuple(sorted(value.protected_root_identities)),
        tuple(sorted(value.known_source_identity_refs)),
        tuple(sorted(value.known_target_identity_refs)),
    )


_BUILTIN_NESTED_TARGET_GUARD_CONTEXT_PROJECTION = (
    _nested_target_guard_context_projection
)


def _canonical_nested_target_path_from_token(token: bytes) -> str:
    try:
        spelling = token.decode("ascii")
    except UnicodeDecodeError:
        raise _InvalidNestedTargetResolution from None
    if (
        not spelling.startswith("/")
        or spelling == "/"
        or spelling.endswith("/")
        or "//" in spelling
        or len(token) > _MAX_TARGET_PATH_BYTES
    ):
        raise _InvalidNestedTargetResolution
    components = spelling[1:].split("/")
    if (
        not 1 <= len(components) <= _MAX_TARGET_PATH_COMPONENTS
        or any(
            not component
            or component in {".", ".."}
            or len(component.encode("ascii"))
            > _MAX_TARGET_PATH_COMPONENT_BYTES
            for component in components
        )
    ):
        raise _InvalidNestedTargetResolution
    for component in components:
        _BUILTIN_VALIDATE_COMPONENT(component)
    return spelling


def _direct_target_path_ref(path: str) -> str:
    """Reproduce the first-hop path-reference domain for re-entry checks."""

    if type(path) is not str:
        raise _InvalidNestedTargetResolution
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "kind": "repository_executable_shebang_target_path_ref",
            "resolution_scope": _DIRECT_TARGET_RESOLUTION_SCOPE,
            "schema_version": 1,
            "target_path_ascii": path,
        }
    )


def _nested_target_path_context_digest(paths: tuple[str, ...]) -> str:
    if type(paths) is not tuple or any(type(path) is not str for path in paths):
        raise _InvalidNestedTargetResolution
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "cycle_scope": _FIXED_CYCLE_SCOPE,
            "kind": (
                "repository_executable_shebang_nested_target_path_context"
            ),
            "maximum_resolution_depth": _FIXED_MAXIMUM_RESOLUTION_DEPTH,
            "ordered_nested_target_path_refs": [
                _BUILTIN_DIRECT_TARGET_PATH_REF(path) for path in paths
            ],
            "resolution_depth": _FIXED_RESOLUTION_DEPTH,
            "resolution_scope": _FIXED_RESOLUTION_SCOPE,
            "schema_version": _FIXED_SCHEMA_VERSION,
        }
    )


def _validate_expected_nested_target_paths(
    derived: tuple[_DerivedNestedRequirement, ...],
    expected_nested_target_paths: Any,
) -> tuple[str, ...]:
    if type(expected_nested_target_paths) is not tuple:
        raise _InvalidNestedTargetResolution
    used: list[str] = []
    spellings: set[str] = set()
    for item in derived:
        _BUILTIN_DERIVED_NESTED_REQUIREMENT_PROJECTION(item)
        path = item.nested_target_path
        if path is None:
            continue
        if path not in spellings:
            used.append(path)
            spellings.add(path)
    if len(expected_nested_target_paths) > _MAX_TARGET_PATHS:
        raise _InvalidNestedTargetResolution
    validated: list[str] = []
    total_bytes = 0
    for value in expected_nested_target_paths:
        if type(value) is not _BUILTIN_CONCRETE_PATH:
            raise _InvalidNestedTargetResolution
        try:
            encoded = _BUILTIN_FSPATH(value).encode("ascii")
        except (AttributeError, TypeError, UnicodeEncodeError):
            raise _InvalidNestedTargetResolution from None
        canonical = _BUILTIN_CANONICAL_NESTED_TARGET_PATH(encoded)
        if canonical != _BUILTIN_FSPATH(value):
            raise _InvalidNestedTargetResolution
        total_bytes += len(encoded)
        if total_bytes > _MAX_TOTAL_TARGET_PATH_BYTES:
            raise _InvalidNestedTargetResolution
        validated.append(canonical)
    paths = tuple(validated)
    if paths != tuple(used):
        raise _InvalidNestedTargetResolution
    return paths


def _target_file_syntax(
    runtime_file: dict[str, Any],
    staged_file: dict[str, Any],
    retained: Any,
    *,
    target_staging_context_digest: str,
) -> tuple[
    str,
    str | None,
    str | None,
    int,
    str | None,
    str | None,
    int,
    bytes | None,
]:
    header = _BUILTIN_TARGET_DESCRIPTOR_REMEASUREMENT(
        retained,
        staged_file,
        target_staging_context_digest=target_staging_context_digest,
    )
    classification, directive_ref, directive = (
        _BUILTIN_TARGET_CLASSIFY_HEADER(
            staged_file["target_staged_file_ref"],
            header,
        )
    )
    if (
        runtime_file["target_staged_file_ref"]
        != staged_file["target_staged_file_ref"]
        or runtime_file["staged_filesystem_identity_ref"]
        != staged_file["staged_filesystem_identity_ref"]
        or runtime_file["content_digest"] != staged_file["content_digest"]
        or runtime_file["content_bytes"] != staged_file["content_bytes"]
        or runtime_file["classification"] != classification
        or runtime_file["shebang_directive_ref"] != directive_ref
    ):
        raise _InvalidNestedTargetResolution
    token_ref: str | None = None
    token_bytes = 0
    separator_kind: str | None = None
    tail_ref: str | None = None
    tail_bytes = 0
    token: bytes | None = None
    if classification == "posix_shebang":
        if directive_ref is None or directive is None:
            raise _InvalidNestedTargetResolution
        token, separator_kind, tail = _BUILTIN_TARGET_SPLIT_DIRECTIVE(
            directive
        )
        token_ref = _BUILTIN_TARGET_INTERPRETER_TOKEN_REF(
            target_runtime_file_ref=runtime_file["target_runtime_file_ref"],
            target_shebang_directive_ref=directive_ref,
            token=token,
        )
        token_bytes = len(token)
        if tail is not None:
            if separator_kind is None:
                raise _InvalidNestedTargetResolution
            tail_ref = _BUILTIN_TARGET_ARGUMENT_TAIL_REF(
                target_runtime_file_ref=runtime_file[
                    "target_runtime_file_ref"
                ],
                target_shebang_directive_ref=directive_ref,
                interpreter_token_ref=token_ref,
                separator_kind=separator_kind,
                tail=tail,
            )
            tail_bytes = len(tail)
    return (
        classification,
        directive_ref,
        token_ref,
        token_bytes,
        separator_kind,
        tail_ref,
        tail_bytes,
        token,
    )


def _derive_nested_requirements(
    requirements_canonical: dict[str, Any],
    runtime_canonical: dict[str, Any],
    staging_canonical: dict[str, Any],
    retained_files: tuple[Any, ...],
) -> tuple[_DerivedNestedRequirement, ...]:
    runtime_files = tuple(dict(item) for item in runtime_canonical["files"])
    staged_files = tuple(
        dict(item) for item in staging_canonical["staged_files"]
    )
    if not (
        len(runtime_files) == len(staged_files) == len(retained_files)
    ):
        raise _InvalidNestedTargetResolution
    target_staging_context_digest = staging_canonical[
        "target_staging_context_digest"
    ]
    syntax_by_runtime_ref: dict[str, tuple[Any, ...]] = {}
    for runtime_file, staged_file, retained in zip(
        runtime_files,
        staged_files,
        retained_files,
        strict=True,
    ):
        syntax = _BUILTIN_TARGET_FILE_SYNTAX(
            runtime_file,
            staged_file,
            retained,
            target_staging_context_digest=target_staging_context_digest,
        )
        runtime_ref = runtime_file["target_runtime_file_ref"]
        if runtime_ref in syntax_by_runtime_ref:
            raise _InvalidNestedTargetResolution
        syntax_by_runtime_ref[runtime_ref] = syntax

    known_first_hop_path_refs = {
        item["target_path_ref"] for item in staged_files
    }
    actual_requirements = requirements_canonical["requirements"]
    derived: list[_DerivedNestedRequirement] = []
    for value in actual_requirements:
        if type(value) is not dict:
            raise _InvalidNestedTargetResolution
        canonical = dict(value)
        target_runtime_ref = canonical["target_runtime_file_ref"]
        path: str | None = None
        if canonical["disposition"] == "native_not_applicable":
            if target_runtime_ref is not None:
                raise _InvalidNestedTargetResolution
        else:
            if target_runtime_ref is None:
                raise _InvalidNestedTargetResolution
            syntax = syntax_by_runtime_ref.get(target_runtime_ref)
            if syntax is None:
                raise _InvalidNestedTargetResolution
            (
                classification,
                directive_ref,
                token_ref,
                token_bytes,
                separator_kind,
                tail_ref,
                tail_bytes,
                token,
            ) = syntax
            if (
                canonical["target_runtime_classification"] != classification
                or canonical["target_shebang_directive_ref"]
                != directive_ref
                or canonical["interpreter_token_ref"] != token_ref
                or canonical["interpreter_token_bytes"] != token_bytes
                or canonical["argument_separator_kind"] != separator_kind
                or canonical["argument_tail_ref"] != tail_ref
                or canonical["argument_tail_bytes"] != tail_bytes
            ):
                raise _InvalidNestedTargetResolution
            if classification in {"elf", "mach_o"}:
                if canonical["disposition"] != "native_binary_no_shebang":
                    raise _InvalidNestedTargetResolution
            elif classification == "posix_shebang":
                if (
                    canonical["disposition"]
                    != "absolute_interpreter_token"
                    or token is None
                ):
                    raise _InvalidNestedTargetResolution
                path = _BUILTIN_CANONICAL_NESTED_TARGET_PATH(token)
                if _BUILTIN_DIRECT_TARGET_PATH_REF(
                    path
                ) in known_first_hop_path_refs:
                    raise _InvalidNestedTargetResolution
            else:
                # Nonabsolute, unsupported, and unknown target requirements
                # cannot become partial success at this boundary.
                raise _InvalidNestedTargetResolution
        derived.append(
            _FIXED_DERIVED_NESTED_REQUIREMENT_TYPE(
                upstream=canonical,
                nested_target_path=path,
            )
        )
    return tuple(derived)


def _validated_chain_snapshot(
    expected_target_requirements: (
        RepositoryExecutableShebangTargetRequirementsReceipt
    ),
    expected_target_runtime: (
        RepositoryExecutableShebangTargetRuntimeManifestReceipt
    ),
    expected_target_staging: RepositoryExecutableShebangTargetStagingReceipt,
    lease: RepositoryExecutableShebangTargetStageLease,
) -> tuple[
    tuple[_DerivedNestedRequirement, ...],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    tuple[Any, ...],
    tuple[int, int] | None,
    frozenset[str],
]:
    if (
        type(expected_target_requirements)
        is not _FIXED_TARGET_REQUIREMENTS_RECEIPT_TYPE
        or type(expected_target_runtime)
        is not _FIXED_TARGET_RUNTIME_RECEIPT_TYPE
        or type(expected_target_staging)
        is not _FIXED_TARGET_STAGING_RECEIPT_TYPE
        or type(lease) is not _FIXED_TARGET_STAGE_LEASE_TYPE
    ):
        raise _InvalidNestedTargetResolution
    staging_canonical = _BUILTIN_TARGET_STAGING_PROJECTION(
        expected_target_staging
    )
    runtime_canonical = _BUILTIN_TARGET_RUNTIME_PROJECTION(
        expected_target_runtime
    )
    requirements_canonical = _BUILTIN_TARGET_REQUIREMENTS_PROJECTION(
        expected_target_requirements
    )
    staging_digest = _BUILTIN_CANONICAL_DIGEST(staging_canonical)
    runtime_digest = _BUILTIN_CANONICAL_DIGEST(runtime_canonical)
    requirements_digest = _BUILTIN_CANONICAL_DIGEST(requirements_canonical)
    if (
        runtime_canonical["target_staging_receipt_digest"] != staging_digest
        or requirements_canonical["target_staging_receipt_digest"]
        != staging_digest
        or requirements_canonical[
            "target_runtime_manifest_receipt_digest"
        ]
        != runtime_digest
    ):
        raise _InvalidNestedTargetResolution
    lineage_fields = (
        "shebang_requirements_receipt_digest",
        "runtime_manifest_receipt_digest",
        "staging_receipt_digest",
        "registration_digest",
        "repository_ref",
        "verification_commands_digest",
        "resolution_context_digest",
        "source_staging_context_digest",
        "target_path_context_digest",
        "target_staging_context_digest",
    )
    if any(
        requirements_canonical[field] != runtime_canonical[field]
        or requirements_canonical[field] != staging_canonical[field]
        for field in lineage_fields
    ) or not (
        requirements_canonical["target_resolution_receipt_digest"]
        == runtime_canonical["target_resolution_receipt_digest"]
        == staging_canonical["expected_target_resolution_receipt_digest"]
        == staging_canonical["action_target_resolution_receipt_digest"]
        == staging_canonical["post_stage_target_resolution_receipt_digest"]
    ):
        raise _InvalidNestedTargetResolution

    active_canonical, retained_files = (
        _BUILTIN_ACTIVE_TARGET_STAGE_SNAPSHOT(
            expected_target_staging,
            lease,
        )
    )
    if active_canonical != staging_canonical:
        raise _InvalidNestedTargetResolution
    fresh_runtime = _BUILTIN_INSPECT_TARGET_RUNTIME(
        expected_target_staging,
        lease=lease,
    )
    if _BUILTIN_TARGET_RUNTIME_PROJECTION(
        fresh_runtime
    ) != runtime_canonical:
        raise _InvalidNestedTargetResolution
    fresh_requirements = _BUILTIN_INSPECT_TARGET_REQUIREMENTS(
        expected_target_runtime,
        expected_target_staging=expected_target_staging,
        lease=lease,
    )
    if _BUILTIN_TARGET_REQUIREMENTS_PROJECTION(
        fresh_requirements
    ) != requirements_canonical:
        raise _InvalidNestedTargetResolution

    derived = _BUILTIN_DERIVE_NESTED_REQUIREMENTS(
        requirements_canonical,
        runtime_canonical,
        staging_canonical,
        retained_files,
    )
    protected_root_identity: tuple[int, int] | None = None
    if staging_canonical["staging_root_used"]:
        metadata = lease._root_metadata
        if (
            type(metadata) is not tuple
            or len(metadata) != 9
            or any(type(item) is not int for item in metadata)
        ):
            raise _InvalidNestedTargetResolution
        protected_root_identity = (metadata[0], metadata[1])
    elif lease._root_metadata is not None:
        raise _InvalidNestedTargetResolution
    known_first_hop_identities = frozenset(
        item["source_filesystem_identity_ref"]
        for item in staging_canonical["staged_files"]
    )
    if len(known_first_hop_identities) != len(
        staging_canonical["staged_files"]
    ):
        raise _InvalidNestedTargetResolution
    return (
        derived,
        requirements_canonical,
        runtime_canonical,
        staging_canonical,
        retained_files,
        protected_root_identity,
        known_first_hop_identities,
    )


def _require_supported_platform() -> None:
    if not _FIXED_PLATFORM_SUPPORTED:
        raise _InvalidNestedTargetResolution


def _metadata_signature(metadata: os.stat_result) -> tuple[int, ...]:
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


def _directory_signature(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


def _validate_component(component: str) -> None:
    try:
        encoded = component.encode("ascii")
    except UnicodeEncodeError:
        raise _InvalidNestedTargetResolution from None
    if (
        not component
        or component in {".", ".."}
        or "/" in component
        or "\x00" in component
        or len(encoded) > _MAX_TARGET_PATH_COMPONENT_BYTES
        or _BUILTIN_UNICODE_NORMALIZE("NFC", component) != component
        or any(
            _BUILTIN_UNICODE_CATEGORY(character).startswith("C")
            for character in component
        )
    ):
        raise _InvalidNestedTargetResolution


def _entry_spelling_state(directory_descriptor: int, name: str) -> str:
    _BUILTIN_VALIDATE_COMPONENT(name)
    target = _BUILTIN_UNICODE_NORMALIZE("NFC", name).casefold()
    exact_matches = 0
    folded_matches = 0
    count = 0
    encoded_bytes = 0
    try:
        with _BUILTIN_SCANDIR(directory_descriptor) as entries:
            for entry in entries:
                count += 1
                if count > _MAX_DIRECTORY_ENTRIES:
                    raise _InvalidNestedTargetResolution
                try:
                    encoded_bytes += len(entry.name.encode("utf-8"))
                except UnicodeError:
                    raise _InvalidNestedTargetResolution from None
                if encoded_bytes > _MAX_DIRECTORY_ENTRY_BYTES:
                    raise _InvalidNestedTargetResolution
                folded = _BUILTIN_UNICODE_NORMALIZE(
                    "NFC",
                    entry.name,
                ).casefold()
                if folded == target:
                    folded_matches += 1
                    if entry.name == name:
                        exact_matches += 1
    except OSError:
        raise _InvalidNestedTargetResolution from None
    if exact_matches == 1 and folded_matches == 1:
        return "exact"
    if folded_matches == 0:
        return "absent"
    raise _InvalidNestedTargetResolution


def _directory_open_flags() -> int:
    if not _FIXED_PLATFORM_SUPPORTED:
        raise _InvalidNestedTargetResolution
    return (
        _FIXED_O_RDONLY
        | _FIXED_O_DIRECTORY
        | _FIXED_O_NOFOLLOW
        | _FIXED_O_CLOEXEC
    )


def _root_identity_matches(
    metadata: os.stat_result,
    protected_root_identity: tuple[int, int] | None,
) -> bool:
    return (
        protected_root_identity is not None
        and (metadata.st_dev, metadata.st_ino) == protected_root_identity
    )


def _guard_root_identity_matches(
    metadata: os.stat_result,
    guard_context: _NestedTargetGuardContext | None,
) -> bool:
    if guard_context is None:
        return False
    _BUILTIN_NESTED_TARGET_GUARD_CONTEXT_PROJECTION(guard_context)
    return (
        metadata.st_dev,
        metadata.st_ino,
    ) in guard_context.protected_root_identities


def _identity_ref_in_domain(
    metadata: os.stat_result,
    *,
    kind: str,
) -> str:
    if type(kind) is not str:
        raise _InvalidNestedTargetResolution
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "kind": kind,
            "schema_version": 1,
        }
    )


def _guard_leaf_identity_is_excluded(
    metadata: os.stat_result,
    guard_context: _NestedTargetGuardContext | None,
) -> bool:
    if guard_context is None:
        return False
    _BUILTIN_NESTED_TARGET_GUARD_CONTEXT_PROJECTION(guard_context)
    source_references = (
        _BUILTIN_IDENTITY_REF_IN_DOMAIN(
            metadata,
            kind="repository_executable_file_identity",
        ),
        _BUILTIN_IDENTITY_REF_IN_DOMAIN(
            metadata,
            kind="repository_executable_staged_file_identity",
        ),
    )
    target_references = (
        _BUILTIN_IDENTITY_REF_IN_DOMAIN(
            metadata,
            kind="repository_executable_shebang_target_file_identity",
        ),
        _BUILTIN_IDENTITY_REF_IN_DOMAIN(
            metadata,
            kind=(
                "repository_executable_shebang_target_"
                "staged_file_identity"
            ),
        ),
        _BUILTIN_IDENTITY_REF_IN_DOMAIN(
            metadata,
            kind=(
                "repository_executable_native_loader_target_file_identity"
            ),
        ),
        _BUILTIN_IDENTITY_REF_IN_DOMAIN(
            metadata,
            kind=(
                "repository_executable_native_loader_target_"
                "staged_file_identity"
            ),
        ),
    )
    return any(
        reference in guard_context.known_source_identity_refs
        for reference in source_references
    ) or any(
        reference in guard_context.known_target_identity_refs
        for reference in target_references
    )


def _open_directory_component(
    parent_descriptor: int,
    component: str,
    *,
    protected_root_identity: tuple[int, int] | None,
    guard_context: _NestedTargetGuardContext | None = None,
) -> tuple[int, tuple[int, ...]]:
    if _BUILTIN_ENTRY_SPELLING_STATE(
        parent_descriptor,
        component,
    ) != "exact":
        raise _InvalidNestedTargetResolution
    try:
        descriptor = _BUILTIN_OPEN(
            component,
            _BUILTIN_DIRECTORY_OPEN_FLAGS(),
            dir_fd=parent_descriptor,
        )
    except OSError:
        raise _InvalidNestedTargetResolution from None
    try:
        metadata = _BUILTIN_FSTAT(descriptor)
        namespace_metadata = _BUILTIN_STAT(
            component,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        signature = _BUILTIN_DIRECTORY_SIGNATURE(metadata)
        if (
            not _BUILTIN_S_ISDIR(metadata.st_mode)
            or _BUILTIN_S_ISLNK(namespace_metadata.st_mode)
            or _BUILTIN_DIRECTORY_SIGNATURE(namespace_metadata) != signature
            or _BUILTIN_ROOT_IDENTITY_MATCHES(
                metadata,
                protected_root_identity,
            )
            or _BUILTIN_GUARD_ROOT_IDENTITY_MATCHES(
                metadata,
                guard_context,
            )
        ):
            raise _InvalidNestedTargetResolution
        return descriptor, signature
    except BaseException:
        try:
            _BUILTIN_CLOSE(descriptor)
        except OSError:
            pass
        raise


def _open_target_at(
    directory_descriptor: int,
    name: str,
) -> tuple[int, os.stat_result]:
    if _BUILTIN_ENTRY_SPELLING_STATE(
        directory_descriptor,
        name,
    ) != "exact":
        raise _InvalidNestedTargetResolution
    if not _FIXED_PLATFORM_SUPPORTED:
        raise _InvalidNestedTargetResolution
    flags = (
        _FIXED_O_RDONLY
        | _FIXED_O_CLOEXEC
        | _FIXED_O_NOFOLLOW
        | _FIXED_O_NONBLOCK
    )
    try:
        descriptor = _BUILTIN_OPEN(
            name,
            flags,
            dir_fd=directory_descriptor,
        )
    except OSError:
        raise _InvalidNestedTargetResolution from None
    try:
        metadata = _BUILTIN_FSTAT(descriptor)
        namespace_metadata = _BUILTIN_STAT(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if (
            not _BUILTIN_S_ISREG(metadata.st_mode)
            or metadata.st_mode & 0o111 == 0
            or metadata.st_nlink <= 0
            or _BUILTIN_S_ISLNK(namespace_metadata.st_mode)
            or _BUILTIN_METADATA_SIGNATURE(namespace_metadata)
            != _BUILTIN_METADATA_SIGNATURE(metadata)
        ):
            raise _InvalidNestedTargetResolution
        return descriptor, metadata
    except BaseException:
        try:
            _BUILTIN_CLOSE(descriptor)
        except OSError:
            pass
        raise


def _file_is_sparse(metadata: os.stat_result) -> bool:
    blocks = getattr(metadata, "st_blocks", None)
    if type(blocks) is not int or blocks < 0:
        raise _InvalidNestedTargetResolution
    return metadata.st_size > 0 and blocks * 512 < metadata.st_size


def _target_identity_ref(metadata: os.stat_result) -> str:
    """Use the first-hop identity domain so known-inode re-entry compares."""

    return _BUILTIN_CANONICAL_DIGEST(
        {
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "kind": "repository_executable_shebang_target_file_identity",
            "schema_version": 1,
        }
    )


def _target_metadata_digest(
    metadata: os.stat_result,
    *,
    identity_ref: str,
) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "change_time_ns": metadata.st_ctime_ns,
            "filesystem_identity_ref": identity_ref,
            "group_id": metadata.st_gid,
            "kind": "repository_executable_shebang_target_file_metadata",
            "link_count": metadata.st_nlink,
            "mode": metadata.st_mode,
            "modified_time_ns": metadata.st_mtime_ns,
            "owner_id": metadata.st_uid,
            "schema_version": 1,
            "size_bytes": metadata.st_size,
        }
    )


def _consume_measured_nested_target(
    descriptor: int,
    metadata: os.stat_result,
    measured: _MeasuredNestedTarget,
    consumer: _UniqueNestedTargetConsumer,
) -> None:
    """Hand one still-pinned guarded target to a private action sink."""

    _BUILTIN_MEASURED_NESTED_TARGET_PROJECTION(measured)
    try:
        before_metadata = _BUILTIN_FSTAT(descriptor)
        before_status_flags = _BUILTIN_FCNTL(descriptor, _BUILTIN_F_GETFL)
        before_descriptor_flags = _BUILTIN_FCNTL(
            descriptor,
            _BUILTIN_F_GETFD,
        )
        before_offset = _BUILTIN_LSEEK(descriptor, 0, os.SEEK_CUR)
        before_inheritable = _BUILTIN_GET_INHERITABLE(descriptor)
    except (OSError, ValueError):
        raise _InvalidNestedTargetResolution from None
    if (
        _BUILTIN_METADATA_SIGNATURE(before_metadata) != measured.metadata
        or _BUILTIN_METADATA_SIGNATURE(metadata) != measured.metadata
        or (before_metadata.st_dev, before_metadata.st_ino)
        != measured.identity
        or before_status_flags & _FIXED_O_ACCMODE != _FIXED_O_RDONLY
        or before_offset != measured.content_bytes
        or before_inheritable
    ):
        raise _InvalidNestedTargetResolution
    try:
        consumer(descriptor, metadata, measured)
    except Exception:
        raise _InvalidNestedTargetResolution from None
    try:
        after_metadata = _BUILTIN_FSTAT(descriptor)
        after_status_flags = _BUILTIN_FCNTL(descriptor, _BUILTIN_F_GETFL)
        after_descriptor_flags = _BUILTIN_FCNTL(
            descriptor,
            _BUILTIN_F_GETFD,
        )
        after_offset = _BUILTIN_LSEEK(descriptor, 0, os.SEEK_CUR)
        after_inheritable = _BUILTIN_GET_INHERITABLE(descriptor)
    except (OSError, ValueError):
        raise _InvalidNestedTargetResolution from None
    if (
        _BUILTIN_METADATA_SIGNATURE(after_metadata) != measured.metadata
        or (after_metadata.st_dev, after_metadata.st_ino) != measured.identity
        or after_status_flags != before_status_flags
        or after_descriptor_flags != before_descriptor_flags
        or after_offset != before_offset
        or after_inheritable != before_inheritable
    ):
        raise _InvalidNestedTargetResolution


_BUILTIN_CONSUME_MEASURED_NESTED_TARGET = _consume_measured_nested_target


def _measure_nested_target_path(
    path: str,
    *,
    total_measured_bytes: int,
    protected_root_identity: tuple[int, int] | None,
    known_first_hop_identities: frozenset[str],
    guard_context: _NestedTargetGuardContext | None = None,
    unique_nested_target_consumer: (
        _UniqueNestedTargetConsumer | None
    ) = None,
) -> _MeasuredNestedTarget:
    if type(path) is not str:
        raise _InvalidNestedTargetResolution
    components = tuple(path[1:].split("/"))
    directory_descriptor: int | None = None
    file_descriptor: int | None = None
    directory_chain: list[tuple[int, ...]] = []
    try:
        try:
            directory_descriptor = _BUILTIN_OPEN(
                _FIXED_POSIX_ROOT,
                _BUILTIN_DIRECTORY_OPEN_FLAGS(),
            )
            root_metadata = _BUILTIN_FSTAT(directory_descriptor)
        except OSError:
            raise _InvalidNestedTargetResolution from None
        if (
            not _BUILTIN_S_ISDIR(root_metadata.st_mode)
            or _BUILTIN_ROOT_IDENTITY_MATCHES(
                root_metadata,
                protected_root_identity,
            )
            or _BUILTIN_GUARD_ROOT_IDENTITY_MATCHES(
                root_metadata,
                guard_context,
            )
        ):
            raise _InvalidNestedTargetResolution
        directory_chain.append(_BUILTIN_DIRECTORY_SIGNATURE(root_metadata))
        for component in components[:-1]:
            child, signature = _BUILTIN_OPEN_DIRECTORY_COMPONENT(
                directory_descriptor,
                component,
                protected_root_identity=protected_root_identity,
                guard_context=guard_context,
            )
            try:
                _BUILTIN_CLOSE(directory_descriptor)
            except BaseException:
                try:
                    _BUILTIN_CLOSE(child)
                except OSError:
                    pass
                try:
                    _BUILTIN_CLOSE(directory_descriptor)
                except OSError:
                    pass
                raise
            directory_descriptor = child
            directory_chain.append(signature)
        parent_signature = _BUILTIN_DIRECTORY_SIGNATURE(
            _BUILTIN_FSTAT(directory_descriptor)
        )
        file_descriptor, before = _BUILTIN_OPEN_TARGET_AT(
            directory_descriptor,
            components[-1],
        )
        try:
            file_flags = _BUILTIN_FCNTL(file_descriptor, _BUILTIN_F_GETFL)
            file_inheritable = _BUILTIN_GET_INHERITABLE(file_descriptor)
        except (OSError, ValueError):
            raise _InvalidNestedTargetResolution from None
        if (
            before.st_size < 0
            or before.st_size > _MAX_TARGET_BYTES
            or total_measured_bytes + before.st_size
            > _MAX_TOTAL_TARGET_BYTES
            or _BUILTIN_FILE_IS_SPARSE(before)
            or file_flags & _FIXED_O_ACCMODE != _FIXED_O_RDONLY
            or file_inheritable
        ):
            raise _InvalidNestedTargetResolution
        identity_ref = _BUILTIN_TARGET_IDENTITY_REF(before)
        if (
            identity_ref in known_first_hop_identities
            or _BUILTIN_GUARD_LEAF_IDENTITY_IS_EXCLUDED(
                before,
                guard_context,
            )
        ):
            raise _InvalidNestedTargetResolution

        digest = _BUILTIN_SHA256()
        remaining = before.st_size
        while remaining:
            try:
                chunk = _BUILTIN_READ(
                    file_descriptor,
                    min(_READ_CHUNK_BYTES, remaining),
                )
            except (BlockingIOError, InterruptedError, OSError):
                raise _InvalidNestedTargetResolution from None
            if not chunk or len(chunk) > remaining:
                raise _InvalidNestedTargetResolution
            digest.update(chunk)
            remaining -= len(chunk)
        try:
            boundary = _BUILTIN_READ(file_descriptor, 1)
            after = _BUILTIN_FSTAT(file_descriptor)
            after_flags = _BUILTIN_FCNTL(file_descriptor, _BUILTIN_F_GETFL)
            after_inheritable = _BUILTIN_GET_INHERITABLE(file_descriptor)
        except (OSError, ValueError):
            raise _InvalidNestedTargetResolution from None
        if (
            boundary != b""
            or _BUILTIN_METADATA_SIGNATURE(after)
            != _BUILTIN_METADATA_SIGNATURE(before)
            or after_flags != file_flags
            or after_inheritable != file_inheritable
            or _BUILTIN_DIRECTORY_SIGNATURE(
                _BUILTIN_FSTAT(directory_descriptor)
            )
            != parent_signature
            or _BUILTIN_TARGET_IDENTITY_REF(after)
            in known_first_hop_identities
            or _BUILTIN_GUARD_LEAF_IDENTITY_IS_EXCLUDED(
                after,
                guard_context,
            )
        ):
            raise _InvalidNestedTargetResolution

        measured = _FIXED_MEASURED_NESTED_TARGET_TYPE(
            path=path,
            path_ref=_BUILTIN_DIRECT_TARGET_PATH_REF(path),
            identity=(before.st_dev, before.st_ino),
            metadata=_BUILTIN_METADATA_SIGNATURE(before),
            directory_chain=tuple(directory_chain),
            filesystem_identity_ref=identity_ref,
            metadata_digest=_BUILTIN_TARGET_METADATA_DIGEST(
                before,
                identity_ref=identity_ref,
            ),
            content_digest=_DIGEST_PREFIX + digest.hexdigest(),
            content_bytes=before.st_size,
        )
        if unique_nested_target_consumer is not None:
            _BUILTIN_CONSUME_MEASURED_NESTED_TARGET(
                file_descriptor,
                before,
                measured,
                unique_nested_target_consumer,
            )

        reopened_descriptor: int | None = None
        try:
            reopened_descriptor, reopened = _BUILTIN_OPEN_TARGET_AT(
                directory_descriptor,
                components[-1],
            )
            if (
                _BUILTIN_METADATA_SIGNATURE(reopened)
                != _BUILTIN_METADATA_SIGNATURE(before)
                or _BUILTIN_TARGET_IDENTITY_REF(reopened)
                in known_first_hop_identities
                or _BUILTIN_GUARD_LEAF_IDENTITY_IS_EXCLUDED(
                    reopened,
                    guard_context,
                )
            ):
                raise _InvalidNestedTargetResolution
        finally:
            if reopened_descriptor is not None:
                try:
                    _BUILTIN_CLOSE(reopened_descriptor)
                except OSError:
                    pass
        try:
            namespace_after = _BUILTIN_STAT(
                components[-1],
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            parent_after = _BUILTIN_DIRECTORY_SIGNATURE(
                _BUILTIN_FSTAT(directory_descriptor)
            )
        except OSError:
            raise _InvalidNestedTargetResolution from None
        if (
            _BUILTIN_METADATA_SIGNATURE(namespace_after)
            != _BUILTIN_METADATA_SIGNATURE(before)
            or parent_after != parent_signature
            or _BUILTIN_GUARD_LEAF_IDENTITY_IS_EXCLUDED(
                namespace_after,
                guard_context,
            )
        ):
            raise _InvalidNestedTargetResolution
        return measured
    finally:
        if file_descriptor is not None:
            try:
                _BUILTIN_CLOSE(file_descriptor)
            except OSError:
                pass
        if directory_descriptor is not None:
            try:
                _BUILTIN_CLOSE(directory_descriptor)
            except OSError:
                pass


def _nested_target_namespace_snapshot(
    path: str,
    *,
    protected_root_identity: tuple[int, int] | None,
    known_first_hop_identities: frozenset[str],
    guard_context: _NestedTargetGuardContext | None = None,
) -> tuple[tuple[tuple[int, ...], ...], tuple[int, ...]]:
    if type(path) is not str:
        raise _InvalidNestedTargetResolution
    components = tuple(path[1:].split("/"))
    directory_descriptors: list[int] = []
    target_descriptor: int | None = None
    directory_chain: list[tuple[int, ...]] = []
    try:
        try:
            root_descriptor = _BUILTIN_OPEN(
                _FIXED_POSIX_ROOT,
                _BUILTIN_DIRECTORY_OPEN_FLAGS(),
            )
            directory_descriptors.append(root_descriptor)
            root_metadata = _BUILTIN_FSTAT(root_descriptor)
        except OSError:
            raise _InvalidNestedTargetResolution from None
        if (
            not _BUILTIN_S_ISDIR(root_metadata.st_mode)
            or _BUILTIN_ROOT_IDENTITY_MATCHES(
                root_metadata,
                protected_root_identity,
            )
            or _BUILTIN_GUARD_ROOT_IDENTITY_MATCHES(
                root_metadata,
                guard_context,
            )
        ):
            raise _InvalidNestedTargetResolution
        directory_chain.append(_BUILTIN_DIRECTORY_SIGNATURE(root_metadata))
        for component in components[:-1]:
            child, signature = _BUILTIN_OPEN_DIRECTORY_COMPONENT(
                directory_descriptors[-1],
                component,
                protected_root_identity=protected_root_identity,
                guard_context=guard_context,
            )
            directory_descriptors.append(child)
            directory_chain.append(signature)
        parent = directory_descriptors[-1]
        parent_before = _BUILTIN_DIRECTORY_SIGNATURE(
            _BUILTIN_FSTAT(parent)
        )
        target_descriptor, metadata = _BUILTIN_OPEN_TARGET_AT(
            parent,
            components[-1],
        )
        target_signature = _BUILTIN_METADATA_SIGNATURE(metadata)
        if _BUILTIN_TARGET_IDENTITY_REF(
            metadata
        ) in known_first_hop_identities or (
            _BUILTIN_GUARD_LEAF_IDENTITY_IS_EXCLUDED(
                metadata,
                guard_context,
            )
        ):
            raise _InvalidNestedTargetResolution
        try:
            namespace_after = _BUILTIN_STAT(
                components[-1],
                dir_fd=parent,
                follow_symlinks=False,
            )
            parent_after = _BUILTIN_DIRECTORY_SIGNATURE(
                _BUILTIN_FSTAT(parent)
            )
        except OSError:
            raise _InvalidNestedTargetResolution from None
        if (
            _BUILTIN_METADATA_SIGNATURE(namespace_after) != target_signature
            or parent_after != parent_before
        ):
            raise _InvalidNestedTargetResolution

        for index, component in enumerate(components[:-1]):
            try:
                if (
                    _BUILTIN_ENTRY_SPELLING_STATE(
                        directory_descriptors[index],
                        component,
                    )
                    != "exact"
                ):
                    raise _InvalidNestedTargetResolution
                descriptor_metadata = _BUILTIN_FSTAT(
                    directory_descriptors[index + 1]
                )
                namespace_metadata = _BUILTIN_STAT(
                    component,
                    dir_fd=directory_descriptors[index],
                    follow_symlinks=False,
                )
            except OSError:
                raise _InvalidNestedTargetResolution from None
            expected_signature = directory_chain[index + 1]
            if (
                _BUILTIN_DIRECTORY_SIGNATURE(descriptor_metadata)
                != expected_signature
                or _BUILTIN_DIRECTORY_SIGNATURE(namespace_metadata)
                != expected_signature
                or _BUILTIN_S_ISLNK(namespace_metadata.st_mode)
                or _BUILTIN_ROOT_IDENTITY_MATCHES(
                    descriptor_metadata,
                    protected_root_identity,
                )
                or _BUILTIN_GUARD_ROOT_IDENTITY_MATCHES(
                    descriptor_metadata,
                    guard_context,
                )
            ):
                raise _InvalidNestedTargetResolution
        try:
            if _BUILTIN_ENTRY_SPELLING_STATE(
                parent,
                components[-1],
            ) != "exact":
                raise _InvalidNestedTargetResolution
            final_namespace = _BUILTIN_STAT(
                components[-1],
                dir_fd=parent,
                follow_symlinks=False,
            )
            final_parent = _BUILTIN_FSTAT(parent)
        except OSError:
            raise _InvalidNestedTargetResolution from None
        if (
            _BUILTIN_METADATA_SIGNATURE(final_namespace) != target_signature
            or _BUILTIN_DIRECTORY_SIGNATURE(final_parent) != parent_before
            or _BUILTIN_TARGET_IDENTITY_REF(final_namespace)
            in known_first_hop_identities
            or _BUILTIN_GUARD_LEAF_IDENTITY_IS_EXCLUDED(
                final_namespace,
                guard_context,
            )
        ):
            raise _InvalidNestedTargetResolution
        return tuple(directory_chain), target_signature
    finally:
        if target_descriptor is not None:
            try:
                _BUILTIN_CLOSE(target_descriptor)
            except OSError:
                pass
        for descriptor in reversed(directory_descriptors):
            try:
                _BUILTIN_CLOSE(descriptor)
            except OSError:
                pass


def _nested_target_namespace_matches(
    measured: _MeasuredNestedTarget,
    *,
    protected_root_identity: tuple[int, int] | None,
    known_first_hop_identities: frozenset[str],
    guard_context: _NestedTargetGuardContext | None = None,
) -> bool:
    try:
        _BUILTIN_MEASURED_NESTED_TARGET_PROJECTION(measured)
        directory_chain, target_metadata = (
            _BUILTIN_NESTED_TARGET_NAMESPACE_SNAPSHOT(
            measured.path,
            protected_root_identity=protected_root_identity,
            known_first_hop_identities=known_first_hop_identities,
            guard_context=guard_context,
            )
        )
        return (
            directory_chain == measured.directory_chain
            and target_metadata == measured.metadata
        )
    except (OSError, TypeError, ValueError):
        return False


def _measure_target_set(
    paths: tuple[str, ...],
    *,
    protected_root_identity: tuple[int, int] | None,
    known_first_hop_identities: frozenset[str],
) -> tuple[_MeasuredNestedTarget, ...]:
    if type(paths) is not tuple or any(type(path) is not str for path in paths):
        raise _InvalidNestedTargetResolution
    measured: list[_MeasuredNestedTarget] = []
    identities: set[tuple[int, int]] = set()
    total_bytes = 0
    for path in paths:
        item = _BUILTIN_MEASURE_NESTED_TARGET_PATH(
            path,
            total_measured_bytes=total_bytes,
            protected_root_identity=protected_root_identity,
            known_first_hop_identities=known_first_hop_identities,
        )
        _BUILTIN_MEASURED_NESTED_TARGET_PROJECTION(item)
        if (
            item.identity in identities
            or not _BUILTIN_NESTED_TARGET_NAMESPACE_MATCHES(
                item,
                protected_root_identity=protected_root_identity,
                known_first_hop_identities=known_first_hop_identities,
            )
        ):
            raise _InvalidNestedTargetResolution
        identities.add(item.identity)
        measured.append(item)
        total_bytes += item.content_bytes
    return tuple(measured)


def _measure_guarded_target_set(
    paths: tuple[str, ...],
    *,
    protected_root_identity: tuple[int, int] | None,
    known_first_hop_identities: frozenset[str],
    guard_context: _NestedTargetGuardContext,
) -> tuple[_MeasuredNestedTarget, ...]:
    """Measure with the separate guard's exclusions active before reads."""

    _BUILTIN_NESTED_TARGET_GUARD_CONTEXT_PROJECTION(guard_context)
    if type(paths) is not tuple or any(type(path) is not str for path in paths):
        raise _InvalidNestedTargetResolution
    measured: list[_MeasuredNestedTarget] = []
    identities: set[tuple[int, int]] = set()
    total_bytes = 0
    for path in paths:
        item = _BUILTIN_MEASURE_NESTED_TARGET_PATH(
            path,
            total_measured_bytes=total_bytes,
            protected_root_identity=protected_root_identity,
            known_first_hop_identities=known_first_hop_identities,
            guard_context=guard_context,
        )
        _BUILTIN_MEASURED_NESTED_TARGET_PROJECTION(item)
        if (
            item.identity in identities
            or not _BUILTIN_NESTED_TARGET_NAMESPACE_MATCHES(
                item,
                protected_root_identity=protected_root_identity,
                known_first_hop_identities=known_first_hop_identities,
                guard_context=guard_context,
            )
        ):
            raise _InvalidNestedTargetResolution
        identities.add(item.identity)
        measured.append(item)
        total_bytes += item.content_bytes
    return tuple(measured)


def _measure_guarded_target_set_with_consumer(
    paths: tuple[str, ...],
    *,
    protected_root_identity: tuple[int, int] | None,
    known_first_hop_identities: frozenset[str],
    guard_context: _NestedTargetGuardContext,
    consumer: _UniqueNestedTargetConsumer,
) -> tuple[_MeasuredNestedTarget, ...]:
    """Guardedly measure once while a private sink sees each pinned FD."""

    _BUILTIN_NESTED_TARGET_GUARD_CONTEXT_PROJECTION(guard_context)
    if type(paths) is not tuple or any(type(path) is not str for path in paths):
        raise _InvalidNestedTargetResolution
    measured: list[_MeasuredNestedTarget] = []
    identities: set[tuple[int, int]] = set()
    total_bytes = 0

    def consume_unique_nested_target(
        descriptor: int,
        metadata: os.stat_result,
        target: _MeasuredNestedTarget,
    ) -> None:
        if target.identity in identities:
            raise _InvalidNestedTargetResolution
        consumer(descriptor, metadata, target)

    for path in paths:
        item = _BUILTIN_MEASURE_NESTED_TARGET_PATH(
            path,
            total_measured_bytes=total_bytes,
            protected_root_identity=protected_root_identity,
            known_first_hop_identities=known_first_hop_identities,
            guard_context=guard_context,
            unique_nested_target_consumer=consume_unique_nested_target,
        )
        _BUILTIN_MEASURED_NESTED_TARGET_PROJECTION(item)
        if (
            item.identity in identities
            or not _BUILTIN_NESTED_TARGET_NAMESPACE_MATCHES(
                item,
                protected_root_identity=protected_root_identity,
                known_first_hop_identities=known_first_hop_identities,
                guard_context=guard_context,
            )
        ):
            raise _InvalidNestedTargetResolution
        identities.add(item.identity)
        measured.append(item)
        total_bytes += item.content_bytes
    return tuple(measured)


def _prevalidate_protected_root_ancestors(
    paths: tuple[str, ...],
    *,
    protected_root_identity: tuple[int, int] | None,
) -> None:
    """Reject the anchored staging-root identity before leaf measurement."""

    if type(paths) is not tuple or any(type(path) is not str for path in paths):
        raise _InvalidNestedTargetResolution
    if protected_root_identity is None or not paths:
        return
    for path in paths:
        components = tuple(path[1:].split("/"))
        descriptors: list[int] = []
        try:
            try:
                descriptor = _BUILTIN_OPEN(
                    _FIXED_POSIX_ROOT,
                    _BUILTIN_DIRECTORY_OPEN_FLAGS(),
                )
                descriptors.append(descriptor)
                root_metadata = _BUILTIN_FSTAT(descriptor)
            except OSError:
                raise _InvalidNestedTargetResolution from None
            if (
                not _BUILTIN_S_ISDIR(root_metadata.st_mode)
                or _BUILTIN_ROOT_IDENTITY_MATCHES(
                    root_metadata,
                    protected_root_identity,
                )
            ):
                raise _InvalidNestedTargetResolution
            for component in components[:-1]:
                child, _signature = _BUILTIN_OPEN_DIRECTORY_COMPONENT(
                    descriptors[-1],
                    component,
                    protected_root_identity=protected_root_identity,
                )
                descriptors.append(child)
        finally:
            for descriptor in reversed(descriptors):
                try:
                    _BUILTIN_CLOSE(descriptor)
                except OSError:
                    pass


def _prevalidate_guarded_root_ancestors(
    paths: tuple[str, ...],
    *,
    protected_root_identity: tuple[int, int] | None,
    guard_context: _NestedTargetGuardContext,
) -> None:
    """Reject either staging-root identity before any leaf is opened."""

    _BUILTIN_NESTED_TARGET_GUARD_CONTEXT_PROJECTION(guard_context)
    if type(paths) is not tuple or any(type(path) is not str for path in paths):
        raise _InvalidNestedTargetResolution
    if not paths:
        return
    for path in paths:
        components = tuple(path[1:].split("/"))
        descriptors: list[int] = []
        try:
            try:
                descriptor = _BUILTIN_OPEN(
                    _FIXED_POSIX_ROOT,
                    _BUILTIN_DIRECTORY_OPEN_FLAGS(),
                )
                descriptors.append(descriptor)
                root_metadata = _BUILTIN_FSTAT(descriptor)
            except OSError:
                raise _InvalidNestedTargetResolution from None
            if (
                not _BUILTIN_S_ISDIR(root_metadata.st_mode)
                or _BUILTIN_ROOT_IDENTITY_MATCHES(
                    root_metadata,
                    protected_root_identity,
                )
                or _BUILTIN_GUARD_ROOT_IDENTITY_MATCHES(
                    root_metadata,
                    guard_context,
                )
            ):
                raise _InvalidNestedTargetResolution
            for component in components[:-1]:
                child, _signature = _BUILTIN_OPEN_DIRECTORY_COMPONENT(
                    descriptors[-1],
                    component,
                    protected_root_identity=protected_root_identity,
                    guard_context=guard_context,
                )
                descriptors.append(child)
        finally:
            for descriptor in reversed(descriptors):
                try:
                    _BUILTIN_CLOSE(descriptor)
                except OSError:
                    pass


# Freeze the local no-follow graph after all of its components exist.
_BUILTIN_REQUIRE_SUPPORTED_PLATFORM = _require_supported_platform
_BUILTIN_METADATA_SIGNATURE = _metadata_signature
_BUILTIN_DIRECTORY_SIGNATURE = _directory_signature
_BUILTIN_VALIDATE_COMPONENT = _validate_component
_BUILTIN_ENTRY_SPELLING_STATE = _entry_spelling_state
_BUILTIN_DIRECTORY_OPEN_FLAGS = _directory_open_flags
_BUILTIN_ROOT_IDENTITY_MATCHES = _root_identity_matches
_BUILTIN_GUARD_ROOT_IDENTITY_MATCHES = _guard_root_identity_matches
_BUILTIN_IDENTITY_REF_IN_DOMAIN = _identity_ref_in_domain
_BUILTIN_GUARD_LEAF_IDENTITY_IS_EXCLUDED = (
    _guard_leaf_identity_is_excluded
)
_BUILTIN_OPEN_DIRECTORY_COMPONENT = _open_directory_component
_BUILTIN_OPEN_TARGET_AT = _open_target_at
_BUILTIN_FILE_IS_SPARSE = _file_is_sparse
_BUILTIN_TARGET_IDENTITY_REF = _target_identity_ref
_BUILTIN_TARGET_METADATA_DIGEST = _target_metadata_digest
_BUILTIN_MEASURE_NESTED_TARGET_PATH = _measure_nested_target_path
_BUILTIN_NESTED_TARGET_NAMESPACE_SNAPSHOT = (
    _nested_target_namespace_snapshot
)
_BUILTIN_NESTED_TARGET_NAMESPACE_MATCHES = _nested_target_namespace_matches
_BUILTIN_MEASURE_TARGET_SET = _measure_target_set
_BUILTIN_MEASURE_GUARDED_TARGET_SET = _measure_guarded_target_set
_BUILTIN_MEASURE_GUARDED_TARGET_SET_WITH_CONSUMER = (
    _measure_guarded_target_set_with_consumer
)
_BUILTIN_PREVALIDATE_PROTECTED_ROOT_ANCESTORS = (
    _prevalidate_protected_root_ancestors
)
_BUILTIN_PREVALIDATE_GUARDED_ROOT_ANCESTORS = (
    _prevalidate_guarded_root_ancestors
)


def _public_measurement(
    measured: _MeasuredNestedTarget,
) -> RepositoryExecutableShebangNestedTargetMeasurement:
    _BUILTIN_MEASURED_NESTED_TARGET_PROJECTION(measured)
    reference = _BUILTIN_MEASUREMENT_REF_PROJECTION(
        nested_target_path_ref=measured.path_ref,
        filesystem_identity_ref=measured.filesystem_identity_ref,
        metadata_digest=measured.metadata_digest,
        content_digest=measured.content_digest,
        content_bytes=measured.content_bytes,
    )
    value = _FIXED_MEASUREMENT_TYPE(
        kind=_FIXED_MEASUREMENT_KIND,
        nested_target_path_ref=measured.path_ref,
        filesystem_identity_ref=measured.filesystem_identity_ref,
        metadata_digest=measured.metadata_digest,
        content_digest=measured.content_digest,
        content_bytes=measured.content_bytes,
        nested_target_measurement_ref=_BUILTIN_CANONICAL_DIGEST(reference),
    )
    _BUILTIN_MEASUREMENT_PROJECTION(value)
    return value


def _public_requirement(
    derived: _DerivedNestedRequirement,
    *,
    measurement_by_path: dict[
        str, RepositoryExecutableShebangNestedTargetMeasurement
    ],
) -> RepositoryExecutableShebangNestedTargetRequirement:
    _BUILTIN_DERIVED_NESTED_REQUIREMENT_PROJECTION(derived)
    upstream = derived.upstream
    if type(upstream) is not dict:
        raise _InvalidNestedTargetResolution
    if derived.nested_target_path is not None:
        measurement = measurement_by_path.get(derived.nested_target_path)
        if measurement is None:
            raise _InvalidNestedTargetResolution
        disposition = "direct_absolute_nested_target_measured"
        nested_measurement_ref = measurement.nested_target_measurement_ref
    elif upstream["disposition"] == "native_not_applicable":
        disposition = "source_native_not_applicable"
        nested_measurement_ref = None
    elif upstream["disposition"] == "native_binary_no_shebang":
        disposition = "target_native_not_applicable"
        nested_measurement_ref = None
    else:
        raise _InvalidNestedTargetResolution
    reference = _BUILTIN_REQUIREMENT_REF_PROJECTION(
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
        target_shebang_requirement_ref=upstream[
            "target_shebang_requirement_ref"
        ],
        runtime_classification=upstream["runtime_classification"],
        target_measurement_ref=upstream["target_measurement_ref"],
        target_staged_file_ref=upstream["target_staged_file_ref"],
        target_runtime_file_ref=upstream["target_runtime_file_ref"],
        target_runtime_classification=upstream[
            "target_runtime_classification"
        ],
        target_shebang_directive_ref=upstream[
            "target_shebang_directive_ref"
        ],
        interpreter_token_ref=upstream["interpreter_token_ref"],
        argument_tail_ref=upstream["argument_tail_ref"],
        disposition=disposition,
        nested_target_measurement_ref=nested_measurement_ref,
    )
    value = _FIXED_REQUIREMENT_TYPE(
        kind=_FIXED_REQUIREMENT_KIND,
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
        target_shebang_requirement_ref=upstream[
            "target_shebang_requirement_ref"
        ],
        runtime_classification=upstream["runtime_classification"],
        target_measurement_ref=upstream["target_measurement_ref"],
        target_staged_file_ref=upstream["target_staged_file_ref"],
        target_runtime_file_ref=upstream["target_runtime_file_ref"],
        target_runtime_classification=upstream[
            "target_runtime_classification"
        ],
        target_shebang_directive_ref=upstream[
            "target_shebang_directive_ref"
        ],
        interpreter_token_ref=upstream["interpreter_token_ref"],
        argument_tail_ref=upstream["argument_tail_ref"],
        disposition=disposition,
        nested_target_measurement_ref=nested_measurement_ref,
        nested_target_requirement_ref=_BUILTIN_CANONICAL_DIGEST(reference),
    )
    _BUILTIN_REQUIREMENT_PROJECTION(value)
    return value


def _public_binding(
    upstream: dict[str, Any],
    requirement: RepositoryExecutableShebangNestedTargetRequirement,
) -> RepositoryExecutableShebangNestedTargetBinding:
    if type(upstream) is not dict:
        raise _InvalidNestedTargetResolution
    value = _FIXED_BINDING_TYPE(
        kind=_FIXED_BINDING_KIND,
        command_kind=upstream["command_kind"],
        command_id=upstream["command_id"],
        command_digest=upstream["command_digest"],
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
        target_shebang_requirement_ref=upstream[
            "target_shebang_requirement_ref"
        ],
        nested_target_requirement_ref=(
            requirement.nested_target_requirement_ref
        ),
    )
    _BUILTIN_BINDING_PROJECTION(value)
    return value


# Freeze builders and the chain graph before the public boundary can run.
_BUILTIN_CANONICAL_NESTED_TARGET_PATH = (
    _canonical_nested_target_path_from_token
)
_BUILTIN_DIRECT_TARGET_PATH_REF = _direct_target_path_ref
_BUILTIN_NESTED_TARGET_PATH_CONTEXT_DIGEST = (
    _nested_target_path_context_digest
)
_BUILTIN_VALIDATE_EXPECTED_NESTED_TARGET_PATHS = (
    _validate_expected_nested_target_paths
)
_BUILTIN_TARGET_FILE_SYNTAX = _target_file_syntax
_BUILTIN_DERIVE_NESTED_REQUIREMENTS = _derive_nested_requirements
_BUILTIN_VALIDATED_CHAIN_SNAPSHOT = _validated_chain_snapshot
_BUILTIN_PUBLIC_MEASUREMENT = _public_measurement
_BUILTIN_PUBLIC_REQUIREMENT = _public_requirement
_BUILTIN_PUBLIC_BINDING = _public_binding


def _inspect_staged_executable_shebang_nested_targets(
    expected_target_requirements: (
        RepositoryExecutableShebangTargetRequirementsReceipt
    ),
    *,
    expected_target_runtime: (
        RepositoryExecutableShebangTargetRuntimeManifestReceipt
    ),
    expected_target_staging: RepositoryExecutableShebangTargetStagingReceipt,
    lease: RepositoryExecutableShebangTargetStageLease,
    expected_nested_target_paths: tuple[Path, ...],
    guard_context: _NestedTargetGuardContext | None = None,
    expected_receipt_canonical: dict[str, Any] | None = None,
    closing_guard_anchor: Callable[[], None] | None = None,
    unique_nested_target_consumer: (
        _UniqueNestedTargetConsumer | None
    ) = None,
) -> RepositoryExecutableShebangNestedTargetResolutionReceipt:
    """Frozen private resolver with optional stronger pre-read exclusions."""

    try:
        if guard_context is not None:
            _BUILTIN_NESTED_TARGET_GUARD_CONTEXT_PROJECTION(guard_context)
        if (
            expected_receipt_canonical is not None
            and type(expected_receipt_canonical) is not dict
        ):
            raise _InvalidNestedTargetResolution
        if (
            closing_guard_anchor is not None
            and (
                guard_context is None
                or expected_receipt_canonical is None
                or type(closing_guard_anchor) is not _FIXED_FUNCTION_TYPE
            )
        ):
            raise _InvalidNestedTargetResolution
        if unique_nested_target_consumer is not None and guard_context is None:
            raise _InvalidNestedTargetResolution
        _BUILTIN_REQUIRE_SUPPORTED_PLATFORM()
        (
            derived,
            requirements_canonical,
            runtime_canonical,
            staging_canonical,
            retained_files,
            protected_root_identity,
            known_first_hop_identities,
        ) = _BUILTIN_VALIDATED_CHAIN_SNAPSHOT(
            expected_target_requirements,
            expected_target_runtime,
            expected_target_staging,
            lease,
        )
        paths = _BUILTIN_VALIDATE_EXPECTED_NESTED_TARGET_PATHS(
            derived,
            expected_nested_target_paths,
        )
        if guard_context is None:
            _BUILTIN_PREVALIDATE_PROTECTED_ROOT_ANCESTORS(
                paths,
                protected_root_identity=protected_root_identity,
            )
            first_measurement = _BUILTIN_MEASURE_TARGET_SET(
                paths,
                protected_root_identity=protected_root_identity,
                known_first_hop_identities=known_first_hop_identities,
            )
        elif unique_nested_target_consumer is None:
            _BUILTIN_PREVALIDATE_GUARDED_ROOT_ANCESTORS(
                paths,
                protected_root_identity=protected_root_identity,
                guard_context=guard_context,
            )
            first_measurement = _BUILTIN_MEASURE_GUARDED_TARGET_SET(
                paths,
                protected_root_identity=protected_root_identity,
                known_first_hop_identities=known_first_hop_identities,
                guard_context=guard_context,
            )
        else:
            _BUILTIN_PREVALIDATE_GUARDED_ROOT_ANCESTORS(
                paths,
                protected_root_identity=protected_root_identity,
                guard_context=guard_context,
            )
            first_measurement = (
                _BUILTIN_MEASURE_GUARDED_TARGET_SET_WITH_CONSUMER(
                    paths,
                    protected_root_identity=protected_root_identity,
                    known_first_hop_identities=known_first_hop_identities,
                    guard_context=guard_context,
                    consumer=unique_nested_target_consumer,
                )
            )
        derived_projection = tuple(
            _BUILTIN_DERIVED_NESTED_REQUIREMENT_PROJECTION(item)
            for item in derived
        )
        first_measurement_projection = tuple(
            _BUILTIN_MEASURED_NESTED_TARGET_PROJECTION(item)
            for item in first_measurement
        )

        (
            middle_derived,
            middle_requirements,
            middle_runtime,
            middle_staging,
            middle_retained,
            middle_protected_root,
            middle_known_identities,
        ) = _BUILTIN_VALIDATED_CHAIN_SNAPSHOT(
            expected_target_requirements,
            expected_target_runtime,
            expected_target_staging,
            lease,
        )
        if (
            tuple(
                _BUILTIN_DERIVED_NESTED_REQUIREMENT_PROJECTION(item)
                for item in middle_derived
            )
            != derived_projection
            or middle_requirements != requirements_canonical
            or middle_runtime != runtime_canonical
            or middle_staging != staging_canonical
            or middle_retained is not retained_files
            or middle_protected_root != protected_root_identity
            or middle_known_identities != known_first_hop_identities
            or _BUILTIN_VALIDATE_EXPECTED_NESTED_TARGET_PATHS(
                middle_derived,
                expected_nested_target_paths,
            )
            != paths
        ):
            raise _InvalidNestedTargetResolution
        if guard_context is None:
            _BUILTIN_PREVALIDATE_PROTECTED_ROOT_ANCESTORS(
                paths,
                protected_root_identity=protected_root_identity,
            )
            second_measurement = _BUILTIN_MEASURE_TARGET_SET(
                paths,
                protected_root_identity=protected_root_identity,
                known_first_hop_identities=known_first_hop_identities,
            )
        else:
            _BUILTIN_PREVALIDATE_GUARDED_ROOT_ANCESTORS(
                paths,
                protected_root_identity=protected_root_identity,
                guard_context=guard_context,
            )
            second_measurement = _BUILTIN_MEASURE_GUARDED_TARGET_SET(
                paths,
                protected_root_identity=protected_root_identity,
                known_first_hop_identities=known_first_hop_identities,
                guard_context=guard_context,
            )
        if (
            tuple(
                _BUILTIN_MEASURED_NESTED_TARGET_PROJECTION(item)
                for item in second_measurement
            )
            != first_measurement_projection
        ):
            raise _InvalidNestedTargetResolution

        (
            final_derived,
            final_requirements,
            final_runtime,
            final_staging,
            final_retained,
            final_protected_root,
            final_known_identities,
        ) = _BUILTIN_VALIDATED_CHAIN_SNAPSHOT(
            expected_target_requirements,
            expected_target_runtime,
            expected_target_staging,
            lease,
        )
        if (
            tuple(
                _BUILTIN_DERIVED_NESTED_REQUIREMENT_PROJECTION(item)
                for item in final_derived
            )
            != derived_projection
            or final_requirements != requirements_canonical
            or final_runtime != runtime_canonical
            or final_staging != staging_canonical
            or final_retained is not retained_files
            or final_protected_root != protected_root_identity
            or final_known_identities != known_first_hop_identities
            or _BUILTIN_VALIDATE_EXPECTED_NESTED_TARGET_PATHS(
                final_derived,
                expected_nested_target_paths,
            )
            != paths
            or any(
                not (
                    _BUILTIN_NESTED_TARGET_NAMESPACE_MATCHES(
                        item,
                        protected_root_identity=protected_root_identity,
                        known_first_hop_identities=(
                            known_first_hop_identities
                        ),
                    )
                    if guard_context is None
                    else _BUILTIN_NESTED_TARGET_NAMESPACE_MATCHES(
                        item,
                        protected_root_identity=protected_root_identity,
                        known_first_hop_identities=(
                            known_first_hop_identities
                        ),
                        guard_context=guard_context,
                    )
                )
                for item in first_measurement
            )
        ):
            raise _InvalidNestedTargetResolution

        measurements = tuple(
            _BUILTIN_PUBLIC_MEASUREMENT(item)
            for item in first_measurement
        )
        measurement_by_path = {
            measured.path: public
            for measured, public in zip(
                first_measurement,
                measurements,
                strict=True,
            )
        }
        requirements = tuple(
            _BUILTIN_PUBLIC_REQUIREMENT(
                item,
                measurement_by_path=measurement_by_path,
            )
            for item in derived
        )
        requirement_by_upstream = {
            item.target_shebang_requirement_ref: item
            for item in requirements
        }
        bindings = tuple(
            _BUILTIN_PUBLIC_BINDING(
                upstream,
                requirement_by_upstream[
                    upstream["target_shebang_requirement_ref"]
                ],
            )
            for upstream in requirements_canonical["bindings"]
        )

        receipt = _FIXED_RECEIPT_TYPE(
            kind=_FIXED_RECEIPT_KIND,
            schema_version=_FIXED_SCHEMA_VERSION,
            measurement_source=_FIXED_MEASUREMENT_SOURCE,
            resolution_scope=_FIXED_RESOLUTION_SCOPE,
            resolution_depth=_FIXED_RESOLUTION_DEPTH,
            maximum_resolution_depth=_FIXED_MAXIMUM_RESOLUTION_DEPTH,
            cycle_scope=_FIXED_CYCLE_SCOPE,
            target_shebang_requirements_receipt_digest=(
                _BUILTIN_CANONICAL_DIGEST(requirements_canonical)
            ),
            target_runtime_manifest_receipt_digest=(
                _BUILTIN_CANONICAL_DIGEST(runtime_canonical)
            ),
            target_staging_receipt_digest=(
                _BUILTIN_CANONICAL_DIGEST(staging_canonical)
            ),
            target_resolution_receipt_digest=requirements_canonical[
                "target_resolution_receipt_digest"
            ],
            shebang_requirements_receipt_digest=requirements_canonical[
                "shebang_requirements_receipt_digest"
            ],
            runtime_manifest_receipt_digest=requirements_canonical[
                "runtime_manifest_receipt_digest"
            ],
            staging_receipt_digest=requirements_canonical[
                "staging_receipt_digest"
            ],
            registration_digest=requirements_canonical[
                "registration_digest"
            ],
            repository_ref=requirements_canonical["repository_ref"],
            verification_commands_digest=requirements_canonical[
                "verification_commands_digest"
            ],
            resolution_context_digest=requirements_canonical[
                "resolution_context_digest"
            ],
            source_staging_context_digest=requirements_canonical[
                "source_staging_context_digest"
            ],
            target_path_context_digest=requirements_canonical[
                "target_path_context_digest"
            ],
            target_staging_context_digest=requirements_canonical[
                "target_staging_context_digest"
            ],
            nested_target_path_context_digest=(
                _BUILTIN_NESTED_TARGET_PATH_CONTEXT_DIGEST(paths)
            ),
            measurements=measurements,
            requirements=requirements,
            bindings=bindings,
            requirement_count=len(requirements),
            command_count=len(bindings),
            nested_target_requirement_count=sum(
                item.disposition
                == "direct_absolute_nested_target_measured"
                for item in requirements
            ),
            target_native_not_applicable_count=sum(
                item.disposition == "target_native_not_applicable"
                for item in requirements
            ),
            source_native_not_applicable_count=sum(
                item.disposition == "source_native_not_applicable"
                for item in requirements
            ),
            unique_nested_target_count=len(measurements),
            total_measured_bytes=sum(
                item.content_bytes for item in measurements
            ),
        )
        receipt_canonical = _BUILTIN_RECEIPT_PROJECTION(receipt)
        if (
            expected_receipt_canonical is not None
            and receipt_canonical != expected_receipt_canonical
        ):
            raise _InvalidNestedTargetResolution

        if (
            _BUILTIN_TARGET_REQUIREMENTS_PROJECTION(
                expected_target_requirements
            )
            != requirements_canonical
            or _BUILTIN_TARGET_RUNTIME_PROJECTION(expected_target_runtime)
            != runtime_canonical
            or _BUILTIN_TARGET_STAGING_PROJECTION(expected_target_staging)
            != staging_canonical
        ):
            raise _InvalidNestedTargetResolution
        closing_canonical, closing_retained = (
            _BUILTIN_ACTIVE_TARGET_STAGE_SNAPSHOT(
                expected_target_staging,
                lease,
            )
        )
        if (
            closing_canonical != staging_canonical
            or closing_retained is not retained_files
        ):
            raise _InvalidNestedTargetResolution
        for retained, staged_file in zip(
            closing_retained,
            staging_canonical["staged_files"],
            strict=True,
        ):
            _BUILTIN_TARGET_CLOSING_DESCRIPTOR_ANCHOR(
                retained,
                dict(staged_file),
                target_staging_context_digest=staging_canonical[
                    "target_staging_context_digest"
                ],
            )
        if (
            closing_guard_anchor is not None
            and closing_guard_anchor() is not None
        ):
            raise _InvalidNestedTargetResolution
        if any(
            not (
                _BUILTIN_NESTED_TARGET_NAMESPACE_MATCHES(
                    item,
                    protected_root_identity=protected_root_identity,
                    known_first_hop_identities=known_first_hop_identities,
                )
                if guard_context is None
                else _BUILTIN_NESTED_TARGET_NAMESPACE_MATCHES(
                    item,
                    protected_root_identity=protected_root_identity,
                    known_first_hop_identities=known_first_hop_identities,
                    guard_context=guard_context,
                )
            )
            for item in first_measurement
        ):
            raise _InvalidNestedTargetResolution
        return receipt
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise _FIXED_VALIDATION_ERROR(_INVALID_MESSAGE) from None


_BUILTIN_INSPECT_STAGED_EXECUTABLE_SHEBANG_NESTED_TARGETS = (
    _inspect_staged_executable_shebang_nested_targets
)


def inspect_staged_executable_shebang_nested_targets(
    expected_target_requirements: (
        RepositoryExecutableShebangTargetRequirementsReceipt
    ),
    *,
    expected_target_runtime: (
        RepositoryExecutableShebangTargetRuntimeManifestReceipt
    ),
    expected_target_staging: RepositoryExecutableShebangTargetStagingReceipt,
    lease: RepositoryExecutableShebangTargetStageLease,
    expected_nested_target_paths: tuple[Path, ...],
) -> RepositoryExecutableShebangNestedTargetResolutionReceipt:
    """Measure exactly one additional absolute target hop at depth two."""

    return _BUILTIN_INSPECT_STAGED_EXECUTABLE_SHEBANG_NESTED_TARGETS(
        expected_target_requirements,
        expected_target_runtime=expected_target_runtime,
        expected_target_staging=expected_target_staging,
        lease=lease,
        expected_nested_target_paths=expected_nested_target_paths,
    )


__all__ = [
    "CYCLE_SCOPE",
    "MAXIMUM_RESOLUTION_DEPTH",
    "MEASUREMENT_SOURCE",
    "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_BINDING_KIND",
    "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_MEASUREMENT_KIND",
    "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_REQUIREMENT_KIND",
    "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RESOLUTION_EVIDENCE_KIND",
    "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RESOLUTION_KIND",
    "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RESOLUTION_SCHEMA_VERSION",
    "RESOLUTION_DEPTH",
    "RESOLUTION_SCOPE",
    "RepositoryExecutableShebangNestedTargetBinding",
    "RepositoryExecutableShebangNestedTargetMeasurement",
    "RepositoryExecutableShebangNestedTargetRequirement",
    "RepositoryExecutableShebangNestedTargetResolutionReceipt",
    "inspect_staged_executable_shebang_nested_targets",
]
