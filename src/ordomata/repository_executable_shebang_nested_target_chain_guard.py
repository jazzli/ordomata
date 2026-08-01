"""Known-chain identity guard for one bounded nested shebang target.

This separate Class 0 boundary consumes the exact source-stage and staged-
target proof chain and freshly reproduces the fixed-depth nested-target
measurement with stronger identity exclusions active before candidate bytes
are read.  It rejects exact original and staged source/target executable
identities and every anchored staging-root identity present.  It does not claim
generic cycle closure, path-based source re-entry exclusion, broader protected-
root closure, freshness, authority, staging, dispatch, or execution.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Any

from .authorization import canonical_json
from .errors import ValidationError
from .repository_executable_resolution import (
    MEASUREMENT_SOURCE as SOURCE_MEASUREMENT_SOURCE,
    REPOSITORY_EXECUTABLE_RESOLUTION_SCOPE as SOURCE_RESOLUTION_SCOPE,
)
from .repository_executable_shebang_nested_target_resolution import (
    MAXIMUM_RESOLUTION_DEPTH as NESTED_MAXIMUM_RESOLUTION_DEPTH,
    RESOLUTION_DEPTH as NESTED_RESOLUTION_DEPTH,
    RepositoryExecutableShebangNestedTargetBinding,
    RepositoryExecutableShebangNestedTargetMeasurement,
    RepositoryExecutableShebangNestedTargetRequirement,
    RepositoryExecutableShebangNestedTargetResolutionReceipt,
    _NestedTargetGuardContext,
    _inspect_staged_executable_shebang_nested_targets,
    _receipt_projection as _nested_resolution_projection_v1,
)
from .repository_executable_shebang_target_requirements import (
    RepositoryExecutableShebangTargetRequirementsReceipt,
)
from .repository_executable_shebang_target_runtime_manifest import (
    RepositoryExecutableShebangTargetRuntimeManifestReceipt,
    _active_target_stage_snapshot,
)
from .repository_executable_shebang_target_staging import (
    RepositoryExecutableShebangTargetStageLease,
    RepositoryExecutableShebangTargetStagingReceipt,
)
from .repository_executable_staging import (
    REPOSITORY_EXECUTABLE_STAGE_BINDING_KIND,
    REPOSITORY_EXECUTABLE_STAGED_FILE_KIND,
    REPOSITORY_EXECUTABLE_STAGING_KIND,
    REPOSITORY_EXECUTABLE_STAGING_SCHEMA_VERSION,
    STAGING_SCOPE as SOURCE_STAGING_SCOPE,
    STAGING_SOURCE as SOURCE_STAGING_SOURCE,
    RepositoryExecutableStageBinding,
    RepositoryExecutableStageLease,
    RepositoryExecutableStagedFile,
    RepositoryExecutableStagingReceipt,
    _RetainedStagedFile,
)


REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_CHAIN_GUARD_SCHEMA_VERSION = 1
REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_CHAIN_GUARD_KIND = (
    "repository_executable_shebang_nested_target_chain_guard"
)
REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_CHAIN_GUARD_EVIDENCE_KIND = (
    "repository_executable_shebang_nested_target_chain_guard_validation"
)
REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_CHAIN_GUARDED_MEASUREMENT_KIND = (
    "repository_executable_shebang_nested_target_chain_guarded_measurement"
)
REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_CHAIN_GUARD_REQUIREMENT_KIND = (
    "repository_executable_shebang_nested_target_chain_guard_requirement"
)
REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_CHAIN_GUARD_BINDING_KIND = (
    "repository_executable_shebang_nested_target_chain_guard_binding"
)
INSPECTION_SOURCE = "controller_inspected"
GUARD_SCOPE = "known_source_chain_identity_and_staging_root_identity_v1"
RESOLUTION_DEPTH = 2
MAXIMUM_RESOLUTION_DEPTH = 2

_FIXED_SCHEMA_VERSION = (
    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_CHAIN_GUARD_SCHEMA_VERSION
)
_FIXED_RECEIPT_KIND = (
    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_CHAIN_GUARD_KIND
)
_FIXED_EVIDENCE_KIND = (
    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_CHAIN_GUARD_EVIDENCE_KIND
)
_FIXED_GUARDED_MEASUREMENT_KIND = (
    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_CHAIN_GUARDED_MEASUREMENT_KIND
)
_FIXED_REQUIREMENT_KIND = (
    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_CHAIN_GUARD_REQUIREMENT_KIND
)
_FIXED_BINDING_KIND = (
    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_CHAIN_GUARD_BINDING_KIND
)
_FIXED_INSPECTION_SOURCE = INSPECTION_SOURCE
_FIXED_GUARD_SCOPE = GUARD_SCOPE
_FIXED_RESOLUTION_DEPTH = RESOLUTION_DEPTH
_FIXED_MAXIMUM_RESOLUTION_DEPTH = MAXIMUM_RESOLUTION_DEPTH
_FIXED_SOURCE_MEASUREMENT_SOURCE = SOURCE_MEASUREMENT_SOURCE
_FIXED_SOURCE_RESOLUTION_SCOPE = SOURCE_RESOLUTION_SCOPE
_FIXED_SOURCE_STAGING_SCHEMA_VERSION = (
    REPOSITORY_EXECUTABLE_STAGING_SCHEMA_VERSION
)
_FIXED_SOURCE_STAGING_KIND = REPOSITORY_EXECUTABLE_STAGING_KIND
_FIXED_SOURCE_STAGED_FILE_KIND = REPOSITORY_EXECUTABLE_STAGED_FILE_KIND
_FIXED_SOURCE_STAGE_BINDING_KIND = REPOSITORY_EXECUTABLE_STAGE_BINDING_KIND
_FIXED_SOURCE_STAGING_SOURCE = SOURCE_STAGING_SOURCE
_FIXED_SOURCE_STAGING_SCOPE = SOURCE_STAGING_SCOPE

_INVALID_MESSAGE = (
    "repository executable shebang nested target chain guard is invalid"
)
_DIGEST_PREFIX = "sha256:"
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_BUILTIN_DIGEST_FULLMATCH = _DIGEST_PATTERN.fullmatch
_IDENTIFIER_PATTERN = re.compile(r"[a-z][a-z0-9_.-]{0,119}\Z")
_BUILTIN_IDENTIFIER_FULLMATCH = _IDENTIFIER_PATTERN.fullmatch
_COMMAND_KINDS = ("format", "lint", "type_check", "test", "build")
_FIXED_COMMAND_KINDS = _COMMAND_KINDS
_DISPOSITIONS = (
    "source_native_not_applicable",
    "target_native_not_applicable",
    "known_chain_guard_verified",
)
_FIXED_DISPOSITIONS = _DISPOSITIONS
_MAX_FILES = 80
_MAX_REQUIREMENTS = 80
_MAX_COMMANDS = 80
_MAX_TOTAL_BYTES = 256 * 1024 * 1024
_SOURCE_STAGED_FILE_MODE = 0o400
_STAGING_ROOT_MODE = 0o700

# Capture the shipped proof graph.  Public attributes, dataclass equality,
# and transparent ``to_canonical`` methods remain patchable and are not proof.
_BUILTIN_CANONICAL_JSON = canonical_json
_BUILTIN_SHA256 = hashlib.sha256
_BUILTIN_GETPID = os.getpid
_BUILTIN_GETEUID = os.geteuid
_BUILTIN_FSTAT = os.fstat
_BUILTIN_GET_INHERITABLE = os.get_inheritable
_BUILTIN_FCNTL = fcntl.fcntl
_FIXED_F_GETFL = fcntl.F_GETFL
_FIXED_O_ACCMODE = os.O_ACCMODE
_FIXED_O_RDONLY = os.O_RDONLY
_BUILTIN_S_ISDIR = stat.S_ISDIR
_BUILTIN_S_ISREG = stat.S_ISREG
_BUILTIN_S_IMODE = stat.S_IMODE
_FIXED_VALIDATION_ERROR = ValidationError
_FIXED_CONCRETE_PATH_TYPE = type(Path())

_FIXED_NESTED_RECEIPT_TYPE = (
    RepositoryExecutableShebangNestedTargetResolutionReceipt
)
_FIXED_NESTED_MEASUREMENT_TYPE = (
    RepositoryExecutableShebangNestedTargetMeasurement
)
_FIXED_NESTED_REQUIREMENT_TYPE = (
    RepositoryExecutableShebangNestedTargetRequirement
)
_FIXED_NESTED_BINDING_TYPE = RepositoryExecutableShebangNestedTargetBinding
_FIXED_TARGET_REQUIREMENTS_TYPE = (
    RepositoryExecutableShebangTargetRequirementsReceipt
)
_FIXED_TARGET_RUNTIME_TYPE = (
    RepositoryExecutableShebangTargetRuntimeManifestReceipt
)
_FIXED_TARGET_STAGING_TYPE = RepositoryExecutableShebangTargetStagingReceipt
_FIXED_TARGET_LEASE_TYPE = RepositoryExecutableShebangTargetStageLease
_FIXED_SOURCE_STAGING_TYPE = RepositoryExecutableStagingReceipt
_FIXED_SOURCE_LEASE_TYPE = RepositoryExecutableStageLease
_FIXED_SOURCE_STAGED_FILE_TYPE = RepositoryExecutableStagedFile
_FIXED_SOURCE_STAGE_BINDING_TYPE = RepositoryExecutableStageBinding
_FIXED_RETAINED_SOURCE_FILE_TYPE = _RetainedStagedFile
_FIXED_GUARD_CONTEXT_TYPE = _NestedTargetGuardContext

_BUILTIN_NESTED_RESOLUTION_PROJECTION = _nested_resolution_projection_v1
_BUILTIN_ACTIVE_TARGET_STAGE_SNAPSHOT = _active_target_stage_snapshot
_BUILTIN_INSPECT_NESTED_TARGETS = (
    _inspect_staged_executable_shebang_nested_targets
)


def _captured_canonical_digest(value: Any) -> str:
    encoded = _BUILTIN_CANONICAL_JSON(value).encode("utf-8")
    return _DIGEST_PREFIX + _BUILTIN_SHA256(encoded).hexdigest()


_BUILTIN_CANONICAL_DIGEST = _captured_canonical_digest


class _InvalidNestedTargetChainGuard(ValueError):
    """Private invalid-input sentinel with no public detail."""


@dataclass(frozen=True, slots=True)
class RepositoryExecutableShebangNestedTargetChainGuardedMeasurement:
    """One nested measurement bound to exact known identity sets."""

    kind: str
    nested_target_measurement_ref: str = field(repr=False)
    known_source_identity_set_digest: str = field(repr=False)
    known_target_identity_set_digest: str = field(repr=False)
    protected_staging_root_identity_set_digest: str = field(repr=False)
    guarded_measurement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _guarded_measurement_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableShebangNestedTargetChainGuardRequirement:
    """One nested requirement's narrow known-chain guard outcome."""

    kind: str
    staged_file_ref: str = field(repr=False)
    runtime_file_ref: str = field(repr=False)
    requirement_ref: str = field(repr=False)
    target_requirement_ref: str = field(repr=False)
    target_stage_requirement_ref: str = field(repr=False)
    target_runtime_requirement_ref: str = field(repr=False)
    target_shebang_requirement_ref: str = field(repr=False)
    nested_target_requirement_ref: str = field(repr=False)
    nested_target_measurement_ref: str | None = field(repr=False)
    disposition: str
    guarded_measurement_ref: str | None = field(repr=False)
    chain_guard_requirement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _guard_requirement_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableShebangNestedTargetChainGuardBinding:
    """One command bound through the complete nested requirement lineage."""

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

    def to_canonical(self) -> dict[str, Any]:
        return _guard_binding_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableShebangNestedTargetChainGuardReceipt:
    """Digest-only evidence for exact known-chain identity exclusions."""

    kind: str
    schema_version: int
    inspection_source: str
    guard_scope: str
    resolution_depth: int
    maximum_resolution_depth: int
    nested_target_resolution_receipt_digest: str = field(repr=False)
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
    guarded_measurements: tuple[
        RepositoryExecutableShebangNestedTargetChainGuardedMeasurement, ...
    ] = field(repr=False)
    requirements: tuple[
        RepositoryExecutableShebangNestedTargetChainGuardRequirement, ...
    ] = field(repr=False)
    bindings: tuple[
        RepositoryExecutableShebangNestedTargetChainGuardBinding, ...
    ] = field(repr=False)
    requirement_count: int
    command_count: int
    known_chain_guard_verified_count: int
    target_native_not_applicable_count: int
    source_native_not_applicable_count: int
    guarded_measurement_count: int
    known_source_identity_count: int
    known_target_identity_count: int
    protected_staging_root_identity_count: int
    total_guarded_bytes: int

    def to_canonical(self) -> dict[str, Any]:
        return _receipt_projection(self)

    @property
    def receipt_digest(self) -> str:
        return _BUILTIN_CANONICAL_DIGEST(_receipt_projection(self))

    def to_evidence(self) -> dict[str, Any]:
        return _evidence_projection(self)


_FIXED_GUARDED_MEASUREMENT_TYPE = (
    RepositoryExecutableShebangNestedTargetChainGuardedMeasurement
)
_FIXED_GUARD_REQUIREMENT_TYPE = (
    RepositoryExecutableShebangNestedTargetChainGuardRequirement
)
_FIXED_GUARD_BINDING_TYPE = (
    RepositoryExecutableShebangNestedTargetChainGuardBinding
)
_FIXED_RECEIPT_TYPE = RepositoryExecutableShebangNestedTargetChainGuardReceipt


def _is_digest(value: Any) -> bool:
    return type(value) is str and _BUILTIN_DIGEST_FULLMATCH(value) is not None


_BUILTIN_IS_DIGEST = _is_digest


def _guarded_measurement_ref_projection(
    *,
    nested_target_measurement_ref: str,
    known_source_identity_set_digest: str,
    known_target_identity_set_digest: str,
    protected_staging_root_identity_set_digest: str,
) -> dict[str, Any]:
    values = (
        nested_target_measurement_ref,
        known_source_identity_set_digest,
        known_target_identity_set_digest,
        protected_staging_root_identity_set_digest,
    )
    if not all(_BUILTIN_IS_DIGEST(value) for value in values):
        raise _InvalidNestedTargetChainGuard
    return {
        "guard_scope": _FIXED_GUARD_SCOPE,
        "kind": (
            "repository_executable_shebang_nested_target_"
            "chain_guarded_measurement_ref"
        ),
        "known_source_identity_set_digest": (
            known_source_identity_set_digest
        ),
        "known_target_identity_set_digest": (
            known_target_identity_set_digest
        ),
        "nested_target_measurement_ref": nested_target_measurement_ref,
        "protected_staging_root_identity_set_digest": (
            protected_staging_root_identity_set_digest
        ),
        "schema_version": _FIXED_SCHEMA_VERSION,
    }


def _guarded_measurement_projection(
    value: RepositoryExecutableShebangNestedTargetChainGuardedMeasurement,
) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_GUARDED_MEASUREMENT_TYPE
        or type(value.kind) is not str
        or value.kind != _FIXED_GUARDED_MEASUREMENT_KIND
    ):
        raise _InvalidNestedTargetChainGuard
    reference = _BUILTIN_GUARDED_MEASUREMENT_REF_PROJECTION(
        nested_target_measurement_ref=value.nested_target_measurement_ref,
        known_source_identity_set_digest=(
            value.known_source_identity_set_digest
        ),
        known_target_identity_set_digest=(
            value.known_target_identity_set_digest
        ),
        protected_staging_root_identity_set_digest=(
            value.protected_staging_root_identity_set_digest
        ),
    )
    if value.guarded_measurement_ref != _BUILTIN_CANONICAL_DIGEST(reference):
        raise _InvalidNestedTargetChainGuard
    return {
        "guarded_measurement_ref": value.guarded_measurement_ref,
        "kind": value.kind,
        "known_source_identity_set_digest": (
            value.known_source_identity_set_digest
        ),
        "known_target_identity_set_digest": (
            value.known_target_identity_set_digest
        ),
        "nested_target_measurement_ref": value.nested_target_measurement_ref,
        "protected_staging_root_identity_set_digest": (
            value.protected_staging_root_identity_set_digest
        ),
    }


def _guard_requirement_ref_projection(
    *,
    nested_target_requirement_ref: str,
    nested_target_measurement_ref: str | None,
    disposition: str,
    guarded_measurement_ref: str | None,
) -> dict[str, Any]:
    if (
        not _BUILTIN_IS_DIGEST(nested_target_requirement_ref)
        or (
            nested_target_measurement_ref is not None
            and not _BUILTIN_IS_DIGEST(nested_target_measurement_ref)
        )
        or type(disposition) is not str
        or disposition not in _FIXED_DISPOSITIONS
        or (
            guarded_measurement_ref is not None
            and not _BUILTIN_IS_DIGEST(guarded_measurement_ref)
        )
        or (
            disposition == "known_chain_guard_verified"
            and (
                nested_target_measurement_ref is None
                or guarded_measurement_ref is None
            )
        )
        or (
            disposition != "known_chain_guard_verified"
            and (
                nested_target_measurement_ref is not None
                or guarded_measurement_ref is not None
            )
        )
    ):
        raise _InvalidNestedTargetChainGuard
    return {
        "disposition": disposition,
        "guard_scope": _FIXED_GUARD_SCOPE,
        "guarded_measurement_ref": guarded_measurement_ref,
        "kind": (
            "repository_executable_shebang_nested_target_"
            "chain_guard_requirement_ref"
        ),
        "nested_target_measurement_ref": nested_target_measurement_ref,
        "nested_target_requirement_ref": nested_target_requirement_ref,
        "schema_version": _FIXED_SCHEMA_VERSION,
    }


def _guard_requirement_projection(
    value: RepositoryExecutableShebangNestedTargetChainGuardRequirement,
) -> dict[str, Any]:
    lineage = (
        value.staged_file_ref,
        value.runtime_file_ref,
        value.requirement_ref,
        value.target_requirement_ref,
        value.target_stage_requirement_ref,
        value.target_runtime_requirement_ref,
        value.target_shebang_requirement_ref,
        value.nested_target_requirement_ref,
    )
    if (
        type(value) is not _FIXED_GUARD_REQUIREMENT_TYPE
        or type(value.kind) is not str
        or value.kind != _FIXED_REQUIREMENT_KIND
        or not all(_BUILTIN_IS_DIGEST(item) for item in lineage)
    ):
        raise _InvalidNestedTargetChainGuard
    reference = _BUILTIN_GUARD_REQUIREMENT_REF_PROJECTION(
        nested_target_requirement_ref=value.nested_target_requirement_ref,
        nested_target_measurement_ref=value.nested_target_measurement_ref,
        disposition=value.disposition,
        guarded_measurement_ref=value.guarded_measurement_ref,
    )
    if (
        value.chain_guard_requirement_ref
        != _BUILTIN_CANONICAL_DIGEST(reference)
    ):
        raise _InvalidNestedTargetChainGuard
    return {
        "chain_guard_requirement_ref": value.chain_guard_requirement_ref,
        "disposition": value.disposition,
        "guarded_measurement_ref": value.guarded_measurement_ref,
        "kind": value.kind,
        "nested_target_measurement_ref": value.nested_target_measurement_ref,
        "nested_target_requirement_ref": value.nested_target_requirement_ref,
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


def _guard_binding_projection(
    value: RepositoryExecutableShebangNestedTargetChainGuardBinding,
) -> dict[str, Any]:
    lineage = (
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
    )
    if (
        type(value) is not _FIXED_GUARD_BINDING_TYPE
        or type(value.kind) is not str
        or value.kind != _FIXED_BINDING_KIND
        or type(value.command_kind) is not str
        or value.command_kind not in _FIXED_COMMAND_KINDS
        or type(value.command_id) is not str
        or _BUILTIN_IDENTIFIER_FULLMATCH(value.command_id) is None
        or not all(_BUILTIN_IS_DIGEST(item) for item in lineage)
    ):
        raise _InvalidNestedTargetChainGuard
    return {
        "chain_guard_requirement_ref": value.chain_guard_requirement_ref,
        "command_digest": value.command_digest,
        "command_id": value.command_id,
        "command_kind": value.command_kind,
        "kind": value.kind,
        "nested_target_requirement_ref": value.nested_target_requirement_ref,
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


_BUILTIN_GUARDED_MEASUREMENT_REF_PROJECTION = (
    _guarded_measurement_ref_projection
)
_BUILTIN_GUARDED_MEASUREMENT_PROJECTION = _guarded_measurement_projection
_BUILTIN_GUARD_REQUIREMENT_REF_PROJECTION = (
    _guard_requirement_ref_projection
)
_BUILTIN_GUARD_REQUIREMENT_PROJECTION = _guard_requirement_projection
_BUILTIN_GUARD_BINDING_PROJECTION = _guard_binding_projection


def _guard_summary_ref_projection(
    *,
    nested_target_resolution_receipt_digest: str,
    known_source_identity_set_digest: str,
    known_target_identity_set_digest: str,
    protected_staging_root_identity_set_digest: str,
    guarded_measurement_count: int,
    known_source_identity_count: int,
    known_target_identity_count: int,
    protected_staging_root_identity_count: int,
    total_guarded_bytes: int,
) -> dict[str, Any]:
    digest_fields = (
        nested_target_resolution_receipt_digest,
        known_source_identity_set_digest,
        known_target_identity_set_digest,
        protected_staging_root_identity_set_digest,
    )
    count_fields = (
        guarded_measurement_count,
        known_source_identity_count,
        known_target_identity_count,
        protected_staging_root_identity_count,
        total_guarded_bytes,
    )
    if (
        not all(_BUILTIN_IS_DIGEST(item) for item in digest_fields)
        or any(type(item) is not int or item < 0 for item in count_fields)
        or protected_staging_root_identity_count not in {1, 2}
        or total_guarded_bytes > _MAX_TOTAL_BYTES
    ):
        raise _InvalidNestedTargetChainGuard
    return {
        "guard_scope": _FIXED_GUARD_SCOPE,
        "guarded_measurement_count": guarded_measurement_count,
        "kind": (
            "repository_executable_shebang_nested_target_"
            "chain_guard_summary_ref"
        ),
        "known_source_identity_count": known_source_identity_count,
        "known_source_identity_set_digest": (
            known_source_identity_set_digest
        ),
        "known_target_identity_count": known_target_identity_count,
        "known_target_identity_set_digest": (
            known_target_identity_set_digest
        ),
        "nested_target_resolution_receipt_digest": (
            nested_target_resolution_receipt_digest
        ),
        "protected_staging_root_identity_count": (
            protected_staging_root_identity_count
        ),
        "protected_staging_root_identity_set_digest": (
            protected_staging_root_identity_set_digest
        ),
        "schema_version": _FIXED_SCHEMA_VERSION,
        "total_guarded_bytes": total_guarded_bytes,
    }


_BUILTIN_GUARD_SUMMARY_REF_PROJECTION = _guard_summary_ref_projection


def _receipt_projection(
    value: RepositoryExecutableShebangNestedTargetChainGuardReceipt,
) -> dict[str, Any]:
    digest_fields = (
        value.nested_target_resolution_receipt_digest,
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
    )
    count_fields = (
        value.requirement_count,
        value.command_count,
        value.known_chain_guard_verified_count,
        value.target_native_not_applicable_count,
        value.source_native_not_applicable_count,
        value.guarded_measurement_count,
        value.known_source_identity_count,
        value.known_target_identity_count,
        value.protected_staging_root_identity_count,
        value.total_guarded_bytes,
    )
    if (
        type(value) is not _FIXED_RECEIPT_TYPE
        or type(value.kind) is not str
        or value.kind != _FIXED_RECEIPT_KIND
        or type(value.schema_version) is not int
        or value.schema_version != _FIXED_SCHEMA_VERSION
        or type(value.inspection_source) is not str
        or value.inspection_source != _FIXED_INSPECTION_SOURCE
        or type(value.guard_scope) is not str
        or value.guard_scope != _FIXED_GUARD_SCOPE
        or type(value.resolution_depth) is not int
        or value.resolution_depth != _FIXED_RESOLUTION_DEPTH
        or type(value.maximum_resolution_depth) is not int
        or value.maximum_resolution_depth
        != _FIXED_MAXIMUM_RESOLUTION_DEPTH
        or not all(_BUILTIN_IS_DIGEST(item) for item in digest_fields)
        or type(value.guarded_measurements) is not tuple
        or len(value.guarded_measurements) > _MAX_FILES
        or type(value.requirements) is not tuple
        or not 1 <= len(value.requirements) <= _MAX_REQUIREMENTS
        or type(value.bindings) is not tuple
        or not 1 <= len(value.bindings) <= _MAX_COMMANDS
        or any(type(item) is not int or item < 0 for item in count_fields)
        or value.requirement_count != len(value.requirements)
        or value.command_count != len(value.bindings)
        or value.guarded_measurement_count != len(value.guarded_measurements)
        or value.total_guarded_bytes > _MAX_TOTAL_BYTES
        or value.protected_staging_root_identity_count not in {1, 2}
    ):
        raise _InvalidNestedTargetChainGuard

    expected_guard_summary_ref = _BUILTIN_CANONICAL_DIGEST(
        _BUILTIN_GUARD_SUMMARY_REF_PROJECTION(
            nested_target_resolution_receipt_digest=(
                value.nested_target_resolution_receipt_digest
            ),
            known_source_identity_set_digest=(
                value.known_source_identity_set_digest
            ),
            known_target_identity_set_digest=(
                value.known_target_identity_set_digest
            ),
            protected_staging_root_identity_set_digest=(
                value.protected_staging_root_identity_set_digest
            ),
            guarded_measurement_count=value.guarded_measurement_count,
            known_source_identity_count=value.known_source_identity_count,
            known_target_identity_count=value.known_target_identity_count,
            protected_staging_root_identity_count=(
                value.protected_staging_root_identity_count
            ),
            total_guarded_bytes=value.total_guarded_bytes,
        )
    )
    if value.guard_summary_ref != expected_guard_summary_ref:
        raise _InvalidNestedTargetChainGuard

    guarded_measurements = [
        _BUILTIN_GUARDED_MEASUREMENT_PROJECTION(item)
        for item in value.guarded_measurements
    ]
    requirements = [
        _BUILTIN_GUARD_REQUIREMENT_PROJECTION(item)
        for item in value.requirements
    ]
    bindings = [
        _BUILTIN_GUARD_BINDING_PROJECTION(item) for item in value.bindings
    ]

    guarded_by_nested: dict[str, str] = {}
    guarded_refs: set[str] = set()
    for item in value.guarded_measurements:
        if (
            item.nested_target_measurement_ref in guarded_by_nested
            or item.guarded_measurement_ref in guarded_refs
            or item.known_source_identity_set_digest
            != value.known_source_identity_set_digest
            or item.known_target_identity_set_digest
            != value.known_target_identity_set_digest
            or item.protected_staging_root_identity_set_digest
            != value.protected_staging_root_identity_set_digest
        ):
            raise _InvalidNestedTargetChainGuard
        guarded_by_nested[item.nested_target_measurement_ref] = (
            item.guarded_measurement_ref
        )
        guarded_refs.add(item.guarded_measurement_ref)

    requirement_by_nested: dict[
        str,
        RepositoryExecutableShebangNestedTargetChainGuardRequirement,
    ] = {}
    requirement_refs: set[str] = set()
    verified_guarded_refs: list[str] = []
    seen_verified_guarded_refs: set[str] = set()
    dispositions = {item: 0 for item in _FIXED_DISPOSITIONS}
    for item in value.requirements:
        if (
            item.nested_target_requirement_ref in requirement_by_nested
            or item.chain_guard_requirement_ref in requirement_refs
        ):
            raise _InvalidNestedTargetChainGuard
        if item.disposition == "known_chain_guard_verified":
            if (
                item.nested_target_measurement_ref not in guarded_by_nested
                or guarded_by_nested[item.nested_target_measurement_ref]
                != item.guarded_measurement_ref
            ):
                raise _InvalidNestedTargetChainGuard
            assert item.guarded_measurement_ref is not None
            if item.guarded_measurement_ref not in seen_verified_guarded_refs:
                verified_guarded_refs.append(item.guarded_measurement_ref)
                seen_verified_guarded_refs.add(item.guarded_measurement_ref)
        requirement_by_nested[item.nested_target_requirement_ref] = item
        requirement_refs.add(item.chain_guard_requirement_ref)
        dispositions[item.disposition] += 1
    if (
        tuple(verified_guarded_refs)
        != tuple(item.guarded_measurement_ref for item in value.guarded_measurements)
        or dispositions["known_chain_guard_verified"]
        != value.known_chain_guard_verified_count
        or dispositions["target_native_not_applicable"]
        != value.target_native_not_applicable_count
        or dispositions["source_native_not_applicable"]
        != value.source_native_not_applicable_count
    ):
        raise _InvalidNestedTargetChainGuard

    command_ids: set[str] = set()
    prior_kind_index = -1
    bound_requirements: set[str] = set()
    for item in value.bindings:
        expected = requirement_by_nested.get(item.nested_target_requirement_ref)
        kind_index = _FIXED_COMMAND_KINDS.index(item.command_kind)
        if (
            expected is None
            or kind_index < prior_kind_index
            or item.command_id in command_ids
            or item.chain_guard_requirement_ref
            != expected.chain_guard_requirement_ref
            or item.staged_file_ref != expected.staged_file_ref
            or item.runtime_file_ref != expected.runtime_file_ref
            or item.requirement_ref != expected.requirement_ref
            or item.target_requirement_ref != expected.target_requirement_ref
            or item.target_stage_requirement_ref
            != expected.target_stage_requirement_ref
            or item.target_runtime_requirement_ref
            != expected.target_runtime_requirement_ref
            or item.target_shebang_requirement_ref
            != expected.target_shebang_requirement_ref
        ):
            raise _InvalidNestedTargetChainGuard
        command_ids.add(item.command_id)
        bound_requirements.add(item.nested_target_requirement_ref)
        prior_kind_index = kind_index
    if bound_requirements != set(requirement_by_nested):
        raise _InvalidNestedTargetChainGuard

    return {
        "bindings": bindings,
        "command_count": value.command_count,
        "guard_scope": value.guard_scope,
        "guard_summary_ref": value.guard_summary_ref,
        "guarded_measurement_count": value.guarded_measurement_count,
        "guarded_measurements": guarded_measurements,
        "inspection_source": value.inspection_source,
        "kind": value.kind,
        "known_chain_guard_verified_count": (
            value.known_chain_guard_verified_count
        ),
        "known_source_identity_count": value.known_source_identity_count,
        "known_source_identity_set_digest": (
            value.known_source_identity_set_digest
        ),
        "known_target_identity_count": value.known_target_identity_count,
        "known_target_identity_set_digest": (
            value.known_target_identity_set_digest
        ),
        "maximum_resolution_depth": value.maximum_resolution_depth,
        "nested_target_path_context_digest": (
            value.nested_target_path_context_digest
        ),
        "nested_target_resolution_receipt_digest": (
            value.nested_target_resolution_receipt_digest
        ),
        "protected_staging_root_identity_count": (
            value.protected_staging_root_identity_count
        ),
        "protected_staging_root_identity_set_digest": (
            value.protected_staging_root_identity_set_digest
        ),
        "registration_digest": value.registration_digest,
        "repository_ref": value.repository_ref,
        "requirement_count": value.requirement_count,
        "requirements": requirements,
        "resolution_context_digest": value.resolution_context_digest,
        "resolution_depth": value.resolution_depth,
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
        "total_guarded_bytes": value.total_guarded_bytes,
        "verification_commands_digest": value.verification_commands_digest,
    }


def _evidence_projection(
    value: RepositoryExecutableShebangNestedTargetChainGuardReceipt,
) -> dict[str, Any]:
    canonical = _BUILTIN_RECEIPT_PROJECTION(value)
    path_lookup_performed = canonical["guarded_measurement_count"] > 0
    target_staging_root_present = (
        canonical["protected_staging_root_identity_count"] == 2
    )
    return {
        "active_source_stage_lease_anchor_verified": True,
        "active_target_stage_lease_verified": True,
        "authority_granted": False,
        "authorization_decision": False,
        "authorization_verified": False,
        "broader_protected_root_exclusion_verified": False,
        "candidate_bytes_exposed": False,
        "command_count": canonical["command_count"],
        "current_freshness_verified": False,
        "dependency_closure_verified": False,
        "descriptor_numbers_exposed": False,
        "effect_class": 0,
        "execution_enabled": False,
        "generic_cycle_exclusion_verified": False,
        "guard_scope": canonical["guard_scope"],
        "guarded_measurement_count": canonical["guarded_measurement_count"],
        "harness_invoked": False,
        "inspection_source": canonical["inspection_source"],
        "kind": _FIXED_EVIDENCE_KIND,
        "known_chain_identity_reentry_exclusion_verified": True,
        "known_source_identity_count": canonical[
            "known_source_identity_count"
        ],
        "known_source_identity_reentry_exclusion_verified": True,
        "known_source_original_identity_reentry_excluded": True,
        "known_source_staged_identity_reentry_excluded": True,
        "known_target_identity_count": canonical[
            "known_target_identity_count"
        ],
        "known_target_identity_reentry_exclusion_verified": True,
        "known_target_original_identity_reentry_excluded": True,
        "known_target_staged_identity_reentry_excluded": True,
        "maximum_resolution_depth": canonical["maximum_resolution_depth"],
        "model_invoked": False,
        "nested_target_paths_exposed": False,
        "nested_resolution_reproduced": True,
        "path_lookup_performed": path_lookup_performed,
        "protected_staging_root_identity_count": canonical[
            "protected_staging_root_identity_count"
        ],
        "protected_staging_root_identity_exclusion_verified": True,
        "receipt_authenticity_verified": False,
        "receipt_digest": _BUILTIN_CANONICAL_DIGEST(canonical),
        "requirement_count": canonical["requirement_count"],
        "resolution_depth": canonical["resolution_depth"],
        "schema_version": canonical["schema_version"],
        "source_path_reentry_exclusion_verified": False,
        "source_staging_root_identity_ancestor_excluded": True,
        "source_staging_root_identity_exclusion_verified": True,
        "source_staging_root_path_reentry_exclusion_verified": False,
        "source_staging_root_path_reopen_performed": False,
        "staging_enabled": False,
        "subprocess_invoked": False,
        "target_staging_root_identity_exclusion_verified": (
            target_staging_root_present
        ),
        "target_staging_root_identity_ancestor_excluded": (
            target_staging_root_present
        ),
        "target_staging_root_path_reentry_exclusion_verified": False,
        "target_staging_root_path_reopen_performed": False,
        "temporary_names_exposed": False,
        "total_guarded_bytes": canonical["total_guarded_bytes"],
        "two_pass_guard_measurement_verified": True,
        "closing_namespace_guard_verified": path_lookup_performed,
        "validation_mode": "read_only",
    }


_BUILTIN_RECEIPT_PROJECTION = _receipt_projection
_BUILTIN_EVIDENCE_PROJECTION = _evidence_projection


def _source_staged_file_projection(
    value: RepositoryExecutableStagedFile,
) -> dict[str, Any]:
    digest_fields = (
        value.source_filesystem_identity_ref,
        value.source_metadata_digest,
        value.staged_file_ref,
        value.staged_filesystem_identity_ref,
        value.staged_metadata_digest,
        value.content_digest,
    )
    if (
        type(value) is not _FIXED_SOURCE_STAGED_FILE_TYPE
        or type(value.kind) is not str
        or value.kind != _FIXED_SOURCE_STAGED_FILE_KIND
        or not all(_BUILTIN_IS_DIGEST(item) for item in digest_fields)
        or type(value.content_bytes) is not int
        or not 0 <= value.content_bytes <= 64 * 1024 * 1024
    ):
        raise _InvalidNestedTargetChainGuard
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


def _source_stage_binding_projection(
    value: RepositoryExecutableStageBinding,
) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_SOURCE_STAGE_BINDING_TYPE
        or type(value.kind) is not str
        or value.kind != _FIXED_SOURCE_STAGE_BINDING_KIND
        or type(value.command_kind) is not str
        or value.command_kind not in _FIXED_COMMAND_KINDS
        or type(value.command_id) is not str
        or _BUILTIN_IDENTIFIER_FULLMATCH(value.command_id) is None
        or not all(
            _BUILTIN_IS_DIGEST(item)
            for item in (
                value.command_digest,
                value.declared_executable_ref,
                value.resolved_executable_ref,
                value.staged_file_ref,
            )
        )
    ):
        raise _InvalidNestedTargetChainGuard
    return {
        "command_digest": value.command_digest,
        "command_id": value.command_id,
        "command_kind": value.command_kind,
        "declared_executable_ref": value.declared_executable_ref,
        "kind": value.kind,
        "resolved_executable_ref": value.resolved_executable_ref,
        "staged_file_ref": value.staged_file_ref,
    }


def _source_staging_projection(
    value: RepositoryExecutableStagingReceipt,
) -> dict[str, Any]:
    digests = (
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
        type(value) is not _FIXED_SOURCE_STAGING_TYPE
        or type(value.kind) is not str
        or value.kind != _FIXED_SOURCE_STAGING_KIND
        or type(value.schema_version) is not int
        or value.schema_version != _FIXED_SOURCE_STAGING_SCHEMA_VERSION
        or type(value.measurement_source) is not str
        or value.measurement_source != _FIXED_SOURCE_MEASUREMENT_SOURCE
        or type(value.resolution_scope) is not str
        or value.resolution_scope != _FIXED_SOURCE_RESOLUTION_SCOPE
        or type(value.staging_source) is not str
        or value.staging_source != _FIXED_SOURCE_STAGING_SOURCE
        or type(value.staging_scope) is not str
        or value.staging_scope != _FIXED_SOURCE_STAGING_SCOPE
        or not all(_BUILTIN_IS_DIGEST(item) for item in digests)
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
        or not 0 <= value.total_staged_bytes <= _MAX_TOTAL_BYTES
    ):
        raise _InvalidNestedTargetChainGuard
    staged_files = [
        _BUILTIN_SOURCE_STAGED_FILE_PROJECTION(item)
        for item in value.staged_files
    ]
    bindings = [
        _BUILTIN_SOURCE_STAGE_BINDING_PROJECTION(item)
        for item in value.bindings
    ]
    file_by_ref: dict[str, RepositoryExecutableStagedFile] = {}
    source_refs: set[str] = set()
    staged_refs: set[str] = set()
    total_bytes = 0
    for item in value.staged_files:
        if (
            item.staged_file_ref in file_by_ref
            or item.source_filesystem_identity_ref in source_refs
            or item.staged_filesystem_identity_ref in staged_refs
        ):
            raise _InvalidNestedTargetChainGuard
        expected_ref = _BUILTIN_CANONICAL_DIGEST(
            {
                "content_bytes": item.content_bytes,
                "content_digest": item.content_digest,
                "kind": "repository_executable_staged_file_ref",
                "schema_version": 1,
                "source_filesystem_identity_ref": (
                    item.source_filesystem_identity_ref
                ),
                "source_metadata_digest": item.source_metadata_digest,
                "staged_filesystem_identity_ref": (
                    item.staged_filesystem_identity_ref
                ),
                "staged_metadata_digest": item.staged_metadata_digest,
                "staging_context_digest": value.staging_context_digest,
            }
        )
        if item.staged_file_ref != expected_ref:
            raise _InvalidNestedTargetChainGuard
        file_by_ref[item.staged_file_ref] = item
        source_refs.add(item.source_filesystem_identity_ref)
        staged_refs.add(item.staged_filesystem_identity_ref)
        total_bytes += item.content_bytes
    command_ids: set[str] = set()
    bound_refs: set[str] = set()
    first_use: list[str] = []
    prior_kind_index = -1
    for item in value.bindings:
        kind_index = _FIXED_COMMAND_KINDS.index(item.command_kind)
        if (
            kind_index < prior_kind_index
            or item.command_id in command_ids
            or item.staged_file_ref not in file_by_ref
        ):
            raise _InvalidNestedTargetChainGuard
        command_ids.add(item.command_id)
        if item.staged_file_ref not in bound_refs:
            first_use.append(item.staged_file_ref)
        bound_refs.add(item.staged_file_ref)
        prior_kind_index = kind_index
    if (
        total_bytes != value.total_staged_bytes
        or bound_refs != set(file_by_ref)
        or tuple(first_use)
        != tuple(item.staged_file_ref for item in value.staged_files)
    ):
        raise _InvalidNestedTargetChainGuard
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


_BUILTIN_SOURCE_STAGED_FILE_PROJECTION = _source_staged_file_projection
_BUILTIN_SOURCE_STAGE_BINDING_PROJECTION = _source_stage_binding_projection
_BUILTIN_SOURCE_STAGING_PROJECTION = _source_staging_projection


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


_BUILTIN_METADATA_SIGNATURE = _metadata_signature


def _source_root_context_digest(metadata: tuple[int, ...]) -> str:
    if (
        type(metadata) is not tuple
        or len(metadata) != 9
        or any(type(item) is not int for item in metadata)
        or not _BUILTIN_S_ISDIR(metadata[2])
        or _BUILTIN_S_IMODE(metadata[2]) != _STAGING_ROOT_MODE
        or metadata[3] <= 0
        or metadata[4] != _BUILTIN_GETEUID()
    ):
        raise _InvalidNestedTargetChainGuard
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "directory_device": metadata[0],
            "directory_inode": metadata[1],
            "directory_mode": _BUILTIN_S_IMODE(metadata[2]),
            "directory_owner": metadata[4],
            "kind": "repository_executable_staging_context",
            "schema_version": 1,
            "staging_scope": _FIXED_SOURCE_STAGING_SCOPE,
        }
    )


def _verify_source_retained_file(
    retained: _RetainedStagedFile,
    anchored: RepositoryExecutableStagedFile,
) -> None:
    if (
        type(retained) is not _FIXED_RETAINED_SOURCE_FILE_TYPE
        or retained.staged_file is not anchored
        or type(retained.descriptor) is not int
        or retained.descriptor < 0
        or type(retained.metadata) is not tuple
        or len(retained.metadata) != 9
        or any(type(item) is not int for item in retained.metadata)
    ):
        raise _InvalidNestedTargetChainGuard
    try:
        metadata = _BUILTIN_FSTAT(retained.descriptor)
        flags = _BUILTIN_FCNTL(retained.descriptor, _FIXED_F_GETFL)
        inheritable = _BUILTIN_GET_INHERITABLE(retained.descriptor)
    except (OSError, ValueError):
        raise _InvalidNestedTargetChainGuard from None
    signature = _BUILTIN_METADATA_SIGNATURE(metadata)
    staged_identity_ref = _BUILTIN_CANONICAL_DIGEST(
        {
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "kind": "repository_executable_staged_file_identity",
            "schema_version": 1,
        }
    )
    staged_metadata_digest = _BUILTIN_CANONICAL_DIGEST(
        {
            "change_time_ns": metadata.st_ctime_ns,
            "filesystem_identity_ref": staged_identity_ref,
            "group_id": metadata.st_gid,
            "kind": "repository_executable_staged_file_metadata",
            "link_count": metadata.st_nlink,
            "mode": metadata.st_mode,
            "modified_time_ns": metadata.st_mtime_ns,
            "owner_id": metadata.st_uid,
            "schema_version": 1,
            "size_bytes": metadata.st_size,
        }
    )
    if (
        signature != retained.metadata
        or not _BUILTIN_S_ISREG(metadata.st_mode)
        or metadata.st_uid != _BUILTIN_GETEUID()
        or _BUILTIN_S_IMODE(metadata.st_mode) != _SOURCE_STAGED_FILE_MODE
        or metadata.st_nlink != 0
        or metadata.st_size != anchored.content_bytes
        or flags & _FIXED_O_ACCMODE != _FIXED_O_RDONLY
        or inheritable
        or staged_identity_ref != anchored.staged_filesystem_identity_ref
        or staged_metadata_digest != anchored.staged_metadata_digest
    ):
        raise _InvalidNestedTargetChainGuard


def _active_source_stage_snapshot(
    expected_source_staging: RepositoryExecutableStagingReceipt,
    source_lease: RepositoryExecutableStageLease,
) -> tuple[
    dict[str, Any],
    tuple[_RetainedStagedFile, ...],
    tuple[int, int],
    frozenset[str],
]:
    if (
        type(expected_source_staging) is not _FIXED_SOURCE_STAGING_TYPE
        or type(source_lease) is not _FIXED_SOURCE_LEASE_TYPE
        or type(source_lease._owner_pid) is not int
        or source_lease._owner_pid <= 0
        or source_lease._owner_pid != _BUILTIN_GETPID()
        or type(source_lease._state) is not str
        or source_lease._state != "active"
        or source_lease._receipt is not expected_source_staging
        or source_lease._cleanup_receipt is not None
        or source_lease._cleanup_receipt_digest_anchor is not None
        or type(source_lease._receipt_digest_anchor) is not str
        or type(source_lease._receipt_staged_file_refs_anchor) is not tuple
        or source_lease._root_descriptor is not None
        or source_lease._pending_name is not None
        or source_lease._pending_identity is not None
        or type(source_lease._pending_descriptors) is not tuple
        or source_lease._pending_descriptors != ()
        or source_lease._descriptor_release_unverifiable is not False
        or type(source_lease._files) is not tuple
        or type(source_lease._root_metadata) is not tuple
    ):
        raise _InvalidNestedTargetChainGuard
    canonical = _BUILTIN_SOURCE_STAGING_PROJECTION(expected_source_staging)
    receipt_digest = _BUILTIN_CANONICAL_DIGEST(canonical)
    if (
        source_lease._receipt_digest_anchor != receipt_digest
        or source_lease._receipt_staged_file_refs_anchor
        != tuple(
            item.staged_file_ref for item in expected_source_staging.staged_files
        )
        or len(source_lease._files)
        != expected_source_staging.unique_file_count
        or _BUILTIN_SOURCE_ROOT_CONTEXT_DIGEST(source_lease._root_metadata)
        != expected_source_staging.staging_context_digest
    ):
        raise _InvalidNestedTargetChainGuard
    for retained, anchored in zip(
        source_lease._files,
        expected_source_staging.staged_files,
        strict=True,
    ):
        _BUILTIN_VERIFY_SOURCE_RETAINED_FILE(retained, anchored)
    identity_refs = frozenset(
        reference
        for item in canonical["staged_files"]
        for reference in (
            item["source_filesystem_identity_ref"],
            item["staged_filesystem_identity_ref"],
        )
    )
    if len(identity_refs) != 2 * len(canonical["staged_files"]):
        raise _InvalidNestedTargetChainGuard
    return (
        canonical,
        source_lease._files,
        (source_lease._root_metadata[0], source_lease._root_metadata[1]),
        identity_refs,
    )


_BUILTIN_SOURCE_ROOT_CONTEXT_DIGEST = _source_root_context_digest
_BUILTIN_VERIFY_SOURCE_RETAINED_FILE = _verify_source_retained_file
_BUILTIN_ACTIVE_SOURCE_STAGE_SNAPSHOT = _active_source_stage_snapshot


def _active_target_context_snapshot(
    expected_target_staging: RepositoryExecutableShebangTargetStagingReceipt,
    target_lease: RepositoryExecutableShebangTargetStageLease,
) -> tuple[
    dict[str, Any],
    tuple[Any, ...],
    tuple[int, int] | None,
    frozenset[str],
]:
    if (
        type(expected_target_staging) is not _FIXED_TARGET_STAGING_TYPE
        or type(target_lease) is not _FIXED_TARGET_LEASE_TYPE
    ):
        raise _InvalidNestedTargetChainGuard
    try:
        canonical, retained = _BUILTIN_ACTIVE_TARGET_STAGE_SNAPSHOT(
            expected_target_staging,
            target_lease,
        )
    except (AttributeError, OSError, TypeError, ValueError):
        raise _InvalidNestedTargetChainGuard from None
    if type(canonical) is not dict or type(retained) is not tuple:
        raise _InvalidNestedTargetChainGuard
    identity_refs = frozenset(
        reference
        for item in canonical["staged_files"]
        for reference in (
            item["source_filesystem_identity_ref"],
            item["staged_filesystem_identity_ref"],
        )
    )
    if len(identity_refs) != 2 * len(canonical["staged_files"]):
        raise _InvalidNestedTargetChainGuard
    root_identity: tuple[int, int] | None = None
    if canonical["staging_root_used"]:
        metadata = target_lease._root_metadata
        if (
            type(metadata) is not tuple
            or len(metadata) != 9
            or any(type(item) is not int for item in metadata)
        ):
            raise _InvalidNestedTargetChainGuard
        root_identity = (metadata[0], metadata[1])
    elif target_lease._root_metadata is not None:
        raise _InvalidNestedTargetChainGuard
    return canonical, retained, root_identity, identity_refs


def _identity_set_digest(identity_refs: frozenset[str], *, role: str) -> str:
    if (
        type(identity_refs) is not frozenset
        or type(role) is not str
        or role not in {"source_executable", "shebang_target"}
        or any(not _BUILTIN_IS_DIGEST(item) for item in identity_refs)
    ):
        raise _InvalidNestedTargetChainGuard
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "guard_scope": _FIXED_GUARD_SCOPE,
            "identity_refs": sorted(identity_refs),
            "kind": (
                "repository_executable_shebang_nested_target_"
                "known_identity_set"
            ),
            "role": role,
            "schema_version": _FIXED_SCHEMA_VERSION,
        }
    )


def _protected_root_set(
    source_root_identity: tuple[int, int],
    target_root_identity: tuple[int, int] | None,
) -> tuple[frozenset[tuple[int, int]], str]:
    if (
        type(source_root_identity) is not tuple
        or len(source_root_identity) != 2
        or any(type(item) is not int or item < 0 for item in source_root_identity)
        or (
            target_root_identity is not None
            and (
                type(target_root_identity) is not tuple
                or len(target_root_identity) != 2
                or any(
                    type(item) is not int or item < 0
                    for item in target_root_identity
                )
            )
        )
    ):
        raise _InvalidNestedTargetChainGuard
    records = [
        {
            "identity_ref": _BUILTIN_CANONICAL_DIGEST(
                {
                    "device": source_root_identity[0],
                    "inode": source_root_identity[1],
                    "kind": "repository_executable_staging_root_identity",
                    "schema_version": 1,
                }
            ),
            "role": "source_executable_stage",
        }
    ]
    identities = {source_root_identity}
    if target_root_identity is not None:
        if target_root_identity in identities:
            raise _InvalidNestedTargetChainGuard
        identities.add(target_root_identity)
        records.append(
            {
                "identity_ref": _BUILTIN_CANONICAL_DIGEST(
                    {
                        "device": target_root_identity[0],
                        "inode": target_root_identity[1],
                        "kind": (
                            "repository_executable_shebang_target_"
                            "staging_root_identity"
                        ),
                        "schema_version": 1,
                    }
                ),
                "role": "shebang_target_stage",
            }
        )
    identity_set = frozenset(identities)
    digest = _BUILTIN_CANONICAL_DIGEST(
        {
            "guard_scope": _FIXED_GUARD_SCOPE,
            "identities": records,
            "kind": (
                "repository_executable_shebang_nested_target_"
                "protected_staging_root_identity_set"
            ),
            "schema_version": _FIXED_SCHEMA_VERSION,
        }
    )
    return identity_set, digest


def _validate_lineage(
    nested: dict[str, Any],
    target: dict[str, Any],
    source: dict[str, Any],
) -> None:
    if (
        type(nested) is not dict
        or type(target) is not dict
        or type(source) is not dict
    ):
        raise _InvalidNestedTargetChainGuard
    source_digest = _BUILTIN_CANONICAL_DIGEST(source)
    target_digest = _BUILTIN_CANONICAL_DIGEST(target)
    if (
        nested["staging_receipt_digest"] != source_digest
        or nested["source_staging_context_digest"]
        != source["staging_context_digest"]
        or nested["target_staging_receipt_digest"] != target_digest
        or target["staging_receipt_digest"] != source_digest
        or target["source_staging_context_digest"]
        != source["staging_context_digest"]
    ):
        raise _InvalidNestedTargetChainGuard
    common = (
        ("registration_digest", "registration_digest"),
        ("repository_ref", "repository_ref"),
        ("verification_commands_digest", "verification_commands_digest"),
        ("resolution_context_digest", "resolution_context_digest"),
    )
    if any(
        nested[nested_key] != source[source_key]
        or target[nested_key] != source[source_key]
        for nested_key, source_key in common
    ):
        raise _InvalidNestedTargetChainGuard


_BUILTIN_ACTIVE_TARGET_CONTEXT_SNAPSHOT = _active_target_context_snapshot
_BUILTIN_IDENTITY_SET_DIGEST = _identity_set_digest
_BUILTIN_PROTECTED_ROOT_SET = _protected_root_set
_BUILTIN_VALIDATE_LINEAGE = _validate_lineage


def _build_guarded_measurements(
    nested: dict[str, Any],
    *,
    known_source_identity_set_digest: str,
    known_target_identity_set_digest: str,
    protected_staging_root_identity_set_digest: str,
) -> tuple[
    RepositoryExecutableShebangNestedTargetChainGuardedMeasurement, ...
]:
    values: list[
        RepositoryExecutableShebangNestedTargetChainGuardedMeasurement
    ] = []
    for item in nested["measurements"]:
        reference = _BUILTIN_GUARDED_MEASUREMENT_REF_PROJECTION(
            nested_target_measurement_ref=item[
                "nested_target_measurement_ref"
            ],
            known_source_identity_set_digest=(
                known_source_identity_set_digest
            ),
            known_target_identity_set_digest=(
                known_target_identity_set_digest
            ),
            protected_staging_root_identity_set_digest=(
                protected_staging_root_identity_set_digest
            ),
        )
        value = _FIXED_GUARDED_MEASUREMENT_TYPE(
            kind=_FIXED_GUARDED_MEASUREMENT_KIND,
            nested_target_measurement_ref=item[
                "nested_target_measurement_ref"
            ],
            known_source_identity_set_digest=(
                known_source_identity_set_digest
            ),
            known_target_identity_set_digest=(
                known_target_identity_set_digest
            ),
            protected_staging_root_identity_set_digest=(
                protected_staging_root_identity_set_digest
            ),
            guarded_measurement_ref=_BUILTIN_CANONICAL_DIGEST(reference),
        )
        _BUILTIN_GUARDED_MEASUREMENT_PROJECTION(value)
        values.append(value)
    return tuple(values)


def _build_guard_requirements(
    nested: dict[str, Any],
    guarded_measurements: tuple[
        RepositoryExecutableShebangNestedTargetChainGuardedMeasurement, ...
    ],
) -> tuple[RepositoryExecutableShebangNestedTargetChainGuardRequirement, ...]:
    guarded_by_nested = {
        item.nested_target_measurement_ref: item.guarded_measurement_ref
        for item in guarded_measurements
    }
    values: list[
        RepositoryExecutableShebangNestedTargetChainGuardRequirement
    ] = []
    for item in nested["requirements"]:
        nested_measurement_ref = item["nested_target_measurement_ref"]
        if item["disposition"] == "direct_absolute_nested_target_measured":
            disposition = "known_chain_guard_verified"
            guarded_ref = guarded_by_nested.get(nested_measurement_ref)
            if guarded_ref is None:
                raise _InvalidNestedTargetChainGuard
        elif item["disposition"] in {
            "source_native_not_applicable",
            "target_native_not_applicable",
        }:
            disposition = item["disposition"]
            guarded_ref = None
        else:
            raise _InvalidNestedTargetChainGuard
        reference = _BUILTIN_GUARD_REQUIREMENT_REF_PROJECTION(
            nested_target_requirement_ref=item[
                "nested_target_requirement_ref"
            ],
            nested_target_measurement_ref=nested_measurement_ref,
            disposition=disposition,
            guarded_measurement_ref=guarded_ref,
        )
        value = _FIXED_GUARD_REQUIREMENT_TYPE(
            kind=_FIXED_REQUIREMENT_KIND,
            staged_file_ref=item["staged_file_ref"],
            runtime_file_ref=item["runtime_file_ref"],
            requirement_ref=item["requirement_ref"],
            target_requirement_ref=item["target_requirement_ref"],
            target_stage_requirement_ref=item[
                "target_stage_requirement_ref"
            ],
            target_runtime_requirement_ref=item[
                "target_runtime_requirement_ref"
            ],
            target_shebang_requirement_ref=item[
                "target_shebang_requirement_ref"
            ],
            nested_target_requirement_ref=item[
                "nested_target_requirement_ref"
            ],
            nested_target_measurement_ref=nested_measurement_ref,
            disposition=disposition,
            guarded_measurement_ref=guarded_ref,
            chain_guard_requirement_ref=_BUILTIN_CANONICAL_DIGEST(reference),
        )
        _BUILTIN_GUARD_REQUIREMENT_PROJECTION(value)
        values.append(value)
    return tuple(values)


def _build_guard_bindings(
    nested: dict[str, Any],
    requirements: tuple[
        RepositoryExecutableShebangNestedTargetChainGuardRequirement, ...
    ],
) -> tuple[RepositoryExecutableShebangNestedTargetChainGuardBinding, ...]:
    requirement_by_nested = {
        item.nested_target_requirement_ref: item for item in requirements
    }
    values: list[RepositoryExecutableShebangNestedTargetChainGuardBinding] = []
    for item in nested["bindings"]:
        requirement = requirement_by_nested.get(
            item["nested_target_requirement_ref"]
        )
        if requirement is None:
            raise _InvalidNestedTargetChainGuard
        value = _FIXED_GUARD_BINDING_TYPE(
            kind=_FIXED_BINDING_KIND,
            command_kind=item["command_kind"],
            command_id=item["command_id"],
            command_digest=item["command_digest"],
            staged_file_ref=item["staged_file_ref"],
            runtime_file_ref=item["runtime_file_ref"],
            requirement_ref=item["requirement_ref"],
            target_requirement_ref=item["target_requirement_ref"],
            target_stage_requirement_ref=item[
                "target_stage_requirement_ref"
            ],
            target_runtime_requirement_ref=item[
                "target_runtime_requirement_ref"
            ],
            target_shebang_requirement_ref=item[
                "target_shebang_requirement_ref"
            ],
            nested_target_requirement_ref=item[
                "nested_target_requirement_ref"
            ],
            chain_guard_requirement_ref=(
                requirement.chain_guard_requirement_ref
            ),
        )
        _BUILTIN_GUARD_BINDING_PROJECTION(value)
        values.append(value)
    return tuple(values)


_BUILTIN_BUILD_GUARDED_MEASUREMENTS = _build_guarded_measurements
_BUILTIN_BUILD_GUARD_REQUIREMENTS = _build_guard_requirements
_BUILTIN_BUILD_GUARD_BINDINGS = _build_guard_bindings


def inspect_staged_executable_shebang_nested_target_chain_guard(
    expected_nested_resolution: (
        RepositoryExecutableShebangNestedTargetResolutionReceipt
    ),
    *,
    expected_target_requirements: (
        RepositoryExecutableShebangTargetRequirementsReceipt
    ),
    expected_target_runtime: (
        RepositoryExecutableShebangTargetRuntimeManifestReceipt
    ),
    expected_target_staging: RepositoryExecutableShebangTargetStagingReceipt,
    target_lease: RepositoryExecutableShebangTargetStageLease,
    expected_source_staging: RepositoryExecutableStagingReceipt,
    source_lease: RepositoryExecutableStageLease,
    expected_nested_target_paths: tuple[Path, ...],
) -> RepositoryExecutableShebangNestedTargetChainGuardReceipt:
    """Verify exact known source-chain identities before any candidate read."""

    try:
        if (
            type(expected_nested_resolution) is not _FIXED_NESTED_RECEIPT_TYPE
            or type(expected_target_requirements)
            is not _FIXED_TARGET_REQUIREMENTS_TYPE
            or type(expected_target_runtime) is not _FIXED_TARGET_RUNTIME_TYPE
            or type(expected_target_staging) is not _FIXED_TARGET_STAGING_TYPE
            or type(target_lease) is not _FIXED_TARGET_LEASE_TYPE
            or type(expected_source_staging) is not _FIXED_SOURCE_STAGING_TYPE
            or type(source_lease) is not _FIXED_SOURCE_LEASE_TYPE
        ):
            raise _InvalidNestedTargetChainGuard
        nested_canonical = _BUILTIN_NESTED_RESOLUTION_PROJECTION(
            expected_nested_resolution
        )
        (
            source_canonical,
            source_files,
            source_root_identity,
            known_source_identity_refs,
        ) = _BUILTIN_ACTIVE_SOURCE_STAGE_SNAPSHOT(
            expected_source_staging,
            source_lease,
        )
        (
            target_canonical,
            target_files,
            target_root_identity,
            known_target_identity_refs,
        ) = _BUILTIN_ACTIVE_TARGET_CONTEXT_SNAPSHOT(
            expected_target_staging,
            target_lease,
        )
        _BUILTIN_VALIDATE_LINEAGE(
            nested_canonical,
            target_canonical,
            source_canonical,
        )
        protected_root_identities, protected_root_set_digest = (
            _BUILTIN_PROTECTED_ROOT_SET(
                source_root_identity,
                target_root_identity,
            )
        )
        source_identity_set_digest = _BUILTIN_IDENTITY_SET_DIGEST(
            known_source_identity_refs,
            role="source_executable",
        )
        target_identity_set_digest = _BUILTIN_IDENTITY_SET_DIGEST(
            known_target_identity_refs,
            role="shebang_target",
        )
        guard_context = _FIXED_GUARD_CONTEXT_TYPE(
            protected_root_identities=protected_root_identities,
            known_source_identity_refs=known_source_identity_refs,
            known_target_identity_refs=known_target_identity_refs,
        )

        action = _BUILTIN_INSPECT_NESTED_TARGETS(
            expected_target_requirements,
            expected_target_runtime=expected_target_runtime,
            expected_target_staging=expected_target_staging,
            lease=target_lease,
            expected_nested_target_paths=expected_nested_target_paths,
            guard_context=guard_context,
        )
        action_canonical = _BUILTIN_NESTED_RESOLUTION_PROJECTION(action)
        if action_canonical != nested_canonical:
            raise _InvalidNestedTargetChainGuard

        (
            middle_source,
            middle_source_files,
            middle_source_root,
            middle_source_identities,
        ) = _BUILTIN_ACTIVE_SOURCE_STAGE_SNAPSHOT(
            expected_source_staging,
            source_lease,
        )
        (
            middle_target,
            middle_target_files,
            middle_target_root,
            middle_target_identities,
        ) = _BUILTIN_ACTIVE_TARGET_CONTEXT_SNAPSHOT(
            expected_target_staging,
            target_lease,
        )
        if (
            middle_source != source_canonical
            or middle_source_files is not source_files
            or middle_source_root != source_root_identity
            or middle_source_identities != known_source_identity_refs
            or middle_target != target_canonical
            or middle_target_files is not target_files
            or middle_target_root != target_root_identity
            or middle_target_identities != known_target_identity_refs
        ):
            raise _InvalidNestedTargetChainGuard

        guarded_measurements = _BUILTIN_BUILD_GUARDED_MEASUREMENTS(
            nested_canonical,
            known_source_identity_set_digest=source_identity_set_digest,
            known_target_identity_set_digest=target_identity_set_digest,
            protected_staging_root_identity_set_digest=(
                protected_root_set_digest
            ),
        )
        requirements = _BUILTIN_BUILD_GUARD_REQUIREMENTS(
            nested_canonical,
            guarded_measurements,
        )
        bindings = _BUILTIN_BUILD_GUARD_BINDINGS(
            nested_canonical,
            requirements,
        )
        nested_receipt_digest = _BUILTIN_CANONICAL_DIGEST(nested_canonical)
        guarded_measurement_count = len(guarded_measurements)
        known_source_identity_count = len(known_source_identity_refs)
        known_target_identity_count = len(known_target_identity_refs)
        protected_staging_root_identity_count = len(
            protected_root_identities
        )
        total_guarded_bytes = nested_canonical["total_measured_bytes"]
        guard_summary_ref = _BUILTIN_CANONICAL_DIGEST(
            _BUILTIN_GUARD_SUMMARY_REF_PROJECTION(
                nested_target_resolution_receipt_digest=(
                    nested_receipt_digest
                ),
                known_source_identity_set_digest=(
                    source_identity_set_digest
                ),
                known_target_identity_set_digest=(
                    target_identity_set_digest
                ),
                protected_staging_root_identity_set_digest=(
                    protected_root_set_digest
                ),
                guarded_measurement_count=guarded_measurement_count,
                known_source_identity_count=known_source_identity_count,
                known_target_identity_count=known_target_identity_count,
                protected_staging_root_identity_count=(
                    protected_staging_root_identity_count
                ),
                total_guarded_bytes=total_guarded_bytes,
            )
        )
        receipt = _FIXED_RECEIPT_TYPE(
            kind=_FIXED_RECEIPT_KIND,
            schema_version=_FIXED_SCHEMA_VERSION,
            inspection_source=_FIXED_INSPECTION_SOURCE,
            guard_scope=_FIXED_GUARD_SCOPE,
            resolution_depth=_FIXED_RESOLUTION_DEPTH,
            maximum_resolution_depth=_FIXED_MAXIMUM_RESOLUTION_DEPTH,
            nested_target_resolution_receipt_digest=(
                nested_receipt_digest
            ),
            target_shebang_requirements_receipt_digest=nested_canonical[
                "target_shebang_requirements_receipt_digest"
            ],
            target_runtime_manifest_receipt_digest=nested_canonical[
                "target_runtime_manifest_receipt_digest"
            ],
            target_staging_receipt_digest=nested_canonical[
                "target_staging_receipt_digest"
            ],
            target_resolution_receipt_digest=nested_canonical[
                "target_resolution_receipt_digest"
            ],
            shebang_requirements_receipt_digest=nested_canonical[
                "shebang_requirements_receipt_digest"
            ],
            runtime_manifest_receipt_digest=nested_canonical[
                "runtime_manifest_receipt_digest"
            ],
            source_staging_receipt_digest=(
                _BUILTIN_CANONICAL_DIGEST(source_canonical)
            ),
            registration_digest=nested_canonical["registration_digest"],
            repository_ref=nested_canonical["repository_ref"],
            verification_commands_digest=nested_canonical[
                "verification_commands_digest"
            ],
            resolution_context_digest=nested_canonical[
                "resolution_context_digest"
            ],
            source_staging_context_digest=nested_canonical[
                "source_staging_context_digest"
            ],
            target_path_context_digest=nested_canonical[
                "target_path_context_digest"
            ],
            target_staging_context_digest=nested_canonical[
                "target_staging_context_digest"
            ],
            nested_target_path_context_digest=nested_canonical[
                "nested_target_path_context_digest"
            ],
            known_source_identity_set_digest=source_identity_set_digest,
            known_target_identity_set_digest=target_identity_set_digest,
            protected_staging_root_identity_set_digest=(
                protected_root_set_digest
            ),
            guard_summary_ref=guard_summary_ref,
            guarded_measurements=guarded_measurements,
            requirements=requirements,
            bindings=bindings,
            requirement_count=len(requirements),
            command_count=len(bindings),
            known_chain_guard_verified_count=sum(
                item.disposition == "known_chain_guard_verified"
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
            guarded_measurement_count=guarded_measurement_count,
            known_source_identity_count=known_source_identity_count,
            known_target_identity_count=known_target_identity_count,
            protected_staging_root_identity_count=(
                protected_staging_root_identity_count
            ),
            total_guarded_bytes=total_guarded_bytes,
        )
        _BUILTIN_RECEIPT_PROJECTION(receipt)

        if (
            _BUILTIN_NESTED_RESOLUTION_PROJECTION(
                expected_nested_resolution
            )
            != nested_canonical
            or _BUILTIN_SOURCE_STAGING_PROJECTION(expected_source_staging)
            != source_canonical
        ):
            raise _InvalidNestedTargetChainGuard
        (
            final_source,
            final_source_files,
            final_source_root,
            final_source_identities,
        ) = _BUILTIN_ACTIVE_SOURCE_STAGE_SNAPSHOT(
            expected_source_staging,
            source_lease,
        )
        (
            final_target,
            final_target_files,
            final_target_root,
            final_target_identities,
        ) = _BUILTIN_ACTIVE_TARGET_CONTEXT_SNAPSHOT(
            expected_target_staging,
            target_lease,
        )
        if (
            final_source != source_canonical
            or final_source_files is not source_files
            or final_source_root != source_root_identity
            or final_source_identities != known_source_identity_refs
            or final_target != target_canonical
            or final_target_files is not target_files
            or final_target_root != target_root_identity
            or final_target_identities != known_target_identity_refs
        ):
            raise _InvalidNestedTargetChainGuard
        def closing_source_anchor() -> None:
            (
                closing_source,
                closing_source_files,
                closing_source_root,
                closing_source_identities,
            ) = _BUILTIN_ACTIVE_SOURCE_STAGE_SNAPSHOT(
                expected_source_staging,
                source_lease,
            )
            if (
                closing_source != source_canonical
                or closing_source_files is not source_files
                or closing_source_root != source_root_identity
                or closing_source_identities != known_source_identity_refs
            ):
                raise _InvalidNestedTargetChainGuard

        # Receipt construction is complete before this last reproduction.
        # Its target descriptor anchors run first, the exact source lease is
        # then re-anchored, and guarded namespace validation remains the final
        # proof action before the private resolver returns.
        _BUILTIN_INSPECT_NESTED_TARGETS(
            expected_target_requirements,
            expected_target_runtime=expected_target_runtime,
            expected_target_staging=expected_target_staging,
            lease=target_lease,
            expected_nested_target_paths=expected_nested_target_paths,
            guard_context=guard_context,
            expected_receipt_canonical=nested_canonical,
            closing_guard_anchor=closing_source_anchor,
        )
        return receipt
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise _FIXED_VALIDATION_ERROR(_INVALID_MESSAGE) from None


__all__ = [
    "GUARD_SCOPE",
    "INSPECTION_SOURCE",
    "MAXIMUM_RESOLUTION_DEPTH",
    "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_CHAIN_GUARD_BINDING_KIND",
    "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_CHAIN_GUARD_EVIDENCE_KIND",
    "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_CHAIN_GUARD_KIND",
    "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_CHAIN_GUARD_REQUIREMENT_KIND",
    "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_CHAIN_GUARD_SCHEMA_VERSION",
    "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_CHAIN_GUARDED_MEASUREMENT_KIND",
    "RESOLUTION_DEPTH",
    "RepositoryExecutableShebangNestedTargetChainGuardBinding",
    "RepositoryExecutableShebangNestedTargetChainGuardReceipt",
    "RepositoryExecutableShebangNestedTargetChainGuardRequirement",
    "RepositoryExecutableShebangNestedTargetChainGuardedMeasurement",
    "inspect_staged_executable_shebang_nested_target_chain_guard",
]
