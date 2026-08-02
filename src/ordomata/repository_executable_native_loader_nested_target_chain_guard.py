"""Known-chain identity guard for bounded native-loader target inspection.

This separate Class 0 boundary consumes the exact source-stage and staged-
target proof chain and reproduces the fixed depth-two native-loader target
measurement with stronger exclusions active before candidate bytes are read.
It excludes exact original and staged source/target executable identities and
every anchored staging-root identity present.  It does not claim general cycle
closure, path-spelling source re-entry exclusion, broader protected-root
closure, freshness, authority, staging, dispatch, or execution.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import re
from typing import Any

from .authorization import canonical_json
from .errors import ValidationError
from .repository_executable_native_loader_nested_target_resolution import (
    RepositoryExecutableNativeLoaderNestedTargetBinding,
    RepositoryExecutableNativeLoaderNestedTargetLineage,
    RepositoryExecutableNativeLoaderNestedTargetMeasurement,
    RepositoryExecutableNativeLoaderNestedTargetRequirement,
    RepositoryExecutableNativeLoaderNestedTargetResolutionReceipt,
    _NestedTargetGuardContext,
    _UniqueNestedTargetConsumer,
    _inspect_staged_executable_native_loader_nested_targets,
    _receipt_projection as _nested_resolution_projection_v1,
)
from .repository_executable_native_loader_target_loader_requirements import (
    RepositoryExecutableNativeLoaderTargetLoaderRequirementsReceipt,
)
from .repository_executable_native_loader_target_resolution import (
    RepositoryExecutableNativeLoaderTargetResolutionReceipt,
)
from .repository_executable_native_loader_target_runtime_manifest import (
    RepositoryExecutableNativeLoaderTargetRuntimeManifestReceipt,
    _active_target_stage_snapshot,
)
from .repository_executable_native_loader_target_staging import (
    RepositoryExecutableNativeLoaderTargetStageLease,
    RepositoryExecutableNativeLoaderTargetStagingReceipt,
)
from .repository_executable_shebang_nested_target_chain_guard import (
    _active_source_stage_snapshot,
    _source_staging_projection,
)
from .repository_executable_staging import (
    RepositoryExecutableStageLease,
    RepositoryExecutableStagingReceipt,
)


REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_CHAIN_GUARD_SCHEMA_VERSION = 1
REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_CHAIN_GUARD_KIND = (
    "repository_executable_native_loader_nested_target_chain_guard"
)
REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_CHAIN_GUARD_EVIDENCE_KIND = (
    "repository_executable_native_loader_nested_target_chain_guard_validation"
)
REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_CHAIN_GUARDED_MEASUREMENT_KIND = (
    "repository_executable_native_loader_nested_target_chain_guarded_measurement"
)
REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_CHAIN_GUARD_REQUIREMENT_KIND = (
    "repository_executable_native_loader_nested_target_chain_guard_requirement"
)
REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_CHAIN_GUARD_LINEAGE_KIND = (
    "repository_executable_native_loader_nested_target_chain_guard_lineage"
)
REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_CHAIN_GUARD_BINDING_KIND = (
    "repository_executable_native_loader_nested_target_chain_guard_binding"
)
INSPECTION_SOURCE = "controller_inspected"
GUARD_SCOPE = (
    "known_native_loader_source_chain_identity_and_staging_root_identity_v1"
)
RESOLUTION_DEPTH = 2
MAXIMUM_RESOLUTION_DEPTH = 2

_FIXED_SCHEMA_VERSION = 1
_FIXED_RECEIPT_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_CHAIN_GUARD_KIND
)
_FIXED_EVIDENCE_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_CHAIN_GUARD_EVIDENCE_KIND
)
_FIXED_MEASUREMENT_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_CHAIN_GUARDED_MEASUREMENT_KIND
)
_FIXED_REQUIREMENT_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_CHAIN_GUARD_REQUIREMENT_KIND
)
_FIXED_LINEAGE_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_CHAIN_GUARD_LINEAGE_KIND
)
_FIXED_BINDING_KIND = (
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_CHAIN_GUARD_BINDING_KIND
)
_FIXED_INSPECTION_SOURCE = INSPECTION_SOURCE
_FIXED_GUARD_SCOPE = GUARD_SCOPE
_INVALID_MESSAGE = (
    "repository executable native loader nested target chain guard is invalid"
)
_DIGEST_PREFIX = "sha256:"
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER_PATTERN = re.compile(r"[a-z][a-z0-9_.-]{0,119}\Z")
_COMMAND_KINDS = ("format", "lint", "type_check", "test", "build")
_REQUIREMENT_DISPOSITIONS = (
    "known_chain_guard_verified",
    "loader_declaration_absent",
    "unsupported_native_layout",
    "non_native_not_applicable",
)
_LINEAGE_DISPOSITIONS = (
    "guard_requirement_bound",
    "loader_declaration_absent",
    "unsupported_native_layout",
    "non_native_not_applicable",
)
_MAX_FILES = 80
_MAX_REQUIREMENTS = 80
_MAX_LINEAGES = 80
_MAX_COMMANDS = 80
_MAX_TOTAL_BYTES = 256 * 1024 * 1024

_BUILTIN_CANONICAL_JSON = canonical_json
_BUILTIN_SHA256 = hashlib.sha256
_FIXED_VALIDATION_ERROR = ValidationError
_FIXED_NESTED_RECEIPT_TYPE = (
    RepositoryExecutableNativeLoaderNestedTargetResolutionReceipt
)
_FIXED_NESTED_MEASUREMENT_TYPE = (
    RepositoryExecutableNativeLoaderNestedTargetMeasurement
)
_FIXED_NESTED_REQUIREMENT_TYPE = (
    RepositoryExecutableNativeLoaderNestedTargetRequirement
)
_FIXED_NESTED_LINEAGE_TYPE = (
    RepositoryExecutableNativeLoaderNestedTargetLineage
)
_FIXED_NESTED_BINDING_TYPE = (
    RepositoryExecutableNativeLoaderNestedTargetBinding
)
_FIXED_TARGET_REQUIREMENTS_TYPE = (
    RepositoryExecutableNativeLoaderTargetLoaderRequirementsReceipt
)
_FIXED_TARGET_RUNTIME_TYPE = (
    RepositoryExecutableNativeLoaderTargetRuntimeManifestReceipt
)
_FIXED_TARGET_STAGING_TYPE = (
    RepositoryExecutableNativeLoaderTargetStagingReceipt
)
_FIXED_TARGET_RESOLUTION_TYPE = (
    RepositoryExecutableNativeLoaderTargetResolutionReceipt
)
_FIXED_TARGET_LEASE_TYPE = RepositoryExecutableNativeLoaderTargetStageLease
_FIXED_SOURCE_STAGING_TYPE = RepositoryExecutableStagingReceipt
_FIXED_SOURCE_LEASE_TYPE = RepositoryExecutableStageLease
_FIXED_GUARD_CONTEXT_TYPE = _NestedTargetGuardContext
_BUILTIN_NESTED_RESOLUTION_PROJECTION = _nested_resolution_projection_v1
_BUILTIN_ACTIVE_TARGET_STAGE_SNAPSHOT = _active_target_stage_snapshot
_BUILTIN_ACTIVE_SOURCE_STAGE_SNAPSHOT = _active_source_stage_snapshot
_BUILTIN_SOURCE_STAGING_PROJECTION = _source_staging_projection
_BUILTIN_INSPECT_NESTED_TARGETS = (
    _inspect_staged_executable_native_loader_nested_targets
)


def _captured_canonical_digest(value: Any) -> str:
    encoded = _BUILTIN_CANONICAL_JSON(value).encode("utf-8")
    return _DIGEST_PREFIX + _BUILTIN_SHA256(encoded).hexdigest()


_BUILTIN_CANONICAL_DIGEST = _captured_canonical_digest


class _InvalidNativeLoaderNestedTargetChainGuard(ValueError):
    """Private invalid-input sentinel with no public detail."""


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeLoaderNestedTargetChainGuardedMeasurement:
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
class RepositoryExecutableNativeLoaderNestedTargetChainGuardRequirement:
    """One native-loader target requirement's guarded outcome."""

    kind: str
    target_staged_file_ref: str = field(repr=False)
    target_runtime_file_ref: str = field(repr=False)
    target_loader_requirement_ref: str = field(repr=False)
    nested_target_requirement_ref: str = field(repr=False)
    nested_target_measurement_ref: str | None = field(repr=False)
    disposition: str
    guarded_measurement_ref: str | None = field(repr=False)
    chain_guard_requirement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _guard_requirement_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeLoaderNestedTargetChainGuardLineage:
    """One source command lineage bound through guarded native-loader proof."""

    kind: str
    staged_file_ref: str = field(repr=False)
    runtime_file_ref: str = field(repr=False)
    requirement_ref: str = field(repr=False)
    target_requirement_ref: str = field(repr=False)
    target_stage_requirement_ref: str = field(repr=False)
    target_runtime_requirement_ref: str = field(repr=False)
    target_loader_lineage_ref: str = field(repr=False)
    nested_target_lineage_ref: str = field(repr=False)
    nested_target_requirement_ref: str | None = field(repr=False)
    disposition: str
    chain_guard_requirement_ref: str | None = field(repr=False)
    chain_guard_lineage_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _guard_lineage_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeLoaderNestedTargetChainGuardBinding:
    """One command bound to a guarded native-loader lineage."""

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

    def to_canonical(self) -> dict[str, Any]:
        return _guard_binding_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeLoaderNestedTargetChainGuardReceipt:
    """Digest-only evidence for exact native-loader chain exclusions."""

    kind: str
    schema_version: int
    inspection_source: str
    guard_scope: str
    resolution_depth: int
    maximum_resolution_depth: int
    nested_target_resolution_receipt_digest: str = field(repr=False)
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
    known_source_identity_set_digest: str = field(repr=False)
    known_target_identity_set_digest: str = field(repr=False)
    protected_staging_root_identity_set_digest: str = field(repr=False)
    guard_summary_ref: str = field(repr=False)
    guarded_measurements: tuple[
        RepositoryExecutableNativeLoaderNestedTargetChainGuardedMeasurement, ...
    ] = field(repr=False)
    requirements: tuple[
        RepositoryExecutableNativeLoaderNestedTargetChainGuardRequirement, ...
    ] = field(repr=False)
    lineages: tuple[
        RepositoryExecutableNativeLoaderNestedTargetChainGuardLineage, ...
    ] = field(repr=False)
    bindings: tuple[
        RepositoryExecutableNativeLoaderNestedTargetChainGuardBinding, ...
    ] = field(repr=False)
    requirement_count: int
    lineage_count: int
    command_count: int
    known_chain_guard_verified_count: int
    loader_declaration_absent_count: int
    unsupported_native_layout_count: int
    non_native_not_applicable_count: int
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
    RepositoryExecutableNativeLoaderNestedTargetChainGuardedMeasurement
)
_FIXED_GUARD_REQUIREMENT_TYPE = (
    RepositoryExecutableNativeLoaderNestedTargetChainGuardRequirement
)
_FIXED_GUARD_LINEAGE_TYPE = (
    RepositoryExecutableNativeLoaderNestedTargetChainGuardLineage
)
_FIXED_GUARD_BINDING_TYPE = (
    RepositoryExecutableNativeLoaderNestedTargetChainGuardBinding
)
_FIXED_RECEIPT_TYPE = (
    RepositoryExecutableNativeLoaderNestedTargetChainGuardReceipt
)


def _is_digest(value: Any) -> bool:
    return type(value) is str and _DIGEST_PATTERN.fullmatch(value) is not None


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
        raise _InvalidNativeLoaderNestedTargetChainGuard
    return {
        "guard_scope": _FIXED_GUARD_SCOPE,
        "kind": (
            "repository_executable_native_loader_nested_target_"
            "chain_guarded_measurement_ref"
        ),
        "known_source_identity_set_digest": known_source_identity_set_digest,
        "known_target_identity_set_digest": known_target_identity_set_digest,
        "nested_target_measurement_ref": nested_target_measurement_ref,
        "protected_staging_root_identity_set_digest": (
            protected_staging_root_identity_set_digest
        ),
        "schema_version": _FIXED_SCHEMA_VERSION,
    }


def _guarded_measurement_projection(
    value: RepositoryExecutableNativeLoaderNestedTargetChainGuardedMeasurement,
) -> dict[str, Any]:
    if type(value) is not _FIXED_GUARDED_MEASUREMENT_TYPE or value.kind != _FIXED_MEASUREMENT_KIND:
        raise _InvalidNativeLoaderNestedTargetChainGuard
    reference = _BUILTIN_GUARDED_MEASUREMENT_REF_PROJECTION(
        nested_target_measurement_ref=value.nested_target_measurement_ref,
        known_source_identity_set_digest=value.known_source_identity_set_digest,
        known_target_identity_set_digest=value.known_target_identity_set_digest,
        protected_staging_root_identity_set_digest=(
            value.protected_staging_root_identity_set_digest
        ),
    )
    if value.guarded_measurement_ref != _BUILTIN_CANONICAL_DIGEST(reference):
        raise _InvalidNativeLoaderNestedTargetChainGuard
    return {**reference, "kind": value.kind, "guarded_measurement_ref": value.guarded_measurement_ref}


_BUILTIN_GUARDED_MEASUREMENT_REF_PROJECTION = (
    _guarded_measurement_ref_projection
)
_BUILTIN_GUARDED_MEASUREMENT_PROJECTION = _guarded_measurement_projection


def _guard_requirement_ref_projection(
    *,
    nested_target_requirement_ref: str,
    nested_target_measurement_ref: str | None,
    disposition: str,
    guarded_measurement_ref: str | None,
) -> dict[str, Any]:
    verified = disposition == "known_chain_guard_verified"
    if (
        not _BUILTIN_IS_DIGEST(nested_target_requirement_ref)
        or type(disposition) is not str
        or disposition not in _REQUIREMENT_DISPOSITIONS
        or (
            nested_target_measurement_ref is not None
            and not _BUILTIN_IS_DIGEST(nested_target_measurement_ref)
        )
        or (
            guarded_measurement_ref is not None
            and not _BUILTIN_IS_DIGEST(guarded_measurement_ref)
        )
        or verified
        != (
            nested_target_measurement_ref is not None
            and guarded_measurement_ref is not None
        )
        or (
            not verified
            and (
                nested_target_measurement_ref is not None
                or guarded_measurement_ref is not None
            )
        )
    ):
        raise _InvalidNativeLoaderNestedTargetChainGuard
    return {
        "disposition": disposition,
        "guard_scope": _FIXED_GUARD_SCOPE,
        "guarded_measurement_ref": guarded_measurement_ref,
        "kind": (
            "repository_executable_native_loader_nested_target_"
            "chain_guard_requirement_ref"
        ),
        "nested_target_measurement_ref": nested_target_measurement_ref,
        "nested_target_requirement_ref": nested_target_requirement_ref,
        "schema_version": _FIXED_SCHEMA_VERSION,
    }


def _guard_requirement_projection(
    value: RepositoryExecutableNativeLoaderNestedTargetChainGuardRequirement,
) -> dict[str, Any]:
    lineage = (
        value.target_staged_file_ref,
        value.target_runtime_file_ref,
        value.target_loader_requirement_ref,
        value.nested_target_requirement_ref,
        value.chain_guard_requirement_ref,
    )
    if (
        type(value) is not _FIXED_GUARD_REQUIREMENT_TYPE
        or value.kind != _FIXED_REQUIREMENT_KIND
        or not all(_BUILTIN_IS_DIGEST(item) for item in lineage)
    ):
        raise _InvalidNativeLoaderNestedTargetChainGuard
    reference = _BUILTIN_GUARD_REQUIREMENT_REF_PROJECTION(
        nested_target_requirement_ref=value.nested_target_requirement_ref,
        nested_target_measurement_ref=value.nested_target_measurement_ref,
        disposition=value.disposition,
        guarded_measurement_ref=value.guarded_measurement_ref,
    )
    if value.chain_guard_requirement_ref != _BUILTIN_CANONICAL_DIGEST(reference):
        raise _InvalidNativeLoaderNestedTargetChainGuard
    return {
        **reference,
        "chain_guard_requirement_ref": value.chain_guard_requirement_ref,
        "kind": value.kind,
        "target_loader_requirement_ref": value.target_loader_requirement_ref,
        "target_runtime_file_ref": value.target_runtime_file_ref,
        "target_staged_file_ref": value.target_staged_file_ref,
    }


def _guard_lineage_ref_projection(
    *,
    nested_target_lineage_ref: str,
    nested_target_requirement_ref: str | None,
    disposition: str,
    chain_guard_requirement_ref: str | None,
) -> dict[str, Any]:
    bound = disposition == "guard_requirement_bound"
    if (
        not _BUILTIN_IS_DIGEST(nested_target_lineage_ref)
        or type(disposition) is not str
        or disposition not in _LINEAGE_DISPOSITIONS
        or (
            nested_target_requirement_ref is not None
            and not _BUILTIN_IS_DIGEST(nested_target_requirement_ref)
        )
        or (
            chain_guard_requirement_ref is not None
            and not _BUILTIN_IS_DIGEST(chain_guard_requirement_ref)
        )
        or bound
        != (
            nested_target_requirement_ref is not None
            and chain_guard_requirement_ref is not None
        )
        or (
            not bound
            and (
                nested_target_requirement_ref is not None
                or chain_guard_requirement_ref is not None
            )
        )
    ):
        raise _InvalidNativeLoaderNestedTargetChainGuard
    return {
        "chain_guard_requirement_ref": chain_guard_requirement_ref,
        "disposition": disposition,
        "guard_scope": _FIXED_GUARD_SCOPE,
        "kind": (
            "repository_executable_native_loader_nested_target_"
            "chain_guard_lineage_ref"
        ),
        "nested_target_lineage_ref": nested_target_lineage_ref,
        "nested_target_requirement_ref": nested_target_requirement_ref,
        "schema_version": _FIXED_SCHEMA_VERSION,
    }


def _guard_lineage_projection(
    value: RepositoryExecutableNativeLoaderNestedTargetChainGuardLineage,
) -> dict[str, Any]:
    digests = (
        value.staged_file_ref,
        value.runtime_file_ref,
        value.requirement_ref,
        value.target_requirement_ref,
        value.target_stage_requirement_ref,
        value.target_runtime_requirement_ref,
        value.target_loader_lineage_ref,
        value.nested_target_lineage_ref,
        value.chain_guard_lineage_ref,
    )
    if (
        type(value) is not _FIXED_GUARD_LINEAGE_TYPE
        or value.kind != _FIXED_LINEAGE_KIND
        or not all(_BUILTIN_IS_DIGEST(item) for item in digests)
    ):
        raise _InvalidNativeLoaderNestedTargetChainGuard
    reference = _BUILTIN_GUARD_LINEAGE_REF_PROJECTION(
        nested_target_lineage_ref=value.nested_target_lineage_ref,
        nested_target_requirement_ref=value.nested_target_requirement_ref,
        disposition=value.disposition,
        chain_guard_requirement_ref=value.chain_guard_requirement_ref,
    )
    if value.chain_guard_lineage_ref != _BUILTIN_CANONICAL_DIGEST(reference):
        raise _InvalidNativeLoaderNestedTargetChainGuard
    return {
        **reference,
        "chain_guard_lineage_ref": value.chain_guard_lineage_ref,
        "kind": value.kind,
        "requirement_ref": value.requirement_ref,
        "runtime_file_ref": value.runtime_file_ref,
        "staged_file_ref": value.staged_file_ref,
        "target_loader_lineage_ref": value.target_loader_lineage_ref,
        "target_requirement_ref": value.target_requirement_ref,
        "target_runtime_requirement_ref": value.target_runtime_requirement_ref,
        "target_stage_requirement_ref": value.target_stage_requirement_ref,
    }


def _guard_binding_projection(
    value: RepositoryExecutableNativeLoaderNestedTargetChainGuardBinding,
) -> dict[str, Any]:
    digests = (
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
    )
    if (
        type(value) is not _FIXED_GUARD_BINDING_TYPE
        or value.kind != _FIXED_BINDING_KIND
        or type(value.command_kind) is not str
        or value.command_kind not in _COMMAND_KINDS
        or type(value.command_id) is not str
        or _IDENTIFIER_PATTERN.fullmatch(value.command_id) is None
        or not all(_BUILTIN_IS_DIGEST(item) for item in digests)
    ):
        raise _InvalidNativeLoaderNestedTargetChainGuard
    return {
        "chain_guard_lineage_ref": value.chain_guard_lineage_ref,
        "command_digest": value.command_digest,
        "command_id": value.command_id,
        "command_kind": value.command_kind,
        "kind": value.kind,
        "nested_target_lineage_ref": value.nested_target_lineage_ref,
        "requirement_ref": value.requirement_ref,
        "runtime_file_ref": value.runtime_file_ref,
        "staged_file_ref": value.staged_file_ref,
        "target_loader_lineage_ref": value.target_loader_lineage_ref,
        "target_requirement_ref": value.target_requirement_ref,
        "target_runtime_requirement_ref": value.target_runtime_requirement_ref,
        "target_stage_requirement_ref": value.target_stage_requirement_ref,
    }


_BUILTIN_GUARD_REQUIREMENT_REF_PROJECTION = _guard_requirement_ref_projection
_BUILTIN_GUARD_REQUIREMENT_PROJECTION = _guard_requirement_projection
_BUILTIN_GUARD_LINEAGE_REF_PROJECTION = _guard_lineage_ref_projection
_BUILTIN_GUARD_LINEAGE_PROJECTION = _guard_lineage_projection
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
    digests = (
        nested_target_resolution_receipt_digest,
        known_source_identity_set_digest,
        known_target_identity_set_digest,
        protected_staging_root_identity_set_digest,
    )
    counts = (
        guarded_measurement_count,
        known_source_identity_count,
        known_target_identity_count,
        protected_staging_root_identity_count,
        total_guarded_bytes,
    )
    if (
        not all(_BUILTIN_IS_DIGEST(item) for item in digests)
        or any(type(item) is not int or item < 0 for item in counts)
        or protected_staging_root_identity_count not in {1, 2}
        or total_guarded_bytes > _MAX_TOTAL_BYTES
    ):
        raise _InvalidNativeLoaderNestedTargetChainGuard
    return {
        "guard_scope": _FIXED_GUARD_SCOPE,
        "guarded_measurement_count": guarded_measurement_count,
        "kind": (
            "repository_executable_native_loader_nested_target_"
            "chain_guard_summary_ref"
        ),
        "known_source_identity_count": known_source_identity_count,
        "known_source_identity_set_digest": known_source_identity_set_digest,
        "known_target_identity_count": known_target_identity_count,
        "known_target_identity_set_digest": known_target_identity_set_digest,
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
    value: RepositoryExecutableNativeLoaderNestedTargetChainGuardReceipt,
) -> dict[str, Any]:
    digest_fields = (
        value.nested_target_resolution_receipt_digest,
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
        value.known_source_identity_set_digest,
        value.known_target_identity_set_digest,
        value.protected_staging_root_identity_set_digest,
        value.guard_summary_ref,
    )
    count_fields = (
        value.requirement_count,
        value.lineage_count,
        value.command_count,
        value.known_chain_guard_verified_count,
        value.loader_declaration_absent_count,
        value.unsupported_native_layout_count,
        value.non_native_not_applicable_count,
        value.guarded_measurement_count,
        value.known_source_identity_count,
        value.known_target_identity_count,
        value.protected_staging_root_identity_count,
        value.total_guarded_bytes,
    )
    if (
        type(value) is not _FIXED_RECEIPT_TYPE
        or value.kind != _FIXED_RECEIPT_KIND
        or type(value.schema_version) is not int
        or value.schema_version != _FIXED_SCHEMA_VERSION
        or value.inspection_source != _FIXED_INSPECTION_SOURCE
        or value.guard_scope != _FIXED_GUARD_SCOPE
        or type(value.resolution_depth) is not int
        or value.resolution_depth != RESOLUTION_DEPTH
        or type(value.maximum_resolution_depth) is not int
        or value.maximum_resolution_depth != MAXIMUM_RESOLUTION_DEPTH
        or not all(_BUILTIN_IS_DIGEST(item) for item in digest_fields)
        or type(value.guarded_measurements) is not tuple
        or len(value.guarded_measurements) > _MAX_FILES
        or type(value.requirements) is not tuple
        or len(value.requirements) > _MAX_REQUIREMENTS
        or type(value.lineages) is not tuple
        or not 1 <= len(value.lineages) <= _MAX_LINEAGES
        or type(value.bindings) is not tuple
        or not 1 <= len(value.bindings) <= _MAX_COMMANDS
        or any(type(item) is not int or item < 0 for item in count_fields)
        or value.requirement_count != len(value.requirements)
        or value.lineage_count != len(value.lineages)
        or value.command_count != len(value.bindings)
        or value.guarded_measurement_count != len(value.guarded_measurements)
        or value.protected_staging_root_identity_count not in {1, 2}
        or value.total_guarded_bytes > _MAX_TOTAL_BYTES
    ):
        raise _InvalidNativeLoaderNestedTargetChainGuard

    guarded = [
        _BUILTIN_GUARDED_MEASUREMENT_PROJECTION(item)
        for item in value.guarded_measurements
    ]
    requirements = [
        _BUILTIN_GUARD_REQUIREMENT_PROJECTION(item)
        for item in value.requirements
    ]
    lineages = [
        _BUILTIN_GUARD_LINEAGE_PROJECTION(item) for item in value.lineages
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
            raise _InvalidNativeLoaderNestedTargetChainGuard
        guarded_by_nested[item.nested_target_measurement_ref] = (
            item.guarded_measurement_ref
        )
        guarded_refs.add(item.guarded_measurement_ref)

    requirement_by_nested: dict[
        str, RepositoryExecutableNativeLoaderNestedTargetChainGuardRequirement
    ] = {}
    used_guarded: set[str] = set()
    dispositions = {item: 0 for item in _REQUIREMENT_DISPOSITIONS}
    for item in value.requirements:
        if (
            item.nested_target_requirement_ref in requirement_by_nested
            or item.chain_guard_requirement_ref
            in {
                other.chain_guard_requirement_ref
                for other in requirement_by_nested.values()
            }
        ):
            raise _InvalidNativeLoaderNestedTargetChainGuard
        if item.disposition == "known_chain_guard_verified":
            guarded_ref = guarded_by_nested.get(
                item.nested_target_measurement_ref or ""
            )
            if guarded_ref != item.guarded_measurement_ref:
                raise _InvalidNativeLoaderNestedTargetChainGuard
            used_guarded.add(guarded_ref)
        requirement_by_nested[item.nested_target_requirement_ref] = item
        dispositions[item.disposition] += 1

    lineage_by_nested: dict[
        str, RepositoryExecutableNativeLoaderNestedTargetChainGuardLineage
    ] = {}
    used_requirements: set[str] = set()
    for item in value.lineages:
        if (
            item.nested_target_lineage_ref in lineage_by_nested
            or item.chain_guard_lineage_ref
            in {other.chain_guard_lineage_ref for other in lineage_by_nested.values()}
        ):
            raise _InvalidNativeLoaderNestedTargetChainGuard
        if item.disposition == "guard_requirement_bound":
            requirement = requirement_by_nested.get(
                item.nested_target_requirement_ref or ""
            )
            if (
                requirement is None
                or item.chain_guard_requirement_ref
                != requirement.chain_guard_requirement_ref
            ):
                raise _InvalidNativeLoaderNestedTargetChainGuard
            used_requirements.add(requirement.nested_target_requirement_ref)
        lineage_by_nested[item.nested_target_lineage_ref] = item

    command_ids: set[str] = set()
    bound_lineages: list[str] = []
    prior_kind = -1
    for item in value.bindings:
        lineage = lineage_by_nested.get(item.nested_target_lineage_ref)
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
            or item.chain_guard_lineage_ref != lineage.chain_guard_lineage_ref
            or item.command_id in command_ids
            or kind_index < prior_kind
        ):
            raise _InvalidNativeLoaderNestedTargetChainGuard
        command_ids.add(item.command_id)
        if item.nested_target_lineage_ref not in bound_lineages:
            bound_lineages.append(item.nested_target_lineage_ref)
        prior_kind = kind_index

    expected_summary = _BUILTIN_CANONICAL_DIGEST(
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
    if (
        used_guarded != guarded_refs
        or used_requirements != set(requirement_by_nested)
        or tuple(bound_lineages)
        != tuple(item.nested_target_lineage_ref for item in value.lineages)
        or dispositions["known_chain_guard_verified"]
        != value.known_chain_guard_verified_count
        or dispositions["loader_declaration_absent"]
        != value.loader_declaration_absent_count
        or dispositions["unsupported_native_layout"]
        != value.unsupported_native_layout_count
        or dispositions["non_native_not_applicable"]
        != value.non_native_not_applicable_count
        or sum(dispositions.values()) != value.requirement_count
        or value.guard_summary_ref != expected_summary
    ):
        raise _InvalidNativeLoaderNestedTargetChainGuard

    return {
        "bindings": bindings,
        "command_count": value.command_count,
        "guard_scope": value.guard_scope,
        "guard_summary_ref": value.guard_summary_ref,
        "guarded_measurement_count": value.guarded_measurement_count,
        "guarded_measurements": guarded,
        "inspection_source": value.inspection_source,
        "kind": value.kind,
        "known_chain_guard_verified_count": value.known_chain_guard_verified_count,
        "known_source_identity_count": value.known_source_identity_count,
        "known_source_identity_set_digest": value.known_source_identity_set_digest,
        "known_target_identity_count": value.known_target_identity_count,
        "known_target_identity_set_digest": value.known_target_identity_set_digest,
        "lineage_count": value.lineage_count,
        "lineages": lineages,
        "loader_declaration_absent_count": value.loader_declaration_absent_count,
        "maximum_resolution_depth": value.maximum_resolution_depth,
        "native_loader_requirements_receipt_digest": value.native_loader_requirements_receipt_digest,
        "nested_loader_path_context_digest": value.nested_loader_path_context_digest,
        "nested_target_resolution_receipt_digest": value.nested_target_resolution_receipt_digest,
        "non_native_not_applicable_count": value.non_native_not_applicable_count,
        "protected_staging_root_identity_count": value.protected_staging_root_identity_count,
        "protected_staging_root_identity_set_digest": value.protected_staging_root_identity_set_digest,
        "registration_digest": value.registration_digest,
        "repository_ref": value.repository_ref,
        "requirement_count": value.requirement_count,
        "requirements": requirements,
        "resolution_context_digest": value.resolution_context_digest,
        "resolution_depth": value.resolution_depth,
        "runtime_manifest_receipt_digest": value.runtime_manifest_receipt_digest,
        "schema_version": value.schema_version,
        "source_staging_context_digest": value.source_staging_context_digest,
        "source_staging_receipt_digest": value.source_staging_receipt_digest,
        "target_loader_requirements_receipt_digest": value.target_loader_requirements_receipt_digest,
        "target_resolution_receipt_digest": value.target_resolution_receipt_digest,
        "target_runtime_manifest_receipt_digest": value.target_runtime_manifest_receipt_digest,
        "target_staging_context_digest": value.target_staging_context_digest,
        "target_staging_receipt_digest": value.target_staging_receipt_digest,
        "first_loader_path_context_digest": value.first_loader_path_context_digest,
        "total_guarded_bytes": value.total_guarded_bytes,
        "unsupported_native_layout_count": value.unsupported_native_layout_count,
        "verification_commands_digest": value.verification_commands_digest,
    }


_BUILTIN_RECEIPT_PROJECTION = _receipt_projection


def _evidence_projection(
    value: RepositoryExecutableNativeLoaderNestedTargetChainGuardReceipt,
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
        "closing_namespace_guard_verified": path_lookup_performed,
        "command_count": canonical["command_count"],
        "current_freshness_verified": False,
        "dependency_closure_verified": False,
        "descriptor_numbers_exposed": False,
        "effect_class": 0,
        "execution_enabled": False,
        "generic_cycle_exclusion_verified": False,
        "guard_scope": canonical["guard_scope"],
        "guard_summary_ref": canonical["guard_summary_ref"],
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
        "nested_target_resolution_receipt_digest": canonical[
            "nested_target_resolution_receipt_digest"
        ],
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
        "target_staging_root_identity_ancestor_excluded": (
            target_staging_root_present
        ),
        "target_staging_root_identity_exclusion_verified": (
            target_staging_root_present
        ),
        "target_staging_root_path_reentry_exclusion_verified": False,
        "target_staging_root_path_reopen_performed": False,
        "temporary_names_exposed": False,
        "total_guarded_bytes": canonical["total_guarded_bytes"],
        "two_pass_guard_measurement_verified": True,
        "validation_mode": "read_only",
    }


_BUILTIN_EVIDENCE_PROJECTION = _evidence_projection


def _active_target_context_snapshot(
    expected_target_staging: RepositoryExecutableNativeLoaderTargetStagingReceipt,
    target_lease: RepositoryExecutableNativeLoaderTargetStageLease,
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
        raise _InvalidNativeLoaderNestedTargetChainGuard
    try:
        canonical, retained = _BUILTIN_ACTIVE_TARGET_STAGE_SNAPSHOT(
            expected_target_staging,
            target_lease,
        )
    except (AttributeError, OSError, TypeError, ValueError):
        raise _InvalidNativeLoaderNestedTargetChainGuard from None
    if type(canonical) is not dict or type(retained) is not tuple:
        raise _InvalidNativeLoaderNestedTargetChainGuard
    identity_refs = frozenset(
        reference
        for item in canonical["staged_files"]
        for reference in (
            item["source_filesystem_identity_ref"],
            item["staged_filesystem_identity_ref"],
        )
    )
    if len(identity_refs) != 2 * len(canonical["staged_files"]):
        raise _InvalidNativeLoaderNestedTargetChainGuard
    root_identity: tuple[int, int] | None = None
    if canonical["staging_root_used"]:
        metadata = target_lease._root_metadata
        if (
            type(metadata) is not tuple
            or len(metadata) != 9
            or any(type(item) is not int for item in metadata)
        ):
            raise _InvalidNativeLoaderNestedTargetChainGuard
        root_identity = (metadata[0], metadata[1])
    elif target_lease._root_metadata is not None:
        raise _InvalidNativeLoaderNestedTargetChainGuard
    return canonical, retained, root_identity, identity_refs


def _identity_set_digest(identity_refs: frozenset[str], *, role: str) -> str:
    if (
        type(identity_refs) is not frozenset
        or role not in {"source_executable", "native_loader_target"}
        or any(not _BUILTIN_IS_DIGEST(item) for item in identity_refs)
    ):
        raise _InvalidNativeLoaderNestedTargetChainGuard
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "guard_scope": _FIXED_GUARD_SCOPE,
            "identity_refs": sorted(identity_refs),
            "kind": (
                "repository_executable_native_loader_nested_target_"
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
                or any(type(item) is not int or item < 0 for item in target_root_identity)
            )
        )
    ):
        raise _InvalidNativeLoaderNestedTargetChainGuard
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
            raise _InvalidNativeLoaderNestedTargetChainGuard
        identities.add(target_root_identity)
        records.append(
            {
                "identity_ref": _BUILTIN_CANONICAL_DIGEST(
                    {
                        "device": target_root_identity[0],
                        "inode": target_root_identity[1],
                        "kind": (
                            "repository_executable_native_loader_target_"
                            "staging_root_identity"
                        ),
                        "schema_version": 1,
                    }
                ),
                "role": "native_loader_target_stage",
            }
        )
    identity_set = frozenset(identities)
    digest = _BUILTIN_CANONICAL_DIGEST(
        {
            "guard_scope": _FIXED_GUARD_SCOPE,
            "identities": records,
            "kind": (
                "repository_executable_native_loader_nested_target_"
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
    if not all(type(item) is dict for item in (nested, target, source)):
        raise _InvalidNativeLoaderNestedTargetChainGuard
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
        or nested["first_loader_path_context_digest"]
        != target["loader_path_context_digest"]
        or nested["target_staging_context_digest"]
        != target["target_staging_context_digest"]
    ):
        raise _InvalidNativeLoaderNestedTargetChainGuard
    if any(
        nested[field] != target[field]
        for field in (
            "native_loader_requirements_receipt_digest",
            "runtime_manifest_receipt_digest",
        )
    ):
        raise _InvalidNativeLoaderNestedTargetChainGuard
    common = (
        "registration_digest",
        "repository_ref",
        "verification_commands_digest",
        "resolution_context_digest",
    )
    if any(
        nested[field] != target[field]
        or nested[field] != source[field]
        for field in common
    ):
        raise _InvalidNativeLoaderNestedTargetChainGuard


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
    RepositoryExecutableNativeLoaderNestedTargetChainGuardedMeasurement, ...
]:
    values = []
    for item in nested["measurements"]:
        reference = _BUILTIN_GUARDED_MEASUREMENT_REF_PROJECTION(
            nested_target_measurement_ref=item["nested_target_measurement_ref"],
            known_source_identity_set_digest=known_source_identity_set_digest,
            known_target_identity_set_digest=known_target_identity_set_digest,
            protected_staging_root_identity_set_digest=(
                protected_staging_root_identity_set_digest
            ),
        )
        value = _FIXED_GUARDED_MEASUREMENT_TYPE(
            kind=_FIXED_MEASUREMENT_KIND,
            nested_target_measurement_ref=item["nested_target_measurement_ref"],
            known_source_identity_set_digest=known_source_identity_set_digest,
            known_target_identity_set_digest=known_target_identity_set_digest,
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
        RepositoryExecutableNativeLoaderNestedTargetChainGuardedMeasurement, ...
    ],
) -> tuple[
    RepositoryExecutableNativeLoaderNestedTargetChainGuardRequirement, ...
]:
    guarded_by_nested = {
        item.nested_target_measurement_ref: item.guarded_measurement_ref
        for item in guarded_measurements
    }
    values = []
    for item in nested["requirements"]:
        nested_disposition = item["nested_target_disposition"]
        nested_measurement_ref = item["nested_target_measurement_ref"]
        if nested_disposition == "declared_nested_loader_target_measured":
            disposition = "known_chain_guard_verified"
            guarded_ref = guarded_by_nested.get(nested_measurement_ref)
            if guarded_ref is None:
                raise _InvalidNativeLoaderNestedTargetChainGuard
        elif nested_disposition in _REQUIREMENT_DISPOSITIONS[1:]:
            disposition = nested_disposition
            guarded_ref = None
        else:
            raise _InvalidNativeLoaderNestedTargetChainGuard
        reference = _BUILTIN_GUARD_REQUIREMENT_REF_PROJECTION(
            nested_target_requirement_ref=item["nested_target_requirement_ref"],
            nested_target_measurement_ref=nested_measurement_ref,
            disposition=disposition,
            guarded_measurement_ref=guarded_ref,
        )
        value = _FIXED_GUARD_REQUIREMENT_TYPE(
            kind=_FIXED_REQUIREMENT_KIND,
            target_staged_file_ref=item["target_staged_file_ref"],
            target_runtime_file_ref=item["target_runtime_file_ref"],
            target_loader_requirement_ref=item["target_loader_requirement_ref"],
            nested_target_requirement_ref=item["nested_target_requirement_ref"],
            nested_target_measurement_ref=nested_measurement_ref,
            disposition=disposition,
            guarded_measurement_ref=guarded_ref,
            chain_guard_requirement_ref=_BUILTIN_CANONICAL_DIGEST(reference),
        )
        _BUILTIN_GUARD_REQUIREMENT_PROJECTION(value)
        values.append(value)
    return tuple(values)


def _build_guard_lineages(
    nested: dict[str, Any],
    requirements: tuple[
        RepositoryExecutableNativeLoaderNestedTargetChainGuardRequirement, ...
    ],
) -> tuple[
    RepositoryExecutableNativeLoaderNestedTargetChainGuardLineage, ...
]:
    requirement_by_nested = {
        item.nested_target_requirement_ref: item for item in requirements
    }
    values = []
    for item in nested["lineages"]:
        if item["disposition"] == "nested_loader_requirement_bound":
            disposition = "guard_requirement_bound"
            nested_requirement_ref = item["nested_target_requirement_ref"]
            requirement = requirement_by_nested.get(nested_requirement_ref)
            if requirement is None:
                raise _InvalidNativeLoaderNestedTargetChainGuard
            chain_requirement_ref = requirement.chain_guard_requirement_ref
        elif item["disposition"] in _LINEAGE_DISPOSITIONS[1:]:
            disposition = item["disposition"]
            nested_requirement_ref = None
            chain_requirement_ref = None
        else:
            raise _InvalidNativeLoaderNestedTargetChainGuard
        reference = _BUILTIN_GUARD_LINEAGE_REF_PROJECTION(
            nested_target_lineage_ref=item["nested_target_lineage_ref"],
            nested_target_requirement_ref=nested_requirement_ref,
            disposition=disposition,
            chain_guard_requirement_ref=chain_requirement_ref,
        )
        value = _FIXED_GUARD_LINEAGE_TYPE(
            kind=_FIXED_LINEAGE_KIND,
            staged_file_ref=item["staged_file_ref"],
            runtime_file_ref=item["runtime_file_ref"],
            requirement_ref=item["requirement_ref"],
            target_requirement_ref=item["target_requirement_ref"],
            target_stage_requirement_ref=item["target_stage_requirement_ref"],
            target_runtime_requirement_ref=item["target_runtime_requirement_ref"],
            target_loader_lineage_ref=item["target_loader_lineage_ref"],
            nested_target_lineage_ref=item["nested_target_lineage_ref"],
            nested_target_requirement_ref=nested_requirement_ref,
            disposition=disposition,
            chain_guard_requirement_ref=chain_requirement_ref,
            chain_guard_lineage_ref=_BUILTIN_CANONICAL_DIGEST(reference),
        )
        _BUILTIN_GUARD_LINEAGE_PROJECTION(value)
        values.append(value)
    return tuple(values)


def _build_guard_bindings(
    nested: dict[str, Any],
    lineages: tuple[
        RepositoryExecutableNativeLoaderNestedTargetChainGuardLineage, ...
    ],
) -> tuple[
    RepositoryExecutableNativeLoaderNestedTargetChainGuardBinding, ...
]:
    lineage_by_nested = {
        item.nested_target_lineage_ref: item for item in lineages
    }
    values = []
    for item in nested["bindings"]:
        lineage = lineage_by_nested.get(item["nested_target_lineage_ref"])
        if lineage is None:
            raise _InvalidNativeLoaderNestedTargetChainGuard
        value = _FIXED_GUARD_BINDING_TYPE(
            kind=_FIXED_BINDING_KIND,
            command_kind=item["command_kind"],
            command_id=item["command_id"],
            command_digest=item["command_digest"],
            staged_file_ref=item["staged_file_ref"],
            runtime_file_ref=item["runtime_file_ref"],
            requirement_ref=item["requirement_ref"],
            target_requirement_ref=item["target_requirement_ref"],
            target_stage_requirement_ref=item["target_stage_requirement_ref"],
            target_runtime_requirement_ref=item["target_runtime_requirement_ref"],
            target_loader_lineage_ref=item["target_loader_lineage_ref"],
            nested_target_lineage_ref=item["nested_target_lineage_ref"],
            chain_guard_lineage_ref=lineage.chain_guard_lineage_ref,
        )
        _BUILTIN_GUARD_BINDING_PROJECTION(value)
        values.append(value)
    return tuple(values)


_BUILTIN_BUILD_GUARDED_MEASUREMENTS = _build_guarded_measurements
_BUILTIN_BUILD_GUARD_REQUIREMENTS = _build_guard_requirements
_BUILTIN_BUILD_GUARD_LINEAGES = _build_guard_lineages
_BUILTIN_BUILD_GUARD_BINDINGS = _build_guard_bindings


def _inspect_staged_executable_native_loader_nested_target_chain_guard(
    expected_nested_resolution: (
        RepositoryExecutableNativeLoaderNestedTargetResolutionReceipt
    ),
    *,
    expected_target_requirements: (
        RepositoryExecutableNativeLoaderTargetLoaderRequirementsReceipt
    ),
    expected_target_runtime: (
        RepositoryExecutableNativeLoaderTargetRuntimeManifestReceipt
    ),
    expected_target_staging: (
        RepositoryExecutableNativeLoaderTargetStagingReceipt
    ),
    expected_target_resolution: (
        RepositoryExecutableNativeLoaderTargetResolutionReceipt
    ),
    target_lease: RepositoryExecutableNativeLoaderTargetStageLease,
    expected_source_staging: RepositoryExecutableStagingReceipt,
    source_lease: RepositoryExecutableStageLease,
    expected_loader_paths: tuple[Path, ...],
    expected_nested_loader_paths: tuple[Path, ...],
    unique_nested_target_consumer: (
        _UniqueNestedTargetConsumer | None
    ) = None,
) -> RepositoryExecutableNativeLoaderNestedTargetChainGuardReceipt:
    """Verify exact native-loader source-chain identities before reads."""

    try:
        if (
            type(expected_nested_resolution) is not _FIXED_NESTED_RECEIPT_TYPE
            or type(expected_target_requirements)
            is not _FIXED_TARGET_REQUIREMENTS_TYPE
            or type(expected_target_runtime) is not _FIXED_TARGET_RUNTIME_TYPE
            or type(expected_target_staging) is not _FIXED_TARGET_STAGING_TYPE
            or type(expected_target_resolution)
            is not _FIXED_TARGET_RESOLUTION_TYPE
            or type(target_lease) is not _FIXED_TARGET_LEASE_TYPE
            or type(expected_source_staging) is not _FIXED_SOURCE_STAGING_TYPE
            or type(source_lease) is not _FIXED_SOURCE_LEASE_TYPE
        ):
            raise _InvalidNativeLoaderNestedTargetChainGuard
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
        protected_roots, protected_root_set_digest = (
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
            role="native_loader_target",
        )
        guard_context = _FIXED_GUARD_CONTEXT_TYPE(
            protected_root_identities=protected_roots,
            known_source_identity_refs=known_source_identity_refs,
            known_target_identity_refs=known_target_identity_refs,
        )

        action = _BUILTIN_INSPECT_NESTED_TARGETS(
            expected_target_requirements,
            expected_target_runtime=expected_target_runtime,
            expected_target_staging=expected_target_staging,
            expected_target_resolution=expected_target_resolution,
            lease=target_lease,
            expected_loader_paths=expected_loader_paths,
            expected_nested_loader_paths=expected_nested_loader_paths,
            guard_context=guard_context,
            unique_nested_target_consumer=unique_nested_target_consumer,
        )
        if _BUILTIN_NESTED_RESOLUTION_PROJECTION(action) != nested_canonical:
            raise _InvalidNativeLoaderNestedTargetChainGuard

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
            raise _InvalidNativeLoaderNestedTargetChainGuard

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
        lineages = _BUILTIN_BUILD_GUARD_LINEAGES(
            nested_canonical,
            requirements,
        )
        bindings = _BUILTIN_BUILD_GUARD_BINDINGS(
            nested_canonical,
            lineages,
        )
        nested_digest = _BUILTIN_CANONICAL_DIGEST(nested_canonical)
        guarded_measurement_count = len(guarded_measurements)
        source_identity_count = len(known_source_identity_refs)
        target_identity_count = len(known_target_identity_refs)
        root_identity_count = len(protected_roots)
        total_guarded_bytes = nested_canonical["total_measured_bytes"]
        guard_summary_ref = _BUILTIN_CANONICAL_DIGEST(
            _BUILTIN_GUARD_SUMMARY_REF_PROJECTION(
                nested_target_resolution_receipt_digest=nested_digest,
                known_source_identity_set_digest=source_identity_set_digest,
                known_target_identity_set_digest=target_identity_set_digest,
                protected_staging_root_identity_set_digest=(
                    protected_root_set_digest
                ),
                guarded_measurement_count=guarded_measurement_count,
                known_source_identity_count=source_identity_count,
                known_target_identity_count=target_identity_count,
                protected_staging_root_identity_count=root_identity_count,
                total_guarded_bytes=total_guarded_bytes,
            )
        )
        receipt = _FIXED_RECEIPT_TYPE(
            kind=_FIXED_RECEIPT_KIND,
            schema_version=_FIXED_SCHEMA_VERSION,
            inspection_source=_FIXED_INSPECTION_SOURCE,
            guard_scope=_FIXED_GUARD_SCOPE,
            resolution_depth=RESOLUTION_DEPTH,
            maximum_resolution_depth=MAXIMUM_RESOLUTION_DEPTH,
            nested_target_resolution_receipt_digest=nested_digest,
            target_loader_requirements_receipt_digest=nested_canonical[
                "target_loader_requirements_receipt_digest"
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
            native_loader_requirements_receipt_digest=nested_canonical[
                "native_loader_requirements_receipt_digest"
            ],
            runtime_manifest_receipt_digest=nested_canonical[
                "runtime_manifest_receipt_digest"
            ],
            source_staging_receipt_digest=_BUILTIN_CANONICAL_DIGEST(
                source_canonical
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
            first_loader_path_context_digest=nested_canonical[
                "first_loader_path_context_digest"
            ],
            target_staging_context_digest=nested_canonical[
                "target_staging_context_digest"
            ],
            nested_loader_path_context_digest=nested_canonical[
                "nested_loader_path_context_digest"
            ],
            known_source_identity_set_digest=source_identity_set_digest,
            known_target_identity_set_digest=target_identity_set_digest,
            protected_staging_root_identity_set_digest=(
                protected_root_set_digest
            ),
            guard_summary_ref=guard_summary_ref,
            guarded_measurements=guarded_measurements,
            requirements=requirements,
            lineages=lineages,
            bindings=bindings,
            requirement_count=len(requirements),
            lineage_count=len(lineages),
            command_count=len(bindings),
            known_chain_guard_verified_count=sum(
                item.disposition == "known_chain_guard_verified"
                for item in requirements
            ),
            loader_declaration_absent_count=sum(
                item.disposition == "loader_declaration_absent"
                for item in requirements
            ),
            unsupported_native_layout_count=sum(
                item.disposition == "unsupported_native_layout"
                for item in requirements
            ),
            non_native_not_applicable_count=sum(
                item.disposition == "non_native_not_applicable"
                for item in requirements
            ),
            guarded_measurement_count=guarded_measurement_count,
            known_source_identity_count=source_identity_count,
            known_target_identity_count=target_identity_count,
            protected_staging_root_identity_count=root_identity_count,
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
            raise _InvalidNativeLoaderNestedTargetChainGuard
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
            raise _InvalidNativeLoaderNestedTargetChainGuard

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
                raise _InvalidNativeLoaderNestedTargetChainGuard

        _BUILTIN_INSPECT_NESTED_TARGETS(
            expected_target_requirements,
            expected_target_runtime=expected_target_runtime,
            expected_target_staging=expected_target_staging,
            expected_target_resolution=expected_target_resolution,
            lease=target_lease,
            expected_loader_paths=expected_loader_paths,
            expected_nested_loader_paths=expected_nested_loader_paths,
            guard_context=guard_context,
            expected_receipt_canonical=nested_canonical,
            closing_guard_anchor=closing_source_anchor,
        )
        return receipt
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise _FIXED_VALIDATION_ERROR(_INVALID_MESSAGE) from None


_BUILTIN_INSPECT_NATIVE_LOADER_NESTED_TARGET_CHAIN_GUARD = (
    _inspect_staged_executable_native_loader_nested_target_chain_guard
)


def inspect_staged_executable_native_loader_nested_target_chain_guard(
    expected_nested_resolution: (
        RepositoryExecutableNativeLoaderNestedTargetResolutionReceipt
    ),
    *,
    expected_target_requirements: (
        RepositoryExecutableNativeLoaderTargetLoaderRequirementsReceipt
    ),
    expected_target_runtime: (
        RepositoryExecutableNativeLoaderTargetRuntimeManifestReceipt
    ),
    expected_target_staging: (
        RepositoryExecutableNativeLoaderTargetStagingReceipt
    ),
    expected_target_resolution: (
        RepositoryExecutableNativeLoaderTargetResolutionReceipt
    ),
    target_lease: RepositoryExecutableNativeLoaderTargetStageLease,
    expected_source_staging: RepositoryExecutableStagingReceipt,
    source_lease: RepositoryExecutableStageLease,
    expected_loader_paths: tuple[Path, ...],
    expected_nested_loader_paths: tuple[Path, ...],
) -> RepositoryExecutableNativeLoaderNestedTargetChainGuardReceipt:
    """Verify exact native-loader source-chain identities before reads."""

    return _BUILTIN_INSPECT_NATIVE_LOADER_NESTED_TARGET_CHAIN_GUARD(
        expected_nested_resolution,
        expected_target_requirements=expected_target_requirements,
        expected_target_runtime=expected_target_runtime,
        expected_target_staging=expected_target_staging,
        expected_target_resolution=expected_target_resolution,
        target_lease=target_lease,
        expected_source_staging=expected_source_staging,
        source_lease=source_lease,
        expected_loader_paths=expected_loader_paths,
        expected_nested_loader_paths=expected_nested_loader_paths,
    )


__all__ = [
    "GUARD_SCOPE",
    "INSPECTION_SOURCE",
    "MAXIMUM_RESOLUTION_DEPTH",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_CHAIN_GUARD_BINDING_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_CHAIN_GUARD_EVIDENCE_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_CHAIN_GUARD_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_CHAIN_GUARD_LINEAGE_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_CHAIN_GUARD_REQUIREMENT_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_CHAIN_GUARD_SCHEMA_VERSION",
    "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_CHAIN_GUARDED_MEASUREMENT_KIND",
    "RESOLUTION_DEPTH",
    "RepositoryExecutableNativeLoaderNestedTargetChainGuardBinding",
    "RepositoryExecutableNativeLoaderNestedTargetChainGuardLineage",
    "RepositoryExecutableNativeLoaderNestedTargetChainGuardReceipt",
    "RepositoryExecutableNativeLoaderNestedTargetChainGuardRequirement",
    "RepositoryExecutableNativeLoaderNestedTargetChainGuardedMeasurement",
    "inspect_staged_executable_native_loader_nested_target_chain_guard",
]
