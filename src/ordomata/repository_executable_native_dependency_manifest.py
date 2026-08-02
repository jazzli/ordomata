"""Bind non-absolute native dependency declarations to controller paths.

This Class 0 boundary consumes one exact native-dependency requirements
receipt, runtime manifest, staging receipt, and active process-local lease.
Every bare, relative, or Mach-O tokenized dependency declaration must match an
ordered controller-supplied manifest entry that names one canonical absolute
path.  The boundary does not interpret loader search rules, read a target,
stage a target, mutate the lease, or execute a process.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import re
from typing import Any

from .authorization import canonical_json
from .errors import ValidationError
from .repository_executable_native_dependency_requirements import (
    RepositoryExecutableNativeDependencyDeclaration,
    RepositoryExecutableNativeDependencyRequirement,
    RepositoryExecutableNativeDependencyRequirementBinding,
    RepositoryExecutableNativeDependencyRequirementsReceipt,
    _dependency_name_ref as _dependency_name_ref,
    _receipt_projection as _dependency_receipt_projection,
    inspect_staged_executable_native_dependency_requirements,
)
from .repository_executable_native_loader_requirements import (
    inspect_staged_executable_native_loader_requirements,
)
from .repository_executable_runtime_manifest import (
    RepositoryExecutableRuntimeManifestReceipt,
    _active_stage_snapshot,
    _runtime_manifest_projection,
)
from .repository_executable_staging import (
    RepositoryExecutableStageLease,
    RepositoryExecutableStagingReceipt,
    _staging_receipt_projection,
)


REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_SCHEMA_VERSION = 1
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_KIND = (
    "repository_executable_native_dependency_manifest"
)
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_EVIDENCE_KIND = (
    "repository_executable_native_dependency_manifest_validation"
)
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_ENTRY_KIND = (
    "repository_executable_native_dependency_manifest_entry"
)
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_BINDING_KIND = (
    "repository_executable_native_dependency_manifest_binding"
)
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_REQUIREMENT_KIND = (
    "repository_executable_native_dependency_manifest_requirement"
)
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_COMMAND_BINDING_KIND = (
    "repository_executable_native_dependency_manifest_command_binding"
)
MANIFEST_SOURCE = "controller_explicit"
MANIFEST_SCOPE = "explicit_nonabsolute_native_dependency_manifest_binding_v1"

_FIXED_SCHEMA_VERSION = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_SCHEMA_VERSION
_FIXED_RECEIPT_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_KIND
_FIXED_EVIDENCE_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_EVIDENCE_KIND
_FIXED_ENTRY_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_ENTRY_KIND
_FIXED_BINDING_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_BINDING_KIND
_FIXED_REQUIREMENT_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_REQUIREMENT_KIND
_FIXED_COMMAND_BINDING_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_COMMAND_BINDING_KIND
_FIXED_MANIFEST_SOURCE = MANIFEST_SOURCE
_FIXED_MANIFEST_SCOPE = MANIFEST_SCOPE

_INVALID_MESSAGE = "repository executable native dependency manifest is invalid"
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
_UPSTREAM_DISPOSITIONS = (
    "elf_dependencies_declared",
    "elf_dependencies_absent",
    "mach_o_dependencies_declared",
    "mach_o_dependencies_absent",
    "unsupported_native_layout",
    "non_native_not_applicable",
)
_PATH_STYLES = (
    "absolute",
    "bare",
    "relative",
    "at_rpath",
    "at_loader_path",
    "at_executable_path",
)
_MANIFEST_DISPOSITIONS = (
    "absolute_dependency_not_manifest_applicable",
    "non_absolute_dependency_explicit_manifest_bound",
)
_MAX_FILES = 80
_MAX_COMMANDS = 80
_MAX_DECLARATIONS_PER_FILE = 512
_MAX_DECLARATIONS = _MAX_FILES * _MAX_DECLARATIONS_PER_FILE
_MAX_MANIFEST_ENTRIES = 512
_MAX_DEPENDENCY_NAME_BYTES = 4_095
_MAX_TARGET_PATH_BYTES = 4_095
_MAX_TOTAL_TARGET_PATH_BYTES = 64 * 1024
_MAX_TARGET_PATH_COMPONENTS = 128
_MAX_TARGET_PATH_COMPONENT_BYTES = 255
_CONCRETE_PATH_TYPE = type(Path())

_BUILTIN_SHA256 = hashlib.sha256
_BUILTIN_CANONICAL_JSON = canonical_json


def _captured_canonical_digest(value: Any) -> str:
    encoded = _BUILTIN_CANONICAL_JSON(value).encode("utf-8")
    return _DIGEST_PREFIX + _BUILTIN_SHA256(encoded).hexdigest()


_BUILTIN_CANONICAL_DIGEST = _captured_canonical_digest
_BUILTIN_DEPENDENCY_RECEIPT_PROJECTION = _dependency_receipt_projection
_BUILTIN_RUNTIME_PROJECTION = _runtime_manifest_projection
_BUILTIN_STAGING_PROJECTION = _staging_receipt_projection
_BUILTIN_INSPECT_NATIVE_LOADER = inspect_staged_executable_native_loader_requirements
_BUILTIN_INSPECT_DEPENDENCY_REQUIREMENTS = (
    inspect_staged_executable_native_dependency_requirements
)
_BUILTIN_DEPENDENCY_NAME_REF = _dependency_name_ref
_BUILTIN_ACTIVE_STAGE_SNAPSHOT = _active_stage_snapshot
_FIXED_DEPENDENCY_RECEIPT_TYPE = RepositoryExecutableNativeDependencyRequirementsReceipt
_FIXED_UPSTREAM_REQUIREMENT_TYPE = RepositoryExecutableNativeDependencyRequirement
_FIXED_UPSTREAM_DECLARATION_TYPE = RepositoryExecutableNativeDependencyDeclaration
_FIXED_UPSTREAM_BINDING_TYPE = RepositoryExecutableNativeDependencyRequirementBinding
_FIXED_RUNTIME_TYPE = RepositoryExecutableRuntimeManifestReceipt
_FIXED_STAGING_TYPE = RepositoryExecutableStagingReceipt
_FIXED_LEASE_TYPE = RepositoryExecutableStageLease
_FIXED_VALIDATION_ERROR = ValidationError


class _InvalidNativeDependencyManifest(ValueError):
    """Private fail-closed sentinel whose details never cross the API."""


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeDependencyManifestEntry:
    """One private controller-supplied mapping for a non-absolute declaration."""

    kind: str
    runtime_file_ref: str = field(repr=False)
    dependency_declaration_ref: str = field(repr=False)
    dependency_name: bytes = field(repr=False)
    target_path: Path = field(repr=False)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeDependencyManifestBinding:
    """One digest-only declaration-to-manifest-target binding."""

    kind: str
    runtime_file_ref: str = field(repr=False)
    dependency_declaration_ref: str = field(repr=False)
    dependency_name_ref: str = field(repr=False)
    format_class: str
    ordinal: int
    path_style: str
    manifest_target_ref: str = field(repr=False)
    manifest_binding_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_BINDING_PROJECTION(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeDependencyManifestRequirement:
    """One direct runtime file's explicit manifest outcomes."""

    kind: str
    staged_file_ref: str = field(repr=False)
    runtime_file_ref: str = field(repr=False)
    native_dependency_requirement_ref: str = field(repr=False)
    runtime_classification: str
    dependency_disposition: str
    bindings: tuple[RepositoryExecutableNativeDependencyManifestBinding, ...] = field(repr=False)
    dependency_declaration_count: int
    non_absolute_dependency_count: int
    manifest_bound_dependency_count: int
    manifest_requirement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_REQUIREMENT_PROJECTION(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeDependencyManifestCommandBinding:
    """One registered command bound to one manifest requirement."""

    kind: str
    command_kind: str
    command_id: str = field(repr=False)
    command_digest: str = field(repr=False)
    staged_file_ref: str = field(repr=False)
    runtime_file_ref: str = field(repr=False)
    native_dependency_requirement_ref: str = field(repr=False)
    manifest_requirement_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_COMMAND_BINDING_PROJECTION(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeDependencyManifestReceipt:
    """Digest-only historical evidence for explicit manifest binding."""

    kind: str
    schema_version: int
    manifest_source: str
    manifest_scope: str
    native_dependency_requirements_receipt_digest: str = field(repr=False)
    runtime_manifest_receipt_digest: str = field(repr=False)
    staging_receipt_digest: str = field(repr=False)
    registration_digest: str = field(repr=False)
    repository_ref: str = field(repr=False)
    verification_commands_digest: str = field(repr=False)
    resolution_context_digest: str = field(repr=False)
    staging_context_digest: str = field(repr=False)
    manifest_context_digest: str = field(repr=False)
    requirements: tuple[RepositoryExecutableNativeDependencyManifestRequirement, ...] = field(repr=False)
    command_bindings: tuple[RepositoryExecutableNativeDependencyManifestCommandBinding, ...] = field(repr=False)
    requirement_count: int
    command_count: int
    dependency_declaration_count: int
    non_absolute_dependency_declaration_count: int
    manifest_bound_dependency_count: int
    unique_manifest_target_count: int

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_RECEIPT_PROJECTION(self)

    @property
    def receipt_digest(self) -> str:
        return _BUILTIN_CANONICAL_DIGEST(_BUILTIN_RECEIPT_PROJECTION(self))

    def to_evidence(self) -> dict[str, Any]:
        return _BUILTIN_EVIDENCE_PROJECTION(self)


_FIXED_ENTRY_TYPE = RepositoryExecutableNativeDependencyManifestEntry
_FIXED_BINDING_TYPE = RepositoryExecutableNativeDependencyManifestBinding
_FIXED_REQUIREMENT_TYPE = RepositoryExecutableNativeDependencyManifestRequirement
_FIXED_COMMAND_BINDING_TYPE = RepositoryExecutableNativeDependencyManifestCommandBinding
_FIXED_RECEIPT_TYPE = RepositoryExecutableNativeDependencyManifestReceipt


def _is_digest(value: Any) -> bool:
    return type(value) is str and _DIGEST_PATTERN.fullmatch(value) is not None


_BUILTIN_IS_DIGEST = _is_digest


def _canonical_target_path(path: Any) -> tuple[Path, bytes]:
    if type(path) is not _CONCRETE_PATH_TYPE:
        raise _InvalidNativeDependencyManifest
    try:
        spelling = os.fspath(path)
        encoded = spelling.encode("ascii")
    except (AttributeError, TypeError, UnicodeEncodeError):
        raise _InvalidNativeDependencyManifest from None
    if (
        not spelling.startswith("/")
        or spelling == "/"
        or spelling.endswith("/")
        or "//" in spelling
        or not 1 <= len(encoded) <= _MAX_TARGET_PATH_BYTES
    ):
        raise _InvalidNativeDependencyManifest
    components = spelling[1:].split("/")
    if (
        not 1 <= len(components) <= _MAX_TARGET_PATH_COMPONENTS
        or any(
            not component
            or component in {".", ".."}
            or len(component.encode("ascii")) > _MAX_TARGET_PATH_COMPONENT_BYTES
            for component in components
        )
        or os.fspath(Path(spelling)) != spelling
    ):
        raise _InvalidNativeDependencyManifest
    return path, encoded


_BUILTIN_CANONICAL_TARGET_PATH = _canonical_target_path


def _manifest_target_ref(path: Path) -> str:
    _path, encoded = _BUILTIN_CANONICAL_TARGET_PATH(path)
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "kind": "repository_executable_native_dependency_manifest_target_ref",
            "manifest_scope": _FIXED_MANIFEST_SCOPE,
            "schema_version": _FIXED_SCHEMA_VERSION,
            "target_path_ascii": encoded.decode("ascii"),
        }
    )


_BUILTIN_MANIFEST_TARGET_REF = _manifest_target_ref


def _binding_ref_projection(
    *,
    runtime_file_ref: str,
    dependency_declaration_ref: str,
    dependency_name_ref: str,
    format_class: str,
    ordinal: int,
    path_style: str,
    manifest_target_ref: str,
) -> dict[str, Any]:
    return {
        "dependency_declaration_ref": dependency_declaration_ref,
        "dependency_name_ref": dependency_name_ref,
        "format_class": format_class,
        "kind": "repository_executable_native_dependency_manifest_binding_ref",
        "manifest_scope": _FIXED_MANIFEST_SCOPE,
        "manifest_target_ref": manifest_target_ref,
        "ordinal": ordinal,
        "path_style": path_style,
        "runtime_file_ref": runtime_file_ref,
        "schema_version": _FIXED_SCHEMA_VERSION,
    }


_BUILTIN_BINDING_REF_PROJECTION = _binding_ref_projection


def _binding_projection(
    value: RepositoryExecutableNativeDependencyManifestBinding,
) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_BINDING_TYPE
        or value.kind != _FIXED_BINDING_KIND
        or not all(
            _BUILTIN_IS_DIGEST(item)
            for item in (
                value.runtime_file_ref,
                value.dependency_declaration_ref,
                value.dependency_name_ref,
                value.manifest_target_ref,
                value.manifest_binding_ref,
            )
        )
        or value.format_class not in _FORMAT_CLASSES
        or type(value.ordinal) is not int
        or not 0 <= value.ordinal < _MAX_DECLARATIONS_PER_FILE
        or value.path_style not in _PATH_STYLES
        or value.path_style == "absolute"
    ):
        raise _InvalidNativeDependencyManifest
    reference = _BUILTIN_BINDING_REF_PROJECTION(
        runtime_file_ref=value.runtime_file_ref,
        dependency_declaration_ref=value.dependency_declaration_ref,
        dependency_name_ref=value.dependency_name_ref,
        format_class=value.format_class,
        ordinal=value.ordinal,
        path_style=value.path_style,
        manifest_target_ref=value.manifest_target_ref,
    )
    if value.manifest_binding_ref != _BUILTIN_CANONICAL_DIGEST(reference):
        raise _InvalidNativeDependencyManifest
    return {**reference, "kind": value.kind, "manifest_binding_ref": value.manifest_binding_ref}


_BUILTIN_BINDING_PROJECTION = _binding_projection


def _dependency_disposition_matches_classification(
    dependency_disposition: str,
    runtime_classification: str,
) -> bool:
    if dependency_disposition.startswith("elf_"):
        return runtime_classification == "elf"
    if dependency_disposition.startswith("mach_o_"):
        return runtime_classification == "mach_o"
    if dependency_disposition == "unsupported_native_layout":
        return runtime_classification in {"elf", "mach_o"}
    return (
        dependency_disposition == "non_native_not_applicable"
        and runtime_classification not in {"elf", "mach_o"}
    )


_BUILTIN_DEPENDENCY_DISPOSITION_MATCHES_CLASSIFICATION = _dependency_disposition_matches_classification


def _requirement_ref_projection(
    *,
    staged_file_ref: str,
    runtime_file_ref: str,
    native_dependency_requirement_ref: str,
    runtime_classification: str,
    dependency_disposition: str,
    bindings: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "bindings": bindings,
        "dependency_disposition": dependency_disposition,
        "kind": "repository_executable_native_dependency_manifest_requirement_ref",
        "manifest_scope": _FIXED_MANIFEST_SCOPE,
        "native_dependency_requirement_ref": native_dependency_requirement_ref,
        "runtime_classification": runtime_classification,
        "runtime_file_ref": runtime_file_ref,
        "schema_version": _FIXED_SCHEMA_VERSION,
        "staged_file_ref": staged_file_ref,
    }


_BUILTIN_REQUIREMENT_REF_PROJECTION = _requirement_ref_projection


def _requirement_projection(
    value: RepositoryExecutableNativeDependencyManifestRequirement,
) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_REQUIREMENT_TYPE
        or value.kind != _FIXED_REQUIREMENT_KIND
        or not all(
            _BUILTIN_IS_DIGEST(item)
            for item in (
                value.staged_file_ref,
                value.runtime_file_ref,
                value.native_dependency_requirement_ref,
                value.manifest_requirement_ref,
            )
        )
        or value.runtime_classification not in _RUNTIME_CLASSIFICATIONS
        or value.dependency_disposition not in _UPSTREAM_DISPOSITIONS
        or not _BUILTIN_DEPENDENCY_DISPOSITION_MATCHES_CLASSIFICATION(
            value.dependency_disposition, value.runtime_classification
        )
        or type(value.bindings) is not tuple
        or len(value.bindings) > _MAX_DECLARATIONS_PER_FILE
        or any(
            type(item) is not int or item < 0
            for item in (
                value.dependency_declaration_count,
                value.non_absolute_dependency_count,
                value.manifest_bound_dependency_count,
            )
        )
        or value.manifest_bound_dependency_count != len(value.bindings)
        or value.non_absolute_dependency_count != len(value.bindings)
        or value.dependency_declaration_count < len(value.bindings)
    ):
        raise _InvalidNativeDependencyManifest
    bindings = [_BUILTIN_BINDING_PROJECTION(item) for item in value.bindings]
    if (
        any(
            item.runtime_file_ref != value.runtime_file_ref
            for item in value.bindings
        )
        or len({item.dependency_declaration_ref for item in value.bindings})
        != len(value.bindings)
    ):
        raise _InvalidNativeDependencyManifest
    declared = value.dependency_disposition in {
        "elf_dependencies_declared", "mach_o_dependencies_declared"
    }
    if declared != bool(value.dependency_declaration_count):
        raise _InvalidNativeDependencyManifest
    reference = _BUILTIN_REQUIREMENT_REF_PROJECTION(
        staged_file_ref=value.staged_file_ref,
        runtime_file_ref=value.runtime_file_ref,
        native_dependency_requirement_ref=value.native_dependency_requirement_ref,
        runtime_classification=value.runtime_classification,
        dependency_disposition=value.dependency_disposition,
        bindings=bindings,
    )
    if value.manifest_requirement_ref != _BUILTIN_CANONICAL_DIGEST(reference):
        raise _InvalidNativeDependencyManifest
    return {
        **reference,
        "dependency_declaration_count": value.dependency_declaration_count,
        "kind": value.kind,
        "manifest_bound_dependency_count": value.manifest_bound_dependency_count,
        "manifest_requirement_ref": value.manifest_requirement_ref,
        "non_absolute_dependency_count": value.non_absolute_dependency_count,
    }


_BUILTIN_REQUIREMENT_PROJECTION = _requirement_projection


def _command_binding_projection(
    value: RepositoryExecutableNativeDependencyManifestCommandBinding,
) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_COMMAND_BINDING_TYPE
        or value.kind != _FIXED_COMMAND_BINDING_KIND
        or value.command_kind not in _COMMAND_KINDS
        or type(value.command_id) is not str
        or _IDENTIFIER_PATTERN.fullmatch(value.command_id) is None
        or not all(
            _BUILTIN_IS_DIGEST(item)
            for item in (
                value.command_digest,
                value.staged_file_ref,
                value.runtime_file_ref,
                value.native_dependency_requirement_ref,
                value.manifest_requirement_ref,
            )
        )
    ):
        raise _InvalidNativeDependencyManifest
    return {
        "command_digest": value.command_digest,
        "command_id": value.command_id,
        "command_kind": value.command_kind,
        "kind": value.kind,
        "manifest_requirement_ref": value.manifest_requirement_ref,
        "native_dependency_requirement_ref": value.native_dependency_requirement_ref,
        "runtime_file_ref": value.runtime_file_ref,
        "staged_file_ref": value.staged_file_ref,
    }


_BUILTIN_COMMAND_BINDING_PROJECTION = _command_binding_projection


def _manifest_context_digest(
    requirements: tuple[RepositoryExecutableNativeDependencyManifestRequirement, ...],
) -> str:
    ordered: list[str] = []
    seen: set[str] = set()
    for requirement in requirements:
        for binding in requirement.bindings:
            if binding.manifest_target_ref not in seen:
                ordered.append(binding.manifest_target_ref)
                seen.add(binding.manifest_target_ref)
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "kind": "repository_executable_native_dependency_manifest_context",
            "manifest_scope": _FIXED_MANIFEST_SCOPE,
            "ordered_manifest_target_refs": ordered,
            "schema_version": _FIXED_SCHEMA_VERSION,
        }
    )


_BUILTIN_MANIFEST_CONTEXT_DIGEST = _manifest_context_digest


def _receipt_projection(
    value: RepositoryExecutableNativeDependencyManifestReceipt,
) -> dict[str, Any]:
    digest_fields = (
        value.native_dependency_requirements_receipt_digest,
        value.runtime_manifest_receipt_digest,
        value.staging_receipt_digest,
        value.registration_digest,
        value.repository_ref,
        value.verification_commands_digest,
        value.resolution_context_digest,
        value.staging_context_digest,
        value.manifest_context_digest,
    )
    count_fields = (
        value.dependency_declaration_count,
        value.non_absolute_dependency_declaration_count,
        value.manifest_bound_dependency_count,
        value.unique_manifest_target_count,
    )
    if (
        type(value) is not _FIXED_RECEIPT_TYPE
        or value.kind != _FIXED_RECEIPT_KIND
        or type(value.schema_version) is not int
        or value.schema_version != _FIXED_SCHEMA_VERSION
        or value.manifest_source != _FIXED_MANIFEST_SOURCE
        or value.manifest_scope != _FIXED_MANIFEST_SCOPE
        or not all(_BUILTIN_IS_DIGEST(item) for item in digest_fields)
        or type(value.requirements) is not tuple
        or not 1 <= len(value.requirements) <= _MAX_FILES
        or type(value.command_bindings) is not tuple
        or not 1 <= len(value.command_bindings) <= _MAX_COMMANDS
        or type(value.requirement_count) is not int
        or value.requirement_count != len(value.requirements)
        or type(value.command_count) is not int
        or value.command_count != len(value.command_bindings)
        or any(type(item) is not int or item < 0 for item in count_fields)
        or value.dependency_declaration_count > _MAX_DECLARATIONS
        or value.manifest_bound_dependency_count > _MAX_MANIFEST_ENTRIES
    ):
        raise _InvalidNativeDependencyManifest
    requirements = [_BUILTIN_REQUIREMENT_PROJECTION(item) for item in value.requirements]
    command_bindings = [
        _BUILTIN_COMMAND_BINDING_PROJECTION(item) for item in value.command_bindings
    ]
    by_upstream: dict[str, RepositoryExecutableNativeDependencyManifestRequirement] = {}
    requirement_refs: set[str] = set()
    staged_refs: set[str] = set()
    runtime_refs: set[str] = set()
    declaration_refs: set[str] = set()
    target_refs: list[str] = []
    target_seen: set[str] = set()
    for requirement in value.requirements:
        if (
            requirement.native_dependency_requirement_ref in by_upstream
            or requirement.manifest_requirement_ref in requirement_refs
            or requirement.staged_file_ref in staged_refs
            or requirement.runtime_file_ref in runtime_refs
        ):
            raise _InvalidNativeDependencyManifest
        by_upstream[requirement.native_dependency_requirement_ref] = requirement
        requirement_refs.add(requirement.manifest_requirement_ref)
        staged_refs.add(requirement.staged_file_ref)
        runtime_refs.add(requirement.runtime_file_ref)
        for binding in requirement.bindings:
            if binding.dependency_declaration_ref in declaration_refs:
                raise _InvalidNativeDependencyManifest
            declaration_refs.add(binding.dependency_declaration_ref)
            if binding.manifest_target_ref not in target_seen:
                target_refs.append(binding.manifest_target_ref)
                target_seen.add(binding.manifest_target_ref)
    command_ids: set[str] = set()
    bound_refs: set[str] = set()
    ordered_bound_refs: list[str] = []
    prior_kind_index = -1
    for binding in value.command_bindings:
        requirement = by_upstream.get(binding.native_dependency_requirement_ref)
        kind_index = _COMMAND_KINDS.index(binding.command_kind)
        if (
            requirement is None
            or binding.staged_file_ref != requirement.staged_file_ref
            or binding.runtime_file_ref != requirement.runtime_file_ref
            or binding.manifest_requirement_ref != requirement.manifest_requirement_ref
            or binding.command_id in command_ids
            or kind_index < prior_kind_index
        ):
            raise _InvalidNativeDependencyManifest
        command_ids.add(binding.command_id)
        if binding.manifest_requirement_ref not in bound_refs:
            ordered_bound_refs.append(binding.manifest_requirement_ref)
        bound_refs.add(binding.manifest_requirement_ref)
        prior_kind_index = kind_index
    declaration_count = sum(item.dependency_declaration_count for item in value.requirements)
    non_absolute_count = sum(item.non_absolute_dependency_count for item in value.requirements)
    manifest_count = sum(item.manifest_bound_dependency_count for item in value.requirements)
    if (
        bound_refs != requirement_refs
        or tuple(ordered_bound_refs) != tuple(item.manifest_requirement_ref for item in value.requirements)
        or declaration_count != value.dependency_declaration_count
        or non_absolute_count != value.non_absolute_dependency_declaration_count
        or manifest_count != value.manifest_bound_dependency_count
        or manifest_count != non_absolute_count
        or len(target_refs) != value.unique_manifest_target_count
        or value.manifest_context_digest
        != _BUILTIN_CANONICAL_DIGEST(
            {
                "kind": "repository_executable_native_dependency_manifest_context",
                "manifest_scope": _FIXED_MANIFEST_SCOPE,
                "ordered_manifest_target_refs": target_refs,
                "schema_version": _FIXED_SCHEMA_VERSION,
            }
        )
    ):
        raise _InvalidNativeDependencyManifest
    return {
        "command_bindings": command_bindings,
        "command_count": value.command_count,
        "dependency_declaration_count": value.dependency_declaration_count,
        "kind": value.kind,
        "manifest_bound_dependency_count": value.manifest_bound_dependency_count,
        "manifest_context_digest": value.manifest_context_digest,
        "manifest_scope": value.manifest_scope,
        "manifest_source": value.manifest_source,
        "native_dependency_requirements_receipt_digest": value.native_dependency_requirements_receipt_digest,
        "non_absolute_dependency_declaration_count": value.non_absolute_dependency_declaration_count,
        "registration_digest": value.registration_digest,
        "repository_ref": value.repository_ref,
        "requirement_count": value.requirement_count,
        "requirements": requirements,
        "resolution_context_digest": value.resolution_context_digest,
        "runtime_manifest_receipt_digest": value.runtime_manifest_receipt_digest,
        "schema_version": value.schema_version,
        "staging_context_digest": value.staging_context_digest,
        "staging_receipt_digest": value.staging_receipt_digest,
        "unique_manifest_target_count": value.unique_manifest_target_count,
        "verification_commands_digest": value.verification_commands_digest,
    }


_BUILTIN_RECEIPT_PROJECTION = _receipt_projection


def _evidence_projection(
    value: RepositoryExecutableNativeDependencyManifestReceipt,
) -> dict[str, Any]:
    canonical = _BUILTIN_RECEIPT_PROJECTION(value)
    return {
        "action_receipt_issued": False,
        "active_lease_verified_at_manifest_binding": True,
        "ambient_loader_environment_consulted": False,
        "ambient_loader_search_semantics_applied": False,
        "authority_granted": False,
        "authorization_verified": False,
        "billing_eligible": False,
        "capacity_eligible": False,
        "circuit_eligible": False,
        "command_count": value.command_count,
        "controller_explicit_manifest_complete": True,
        "current_lease_activity_verified": False,
        "dependency_closure_verified": False,
        "dependency_declaration_count": value.dependency_declaration_count,
        "dependency_manifest_raw_values_exposed": False,
        "dispatch_enabled": False,
        "durable_control_plane_persistence_enabled": False,
        "effect_class": 0,
        "execution_enabled": False,
        "future_execution_correspondence_verified": False,
        "harness_invocation_performed": False,
        "host_loader_cache_consulted": False,
        "kind": _FIXED_EVIDENCE_KIND,
        "lease_cleanup_performed": False,
        "lease_mutated": False,
        "live_execution_eligible": False,
        "loader_invocation_performed": False,
        "manifest_bound_dependency_count": value.manifest_bound_dependency_count,
        "model_invocation_performed": False,
        "network_access_performed": False,
        "non_absolute_dependency_declaration_count": value.non_absolute_dependency_declaration_count,
        "path_lookup_performed": False,
        "proposal_lineage_extended": False,
        "receipt_authenticity_verified": False,
        "receipt_digest": _BUILTIN_CANONICAL_DIGEST(canonical),
        "recursive_dependency_resolution_verified": False,
        "registration_digest": value.registration_digest,
        "repository_ref": value.repository_ref,
        "requirement_count": value.requirement_count,
        "route_eligible": False,
        "shared_library_closure_verified": False,
        "source_path_reopen_performed": False,
        "subprocess_invocation_performed": False,
        "target_measurement_performed": False,
        "tokenized_loader_path_expansion_performed": False,
        "unique_manifest_target_count": value.unique_manifest_target_count,
        "validation_mode": "read_only",
        "worker_authorized": False,
        "worktree_integration_enabled": False,
    }


_BUILTIN_EVIDENCE_PROJECTION = _evidence_projection


@dataclass(frozen=True, slots=True)
class _DerivedManifestRequirement:
    upstream: RepositoryExecutableNativeDependencyRequirement = field(repr=False)
    entries: tuple[tuple[RepositoryExecutableNativeDependencyDeclaration, RepositoryExecutableNativeDependencyManifestEntry | None], ...] = field(repr=False)


_FIXED_DERIVED_TYPE = _DerivedManifestRequirement


def _validate_manifest_entry(
    entry: Any,
    declaration: RepositoryExecutableNativeDependencyDeclaration,
) -> tuple[RepositoryExecutableNativeDependencyManifestEntry, str]:
    if (
        type(entry) is not _FIXED_ENTRY_TYPE
        or entry.kind != _FIXED_ENTRY_KIND
        or not _BUILTIN_IS_DIGEST(entry.runtime_file_ref)
        or not _BUILTIN_IS_DIGEST(entry.dependency_declaration_ref)
        or type(entry.dependency_name) is not bytes
        or not 1 <= len(entry.dependency_name) <= _MAX_DEPENDENCY_NAME_BYTES
        or b"\x00" in entry.dependency_name
        or entry.runtime_file_ref != declaration.runtime_file_ref
        or entry.dependency_declaration_ref != declaration.declaration_ref
    ):
        raise _InvalidNativeDependencyManifest
    _path, _encoded = _BUILTIN_CANONICAL_TARGET_PATH(entry.target_path)
    if (
        len(entry.dependency_name) != declaration.dependency_name_bytes
        or _BUILTIN_DEPENDENCY_NAME_REF(
            runtime_file_ref=declaration.runtime_file_ref,
            format_class=declaration.format_class,
            dependency_name=entry.dependency_name,
        )
        != declaration.dependency_name_ref
    ):
        raise _InvalidNativeDependencyManifest
    return entry, _BUILTIN_MANIFEST_TARGET_REF(entry.target_path)


_BUILTIN_VALIDATE_MANIFEST_ENTRY = _validate_manifest_entry


def _validate_expected_manifest(
    expected_requirements: RepositoryExecutableNativeDependencyRequirementsReceipt,
    expected_non_absolute_dependency_manifest: Any,
) -> tuple[tuple[_DerivedManifestRequirement, ...], tuple[str, ...]]:
    if (
        type(expected_non_absolute_dependency_manifest) is not tuple
        or len(expected_non_absolute_dependency_manifest) > _MAX_MANIFEST_ENTRIES
    ):
        raise _InvalidNativeDependencyManifest
    entries = iter(expected_non_absolute_dependency_manifest)
    derived: list[_DerivedManifestRequirement] = []
    target_refs: list[str] = []
    target_ref_seen: set[str] = set()
    total_path_bytes = 0
    consumed = 0
    for requirement in expected_requirements.requirements:
        if type(requirement) is not _FIXED_UPSTREAM_REQUIREMENT_TYPE:
            raise _InvalidNativeDependencyManifest
        local: list[tuple[RepositoryExecutableNativeDependencyDeclaration, RepositoryExecutableNativeDependencyManifestEntry | None]] = []
        for declaration in requirement.declarations:
            if type(declaration) is not _FIXED_UPSTREAM_DECLARATION_TYPE:
                raise _InvalidNativeDependencyManifest
            entry: RepositoryExecutableNativeDependencyManifestEntry | None = None
            if declaration.path_style != "absolute":
                try:
                    candidate = next(entries)
                except StopIteration:
                    raise _InvalidNativeDependencyManifest from None
                entry, target_ref = _BUILTIN_VALIDATE_MANIFEST_ENTRY(candidate, declaration)
                _path, encoded = _BUILTIN_CANONICAL_TARGET_PATH(entry.target_path)
                total_path_bytes += len(encoded)
                if total_path_bytes > _MAX_TOTAL_TARGET_PATH_BYTES:
                    raise _InvalidNativeDependencyManifest
                if target_ref not in target_ref_seen:
                    target_refs.append(target_ref)
                    target_ref_seen.add(target_ref)
                consumed += 1
            local.append((declaration, entry))
        derived.append(_FIXED_DERIVED_TYPE(upstream=requirement, entries=tuple(local)))
    try:
        next(entries)
    except StopIteration:
        pass
    else:
        raise _InvalidNativeDependencyManifest
    if consumed != len(expected_non_absolute_dependency_manifest):
        raise _InvalidNativeDependencyManifest
    return tuple(derived), tuple(target_refs)


_BUILTIN_VALIDATE_EXPECTED_MANIFEST = _validate_expected_manifest


def _validated_chain_snapshot(
    expected_requirements: RepositoryExecutableNativeDependencyRequirementsReceipt,
    expected_runtime: RepositoryExecutableRuntimeManifestReceipt,
    expected_staging: RepositoryExecutableStagingReceipt,
    lease: RepositoryExecutableStageLease,
    expected_non_absolute_dependency_manifest: Any,
) -> tuple[tuple[_DerivedManifestRequirement, ...], tuple[str, ...], str, str, str]:
    if (
        type(expected_requirements) is not _FIXED_DEPENDENCY_RECEIPT_TYPE
        or type(expected_runtime) is not _FIXED_RUNTIME_TYPE
        or type(expected_staging) is not _FIXED_STAGING_TYPE
        or type(lease) is not _FIXED_LEASE_TYPE
    ):
        raise _InvalidNativeDependencyManifest
    requirements_canonical = _BUILTIN_DEPENDENCY_RECEIPT_PROJECTION(expected_requirements)
    runtime_canonical = _BUILTIN_RUNTIME_PROJECTION(expected_runtime)
    staging_canonical = _BUILTIN_STAGING_PROJECTION(expected_staging)
    requirements_digest = _BUILTIN_CANONICAL_DIGEST(requirements_canonical)
    runtime_digest = _BUILTIN_CANONICAL_DIGEST(runtime_canonical)
    staging_digest = _BUILTIN_CANONICAL_DIGEST(staging_canonical)
    if (
        expected_requirements.runtime_manifest_receipt_digest != runtime_digest
        or expected_requirements.staging_receipt_digest != staging_digest
        or expected_runtime.staging_receipt_digest != staging_digest
        or expected_requirements.registration_digest != expected_runtime.registration_digest
        or expected_requirements.registration_digest != expected_staging.registration_digest
        or expected_requirements.repository_ref != expected_runtime.repository_ref
        or expected_requirements.repository_ref != expected_staging.repository_ref
        or expected_requirements.verification_commands_digest != expected_runtime.verification_commands_digest
        or expected_requirements.verification_commands_digest != expected_staging.verification_commands_digest
        or expected_requirements.resolution_context_digest != expected_runtime.resolution_context_digest
        or expected_requirements.resolution_context_digest != expected_staging.resolution_context_digest
        or expected_requirements.staging_context_digest != expected_runtime.staging_context_digest
        or expected_requirements.staging_context_digest != expected_staging.staging_context_digest
    ):
        raise _InvalidNativeDependencyManifest
    fresh_loader = _BUILTIN_INSPECT_NATIVE_LOADER(
        expected_runtime, expected_staging=expected_staging, lease=lease
    )
    fresh_requirements = _BUILTIN_INSPECT_DEPENDENCY_REQUIREMENTS(
        fresh_loader,
        expected_runtime=expected_runtime,
        expected_staging=expected_staging,
        lease=lease,
    )
    if _BUILTIN_DEPENDENCY_RECEIPT_PROJECTION(fresh_requirements) != requirements_canonical:
        raise _InvalidNativeDependencyManifest
    active_staging_canonical, _retained_files = _BUILTIN_ACTIVE_STAGE_SNAPSHOT(expected_staging, lease)
    if active_staging_canonical != staging_canonical:
        raise _InvalidNativeDependencyManifest
    derived, target_refs = _BUILTIN_VALIDATE_EXPECTED_MANIFEST(
        expected_requirements, expected_non_absolute_dependency_manifest
    )
    return derived, target_refs, requirements_digest, runtime_digest, staging_digest


_BUILTIN_VALIDATED_CHAIN_SNAPSHOT = _validated_chain_snapshot


def _public_manifest_binding(
    declaration: RepositoryExecutableNativeDependencyDeclaration,
    entry: RepositoryExecutableNativeDependencyManifestEntry,
) -> RepositoryExecutableNativeDependencyManifestBinding:
    if (
        type(declaration) is not _FIXED_UPSTREAM_DECLARATION_TYPE
        or type(entry) is not _FIXED_ENTRY_TYPE
        or declaration.path_style == "absolute"
    ):
        raise _InvalidNativeDependencyManifest
    target_ref = _BUILTIN_MANIFEST_TARGET_REF(entry.target_path)
    reference = _BUILTIN_BINDING_REF_PROJECTION(
        runtime_file_ref=declaration.runtime_file_ref,
        dependency_declaration_ref=declaration.declaration_ref,
        dependency_name_ref=declaration.dependency_name_ref,
        format_class=declaration.format_class,
        ordinal=declaration.ordinal,
        path_style=declaration.path_style,
        manifest_target_ref=target_ref,
    )
    value = _FIXED_BINDING_TYPE(
        kind=_FIXED_BINDING_KIND,
        runtime_file_ref=declaration.runtime_file_ref,
        dependency_declaration_ref=declaration.declaration_ref,
        dependency_name_ref=declaration.dependency_name_ref,
        format_class=declaration.format_class,
        ordinal=declaration.ordinal,
        path_style=declaration.path_style,
        manifest_target_ref=target_ref,
        manifest_binding_ref=_BUILTIN_CANONICAL_DIGEST(reference),
    )
    _BUILTIN_BINDING_PROJECTION(value)
    return value


_BUILTIN_PUBLIC_MANIFEST_BINDING = _public_manifest_binding


def _public_requirement(
    derived: _DerivedManifestRequirement,
) -> RepositoryExecutableNativeDependencyManifestRequirement:
    if (
        type(derived) is not _FIXED_DERIVED_TYPE
        or type(derived.upstream) is not _FIXED_UPSTREAM_REQUIREMENT_TYPE
    ):
        raise _InvalidNativeDependencyManifest
    upstream = derived.upstream
    bindings = tuple(
        _BUILTIN_PUBLIC_MANIFEST_BINDING(declaration, entry)
        for declaration, entry in derived.entries
        if entry is not None
    )
    reference = _BUILTIN_REQUIREMENT_REF_PROJECTION(
        staged_file_ref=upstream.staged_file_ref,
        runtime_file_ref=upstream.runtime_file_ref,
        native_dependency_requirement_ref=upstream.requirement_ref,
        runtime_classification=upstream.runtime_classification,
        dependency_disposition=upstream.disposition,
        bindings=[_BUILTIN_BINDING_PROJECTION(item) for item in bindings],
    )
    value = _FIXED_REQUIREMENT_TYPE(
        kind=_FIXED_REQUIREMENT_KIND,
        staged_file_ref=upstream.staged_file_ref,
        runtime_file_ref=upstream.runtime_file_ref,
        native_dependency_requirement_ref=upstream.requirement_ref,
        runtime_classification=upstream.runtime_classification,
        dependency_disposition=upstream.disposition,
        bindings=bindings,
        dependency_declaration_count=len(derived.entries),
        non_absolute_dependency_count=len(bindings),
        manifest_bound_dependency_count=len(bindings),
        manifest_requirement_ref=_BUILTIN_CANONICAL_DIGEST(reference),
    )
    _BUILTIN_REQUIREMENT_PROJECTION(value)
    return value


_BUILTIN_PUBLIC_REQUIREMENT = _public_requirement


def inspect_staged_executable_native_dependency_manifest(
    expected_requirements: RepositoryExecutableNativeDependencyRequirementsReceipt,
    *,
    expected_runtime: RepositoryExecutableRuntimeManifestReceipt,
    expected_staging: RepositoryExecutableStagingReceipt,
    lease: RepositoryExecutableStageLease,
    expected_non_absolute_dependency_manifest: tuple[RepositoryExecutableNativeDependencyManifestEntry, ...],
) -> RepositoryExecutableNativeDependencyManifestReceipt:
    """Bind every non-absolute declaration to one explicit controller path."""

    try:
        first = _BUILTIN_VALIDATED_CHAIN_SNAPSHOT(
            expected_requirements,
            expected_runtime,
            expected_staging,
            lease,
            expected_non_absolute_dependency_manifest,
        )
        middle = _BUILTIN_VALIDATED_CHAIN_SNAPSHOT(
            expected_requirements,
            expected_runtime,
            expected_staging,
            lease,
            expected_non_absolute_dependency_manifest,
        )
        if middle != first:
            raise _InvalidNativeDependencyManifest
        final = _BUILTIN_VALIDATED_CHAIN_SNAPSHOT(
            expected_requirements,
            expected_runtime,
            expected_staging,
            lease,
            expected_non_absolute_dependency_manifest,
        )
        if final != first:
            raise _InvalidNativeDependencyManifest
        (
            derived,
            _target_refs,
            requirements_digest,
            runtime_digest,
            staging_digest,
        ) = first
        closing_staging_canonical, _closing_retained_files = _BUILTIN_ACTIVE_STAGE_SNAPSHOT(expected_staging, lease)
        if _BUILTIN_CANONICAL_DIGEST(closing_staging_canonical) != staging_digest:
            raise _InvalidNativeDependencyManifest
        requirements = tuple(_BUILTIN_PUBLIC_REQUIREMENT(item) for item in derived)
        by_upstream = {
            item.native_dependency_requirement_ref: item for item in requirements
        }
        command_bindings: list[RepositoryExecutableNativeDependencyManifestCommandBinding] = []
        for upstream in expected_requirements.bindings:
            if type(upstream) is not _FIXED_UPSTREAM_BINDING_TYPE:
                raise _InvalidNativeDependencyManifest
            requirement = by_upstream.get(upstream.dependency_requirement_ref)
            if (
                requirement is None
                or upstream.staged_file_ref != requirement.staged_file_ref
                or upstream.runtime_file_ref != requirement.runtime_file_ref
            ):
                raise _InvalidNativeDependencyManifest
            binding = _FIXED_COMMAND_BINDING_TYPE(
                kind=_FIXED_COMMAND_BINDING_KIND,
                command_kind=upstream.command_kind,
                command_id=upstream.command_id,
                command_digest=upstream.command_digest,
                staged_file_ref=upstream.staged_file_ref,
                runtime_file_ref=upstream.runtime_file_ref,
                native_dependency_requirement_ref=upstream.dependency_requirement_ref,
                manifest_requirement_ref=requirement.manifest_requirement_ref,
            )
            _BUILTIN_COMMAND_BINDING_PROJECTION(binding)
            command_bindings.append(binding)
        receipt = _FIXED_RECEIPT_TYPE(
            kind=_FIXED_RECEIPT_KIND,
            schema_version=_FIXED_SCHEMA_VERSION,
            manifest_source=_FIXED_MANIFEST_SOURCE,
            manifest_scope=_FIXED_MANIFEST_SCOPE,
            native_dependency_requirements_receipt_digest=requirements_digest,
            runtime_manifest_receipt_digest=runtime_digest,
            staging_receipt_digest=staging_digest,
            registration_digest=expected_requirements.registration_digest,
            repository_ref=expected_requirements.repository_ref,
            verification_commands_digest=expected_requirements.verification_commands_digest,
            resolution_context_digest=expected_requirements.resolution_context_digest,
            staging_context_digest=expected_requirements.staging_context_digest,
            manifest_context_digest=_BUILTIN_MANIFEST_CONTEXT_DIGEST(requirements),
            requirements=requirements,
            command_bindings=tuple(command_bindings),
            requirement_count=len(requirements),
            command_count=len(command_bindings),
            dependency_declaration_count=sum(item.dependency_declaration_count for item in requirements),
            non_absolute_dependency_declaration_count=sum(item.non_absolute_dependency_count for item in requirements),
            manifest_bound_dependency_count=sum(item.manifest_bound_dependency_count for item in requirements),
            unique_manifest_target_count=len(
                {
                    binding.manifest_target_ref
                    for requirement in requirements
                    for binding in requirement.bindings
                }
            ),
        )
        _BUILTIN_RECEIPT_PROJECTION(receipt)
        return receipt
    except (KeyboardInterrupt, SystemExit):
        raise
    except _InvalidNativeDependencyManifest:
        raise _FIXED_VALIDATION_ERROR(_INVALID_MESSAGE) from None
    except Exception:
        raise _FIXED_VALIDATION_ERROR(_INVALID_MESSAGE) from None


__all__ = [
    "MANIFEST_SCOPE",
    "MANIFEST_SOURCE",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_BINDING_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_COMMAND_BINDING_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_ENTRY_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_EVIDENCE_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_REQUIREMENT_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_SCHEMA_VERSION",
    "RepositoryExecutableNativeDependencyManifestBinding",
    "RepositoryExecutableNativeDependencyManifestCommandBinding",
    "RepositoryExecutableNativeDependencyManifestEntry",
    "RepositoryExecutableNativeDependencyManifestReceipt",
    "RepositoryExecutableNativeDependencyManifestRequirement",
    "inspect_staged_executable_native_dependency_manifest",
]
