"""Read-only runtime-header evidence for one active executable stage.

This module deliberately stops before interpreter resolution or dependency
closure.  It remeasures the anonymous files held by an exact active staging
lease, reads a bounded header with ``pread``, and applies a small fixed
classification.  It opens no path, mutates no lease, and executes nothing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import fcntl
import hashlib
import os
import re
import stat
from typing import Any

from .authorization import canonical_digest
from .errors import ValidationError
from .repository_executable_staging import (
    REPOSITORY_EXECUTABLE_STAGE_BINDING_KIND,
    RepositoryExecutableStagedFile,
    RepositoryExecutableStageLease,
    RepositoryExecutableStagingReceipt,
    _RetainedStagedFile,
    _staging_receipt_projection,
)


REPOSITORY_EXECUTABLE_RUNTIME_MANIFEST_SCHEMA_VERSION = 1
REPOSITORY_EXECUTABLE_RUNTIME_MANIFEST_KIND = (
    "repository_executable_runtime_manifest"
)
REPOSITORY_EXECUTABLE_RUNTIME_MANIFEST_EVIDENCE_KIND = (
    "repository_executable_runtime_manifest_validation"
)
REPOSITORY_EXECUTABLE_RUNTIME_FILE_KIND = (
    "repository_executable_runtime_file"
)
REPOSITORY_EXECUTABLE_RUNTIME_BINDING_KIND = (
    "repository_executable_runtime_binding"
)
MANIFEST_SOURCE = "controller_inspected"
MANIFEST_SCOPE = "posix_staged_runtime_header_v1"

_INVALID_MESSAGE = "repository executable runtime manifest is invalid"
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
_MAX_FILES = 80
_MAX_COMMANDS = 80
_MAX_FILE_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_BYTES = 256 * 1024 * 1024
_MAX_HEADER_BYTES = 4_096
_MAX_SHEBANG_DIRECTIVE_BYTES = 255
_FULL_REMEASUREMENT_CHUNK_BYTES = 1024 * 1024
_STAGED_FILE_MODE = 0o400
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
_BUILTIN_STAGING_RECEIPT_PROJECTION = _staging_receipt_projection


class _InvalidRuntimeManifest(ValueError):
    """Internal invalid-input sentinel with no public details."""


@dataclass(frozen=True, slots=True)
class RepositoryExecutableRuntimeFile:
    """One staged file and its bounded runtime-header classification."""

    kind: str
    staged_file_ref: str = field(repr=False)
    staged_filesystem_identity_ref: str = field(repr=False)
    content_digest: str = field(repr=False)
    content_bytes: int
    runtime_file_ref: str = field(repr=False)
    header_digest: str = field(repr=False)
    header_bytes: int
    classification: str
    shebang_directive_ref: str | None = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _runtime_file_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableRuntimeBinding:
    """One registered command bound to one runtime-file observation."""

    kind: str
    command_kind: str
    command_id: str = field(repr=False)
    command_digest: str = field(repr=False)
    staged_file_ref: str = field(repr=False)
    runtime_file_ref: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _runtime_binding_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableRuntimeManifestReceipt:
    """Historical evidence from one active staged-descriptor inspection."""

    kind: str
    schema_version: int
    manifest_source: str
    manifest_scope: str
    staging_receipt_digest: str = field(repr=False)
    registration_digest: str = field(repr=False)
    repository_ref: str = field(repr=False)
    verification_commands_digest: str = field(repr=False)
    resolution_context_digest: str = field(repr=False)
    staging_context_digest: str = field(repr=False)
    files: tuple[RepositoryExecutableRuntimeFile, ...] = field(repr=False)
    bindings: tuple[RepositoryExecutableRuntimeBinding, ...] = field(
        repr=False
    )
    file_count: int
    command_count: int
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


def _is_digest(value: Any) -> bool:
    return type(value) is str and _DIGEST_PATTERN.fullmatch(value) is not None


def _runtime_file_ref_projection(
    *,
    staged_file_ref: str,
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
        "kind": "repository_executable_runtime_file_ref",
        "manifest_scope": MANIFEST_SCOPE,
        "schema_version": (
            REPOSITORY_EXECUTABLE_RUNTIME_MANIFEST_SCHEMA_VERSION
        ),
        "shebang_directive_ref": shebang_directive_ref,
        "staged_file_ref": staged_file_ref,
        "staged_filesystem_identity_ref": staged_filesystem_identity_ref,
    }


def _runtime_file_projection(
    runtime_file: RepositoryExecutableRuntimeFile,
) -> dict[str, Any]:
    if (
        type(runtime_file) is not RepositoryExecutableRuntimeFile
        or runtime_file.kind != REPOSITORY_EXECUTABLE_RUNTIME_FILE_KIND
        or not _is_digest(runtime_file.staged_file_ref)
        or not _is_digest(runtime_file.staged_filesystem_identity_ref)
        or not _is_digest(runtime_file.content_digest)
        or type(runtime_file.content_bytes) is not int
        or not 0 <= runtime_file.content_bytes <= _MAX_FILE_BYTES
        or not _is_digest(runtime_file.runtime_file_ref)
        or not _is_digest(runtime_file.header_digest)
        or type(runtime_file.header_bytes) is not int
        or not 0 <= runtime_file.header_bytes <= _MAX_HEADER_BYTES
        or runtime_file.header_bytes
        != min(runtime_file.content_bytes, _MAX_HEADER_BYTES)
        or type(runtime_file.classification) is not str
        or runtime_file.classification not in _CLASSIFICATIONS
        or (
            runtime_file.classification == "elf"
            and runtime_file.header_bytes < 16
        )
        or (
            runtime_file.classification == "mach_o"
            and runtime_file.header_bytes < 28
        )
        or (
            runtime_file.classification == "posix_shebang"
            and runtime_file.header_bytes < 4
        )
        or (
            runtime_file.classification == "unsupported_shebang"
            and runtime_file.header_bytes < 2
        )
        or (
            runtime_file.shebang_directive_ref is not None
            and not _is_digest(runtime_file.shebang_directive_ref)
        )
        or (
            runtime_file.classification == "posix_shebang"
            and runtime_file.shebang_directive_ref is None
        )
        or (
            runtime_file.classification != "posix_shebang"
            and runtime_file.shebang_directive_ref is not None
        )
    ):
        raise _InvalidRuntimeManifest
    reference_projection = _runtime_file_ref_projection(
        staged_file_ref=runtime_file.staged_file_ref,
        staged_filesystem_identity_ref=(
            runtime_file.staged_filesystem_identity_ref
        ),
        content_digest=runtime_file.content_digest,
        content_bytes=runtime_file.content_bytes,
        header_digest=runtime_file.header_digest,
        header_bytes=runtime_file.header_bytes,
        classification=runtime_file.classification,
        shebang_directive_ref=runtime_file.shebang_directive_ref,
    )
    if runtime_file.runtime_file_ref != _BUILTIN_CANONICAL_DIGEST(
        reference_projection
    ):
        raise _InvalidRuntimeManifest
    return {
        "classification": runtime_file.classification,
        "content_bytes": runtime_file.content_bytes,
        "content_digest": runtime_file.content_digest,
        "header_bytes": runtime_file.header_bytes,
        "header_digest": runtime_file.header_digest,
        "kind": runtime_file.kind,
        "runtime_file_ref": runtime_file.runtime_file_ref,
        "shebang_directive_ref": runtime_file.shebang_directive_ref,
        "staged_file_ref": runtime_file.staged_file_ref,
        "staged_filesystem_identity_ref": (
            runtime_file.staged_filesystem_identity_ref
        ),
    }


def _runtime_binding_projection(
    binding: RepositoryExecutableRuntimeBinding,
) -> dict[str, Any]:
    if (
        type(binding) is not RepositoryExecutableRuntimeBinding
        or binding.kind != REPOSITORY_EXECUTABLE_RUNTIME_BINDING_KIND
        or binding.command_kind not in _COMMAND_KINDS
        or type(binding.command_id) is not str
        or _IDENTIFIER_PATTERN.fullmatch(binding.command_id) is None
        or not _is_digest(binding.command_digest)
        or not _is_digest(binding.staged_file_ref)
        or not _is_digest(binding.runtime_file_ref)
    ):
        raise _InvalidRuntimeManifest
    return {
        "command_digest": binding.command_digest,
        "command_id": binding.command_id,
        "command_kind": binding.command_kind,
        "kind": binding.kind,
        "runtime_file_ref": binding.runtime_file_ref,
        "staged_file_ref": binding.staged_file_ref,
    }


def _runtime_manifest_projection(
    receipt: RepositoryExecutableRuntimeManifestReceipt,
) -> dict[str, Any]:
    digest_fields = (
        receipt.staging_receipt_digest,
        receipt.registration_digest,
        receipt.repository_ref,
        receipt.verification_commands_digest,
        receipt.resolution_context_digest,
        receipt.staging_context_digest,
    )
    if (
        type(receipt) is not RepositoryExecutableRuntimeManifestReceipt
        or receipt.kind != REPOSITORY_EXECUTABLE_RUNTIME_MANIFEST_KIND
        or type(receipt.schema_version) is not int
        or receipt.schema_version
        != REPOSITORY_EXECUTABLE_RUNTIME_MANIFEST_SCHEMA_VERSION
        or receipt.manifest_source != MANIFEST_SOURCE
        or receipt.manifest_scope != MANIFEST_SCOPE
        or not all(_is_digest(value) for value in digest_fields)
        or type(receipt.files) is not tuple
        or not 1 <= len(receipt.files) <= _MAX_FILES
        or type(receipt.bindings) is not tuple
        or not 1 <= len(receipt.bindings) <= _MAX_COMMANDS
        or type(receipt.file_count) is not int
        or receipt.file_count != len(receipt.files)
        or type(receipt.command_count) is not int
        or receipt.command_count != len(receipt.bindings)
        or type(receipt.total_content_bytes) is not int
        or not 0 <= receipt.total_content_bytes <= _MAX_TOTAL_BYTES
        or type(receipt.total_header_bytes) is not int
        or not 0
        <= receipt.total_header_bytes
        <= _MAX_FILES * _MAX_HEADER_BYTES
    ):
        raise _InvalidRuntimeManifest

    files = [_runtime_file_projection(value) for value in receipt.files]
    bindings = [
        _runtime_binding_projection(value) for value in receipt.bindings
    ]
    file_by_staged_ref: dict[str, RepositoryExecutableRuntimeFile] = {}
    runtime_refs: set[str] = set()
    total_content_bytes = 0
    total_header_bytes = 0
    for value in receipt.files:
        if (
            value.staged_file_ref in file_by_staged_ref
            or value.runtime_file_ref in runtime_refs
        ):
            raise _InvalidRuntimeManifest
        file_by_staged_ref[value.staged_file_ref] = value
        runtime_refs.add(value.runtime_file_ref)
        total_content_bytes += value.content_bytes
        total_header_bytes += value.header_bytes

    command_ids: set[str] = set()
    bound_staged_refs: set[str] = set()
    prior_kind_index = -1
    for binding in receipt.bindings:
        runtime_file = file_by_staged_ref.get(binding.staged_file_ref)
        kind_index = _COMMAND_KINDS.index(binding.command_kind)
        if (
            runtime_file is None
            or binding.runtime_file_ref != runtime_file.runtime_file_ref
            or binding.command_id in command_ids
            or kind_index < prior_kind_index
        ):
            raise _InvalidRuntimeManifest
        command_ids.add(binding.command_id)
        bound_staged_refs.add(binding.staged_file_ref)
        prior_kind_index = kind_index
    if (
        bound_staged_refs != set(file_by_staged_ref)
        or total_content_bytes != receipt.total_content_bytes
        or total_header_bytes != receipt.total_header_bytes
    ):
        raise _InvalidRuntimeManifest
    return {
        "bindings": bindings,
        "command_count": receipt.command_count,
        "file_count": receipt.file_count,
        "files": files,
        "kind": receipt.kind,
        "manifest_scope": receipt.manifest_scope,
        "manifest_source": receipt.manifest_source,
        "registration_digest": receipt.registration_digest,
        "repository_ref": receipt.repository_ref,
        "resolution_context_digest": receipt.resolution_context_digest,
        "schema_version": receipt.schema_version,
        "staging_context_digest": receipt.staging_context_digest,
        "staging_receipt_digest": receipt.staging_receipt_digest,
        "total_content_bytes": receipt.total_content_bytes,
        "total_header_bytes": receipt.total_header_bytes,
        "verification_commands_digest": (
            receipt.verification_commands_digest
        ),
    }


def _runtime_manifest_evidence_projection(
    receipt: RepositoryExecutableRuntimeManifestReceipt,
) -> dict[str, Any]:
    canonical = _runtime_manifest_projection(receipt)
    counts = {
        classification: sum(
            value.classification == classification for value in receipt.files
        )
        for classification in _CLASSIFICATIONS
    }
    return {
        "action_receipt_issued": False,
        "active_lease_verified_at_measurement": True,
        "atomic_snapshot_verified": False,
        "authority_granted": False,
        "authorization_verified": False,
        "baseline_execution_correspondence_verified": False,
        "billing_eligible": False,
        "bounded_header_measurement_complete": True,
        "bounded_shebang_syntax_classification_complete": True,
        "capacity_eligible": False,
        "circuit_eligible": False,
        "command_count": receipt.command_count,
        "configuration_coverage_verified": False,
        "current_lease_activity_verified": False,
        "current_source_freshness_verified": False,
        "dependency_environment_coverage_verified": False,
        "dispatch_enabled": False,
        "durable_control_plane_persistence_enabled": False,
        "dynamic_loader_identity_verified": False,
        "effect_class": 0,
        "effective_invocability_verified": False,
        "elf_file_count": counts["elf"],
        "environment_coverage_verified": False,
        "execution_enabled": False,
        "file_count": receipt.file_count,
        "fixed_runtime_format_classification_complete": True,
        "future_execution_correspondence_verified": False,
        "interpreter_authenticity_verified": False,
        "interpreter_identity_verified": False,
        "interpreter_resolution_verified": False,
        "kind": REPOSITORY_EXECUTABLE_RUNTIME_MANIFEST_EVIDENCE_KIND,
        "launcher_identity_verified": False,
        "lease_cleanup_performed": False,
        "lease_mutated": False,
        "live_execution_eligible": False,
        "mach_o_file_count": counts["mach_o"],
        "manifest_scope": receipt.manifest_scope,
        "manifest_source": receipt.manifest_source,
        "module_identity_verified": False,
        "package_identity_verified": False,
        "plugin_identity_verified": False,
        "posix_shebang_file_count": counts["posix_shebang"],
        "proposal_lineage_extended": False,
        "receipt_authenticity_verified": False,
        "receipt_digest": _BUILTIN_CANONICAL_DIGEST(canonical),
        "registration_digest": receipt.registration_digest,
        "repository_ref": receipt.repository_ref,
        "resolution_context_digest": receipt.resolution_context_digest,
        "route_eligible": False,
        "runtime_manifest_complete": False,
        "schema_version": receipt.schema_version,
        "shared_library_identity_verified": False,
        "source_path_reopen_performed": False,
        "staged_byte_correspondence_verified": True,
        "staged_descriptor_full_remeasurement_complete": True,
        "staging_receipt_digest": receipt.staging_receipt_digest,
        "toolchain_completeness_verified": False,
        "total_content_bytes": receipt.total_content_bytes,
        "total_header_bytes": receipt.total_header_bytes,
        "unknown_file_count": counts["unknown"],
        "unsupported_shebang_file_count": counts[
            "unsupported_shebang"
        ],
        "validation_mode": "read_only",
    }


def _read_exact_header(descriptor: int, content_bytes: int) -> bytes:
    expected = min(content_bytes, _MAX_HEADER_BYTES)
    chunks: list[bytes] = []
    offset = 0
    while offset < expected:
        try:
            chunk = os.pread(descriptor, expected - offset, offset)
        except (BlockingIOError, InterruptedError, OSError):
            raise _InvalidRuntimeManifest from None
        if not chunk:
            raise _InvalidRuntimeManifest
        chunks.append(chunk)
        offset += len(chunk)
    header = b"".join(chunks)
    if len(header) != expected:
        raise _InvalidRuntimeManifest
    try:
        boundary_probe = os.pread(descriptor, 1, expected)
    except (BlockingIOError, InterruptedError, OSError):
        raise _InvalidRuntimeManifest from None
    if (
        content_bytes > expected
        and len(boundary_probe) != 1
    ) or (
        content_bytes <= expected
        and boundary_probe != b""
    ):
        raise _InvalidRuntimeManifest
    return header


def _header_digest(staged_file_ref: str, header: bytes) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(
        staged_file_ref.encode("ascii") + b"\x00" + header
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
    staged_file_ref: str,
    header: bytes,
) -> tuple[str, str | None]:
    if header.startswith(b"#!"):
        directive = _bounded_shebang_directive(header)
        if directive is None:
            return "unsupported_shebang", None
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
        magic in _MACH_O_MAGICS
        and len(header) >= _MACH_O_MINIMUM_BYTES[magic]
    ):
        return "mach_o", None
    return "unknown", None


def _active_stage_snapshot(
    expected_staging: Any,
    lease: Any,
) -> tuple[
    dict[str, Any],
    tuple[_RetainedStagedFile, ...],
]:
    if (
        type(expected_staging) is not RepositoryExecutableStagingReceipt
        or type(lease) is not RepositoryExecutableStageLease
        or type(lease._owner_pid) is not int
        or lease._owner_pid != os.getpid()
        or lease._state != "active"
        or lease._receipt is None
        or lease._cleanup_receipt is not None
        or lease._cleanup_receipt_digest_anchor is not None
        or type(lease._receipt_digest_anchor) is not str
        or type(lease._receipt_staged_file_refs_anchor) is not tuple
        or lease._root_descriptor is not None
        or lease._pending_name is not None
        or lease._pending_identity is not None
        or type(lease._pending_descriptors) is not tuple
        or lease._pending_descriptors != ()
        or lease._descriptor_release_unverifiable is not False
        or type(lease._files) is not tuple
    ):
        raise _InvalidRuntimeManifest
    expected_canonical = _BUILTIN_STAGING_RECEIPT_PROJECTION(
        expected_staging
    )
    embedded_canonical = _BUILTIN_STAGING_RECEIPT_PROJECTION(
        lease._receipt
    )
    expected_digest = _BUILTIN_CANONICAL_DIGEST(expected_canonical)
    expected_refs = tuple(
        value.staged_file_ref for value in expected_staging.staged_files
    )
    if (
        embedded_canonical != expected_canonical
        or lease._receipt_digest_anchor != expected_digest
        or lease._receipt_staged_file_refs_anchor != expected_refs
        or len(lease._files) != expected_staging.unique_file_count
        or any(type(value) is not _RetainedStagedFile for value in lease._files)
        or any(
            type(value.staged_file) is not RepositoryExecutableStagedFile
            or type(value.descriptor) is not int
            or value.descriptor < 0
            or type(value.metadata) is not tuple
            or len(value.metadata) != 9
            or any(type(part) is not int for part in value.metadata)
            for value in lease._files
        )
        or tuple(value.staged_file for value in lease._files)
        != expected_staging.staged_files
    ):
        raise _InvalidRuntimeManifest
    return expected_canonical, lease._files


def _verify_anchored_retained_file(
    retained: _RetainedStagedFile,
    anchored: Any,
) -> bytes:
    """Remeasure one descriptor and return its digest-corresponding header."""

    if (
        type(retained) is not _RetainedStagedFile
        or retained.staged_file != anchored
    ):
        raise _InvalidRuntimeManifest
    try:
        before = os.fstat(retained.descriptor)
        before_flags = fcntl.fcntl(retained.descriptor, fcntl.F_GETFL)
        before_inheritable = os.get_inheritable(retained.descriptor)
    except (OSError, ValueError):
        raise _InvalidRuntimeManifest from None
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
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) != _STAGED_FILE_MODE
        or before.st_nlink != 0
        or before.st_size != anchored.content_bytes
        or before_flags & os.O_ACCMODE != os.O_RDONLY
        or before_inheritable
    ):
        raise _InvalidRuntimeManifest

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
        raise _InvalidRuntimeManifest

    digest = hashlib.sha256()
    header_parts: list[bytes] = []
    header_remaining = min(anchored.content_bytes, _MAX_HEADER_BYTES)
    offset = 0
    while offset < anchored.content_bytes:
        requested = min(
            _FULL_REMEASUREMENT_CHUNK_BYTES,
            anchored.content_bytes - offset,
        )
        try:
            chunk = os.pread(retained.descriptor, requested, offset)
        except (BlockingIOError, InterruptedError, OSError):
            raise _InvalidRuntimeManifest from None
        if not chunk or len(chunk) > requested:
            raise _InvalidRuntimeManifest
        digest.update(chunk)
        if header_remaining:
            captured = chunk[:header_remaining]
            header_parts.append(captured)
            header_remaining -= len(captured)
        offset += len(chunk)
    try:
        if os.pread(retained.descriptor, 1, anchored.content_bytes) != b"":
            raise _InvalidRuntimeManifest
        after = os.fstat(retained.descriptor)
        after_flags = fcntl.fcntl(retained.descriptor, fcntl.F_GETFL)
        after_inheritable = os.get_inheritable(retained.descriptor)
    except (OSError, ValueError):
        raise _InvalidRuntimeManifest from None
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
        or len(header) != min(anchored.content_bytes, _MAX_HEADER_BYTES)
        or content_digest != anchored.content_digest
    ):
        raise _InvalidRuntimeManifest
    return header


def _build_runtime_file(
    retained: _RetainedStagedFile,
    header: bytes,
) -> RepositoryExecutableRuntimeFile:
    staged_file = retained.staged_file
    classification, directive_ref = _classify_header(
        staged_file.staged_file_ref,
        header,
    )
    header_digest = _header_digest(staged_file.staged_file_ref, header)
    reference_projection = _runtime_file_ref_projection(
        staged_file_ref=staged_file.staged_file_ref,
        staged_filesystem_identity_ref=(
            staged_file.staged_filesystem_identity_ref
        ),
        content_digest=staged_file.content_digest,
        content_bytes=staged_file.content_bytes,
        header_digest=header_digest,
        header_bytes=len(header),
        classification=classification,
        shebang_directive_ref=directive_ref,
    )
    value = RepositoryExecutableRuntimeFile(
        kind=REPOSITORY_EXECUTABLE_RUNTIME_FILE_KIND,
        staged_file_ref=staged_file.staged_file_ref,
        staged_filesystem_identity_ref=(
            staged_file.staged_filesystem_identity_ref
        ),
        content_digest=staged_file.content_digest,
        content_bytes=staged_file.content_bytes,
        runtime_file_ref=_BUILTIN_CANONICAL_DIGEST(reference_projection),
        header_digest=header_digest,
        header_bytes=len(header),
        classification=classification,
        shebang_directive_ref=directive_ref,
    )
    _runtime_file_projection(value)
    return value


def inspect_staged_executable_runtime_manifest(
    expected_staging: RepositoryExecutableStagingReceipt,
    *,
    lease: RepositoryExecutableStageLease,
) -> RepositoryExecutableRuntimeManifestReceipt:
    """Inspect one exact active stage without mutating or consuming its lease."""

    try:
        staging_canonical, retained_files = _active_stage_snapshot(
            expected_staging,
            lease,
        )
        runtime_files: list[RepositoryExecutableRuntimeFile] = []
        for retained, anchored in zip(
            retained_files,
            expected_staging.staged_files,
            strict=True,
        ):
            remeasured_header = _verify_anchored_retained_file(
                retained,
                anchored,
            )
            header = _read_exact_header(
                retained.descriptor,
                anchored.content_bytes,
            )
            if header != remeasured_header:
                raise _InvalidRuntimeManifest
            runtime_files.append(_build_runtime_file(retained, header))

        final_canonical, final_retained_files = _active_stage_snapshot(
            expected_staging,
            lease,
        )
        if (
            final_canonical != staging_canonical
            or final_retained_files is not retained_files
        ):
            raise _InvalidRuntimeManifest
        for retained, anchored in zip(
            final_retained_files,
            expected_staging.staged_files,
            strict=True,
        ):
            _verify_anchored_retained_file(retained, anchored)

        file_by_staged_ref = {
            value.staged_file_ref: value for value in runtime_files
        }
        bindings: list[RepositoryExecutableRuntimeBinding] = []
        for staging_binding in expected_staging.bindings:
            if staging_binding.kind != REPOSITORY_EXECUTABLE_STAGE_BINDING_KIND:
                raise _InvalidRuntimeManifest
            runtime_file = file_by_staged_ref.get(
                staging_binding.staged_file_ref
            )
            if runtime_file is None:
                raise _InvalidRuntimeManifest
            bindings.append(
                RepositoryExecutableRuntimeBinding(
                    kind=REPOSITORY_EXECUTABLE_RUNTIME_BINDING_KIND,
                    command_kind=staging_binding.command_kind,
                    command_id=staging_binding.command_id,
                    command_digest=staging_binding.command_digest,
                    staged_file_ref=staging_binding.staged_file_ref,
                    runtime_file_ref=runtime_file.runtime_file_ref,
                )
            )

        receipt = RepositoryExecutableRuntimeManifestReceipt(
            kind=REPOSITORY_EXECUTABLE_RUNTIME_MANIFEST_KIND,
            schema_version=(
                REPOSITORY_EXECUTABLE_RUNTIME_MANIFEST_SCHEMA_VERSION
            ),
            manifest_source=MANIFEST_SOURCE,
            manifest_scope=MANIFEST_SCOPE,
            staging_receipt_digest=_BUILTIN_CANONICAL_DIGEST(
                staging_canonical
            ),
            registration_digest=expected_staging.registration_digest,
            repository_ref=expected_staging.repository_ref,
            verification_commands_digest=(
                expected_staging.verification_commands_digest
            ),
            resolution_context_digest=(
                expected_staging.resolution_context_digest
            ),
            staging_context_digest=expected_staging.staging_context_digest,
            files=tuple(runtime_files),
            bindings=tuple(bindings),
            file_count=len(runtime_files),
            command_count=len(bindings),
            total_content_bytes=sum(
                value.content_bytes for value in runtime_files
            ),
            total_header_bytes=sum(
                value.header_bytes for value in runtime_files
            ),
        )
        _runtime_manifest_projection(receipt)
        return receipt
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise ValidationError(_INVALID_MESSAGE) from None


__all__ = [
    "MANIFEST_SCOPE",
    "MANIFEST_SOURCE",
    "REPOSITORY_EXECUTABLE_RUNTIME_BINDING_KIND",
    "REPOSITORY_EXECUTABLE_RUNTIME_FILE_KIND",
    "REPOSITORY_EXECUTABLE_RUNTIME_MANIFEST_EVIDENCE_KIND",
    "REPOSITORY_EXECUTABLE_RUNTIME_MANIFEST_KIND",
    "REPOSITORY_EXECUTABLE_RUNTIME_MANIFEST_SCHEMA_VERSION",
    "RepositoryExecutableRuntimeBinding",
    "RepositoryExecutableRuntimeFile",
    "RepositoryExecutableRuntimeManifestReceipt",
    "inspect_staged_executable_runtime_manifest",
]
