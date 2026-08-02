"""Read-only runtime-header evidence for active manifest-target stage leases.

The inspector accepts only a valid active Class 1 manifest-target staging lease.
It never opens a pathname: each detached, read-only descriptor is fully
remeasured with ``pread`` and its bounded header is classified.  It stops before
dependency parsing, loader search, loading, or execution.
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
from .repository_executable_native_dependency_manifest_target_staging import (
    RepositoryExecutableNativeDependencyManifestTargetStageLease,
    RepositoryExecutableNativeDependencyManifestTargetStagedFile,
    RepositoryExecutableNativeDependencyManifestTargetStagingReceipt,
    _RetainedTarget,
    _staged_file_projection,
    _staging_receipt_projection,
)


REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_RUNTIME_MANIFEST_SCHEMA_VERSION = 1
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_RUNTIME_MANIFEST_KIND = (
    "repository_executable_native_dependency_manifest_target_runtime_manifest"
)
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_RUNTIME_MANIFEST_EVIDENCE_KIND = (
    "repository_executable_native_dependency_manifest_target_runtime_manifest_validation"
)
REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_RUNTIME_FILE_KIND = (
    "repository_executable_native_dependency_manifest_target_runtime_file"
)
MANIFEST_SOURCE = "controller_inspected"
MANIFEST_SCOPE = "staged_explicit_manifest_target_runtime_header_v1"

_FIXED_SCHEMA_VERSION = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_RUNTIME_MANIFEST_SCHEMA_VERSION
_FIXED_MANIFEST_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_RUNTIME_MANIFEST_KIND
_FIXED_EVIDENCE_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_RUNTIME_MANIFEST_EVIDENCE_KIND
_FIXED_FILE_KIND = REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_RUNTIME_FILE_KIND
_FIXED_MANIFEST_SOURCE = MANIFEST_SOURCE
_FIXED_MANIFEST_SCOPE = MANIFEST_SCOPE
_INVALID_MESSAGE = "repository executable native dependency manifest target runtime manifest is invalid"
_DIGEST_PREFIX = "sha256:"
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_FILES = 80
_MAX_FILE_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_BYTES = 256 * 1024 * 1024
_MAX_HEADER_BYTES = 4_096
_MAX_SHEBANG_DIRECTIVE_BYTES = 255
_REMEASUREMENT_CHUNK_BYTES = 1024 * 1024
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


def _captured_canonical_digest(value: Any) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


# Capture the shipped proof graph: public names remain diagnostic conveniences,
# not trusted caller-controlled policy inputs.
_BUILTIN_CANONICAL_DIGEST = _captured_canonical_digest
_BUILTIN_SHA256 = hashlib.sha256
_BUILTIN_PREAD = os.pread
_BUILTIN_FSTAT = os.fstat
_BUILTIN_GETPID = os.getpid
_BUILTIN_GETEUID = os.geteuid
_BUILTIN_GET_INHERITABLE = os.get_inheritable
_BUILTIN_FCNTL = fcntl.fcntl
_BUILTIN_STAGING_PROJECTION = _staging_receipt_projection
_BUILTIN_STAGED_FILE_PROJECTION = _staged_file_projection
_FIXED_VALIDATION_ERROR = ValidationError
_FIXED_STAGE_RECEIPT_TYPE = RepositoryExecutableNativeDependencyManifestTargetStagingReceipt
_FIXED_STAGE_LEASE_TYPE = RepositoryExecutableNativeDependencyManifestTargetStageLease
_FIXED_STAGED_FILE_TYPE = RepositoryExecutableNativeDependencyManifestTargetStagedFile
_FIXED_RETAINED_TYPE = _RetainedTarget


class _InvalidTargetRuntimeManifest(ValueError):
    """Internal sentinel with no public diagnostic detail."""


def _is_digest(value: Any) -> bool:
    return type(value) is str and _DIGEST_PATTERN.fullmatch(value) is not None


def _metadata_signature(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeDependencyManifestTargetRuntimeFile:
    """One fully remeasured staged target and bounded byte-level classification."""

    kind: str
    manifest_target_ref: str = field(repr=False)
    target_staged_file_ref: str = field(repr=False)
    staged_filesystem_identity_ref: str = field(repr=False)
    content_digest: str = field(repr=False)
    content_bytes: int
    target_runtime_file_ref: str = field(repr=False)
    header_digest: str = field(repr=False)
    header_bytes: int
    classification: str
    shebang_directive_ref: str | None = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _runtime_file_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableNativeDependencyManifestTargetRuntimeManifestReceipt:
    """Digest-only Class 0 runtime-header evidence for a detached-copy lease."""

    kind: str
    schema_version: int
    manifest_source: str
    manifest_scope: str
    target_staging_receipt_digest: str = field(repr=False)
    native_dependency_manifest_targets_receipt_digest: str = field(repr=False)
    native_dependency_manifest_receipt_digest: str = field(repr=False)
    native_dependency_requirements_receipt_digest: str = field(repr=False)
    runtime_manifest_receipt_digest: str = field(repr=False)
    staging_receipt_digest: str = field(repr=False)
    registration_digest: str = field(repr=False)
    repository_ref: str = field(repr=False)
    verification_commands_digest: str = field(repr=False)
    resolution_context_digest: str = field(repr=False)
    source_staging_context_digest: str = field(repr=False)
    manifest_context_digest: str = field(repr=False)
    action_measurements_digest: str = field(repr=False)
    post_stage_targets_receipt_digest: str = field(repr=False)
    target_staging_context_digest: str = field(repr=False)
    files: tuple[RepositoryExecutableNativeDependencyManifestTargetRuntimeFile, ...] = field(repr=False)
    file_count: int
    total_content_bytes: int
    total_header_bytes: int

    def to_canonical(self) -> dict[str, Any]:
        return _runtime_manifest_projection(self)

    @property
    def receipt_digest(self) -> str:
        return _BUILTIN_CANONICAL_DIGEST(_runtime_manifest_projection(self))

    def to_evidence(self) -> dict[str, Any]:
        return _runtime_manifest_evidence_projection(self)


_FIXED_RUNTIME_FILE_TYPE = RepositoryExecutableNativeDependencyManifestTargetRuntimeFile
_FIXED_RECEIPT_TYPE = RepositoryExecutableNativeDependencyManifestTargetRuntimeManifestReceipt


def _runtime_file_ref_projection(
    *,
    manifest_target_ref: str,
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
        "kind": "repository_executable_native_dependency_manifest_target_runtime_file_ref",
        "manifest_scope": _FIXED_MANIFEST_SCOPE,
        "manifest_target_ref": manifest_target_ref,
        "schema_version": _FIXED_SCHEMA_VERSION,
        "shebang_directive_ref": shebang_directive_ref,
        "staged_filesystem_identity_ref": staged_filesystem_identity_ref,
        "target_staged_file_ref": target_staged_file_ref,
    }


def _runtime_file_projection(value: RepositoryExecutableNativeDependencyManifestTargetRuntimeFile) -> dict[str, Any]:
    if (
        type(value) is not _FIXED_RUNTIME_FILE_TYPE
        or value.kind != _FIXED_FILE_KIND
        or not all(
            _is_digest(item)
            for item in (
                value.manifest_target_ref,
                value.target_staged_file_ref,
                value.staged_filesystem_identity_ref,
                value.content_digest,
                value.target_runtime_file_ref,
                value.header_digest,
            )
        )
        or type(value.content_bytes) is not int
        or not 0 <= value.content_bytes <= _MAX_FILE_BYTES
        or type(value.header_bytes) is not int
        or not 0 <= value.header_bytes <= min(value.content_bytes, _MAX_HEADER_BYTES)
        or value.classification not in {"elf", "mach_o", "posix_shebang", "unsupported_shebang", "unknown"}
        or (value.shebang_directive_ref is not None and not _is_digest(value.shebang_directive_ref))
    ):
        raise _InvalidTargetRuntimeManifest
    if (
        (value.classification == "posix_shebang") != (value.shebang_directive_ref is not None)
        or value.header_bytes != min(value.content_bytes, _MAX_HEADER_BYTES)
    ):
        raise _InvalidTargetRuntimeManifest
    reference = _runtime_file_ref_projection(
        manifest_target_ref=value.manifest_target_ref,
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
        raise _InvalidTargetRuntimeManifest
    return {
        "classification": value.classification,
        "content_bytes": value.content_bytes,
        "content_digest": value.content_digest,
        "header_bytes": value.header_bytes,
        "header_digest": value.header_digest,
        "kind": value.kind,
        "manifest_target_ref": value.manifest_target_ref,
        "shebang_directive_ref": value.shebang_directive_ref,
        "staged_filesystem_identity_ref": value.staged_filesystem_identity_ref,
        "target_runtime_file_ref": value.target_runtime_file_ref,
        "target_staged_file_ref": value.target_staged_file_ref,
    }


def _runtime_manifest_projection(value: RepositoryExecutableNativeDependencyManifestTargetRuntimeManifestReceipt) -> dict[str, Any]:
    digests = (
        value.target_staging_receipt_digest,
        value.native_dependency_manifest_targets_receipt_digest,
        value.native_dependency_manifest_receipt_digest,
        value.native_dependency_requirements_receipt_digest,
        value.runtime_manifest_receipt_digest,
        value.staging_receipt_digest,
        value.registration_digest,
        value.repository_ref,
        value.verification_commands_digest,
        value.resolution_context_digest,
        value.source_staging_context_digest,
        value.manifest_context_digest,
        value.action_measurements_digest,
        value.post_stage_targets_receipt_digest,
        value.target_staging_context_digest,
    )
    if (
        type(value) is not _FIXED_RECEIPT_TYPE
        or value.kind != _FIXED_MANIFEST_KIND
        or value.schema_version != _FIXED_SCHEMA_VERSION
        or value.manifest_source != _FIXED_MANIFEST_SOURCE
        or value.manifest_scope != _FIXED_MANIFEST_SCOPE
        or not all(_is_digest(item) for item in digests)
        or type(value.files) is not tuple
        or not 0 <= len(value.files) <= _MAX_FILES
        or type(value.file_count) is not int
        or value.file_count != len(value.files)
        or type(value.total_content_bytes) is not int
        or type(value.total_header_bytes) is not int
    ):
        raise _InvalidTargetRuntimeManifest
    files = tuple(_BUILTIN_RUNTIME_FILE_PROJECTION(item) for item in value.files)
    if (
        len({item["target_runtime_file_ref"] for item in files}) != len(files)
        or len({item["target_staged_file_ref"] for item in files}) != len(files)
        or sum(item["content_bytes"] for item in files) != value.total_content_bytes
        or sum(item["header_bytes"] for item in files) != value.total_header_bytes
        or not 0 <= value.total_content_bytes <= _MAX_TOTAL_BYTES
        or not 0 <= value.total_header_bytes <= _MAX_FILES * _MAX_HEADER_BYTES
    ):
        raise _InvalidTargetRuntimeManifest
    return {
        "action_measurements_digest": value.action_measurements_digest,
        "file_count": value.file_count,
        "files": files,
        "kind": value.kind,
        "manifest_context_digest": value.manifest_context_digest,
        "manifest_scope": value.manifest_scope,
        "manifest_source": value.manifest_source,
        "native_dependency_manifest_receipt_digest": value.native_dependency_manifest_receipt_digest,
        "native_dependency_manifest_targets_receipt_digest": value.native_dependency_manifest_targets_receipt_digest,
        "native_dependency_requirements_receipt_digest": value.native_dependency_requirements_receipt_digest,
        "post_stage_targets_receipt_digest": value.post_stage_targets_receipt_digest,
        "registration_digest": value.registration_digest,
        "repository_ref": value.repository_ref,
        "resolution_context_digest": value.resolution_context_digest,
        "runtime_manifest_receipt_digest": value.runtime_manifest_receipt_digest,
        "schema_version": value.schema_version,
        "source_staging_context_digest": value.source_staging_context_digest,
        "staging_receipt_digest": value.staging_receipt_digest,
        "target_staging_context_digest": value.target_staging_context_digest,
        "target_staging_receipt_digest": value.target_staging_receipt_digest,
        "total_content_bytes": value.total_content_bytes,
        "total_header_bytes": value.total_header_bytes,
        "verification_commands_digest": value.verification_commands_digest,
    }


def _runtime_manifest_evidence_projection(value: RepositoryExecutableNativeDependencyManifestTargetRuntimeManifestReceipt) -> dict[str, Any]:
    canonical = _runtime_manifest_projection(value)
    counts = {classification: 0 for classification in ("elf", "mach_o", "posix_shebang", "unsupported_shebang", "unknown")}
    for item in value.files:
        counts[item.classification] += 1
    return {
        "ambient_loader_environment_consulted": False,
        "authority_granted": False,
        "billing_eligible": False,
        "dependency_closure_verified": False,
        "dispatch_enabled": False,
        "effect_class": 0,
        "execution_enabled": False,
        "file_count": value.file_count,
        "harness_invocation_performed": False,
        "kind": _FIXED_EVIDENCE_KIND,
        "loader_invocation_performed": False,
        "manifest_target_raw_values_exposed": False,
        "model_invocation_performed": False,
        "network_access_performed": False,
        "path_open_performed": False,
        "receipt_digest": _BUILTIN_CANONICAL_DIGEST(canonical),
        "recursive_dependency_resolution_verified": False,
        "source_path_reopen_performed": False,
        "staged_descriptor_full_remeasurement_complete": True,
        "subprocess_invocation_performed": False,
        "total_content_bytes": value.total_content_bytes,
        "total_header_bytes": value.total_header_bytes,
        "validation_mode": "read_only",
        **{f"{key}_file_count": count for key, count in counts.items()},
    }


_BUILTIN_RUNTIME_FILE_PROJECTION = _runtime_file_projection
_BUILTIN_RUNTIME_MANIFEST_PROJECTION = _runtime_manifest_projection


def _active_stage_snapshot(expected: Any, lease: Any) -> tuple[dict[str, Any], tuple[_RetainedTarget, ...]]:
    if (
        type(expected) is not _FIXED_STAGE_RECEIPT_TYPE
        or type(lease) is not _FIXED_STAGE_LEASE_TYPE
        or lease._owner_pid != _BUILTIN_GETPID()
        or lease._state != "active"
        or lease._receipt is not expected
        or lease._receipt is not lease._receipt_anchor
        or lease._cleanup_receipt is not None
        or lease._root_descriptor is not None
        or lease._root_metadata is not None
        or lease._files is not lease._files_anchor
        or type(lease._files) is not tuple
    ):
        raise _InvalidTargetRuntimeManifest
    canonical = _BUILTIN_STAGING_PROJECTION(expected)
    if lease._receipt_digest_anchor != _BUILTIN_CANONICAL_DIGEST(canonical):
        raise _InvalidTargetRuntimeManifest
    anchored_files = tuple(dict(item) for item in canonical["staged_files"])
    if (
        len(lease._files) != expected.unique_target_count
        or len(anchored_files) != expected.unique_target_count
        or any(type(item) is not _FIXED_RETAINED_TYPE for item in lease._files)
        or any(
            retained.staged_file is not staged
            for retained, staged in zip(lease._files, expected.staged_files, strict=True)
        )
    ):
        raise _InvalidTargetRuntimeManifest
    return canonical, lease._files


def _read_and_verify(retained: _RetainedTarget, anchored: dict[str, Any]) -> bytes:
    if type(retained) is not _FIXED_RETAINED_TYPE or type(anchored) is not dict:
        raise _InvalidTargetRuntimeManifest
    if _BUILTIN_STAGED_FILE_PROJECTION(retained.staged_file) != anchored:
        raise _InvalidTargetRuntimeManifest
    try:
        before = _BUILTIN_FSTAT(retained.descriptor)
        flags = _BUILTIN_FCNTL(retained.descriptor, fcntl.F_GETFL)
        inheritable = _BUILTIN_GET_INHERITABLE(retained.descriptor)
    except (OSError, ValueError):
        raise _InvalidTargetRuntimeManifest from None
    if (
        _metadata_signature(before) != retained.metadata
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != _BUILTIN_GETEUID()
        or stat.S_IMODE(before.st_mode) != _STAGED_FILE_MODE
        or before.st_nlink != 0
        or before.st_size != anchored["content_bytes"]
        or flags & os.O_ACCMODE != os.O_RDONLY
        or inheritable
    ):
        raise _InvalidTargetRuntimeManifest
    identity_ref = _BUILTIN_CANONICAL_DIGEST({
        "device": before.st_dev,
        "inode": before.st_ino,
        "kind": "repository_executable_native_dependency_manifest_target_staged_file_identity",
        "schema_version": 1,
    })
    metadata_digest = _BUILTIN_CANONICAL_DIGEST({
        "change_time_ns": before.st_ctime_ns,
        "filesystem_identity_ref": identity_ref,
        "group_id": before.st_gid,
        "kind": "repository_executable_native_dependency_manifest_target_staged_file_metadata",
        "link_count": before.st_nlink,
        "mode": before.st_mode,
        "modified_time_ns": before.st_mtime_ns,
        "owner_id": before.st_uid,
        "schema_version": 1,
        "size_bytes": before.st_size,
    })
    if identity_ref != anchored["staged_filesystem_identity_ref"] or metadata_digest != anchored["staged_metadata_digest"]:
        raise _InvalidTargetRuntimeManifest
    digest = _BUILTIN_SHA256()
    header: list[bytes] = []
    header_remaining = min(before.st_size, _MAX_HEADER_BYTES)
    offset = 0
    while offset < before.st_size:
        requested = min(_REMEASUREMENT_CHUNK_BYTES, before.st_size - offset)
        try:
            chunk = _BUILTIN_PREAD(retained.descriptor, requested, offset)
        except (BlockingIOError, InterruptedError, OSError):
            raise _InvalidTargetRuntimeManifest from None
        if not chunk or len(chunk) > requested:
            raise _InvalidTargetRuntimeManifest
        digest.update(chunk)
        if header_remaining:
            captured = chunk[:header_remaining]
            header.append(captured)
            header_remaining -= len(captured)
        offset += len(chunk)
    try:
        boundary = _BUILTIN_PREAD(retained.descriptor, 1, before.st_size)
        after = _BUILTIN_FSTAT(retained.descriptor)
        after_flags = _BUILTIN_FCNTL(retained.descriptor, fcntl.F_GETFL)
        after_inheritable = _BUILTIN_GET_INHERITABLE(retained.descriptor)
    except (OSError, ValueError):
        raise _InvalidTargetRuntimeManifest from None
    result_header = b"".join(header)
    if (
        boundary != b""
        or _metadata_signature(after) != _metadata_signature(before)
        or after_flags != flags
        or after_inheritable != inheritable
        or header_remaining != 0
        or _DIGEST_PREFIX + digest.hexdigest() != anchored["content_digest"]
    ):
        raise _InvalidTargetRuntimeManifest
    return result_header


def _classify_header(staged_file_ref: str, header: bytes) -> tuple[str, str | None]:
    if header.startswith(b"#!"):
        newline = header.find(b"\n", 2)
        directive = header[2:newline] if newline >= 0 else None
        if (
            directive is None
            or not 1 <= len(directive) <= _MAX_SHEBANG_DIRECTIVE_BYTES
            or directive[:1] in {b" ", b"\t"}
            or directive[-1:] in {b" ", b"\t"}
            or not any(value not in {0x20, 0x09} for value in directive)
            or any(value != 0x09 and not 0x20 <= value <= 0x7E for value in directive)
        ):
            return "unsupported_shebang", None
        return "posix_shebang", _BUILTIN_CANONICAL_DIGEST({
            "directive_hex": directive.hex(),
            "kind": "repository_executable_native_dependency_manifest_target_runtime_shebang_directive_ref",
            "schema_version": _FIXED_SCHEMA_VERSION,
            "target_staged_file_ref": staged_file_ref,
        })
    if header.startswith(b"\x7fELF"):
        if len(header) >= 16 and header[4] in {1, 2} and header[5] in {1, 2} and header[6] == 1:
            return "elf", None
        return "unknown", None
    magic = header[:4]
    if magic in _MACH_O_MINIMUM_BYTES and len(header) >= _MACH_O_MINIMUM_BYTES[magic]:
        return "mach_o", None
    return "unknown", None


_BUILTIN_CLASSIFY_HEADER = _classify_header


def _build_runtime_file(anchored: dict[str, Any], header: bytes) -> RepositoryExecutableNativeDependencyManifestTargetRuntimeFile:
    classification, directive_ref = _BUILTIN_CLASSIFY_HEADER(anchored["staged_file_ref"], header)
    header_digest = _DIGEST_PREFIX + _BUILTIN_SHA256(anchored["staged_file_ref"].encode("ascii") + b"\x00" + header).hexdigest()
    reference = _runtime_file_ref_projection(
        manifest_target_ref=anchored["manifest_target_ref"],
        target_staged_file_ref=anchored["staged_file_ref"],
        staged_filesystem_identity_ref=anchored["staged_filesystem_identity_ref"],
        content_digest=anchored["content_digest"],
        content_bytes=anchored["content_bytes"],
        header_digest=header_digest,
        header_bytes=len(header),
        classification=classification,
        shebang_directive_ref=directive_ref,
    )
    value = _FIXED_RUNTIME_FILE_TYPE(
        kind=_FIXED_FILE_KIND,
        manifest_target_ref=anchored["manifest_target_ref"],
        target_staged_file_ref=anchored["staged_file_ref"],
        staged_filesystem_identity_ref=anchored["staged_filesystem_identity_ref"],
        content_digest=anchored["content_digest"],
        content_bytes=anchored["content_bytes"],
        target_runtime_file_ref=_BUILTIN_CANONICAL_DIGEST(reference),
        header_digest=header_digest,
        header_bytes=len(header),
        classification=classification,
        shebang_directive_ref=directive_ref,
    )
    _BUILTIN_RUNTIME_FILE_PROJECTION(value)
    return value


_BUILTIN_ACTIVE_STAGE_SNAPSHOT = _active_stage_snapshot
_BUILTIN_READ_AND_VERIFY = _read_and_verify
_BUILTIN_BUILD_RUNTIME_FILE = _build_runtime_file


def inspect_staged_executable_native_dependency_manifest_target_runtime_manifest(
    expected_target_staging: RepositoryExecutableNativeDependencyManifestTargetStagingReceipt,
    *,
    lease: RepositoryExecutableNativeDependencyManifestTargetStageLease,
) -> RepositoryExecutableNativeDependencyManifestTargetRuntimeManifestReceipt:
    """Inspect the exact active detached manifest-target stage without mutation."""

    try:
        staging_canonical, retained = _BUILTIN_ACTIVE_STAGE_SNAPSHOT(expected_target_staging, lease)
        anchored_files = tuple(dict(item) for item in staging_canonical["staged_files"])
        files = tuple(
            _BUILTIN_BUILD_RUNTIME_FILE(anchored, _BUILTIN_READ_AND_VERIFY(item, anchored))
            for item, anchored in zip(retained, anchored_files, strict=True)
        )
        final_canonical, final_retained = _BUILTIN_ACTIVE_STAGE_SNAPSHOT(expected_target_staging, lease)
        if final_canonical != staging_canonical or final_retained is not retained:
            raise _InvalidTargetRuntimeManifest
        for item, anchored in zip(final_retained, anchored_files, strict=True):
            _BUILTIN_READ_AND_VERIFY(item, anchored)
        receipt = _FIXED_RECEIPT_TYPE(
            kind=_FIXED_MANIFEST_KIND,
            schema_version=_FIXED_SCHEMA_VERSION,
            manifest_source=_FIXED_MANIFEST_SOURCE,
            manifest_scope=_FIXED_MANIFEST_SCOPE,
            target_staging_receipt_digest=_BUILTIN_CANONICAL_DIGEST(staging_canonical),
            native_dependency_manifest_targets_receipt_digest=staging_canonical["native_dependency_manifest_targets_receipt_digest"],
            native_dependency_manifest_receipt_digest=staging_canonical["native_dependency_manifest_receipt_digest"],
            native_dependency_requirements_receipt_digest=staging_canonical["native_dependency_requirements_receipt_digest"],
            runtime_manifest_receipt_digest=staging_canonical["runtime_manifest_receipt_digest"],
            staging_receipt_digest=staging_canonical["staging_receipt_digest"],
            registration_digest=staging_canonical["registration_digest"],
            repository_ref=staging_canonical["repository_ref"],
            verification_commands_digest=staging_canonical["verification_commands_digest"],
            resolution_context_digest=staging_canonical["resolution_context_digest"],
            source_staging_context_digest=staging_canonical["source_staging_context_digest"],
            manifest_context_digest=staging_canonical["manifest_context_digest"],
            action_measurements_digest=staging_canonical["action_measurements_digest"],
            post_stage_targets_receipt_digest=staging_canonical["post_stage_targets_receipt_digest"],
            target_staging_context_digest=staging_canonical["target_staging_context_digest"],
            files=files,
            file_count=len(files),
            total_content_bytes=sum(item.content_bytes for item in files),
            total_header_bytes=sum(item.header_bytes for item in files),
        )
        _BUILTIN_RUNTIME_MANIFEST_PROJECTION(receipt)
        closing_canonical, closing_retained = _BUILTIN_ACTIVE_STAGE_SNAPSHOT(expected_target_staging, lease)
        if closing_canonical != staging_canonical or closing_retained is not retained:
            raise _InvalidTargetRuntimeManifest
        return receipt
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _FIXED_VALIDATION_ERROR(_INVALID_MESSAGE) from None


__all__ = [
    "MANIFEST_SCOPE",
    "MANIFEST_SOURCE",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_RUNTIME_FILE_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_RUNTIME_MANIFEST_EVIDENCE_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_RUNTIME_MANIFEST_KIND",
    "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_RUNTIME_MANIFEST_SCHEMA_VERSION",
    "RepositoryExecutableNativeDependencyManifestTargetRuntimeFile",
    "RepositoryExecutableNativeDependencyManifestTargetRuntimeManifestReceipt",
    "inspect_staged_executable_native_dependency_manifest_target_runtime_manifest",
]
