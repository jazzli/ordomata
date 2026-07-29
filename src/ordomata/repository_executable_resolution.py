"""Read-only resolution and measurement of declared executable files.

This module consumes an exact schema-v4 repository registration and measures
only the direct file named by each command's ``argv[0]``.  Resolution uses
controller-supplied absolute search directories or the registered repository
root, never ambient process state.  A receipt proves only the bytes read while
the function was running.  It is not reusable authority and does not establish
that the same object would be selected or invocable by a future execution.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
import unicodedata
from typing import Any, Callable

from .authorization import canonical_digest
from .errors import ValidationError
from .repository_registration import (
    RepositoryRegistration,
    VerificationCommand,
    _baseline_command_results_projection,
    _executable_toolchain_identities_projection,
    _registration_canonical_projection,
    _verification_command_digest,
    revalidate_repository_registration,
)


REPOSITORY_EXECUTABLE_RESOLUTION_SCHEMA_VERSION = 1
REPOSITORY_EXECUTABLE_RESOLUTION_KIND = "repository_executable_resolution"
REPOSITORY_EXECUTABLE_RESOLUTION_EVIDENCE_KIND = (
    "repository_executable_resolution_validation"
)
REPOSITORY_EXECUTABLE_MEASUREMENT_KIND = "repository_executable_measurement"
MEASUREMENT_SOURCE = "controller_measured"
RESOLUTION_SCOPE = "posix_nofollow_v1"
REPOSITORY_EXECUTABLE_RESOLUTION_MEASUREMENT_SOURCE = MEASUREMENT_SOURCE
REPOSITORY_EXECUTABLE_RESOLUTION_SCOPE = RESOLUTION_SCOPE

_INVALID_MESSAGE = "repository executable resolution is invalid"
_COMMAND_KINDS = ("format", "lint", "type_check", "test", "build")
_CONCRETE_PATH_TYPE = type(Path())
_MAX_SEARCH_DIRECTORIES = 32
_MAX_SEARCH_DIRECTORY_BYTES = 16 * 1024
_MAX_DIRECTORY_ENTRIES = 16_384
_MAX_DIRECTORY_ENTRY_BYTES = 4 * 1024 * 1024
_MAX_EXECUTABLE_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_EXECUTABLE_BYTES = 256 * 1024 * 1024
_READ_CHUNK_BYTES = 1024 * 1024
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER_PATTERN = re.compile(r"[a-z][a-z0-9_.-]{0,119}\Z")

# Keep references to the shipped implementations.  Public methods on the
# transparent registration dataclasses remain patchable and are not trusted as
# canonicalization or revalidation boundaries here.
_BUILTIN_REVALIDATE_REPOSITORY_REGISTRATION = (
    revalidate_repository_registration
)
_BUILTIN_REGISTRATION_CANONICAL_PROJECTION = (
    _registration_canonical_projection
)
_BUILTIN_BASELINE_PROJECTION = _baseline_command_results_projection
_BUILTIN_TOOLCHAIN_IDENTITIES_PROJECTION = (
    _executable_toolchain_identities_projection
)
_BUILTIN_COMMAND_DIGEST = _verification_command_digest


class _InvalidResolution(ValueError):
    """Internal sentinel whose details never cross the public boundary."""


@dataclass(frozen=True, slots=True)
class ResolvedExecutableMeasurement:
    """One declaration-bound direct-file measurement.

    Identifiers, filesystem references, and content hashes are intentionally
    omitted from ``repr`` and from aggregate public evidence.
    """

    kind: str
    command_kind: str
    command_id: str = field(repr=False)
    command_digest: str = field(repr=False)
    declared_executable_kind: str
    declared_executable_ref: str = field(repr=False)
    resolution_method: str
    resolution_root_ref: str = field(repr=False)
    search_directory_index: int | None = field(repr=False)
    resolved_executable_ref: str = field(repr=False)
    filesystem_identity_ref: str = field(repr=False)
    metadata_digest: str = field(repr=False)
    content_digest: str = field(repr=False)
    content_bytes: int

    def to_canonical(self) -> dict[str, Any]:
        return _measurement_projection(self)


@dataclass(frozen=True, slots=True)
class RepositoryExecutableResolutionReceipt:
    """Immutable, non-authorizing aggregate of sequential measurements."""

    kind: str
    schema_version: int
    measurement_source: str
    resolution_scope: str
    registration_digest: str = field(repr=False)
    repository_ref: str = field(repr=False)
    verification_commands_digest: str = field(repr=False)
    baseline_command_results_digest: str = field(repr=False)
    executable_toolchain_identities_digest: str = field(repr=False)
    resolution_context_digest: str = field(repr=False)
    measurements: tuple[ResolvedExecutableMeasurement, ...] = field(
        repr=False
    )
    unique_file_count: int
    total_measured_bytes: int

    def to_canonical(self) -> dict[str, Any]:
        return _receipt_projection(self)

    @property
    def receipt_digest(self) -> str:
        return canonical_digest(_receipt_projection(self))

    def to_evidence(self) -> dict[str, Any]:
        return _receipt_evidence_projection(self)


@dataclass(frozen=True, slots=True)
class _PinnedDirectory:
    path: Path = field(repr=False)
    descriptor: int = field(repr=False)
    metadata: tuple[int, ...] = field(repr=False)
    directory_ref: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class _MeasuredFile:
    identity: tuple[int, int]
    metadata: tuple[int, ...]
    filesystem_identity_ref: str
    metadata_digest: str
    content_digest: str
    content_bytes: int


_UniqueFileConsumer = Callable[
    [int, os.stat_result, _MeasuredFile],
    None,
]


def _measurement_projection(
    measurement: ResolvedExecutableMeasurement,
) -> dict[str, Any]:
    if (
        type(measurement) is not ResolvedExecutableMeasurement
        or measurement.kind != REPOSITORY_EXECUTABLE_MEASUREMENT_KIND
        or measurement.command_kind not in _COMMAND_KINDS
        or type(measurement.command_id) is not str
        or _IDENTIFIER_PATTERN.fullmatch(measurement.command_id) is None
        or type(measurement.command_digest) is not str
        or _DIGEST_PATTERN.fullmatch(measurement.command_digest) is None
        or measurement.declared_executable_kind
        not in {"path_search", "repository_relative"}
        or type(measurement.declared_executable_ref) is not str
        or _DIGEST_PATTERN.fullmatch(measurement.declared_executable_ref)
        is None
        or measurement.resolution_method
        not in {"explicit_search_path", "repository_root_relative"}
        or type(measurement.resolution_root_ref) is not str
        or _DIGEST_PATTERN.fullmatch(measurement.resolution_root_ref) is None
        or (
            measurement.resolution_method == "explicit_search_path"
            and (
                type(measurement.search_directory_index) is not int
                or measurement.search_directory_index < 0
                or measurement.search_directory_index
                >= _MAX_SEARCH_DIRECTORIES
                or measurement.declared_executable_kind != "path_search"
            )
        )
        or (
            measurement.resolution_method == "repository_root_relative"
            and (
                measurement.search_directory_index is not None
                or measurement.declared_executable_kind
                != "repository_relative"
            )
        )
        or type(measurement.resolved_executable_ref) is not str
        or _DIGEST_PATTERN.fullmatch(measurement.resolved_executable_ref)
        is None
        or type(measurement.filesystem_identity_ref) is not str
        or _DIGEST_PATTERN.fullmatch(measurement.filesystem_identity_ref)
        is None
        or type(measurement.metadata_digest) is not str
        or _DIGEST_PATTERN.fullmatch(measurement.metadata_digest) is None
        or type(measurement.content_digest) is not str
        or _DIGEST_PATTERN.fullmatch(measurement.content_digest) is None
        or type(measurement.content_bytes) is not int
        or not 0 <= measurement.content_bytes <= _MAX_EXECUTABLE_BYTES
    ):
        raise _InvalidResolution
    return {
        "command_digest": measurement.command_digest,
        "command_id": measurement.command_id,
        "command_kind": measurement.command_kind,
        "content_bytes": measurement.content_bytes,
        "content_digest": measurement.content_digest,
        "declared_executable_kind": measurement.declared_executable_kind,
        "declared_executable_ref": measurement.declared_executable_ref,
        "filesystem_identity_ref": measurement.filesystem_identity_ref,
        "kind": measurement.kind,
        "metadata_digest": measurement.metadata_digest,
        "resolution_method": measurement.resolution_method,
        "resolution_root_ref": measurement.resolution_root_ref,
        "resolved_executable_ref": measurement.resolved_executable_ref,
        "search_directory_index": measurement.search_directory_index,
    }


def _receipt_projection(
    receipt: RepositoryExecutableResolutionReceipt,
) -> dict[str, Any]:
    if (
        type(receipt) is not RepositoryExecutableResolutionReceipt
        or receipt.kind != REPOSITORY_EXECUTABLE_RESOLUTION_KIND
        or type(receipt.schema_version) is not int
        or receipt.schema_version
        != REPOSITORY_EXECUTABLE_RESOLUTION_SCHEMA_VERSION
        or receipt.measurement_source
        != REPOSITORY_EXECUTABLE_RESOLUTION_MEASUREMENT_SOURCE
        or receipt.resolution_scope != REPOSITORY_EXECUTABLE_RESOLUTION_SCOPE
        or type(receipt.registration_digest) is not str
        or _DIGEST_PATTERN.fullmatch(receipt.registration_digest) is None
        or type(receipt.repository_ref) is not str
        or _DIGEST_PATTERN.fullmatch(receipt.repository_ref) is None
        or type(receipt.verification_commands_digest) is not str
        or _DIGEST_PATTERN.fullmatch(receipt.verification_commands_digest)
        is None
        or type(receipt.baseline_command_results_digest) is not str
        or _DIGEST_PATTERN.fullmatch(receipt.baseline_command_results_digest)
        is None
        or type(receipt.executable_toolchain_identities_digest) is not str
        or _DIGEST_PATTERN.fullmatch(
            receipt.executable_toolchain_identities_digest
        )
        is None
        or type(receipt.resolution_context_digest) is not str
        or _DIGEST_PATTERN.fullmatch(receipt.resolution_context_digest)
        is None
        or type(receipt.measurements) is not tuple
        or not 1 <= len(receipt.measurements) <= 80
        or type(receipt.unique_file_count) is not int
        or not 1 <= receipt.unique_file_count <= len(receipt.measurements)
        or type(receipt.total_measured_bytes) is not int
        or not 0
        <= receipt.total_measured_bytes
        <= _MAX_TOTAL_EXECUTABLE_BYTES
    ):
        raise _InvalidResolution
    measurements = [
        _measurement_projection(measurement)
        for measurement in receipt.measurements
    ]
    command_ids: set[str] = set()
    prior_kind_index = -1
    unique_files: dict[str, tuple[str, str, int]] = {}
    for measurement in receipt.measurements:
        kind_index = _COMMAND_KINDS.index(measurement.command_kind)
        if (
            kind_index < prior_kind_index
            or measurement.command_id in command_ids
        ):
            raise _InvalidResolution
        prior_kind_index = kind_index
        command_ids.add(measurement.command_id)
        file_measurement = (
            measurement.metadata_digest,
            measurement.content_digest,
            measurement.content_bytes,
        )
        prior_file_measurement = unique_files.setdefault(
            measurement.filesystem_identity_ref,
            file_measurement,
        )
        if prior_file_measurement != file_measurement:
            raise _InvalidResolution
    if (
        receipt.unique_file_count != len(unique_files)
        or receipt.total_measured_bytes
        != sum(measurement[2] for measurement in unique_files.values())
    ):
        raise _InvalidResolution
    return {
        "baseline_command_results_digest": (
            receipt.baseline_command_results_digest
        ),
        "executable_toolchain_identities_digest": (
            receipt.executable_toolchain_identities_digest
        ),
        "kind": receipt.kind,
        "measurement_source": receipt.measurement_source,
        "measurements": measurements,
        "registration_digest": receipt.registration_digest,
        "repository_ref": receipt.repository_ref,
        "resolution_context_digest": receipt.resolution_context_digest,
        "resolution_scope": receipt.resolution_scope,
        "schema_version": receipt.schema_version,
        "total_measured_bytes": receipt.total_measured_bytes,
        "unique_file_count": receipt.unique_file_count,
        "verification_commands_digest": (
            receipt.verification_commands_digest
        ),
    }


def _receipt_evidence_projection(
    receipt: RepositoryExecutableResolutionReceipt,
) -> dict[str, Any]:
    canonical = _receipt_projection(receipt)
    return {
        "action_time_revalidation_required": True,
        "action_receipt_issued": False,
        "authority_granted": False,
        "atomic_snapshot_verified": False,
        "baseline_execution_correspondence_verified": False,
        "billing_eligible": False,
        "capacity_eligible": False,
        "current_freshness_verified": False,
        "dependency_environment_coverage_verified": False,
        "dispatch_enabled": False,
        "dynamic_loader_identity_verified": False,
        "effective_invocability_verified": False,
        "environment_coverage_verified": False,
        "executable_authenticity_verified": False,
        "executable_provenance_verified": False,
        "future_execution_correspondence_verified": False,
        "interpreter_identity_verified": False,
        "kind": REPOSITORY_EXECUTABLE_RESOLUTION_EVIDENCE_KIND,
        "live_execution_eligible": False,
        "measurement_count": len(receipt.measurements),
        "measurement_source": receipt.measurement_source,
        "module_identity_verified": False,
        "package_identity_verified": False,
        "persistence_enabled": False,
        "plugin_identity_verified": False,
        "receipt_authenticity_verified": False,
        "receipt_digest": canonical_digest(canonical),
        "registration_digest": receipt.registration_digest,
        "repository_ref": receipt.repository_ref,
        "resolution_context_digest": receipt.resolution_context_digest,
        "resolution_scope": receipt.resolution_scope,
        "repository_snapshot_correspondence_verified": False,
        "route_eligible": False,
        "schema_version": receipt.schema_version,
        "selected_file_content_measurement_complete": True,
        "sequential_resolution_measurement_complete": True,
        "shared_library_identity_verified": False,
        "shebang_identity_verified": False,
        "launcher_identity_verified": False,
        "configuration_coverage_verified": False,
        "toolchain_completeness_verified": False,
        "total_measured_bytes": receipt.total_measured_bytes,
        "unique_file_count": receipt.unique_file_count,
        "v4_identity_claim_correspondence_verified": False,
        "validation_mode": "read_only",
    }


def _require_supported_platform() -> None:
    required_flags = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")
    if (
        os.name != "posix"
        or any(not hasattr(os, name) for name in required_flags)
        or os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.stat not in os.supports_follow_symlinks
    ):
        raise _InvalidResolution


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


def _directory_ref(metadata: os.stat_result) -> str:
    return canonical_digest(
        {
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "kind": "repository_executable_resolution_directory",
            "schema_version": 1,
        }
    )


def _file_identity_ref(metadata: os.stat_result) -> str:
    return canonical_digest(
        {
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "kind": "repository_executable_file_identity",
            "schema_version": 1,
        }
    )


def _file_metadata_digest(
    metadata: os.stat_result,
    *,
    filesystem_identity_ref: str,
) -> str:
    return canonical_digest(
        {
            "change_time_ns": metadata.st_ctime_ns,
            "filesystem_identity_ref": filesystem_identity_ref,
            "group_id": metadata.st_gid,
            "kind": "repository_executable_file_metadata",
            "link_count": metadata.st_nlink,
            "mode": metadata.st_mode,
            "modified_time_ns": metadata.st_mtime_ns,
            "owner_id": metadata.st_uid,
            "schema_version": 1,
            "size_bytes": metadata.st_size,
        }
    )


def _validate_component(component: str) -> None:
    if (
        not component
        or component in {".", ".."}
        or "/" in component
        or "\x00" in component
        or unicodedata.normalize("NFC", component) != component
        or any(
            unicodedata.category(character).startswith("C")
            for character in component
        )
    ):
        raise _InvalidResolution


def _entry_spelling_state(directory_descriptor: int, name: str) -> str:
    """Return ``exact`` or ``absent``; aliases and oversized dirs fail closed."""

    _validate_component(name)
    target = unicodedata.normalize("NFC", name).casefold()
    exact_matches = 0
    folded_matches = 0
    count = 0
    encoded_bytes = 0
    try:
        with os.scandir(directory_descriptor) as entries:
            for entry in entries:
                count += 1
                if count > _MAX_DIRECTORY_ENTRIES:
                    raise _InvalidResolution
                try:
                    encoded_bytes += len(entry.name.encode("utf-8"))
                except UnicodeError:
                    raise _InvalidResolution from None
                if encoded_bytes > _MAX_DIRECTORY_ENTRY_BYTES:
                    raise _InvalidResolution
                folded = unicodedata.normalize("NFC", entry.name).casefold()
                if folded == target:
                    folded_matches += 1
                    if entry.name == name:
                        exact_matches += 1
    except OSError:
        raise _InvalidResolution from None
    if exact_matches == 1 and folded_matches == 1:
        return "exact"
    if folded_matches == 0:
        return "absent"
    raise _InvalidResolution


def _directory_open_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _replace_directory_descriptor(current: int, child: int) -> int:
    try:
        os.close(current)
    except BaseException:
        try:
            os.close(child)
        except OSError:
            pass
        try:
            os.close(current)
        except OSError:
            pass
        raise
    return child


def _open_directory_component(
    parent_descriptor: int,
    component: str,
) -> int:
    if _entry_spelling_state(parent_descriptor, component) != "exact":
        raise _InvalidResolution
    try:
        descriptor = os.open(
            component,
            _directory_open_flags(),
            dir_fd=parent_descriptor,
        )
    except OSError:
        raise _InvalidResolution from None
    try:
        metadata = os.fstat(descriptor)
        namespace_metadata = os.stat(
            component,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(namespace_metadata.st_mode)
            or _metadata_signature(metadata)
            != _metadata_signature(namespace_metadata)
        ):
            raise _InvalidResolution
        return descriptor
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _absolute_path_parts(path: Path) -> tuple[str, ...]:
    if type(path) is not _CONCRETE_PATH_TYPE or not path.is_absolute():
        raise _InvalidResolution
    spelling = os.fspath(path)
    if (
        not spelling
        or "\x00" in spelling
        or unicodedata.normalize("NFC", spelling) != spelling
    ):
        raise _InvalidResolution
    parts = path.parts
    if not parts or parts[0] != os.sep:
        raise _InvalidResolution
    components = tuple(parts[1:])
    for component in components:
        _validate_component(component)
    return components


def _open_absolute_directory(path: Path) -> _PinnedDirectory:
    components = _absolute_path_parts(path)
    try:
        descriptor = os.open(os.sep, _directory_open_flags())
    except OSError:
        raise _InvalidResolution from None
    try:
        for component in components:
            child = _open_directory_component(descriptor, component)
            descriptor = _replace_directory_descriptor(descriptor, child)
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise _InvalidResolution
        return _PinnedDirectory(
            path=path,
            descriptor=descriptor,
            metadata=_metadata_signature(metadata),
            directory_ref=_directory_ref(metadata),
        )
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _reopen_directory_matches(directory: _PinnedDirectory) -> bool:
    reopened: _PinnedDirectory | None = None
    try:
        reopened = _open_absolute_directory(directory.path)
        return (
            reopened.metadata == directory.metadata
            and reopened.directory_ref == directory.directory_ref
        )
    except (OSError, TypeError, ValueError):
        return False
    finally:
        if reopened is not None:
            try:
                os.close(reopened.descriptor)
            except OSError:
                pass


def _open_relative_parent(
    root_descriptor: int,
    parts: tuple[str, ...],
) -> tuple[int, tuple[int, ...], str]:
    try:
        descriptor = os.dup(root_descriptor)
    except OSError:
        raise _InvalidResolution from None
    try:
        for component in parts:
            child = _open_directory_component(descriptor, component)
            descriptor = _replace_directory_descriptor(descriptor, child)
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise _InvalidResolution
        return (
            descriptor,
            _metadata_signature(metadata),
            _directory_ref(metadata),
        )
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _open_executable_at(
    directory_descriptor: int,
    name: str,
) -> tuple[int, os.stat_result] | None:
    if _entry_spelling_state(directory_descriptor, name) == "absent":
        return None
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open(
            name,
            flags,
            dir_fd=directory_descriptor,
        )
    except OSError:
        raise _InvalidResolution from None
    try:
        descriptor_metadata = os.fstat(descriptor)
        namespace_metadata = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(descriptor_metadata.st_mode)
            or descriptor_metadata.st_mode & 0o111 == 0
            or descriptor_metadata.st_nlink <= 0
            or stat.S_ISLNK(namespace_metadata.st_mode)
            or _metadata_signature(namespace_metadata)
            != _metadata_signature(descriptor_metadata)
        ):
            raise _InvalidResolution
        return descriptor, descriptor_metadata
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _file_is_sparse(metadata: os.stat_result) -> bool:
    blocks = getattr(metadata, "st_blocks", None)
    if type(blocks) is not int or blocks < 0:
        raise _InvalidResolution
    return (
        metadata.st_size > 0
        and blocks * 512 < metadata.st_size
    )


def _measure_open_file(
    descriptor: int,
    metadata: os.stat_result,
    *,
    total_measured_bytes: int,
) -> _MeasuredFile:
    if (
        metadata.st_size < 0
        or metadata.st_size > _MAX_EXECUTABLE_BYTES
        or total_measured_bytes + metadata.st_size
        > _MAX_TOTAL_EXECUTABLE_BYTES
        or _file_is_sparse(metadata)
    ):
        raise _InvalidResolution
    digest = hashlib.sha256()
    remaining = metadata.st_size
    while remaining:
        try:
            chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, remaining))
        except (BlockingIOError, InterruptedError, OSError):
            raise _InvalidResolution from None
        if not chunk:
            raise _InvalidResolution
        digest.update(chunk)
        remaining -= len(chunk)
    try:
        if os.read(descriptor, 1) != b"":
            raise _InvalidResolution
        final_metadata = os.fstat(descriptor)
    except OSError:
        raise _InvalidResolution from None
    if _metadata_signature(final_metadata) != _metadata_signature(metadata):
        raise _InvalidResolution
    filesystem_identity_ref = _file_identity_ref(metadata)
    return _MeasuredFile(
        identity=(metadata.st_dev, metadata.st_ino),
        metadata=_metadata_signature(metadata),
        filesystem_identity_ref=filesystem_identity_ref,
        metadata_digest=_file_metadata_digest(
            metadata,
            filesystem_identity_ref=filesystem_identity_ref,
        ),
        content_digest="sha256:" + digest.hexdigest(),
        content_bytes=metadata.st_size,
    )


def _reopen_file_matches(
    directory_descriptor: int,
    name: str,
    measured: _MeasuredFile,
) -> bool:
    reopened: tuple[int, os.stat_result] | None = None
    try:
        reopened = _open_executable_at(directory_descriptor, name)
        if reopened is None:
            return False
        descriptor, metadata = reopened
        return _metadata_signature(metadata) == measured.metadata
    except (OSError, TypeError, ValueError):
        return False
    finally:
        if reopened is not None:
            try:
                os.close(reopened[0])
            except OSError:
                pass


def _search_selection_matches(
    search_directories: tuple[_PinnedDirectory, ...],
    *,
    name: str,
    selected_index: int,
    measured: _MeasuredFile,
) -> bool:
    for index, directory in enumerate(search_directories):
        if index > selected_index:
            break
        opened: tuple[int, os.stat_result] | None = None
        try:
            opened = _open_executable_at(directory.descriptor, name)
            if opened is None:
                if index == selected_index:
                    return False
                continue
            if index != selected_index:
                return False
            return _metadata_signature(opened[1]) == measured.metadata
        except (OSError, TypeError, ValueError):
            return False
        finally:
            if opened is not None:
                try:
                    os.close(opened[0])
                except OSError:
                    pass
    return False


def _declared_executable_parts(command: VerificationCommand) -> tuple[str, ...]:
    value = command.argv[0]
    path = PurePosixPath(value)
    parts = path.parts
    if (
        not parts
        or path.is_absolute()
        or str(path) != value
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise _InvalidResolution
    for part in parts:
        _validate_component(part)
    return tuple(parts)


def _resolution_context_digest(
    search_directories: tuple[_PinnedDirectory, ...],
) -> str:
    return canonical_digest(
        {
            "bare_executable_matching": "exact_entry_name",
            "kind": "repository_executable_resolution_context",
            "maximum_executable_bytes": _MAX_EXECUTABLE_BYTES,
            "maximum_total_executable_bytes": (
                _MAX_TOTAL_EXECUTABLE_BYTES
            ),
            "repository_relative_base": "registered_repository_root",
            "resolution_scope": REPOSITORY_EXECUTABLE_RESOLUTION_SCOPE,
            "schema_version": 1,
            "search_directories": [
                {
                    "directory_ref": directory.directory_ref,
                    "position": index,
                }
                for index, directory in enumerate(search_directories)
            ],
            "symlink_policy": "reject_all_components",
        }
    )


def _resolved_executable_ref(
    *,
    declared_executable_ref: str,
    filesystem_identity_ref: str,
    resolution_method: str,
    resolution_root_ref: str,
    search_directory_index: int | None,
) -> str:
    return canonical_digest(
        {
            "declared_executable_ref": declared_executable_ref,
            "filesystem_identity_ref": filesystem_identity_ref,
            "kind": "repository_resolved_executable",
            "resolution_method": resolution_method,
            "resolution_root_ref": resolution_root_ref,
            "schema_version": 1,
            "search_directory_index": search_directory_index,
        }
    )


def _validate_search_directories(
    search_directories: Any,
) -> tuple[Path, ...]:
    if (
        type(search_directories) is not tuple
        or len(search_directories) > _MAX_SEARCH_DIRECTORIES
    ):
        raise _InvalidResolution
    total_bytes = 0
    paths: list[Path] = []
    spellings: set[str] = set()
    for value in search_directories:
        _absolute_path_parts(value)
        spelling = os.fspath(value)
        try:
            total_bytes += len(spelling.encode("utf-8"))
        except UnicodeError:
            raise _InvalidResolution from None
        if (
            total_bytes > _MAX_SEARCH_DIRECTORY_BYTES
            or spelling in spellings
        ):
            raise _InvalidResolution
        spellings.add(spelling)
        paths.append(value)
    return tuple(paths)


def _registration_commands(
    registration: RepositoryRegistration,
) -> tuple[VerificationCommand, ...]:
    return tuple(
        command
        for kind in _COMMAND_KINDS
        for command in getattr(registration.verification_commands, kind)
    )


def _resolve_repository_executables(
    registration: RepositoryRegistration,
    *,
    search_directories: Any,
    unique_file_consumer: _UniqueFileConsumer | None = None,
) -> RepositoryExecutableResolutionReceipt:
    # The version gate deliberately precedes any repository or search-path
    # inspection.  Older registration schemas retain their exact semantics.
    if (
        type(registration) is not RepositoryRegistration
        or type(registration.schema_version) is not int
        or registration.schema_version != 4
    ):
        raise _InvalidResolution
    _require_supported_platform()
    refreshed = _BUILTIN_REVALIDATE_REPOSITORY_REGISTRATION(registration)
    if refreshed.schema_version != 4:
        raise _InvalidResolution
    paths = _validate_search_directories(search_directories)
    commands = _registration_commands(refreshed)
    if any("/" not in command.argv[0] for command in commands) and not paths:
        raise _InvalidResolution

    canonical_registration = _BUILTIN_REGISTRATION_CANONICAL_PROJECTION(
        refreshed
    )
    baseline = refreshed.baseline_command_results
    identities = refreshed.executable_toolchain_identities
    if baseline is None or identities is None:
        raise _InvalidResolution
    if len(identities.identities) != len(commands):
        raise _InvalidResolution

    root: _PinnedDirectory | None = None
    pinned_search_directories: list[_PinnedDirectory] = []
    try:
        root = _open_absolute_directory(refreshed.repository.canonical_root)
        if refreshed.repository.root_ref != canonical_digest(
            {
                "root_device": root.metadata[0],
                "root_inode": root.metadata[1],
            }
        ):
            raise _InvalidResolution
        for path in paths:
            directory = _open_absolute_directory(path)
            if any(
                existing.metadata[:2] == directory.metadata[:2]
                for existing in pinned_search_directories
            ):
                try:
                    os.close(directory.descriptor)
                except OSError:
                    pass
                raise _InvalidResolution
            pinned_search_directories.append(directory)

        context_digest = _resolution_context_digest(
            tuple(pinned_search_directories)
        )
        measured_files: dict[tuple[int, int], _MeasuredFile] = {}
        selected_entries: dict[tuple[int, int, str], tuple[int, int]] = {}
        measurements: list[ResolvedExecutableMeasurement] = []
        total_measured_bytes = 0

        for command, identity_claim in zip(
            commands,
            identities.identities,
            strict=True,
        ):
            command_digest = _BUILTIN_COMMAND_DIGEST(command)
            if command_digest != identity_claim.command_digest:
                raise _InvalidResolution
            executable = command.argv[0]
            parent_descriptor: int
            parent_owned = False
            parent_metadata: tuple[int, ...]
            resolution_method: str
            resolution_root_ref: str
            search_directory_index: int | None
            entry_name: str
            relative_parts: tuple[str, ...] | None = None

            if "/" in executable:
                if command.cwd != ".":
                    raise _InvalidResolution
                parts = _declared_executable_parts(command)
                relative_parts = parts
                parent_descriptor, parent_metadata, parent_ref = (
                    _open_relative_parent(root.descriptor, parts[:-1])
                )
                parent_owned = True
                entry_name = parts[-1]
                resolution_method = "repository_root_relative"
                resolution_root_ref = refreshed.repository.root_ref
                search_directory_index = None
                try:
                    opened = _open_executable_at(
                        parent_descriptor,
                        entry_name,
                    )
                    if opened is None:
                        raise _InvalidResolution
                except BaseException:
                    try:
                        os.close(parent_descriptor)
                    except OSError:
                        pass
                    parent_owned = False
                    raise
            else:
                _validate_component(executable)
                opened = None
                parent_metadata = ()
                parent_ref = ""
                parent_descriptor = -1
                search_directory_index = None
                for index, directory in enumerate(
                    pinned_search_directories
                ):
                    candidate = _open_executable_at(
                        directory.descriptor,
                        executable,
                    )
                    if candidate is None:
                        continue
                    opened = candidate
                    parent_descriptor = directory.descriptor
                    parent_metadata = directory.metadata
                    parent_ref = directory.directory_ref
                    search_directory_index = index
                    break
                if opened is None or search_directory_index is None:
                    raise _InvalidResolution
                entry_name = executable
                resolution_method = "explicit_search_path"
                resolution_root_ref = parent_ref

            descriptor, file_metadata = opened
            try:
                file_identity = (file_metadata.st_dev, file_metadata.st_ino)
                entry_key = (
                    parent_metadata[0],
                    parent_metadata[1],
                    entry_name,
                )
                prior_identity = selected_entries.get(entry_key)
                if prior_identity is not None and prior_identity != file_identity:
                    raise _InvalidResolution
                selected_entries[entry_key] = file_identity
                measured = measured_files.get(file_identity)
                if measured is None:
                    measured = _measure_open_file(
                        descriptor,
                        file_metadata,
                        total_measured_bytes=total_measured_bytes,
                    )
                    if unique_file_consumer is not None:
                        unique_file_consumer(
                            descriptor,
                            file_metadata,
                            measured,
                        )
                    measured_files[file_identity] = measured
                    total_measured_bytes += measured.content_bytes
                elif measured.metadata != _metadata_signature(file_metadata):
                    raise _InvalidResolution
                if resolution_method == "explicit_search_path":
                    if search_directory_index is None or not (
                        _search_selection_matches(
                            tuple(pinned_search_directories),
                            name=entry_name,
                            selected_index=search_directory_index,
                            measured=measured,
                        )
                    ):
                        raise _InvalidResolution
                elif not _reopen_file_matches(
                    parent_descriptor,
                    entry_name,
                    measured,
                ):
                    raise _InvalidResolution
                if parent_owned:
                    current_parent = os.fstat(parent_descriptor)
                    if (
                        _metadata_signature(current_parent) != parent_metadata
                        or _directory_ref(current_parent) != parent_ref
                    ):
                        raise _InvalidResolution
                    if relative_parts is None:
                        raise _InvalidResolution
                    current_descriptor: int | None = None
                    try:
                        (
                            current_descriptor,
                            current_parent_metadata,
                            current_parent_ref,
                        ) = _open_relative_parent(
                            root.descriptor,
                            relative_parts[:-1],
                        )
                        if (
                            current_parent_metadata != parent_metadata
                            or current_parent_ref != parent_ref
                            or not _reopen_file_matches(
                                current_descriptor,
                                entry_name,
                                measured,
                            )
                        ):
                            raise _InvalidResolution
                    finally:
                        if current_descriptor is not None:
                            try:
                                os.close(current_descriptor)
                            except OSError:
                                pass
                measurements.append(
                    ResolvedExecutableMeasurement(
                        kind=REPOSITORY_EXECUTABLE_MEASUREMENT_KIND,
                        command_kind=command.kind,
                        command_id=command.command_id,
                        command_digest=command_digest,
                        declared_executable_kind=(
                            identity_claim.declared_executable_kind
                        ),
                        declared_executable_ref=(
                            identity_claim.declared_executable_ref
                        ),
                        resolution_method=resolution_method,
                        resolution_root_ref=resolution_root_ref,
                        search_directory_index=search_directory_index,
                        resolved_executable_ref=_resolved_executable_ref(
                            declared_executable_ref=(
                                identity_claim.declared_executable_ref
                            ),
                            filesystem_identity_ref=(
                                measured.filesystem_identity_ref
                            ),
                            resolution_method=resolution_method,
                            resolution_root_ref=resolution_root_ref,
                            search_directory_index=(
                                search_directory_index
                            ),
                        ),
                        filesystem_identity_ref=(
                            measured.filesystem_identity_ref
                        ),
                        metadata_digest=measured.metadata_digest,
                        content_digest=measured.content_digest,
                        content_bytes=measured.content_bytes,
                    )
                )
            finally:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                if parent_owned:
                    try:
                        os.close(parent_descriptor)
                    except OSError:
                        pass

        if not _reopen_directory_matches(root) or any(
            not _reopen_directory_matches(directory)
            for directory in pinned_search_directories
        ):
            raise _InvalidResolution
        final_registration = _BUILTIN_REVALIDATE_REPOSITORY_REGISTRATION(
            refreshed
        )
        if _BUILTIN_REGISTRATION_CANONICAL_PROJECTION(
            final_registration
        ) != canonical_registration:
            raise _InvalidResolution

        return RepositoryExecutableResolutionReceipt(
            kind=REPOSITORY_EXECUTABLE_RESOLUTION_KIND,
            schema_version=REPOSITORY_EXECUTABLE_RESOLUTION_SCHEMA_VERSION,
            measurement_source=(
                REPOSITORY_EXECUTABLE_RESOLUTION_MEASUREMENT_SOURCE
            ),
            resolution_scope=REPOSITORY_EXECUTABLE_RESOLUTION_SCOPE,
            registration_digest=canonical_digest(canonical_registration),
            repository_ref=refreshed.repository.repository_ref,
            verification_commands_digest=canonical_digest(
                canonical_registration["verification_commands"]
            ),
            baseline_command_results_digest=canonical_digest(
                _BUILTIN_BASELINE_PROJECTION(baseline)
            ),
            executable_toolchain_identities_digest=canonical_digest(
                _BUILTIN_TOOLCHAIN_IDENTITIES_PROJECTION(identities)
            ),
            resolution_context_digest=context_digest,
            measurements=tuple(measurements),
            unique_file_count=len(measured_files),
            total_measured_bytes=total_measured_bytes,
        )
    finally:
        for directory in pinned_search_directories:
            try:
                os.close(directory.descriptor)
            except OSError:
                pass
        if root is not None:
            try:
                os.close(root.descriptor)
            except OSError:
                pass


def resolve_repository_executables(
    registration: RepositoryRegistration,
    *,
    search_directories: tuple[Path, ...],
) -> RepositoryExecutableResolutionReceipt:
    """Resolve and measure direct executable files without executing them."""

    try:
        return _resolve_repository_executables(
            registration,
            search_directories=search_directories,
        )
    except (
        AttributeError,
        OSError,
        OverflowError,
        NotImplementedError,
        TypeError,
        ValueError,
        ValidationError,
    ):
        raise ValidationError(_INVALID_MESSAGE) from None


def fresh_repository_executable_resolution_evidence(
    registration: RepositoryRegistration,
    *,
    search_directories: tuple[Path, ...],
) -> dict[str, Any]:
    """Remeasure and return a new aggregate-only evidence projection."""

    receipt = resolve_repository_executables(
        registration,
        search_directories=search_directories,
    )
    return _receipt_evidence_projection(receipt)
