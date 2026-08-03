"""Pure patch reconciliation for detached no-Git worker job-tree bytes.

This module defines the controller's comparison semantics before any future
candidate-tree reader or worker handoff.  It compares an already detached
candidate bundle to the exact source snapshot and materialization receipt,
retaining private add/modify/delete operations in memory and exposing only
digest/count evidence.  It performs no filesystem, process, network, Git,
database, worker, patch-application, or authorization action.

The caller must obtain candidate bytes through a separately reviewed,
descriptor-safe controller boundary.  Supplying a bundle here is not proof that
it came from a materialized job tree or that a worker was contained.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
from typing import Any

from .authorization import canonical_digest
from .errors import ValidationError
from .repository_worker_job_tree import (
    REPOSITORY_WORKER_JOB_TREE_SCHEMA_VERSION,
    RepositoryWorkerJobTreeContract,
    RepositoryWorkerJobTreeSourceBundle,
    RepositoryWorkerJobTreeSourceFile,
    _MAX_SOURCE_BYTES,
    _MAX_SOURCE_FILE_BYTES,
    _MAX_SOURCE_FILES,
    _is_at_or_below,
    _is_at_or_below_casefold,
    _is_canonical_relative_path,
    _path_policy_snapshot,
    _prohibited_component,
    _resource_limits_snapshot,
)
from .repository_worker_job_tree_materialization import (
    MATERIALIZATION_SCOPE,
    REPOSITORY_WORKER_JOB_TREE_MATERIALIZATION_KIND,
    REPOSITORY_WORKER_JOB_TREE_MATERIALIZATION_SCHEMA_VERSION,
    RepositoryWorkerJobTreeMaterializationReceipt,
    _validated_inputs,
)
from .repository_worker_job_tree_snapshot import (
    RepositoryWorkerJobTreeSourceSnapshot,
)


REPOSITORY_WORKER_JOB_TREE_RECONCILIATION_SCHEMA_VERSION = 1
REPOSITORY_WORKER_JOB_TREE_RECONCILIATION_KIND = (
    "repository_worker_no_git_job_tree_reconciliation"
)
REPOSITORY_WORKER_JOB_TREE_CANDIDATE_BUNDLE_KIND = (
    "repository_worker_no_git_job_tree_candidate_bundle"
)
REPOSITORY_WORKER_JOB_TREE_PATCH_OPERATION_KIND = (
    "repository_worker_no_git_job_tree_patch_operation"
)
RECONCILIATION_SCOPE = "controller_detached_no_git_patch_v1"

_INVALID_RECONCILIATION_MESSAGE = (
    "repository worker job tree reconciliation is invalid"
)
_INVALID_CANDIDATE_BUNDLE_MESSAGE = (
    "repository worker job tree candidate bundle is invalid"
)
_INVALID_PATCH_OPERATION_MESSAGE = (
    "repository worker job tree patch operation is invalid"
)
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PATCH_OPERATIONS = ("added", "modified", "deleted")

# Freeze the pure proof graph at import.  Public helpers and dataclass methods
# are transparent convenience surfaces rather than a way to relax a later
# reconciliation check.
_BUILTIN_CANONICAL_DIGEST = canonical_digest
_BUILTIN_VALIDATED_INPUTS = _validated_inputs
_BUILTIN_PATH_POLICY_SNAPSHOT = _path_policy_snapshot
_BUILTIN_RESOURCE_LIMITS_SNAPSHOT = _resource_limits_snapshot
_BUILTIN_IS_AT_OR_BELOW = _is_at_or_below
_BUILTIN_IS_AT_OR_BELOW_CASEFOLD = _is_at_or_below_casefold
_BUILTIN_IS_CANONICAL_RELATIVE_PATH = _is_canonical_relative_path
_BUILTIN_PROHIBITED_COMPONENT = _prohibited_component
_SOURCE_SNAPSHOT_TYPE = RepositoryWorkerJobTreeSourceSnapshot
_CONTRACT_TYPE = RepositoryWorkerJobTreeContract
_SOURCE_BUNDLE_TYPE = RepositoryWorkerJobTreeSourceBundle
_SOURCE_FILE_TYPE = RepositoryWorkerJobTreeSourceFile
_MATERIALIZATION_RECEIPT_TYPE = RepositoryWorkerJobTreeMaterializationReceipt
_BUILTIN_SOURCE_FILE_POST_INIT = RepositoryWorkerJobTreeSourceFile.__post_init__
_BUILTIN_SOURCE_BUNDLE_POST_INIT = (
    RepositoryWorkerJobTreeSourceBundle.__post_init__
)
_BUILTIN_MATERIALIZATION_RECEIPT_POST_INIT = (
    RepositoryWorkerJobTreeMaterializationReceipt.__post_init__
)


class _InvalidReconciliation(ValueError):
    """Private sentinel used to preserve fixed, value-free public failures."""


def _is_digest(value: Any) -> bool:
    return type(value) is str and _DIGEST_PATTERN.fullmatch(value) is not None


_BUILTIN_IS_DIGEST = _is_digest


def _content_digest(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


_BUILTIN_CONTENT_DIGEST = _content_digest


def _source_bundle_digest(bundle: RepositoryWorkerJobTreeSourceBundle) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "files": [
                {
                    "content_bytes": len(item.content),
                    "content_digest": _BUILTIN_CONTENT_DIGEST(item.content),
                    "executable": item.executable,
                    "relative_path": item.relative_path,
                }
                for item in bundle.files
            ],
            "kind": "repository_worker_job_tree_source_bundle",
            "schema_version": REPOSITORY_WORKER_JOB_TREE_SCHEMA_VERSION,
        }
    )


_BUILTIN_SOURCE_BUNDLE_DIGEST = _source_bundle_digest


def _validate_candidate_files(
    files: tuple[RepositoryWorkerJobTreeSourceFile, ...],
) -> None:
    if type(files) is not tuple or len(files) > _MAX_SOURCE_FILES:
        raise _InvalidReconciliation
    if any(type(item) is not _SOURCE_FILE_TYPE for item in files):
        raise _InvalidReconciliation
    try:
        for item in files:
            _BUILTIN_SOURCE_FILE_POST_INIT(item)
        paths = tuple(item.relative_path for item in files)
        sizes = tuple(len(item.content) for item in files)
    except (AttributeError, TypeError, UnicodeError, ValidationError, ValueError):
        raise _InvalidReconciliation from None
    if (
        any(not _BUILTIN_IS_CANONICAL_RELATIVE_PATH(path) for path in paths)
        or paths != tuple(sorted(paths))
        or len(paths) != len(set(paths))
        or sum(sizes) > _MAX_SOURCE_BYTES
    ):
        raise _InvalidReconciliation
    for index, path in enumerate(paths):
        if _BUILTIN_PROHIBITED_COMPONENT(path):
            raise _InvalidReconciliation
        for other in paths[index + 1 :]:
            if (
                _BUILTIN_IS_AT_OR_BELOW_CASEFOLD(path, other)
                or _BUILTIN_IS_AT_OR_BELOW_CASEFOLD(other, path)
            ):
                raise _InvalidReconciliation


_BUILTIN_VALIDATE_CANDIDATE_FILES = _validate_candidate_files


@dataclass(frozen=True, slots=True)
class RepositoryWorkerJobTreeCandidateBundle:
    """Bounded detached candidate bytes; zero files represents all deletion."""

    files: tuple[RepositoryWorkerJobTreeSourceFile, ...] = field(repr=False)

    def __post_init__(self) -> None:
        try:
            _BUILTIN_VALIDATE_CANDIDATE_FILES(self.files)
        except _InvalidReconciliation:
            raise ValidationError(_INVALID_CANDIDATE_BUNDLE_MESSAGE) from None

    @property
    def candidate_file_count(self) -> int:
        self.__post_init__()
        return len(self.files)

    @property
    def candidate_total_bytes(self) -> int:
        self.__post_init__()
        return sum(len(item.content) for item in self.files)

    @property
    def candidate_bundle_digest(self) -> str:
        self.__post_init__()
        return _BUILTIN_CANONICAL_DIGEST(
            {
                "files": [
                    {
                        "content_bytes": len(item.content),
                        "content_digest": _BUILTIN_CONTENT_DIGEST(item.content),
                        "executable": item.executable,
                        "relative_path": item.relative_path,
                    }
                    for item in self.files
                ],
                "kind": REPOSITORY_WORKER_JOB_TREE_CANDIDATE_BUNDLE_KIND,
                "schema_version": (
                    REPOSITORY_WORKER_JOB_TREE_RECONCILIATION_SCHEMA_VERSION
                ),
            }
        )


_CANDIDATE_BUNDLE_TYPE = RepositoryWorkerJobTreeCandidateBundle


@dataclass(frozen=True, slots=True)
class RepositoryWorkerJobTreePatchOperation:
    """One private, deterministic add/modify/delete operation."""

    kind: str
    operation: str
    relative_path: str = field(repr=False)
    before_content: bytes | None = field(repr=False)
    before_executable: bool | None = field(repr=False)
    after_content: bytes | None = field(repr=False)
    after_executable: bool | None = field(repr=False)

    def __post_init__(self) -> None:
        try:
            valid_path = (
                _BUILTIN_IS_CANONICAL_RELATIVE_PATH(self.relative_path)
                and not _BUILTIN_PROHIBITED_COMPONENT(self.relative_path)
            )
            before_is_file = (
                type(self.before_content) is bytes
                and type(self.before_executable) is bool
            )
            before_is_absent = (
                self.before_content is None and self.before_executable is None
            )
            after_is_file = (
                type(self.after_content) is bytes
                and type(self.after_executable) is bool
            )
            after_is_absent = (
                self.after_content is None and self.after_executable is None
            )
            if (
                type(self.kind) is not str
                or self.kind
                != REPOSITORY_WORKER_JOB_TREE_PATCH_OPERATION_KIND
                or type(self.operation) is not str
                or self.operation not in _PATCH_OPERATIONS
                or not valid_path
                or (
                    self.operation == "added"
                    and (not before_is_absent or not after_is_file)
                )
                or (
                    self.operation == "deleted"
                    and (not before_is_file or not after_is_absent)
                )
                or (
                    self.operation == "modified"
                    and (
                        not before_is_file
                        or not after_is_file
                        or (
                            self.before_content == self.after_content
                            and self.before_executable == self.after_executable
                        )
                    )
                )
                or (
                    self.before_content is not None
                    and len(self.before_content) > _MAX_SOURCE_FILE_BYTES
                )
                or (
                    self.after_content is not None
                    and len(self.after_content) > _MAX_SOURCE_FILE_BYTES
                )
            ):
                raise _InvalidReconciliation
        except (AttributeError, TypeError, UnicodeError, ValueError):
            raise ValidationError(_INVALID_PATCH_OPERATION_MESSAGE) from None

    @property
    def operation_digest(self) -> str:
        return _BUILTIN_CANONICAL_DIGEST(_BUILTIN_OPERATION_PROJECTION(self))

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_OPERATION_PROJECTION(self)


_BUILTIN_PATCH_OPERATION_POST_INIT = (
    RepositoryWorkerJobTreePatchOperation.__post_init__
)
_PATCH_OPERATION_TYPE = RepositoryWorkerJobTreePatchOperation


def _operation_projection(
    operation: RepositoryWorkerJobTreePatchOperation,
) -> dict[str, Any]:
    _BUILTIN_PATCH_OPERATION_POST_INIT(operation)
    return {
        "after_content_bytes": (
            None
            if operation.after_content is None
            else len(operation.after_content)
        ),
        "after_content_digest": (
            None
            if operation.after_content is None
            else _BUILTIN_CONTENT_DIGEST(operation.after_content)
        ),
        "after_executable": operation.after_executable,
        "before_content_bytes": (
            None
            if operation.before_content is None
            else len(operation.before_content)
        ),
        "before_content_digest": (
            None
            if operation.before_content is None
            else _BUILTIN_CONTENT_DIGEST(operation.before_content)
        ),
        "before_executable": operation.before_executable,
        "kind": operation.kind,
        "operation": operation.operation,
        "path_ref": _BUILTIN_CANONICAL_DIGEST(
            {
                "kind": REPOSITORY_WORKER_JOB_TREE_PATCH_OPERATION_KIND,
                "relative_path": operation.relative_path,
                "schema_version": (
                    REPOSITORY_WORKER_JOB_TREE_RECONCILIATION_SCHEMA_VERSION
                ),
            }
        ),
    }


_BUILTIN_OPERATION_PROJECTION = _operation_projection


def _derive_operations(
    source_bundle: RepositoryWorkerJobTreeSourceBundle,
    candidate_bundle: RepositoryWorkerJobTreeCandidateBundle,
) -> tuple[RepositoryWorkerJobTreePatchOperation, ...]:
    source_by_path = {
        item.relative_path: item for item in source_bundle.files
    }
    candidate_by_path = {
        item.relative_path: item for item in candidate_bundle.files
    }
    operations: list[RepositoryWorkerJobTreePatchOperation] = []
    for relative_path in sorted(set(source_by_path) | set(candidate_by_path)):
        before = source_by_path.get(relative_path)
        after = candidate_by_path.get(relative_path)
        if before is None:
            assert after is not None
            operations.append(
                _PATCH_OPERATION_TYPE(
                    kind=REPOSITORY_WORKER_JOB_TREE_PATCH_OPERATION_KIND,
                    operation="added",
                    relative_path=relative_path,
                    before_content=None,
                    before_executable=None,
                    after_content=after.content,
                    after_executable=after.executable,
                )
            )
        elif after is None:
            operations.append(
                _PATCH_OPERATION_TYPE(
                    kind=REPOSITORY_WORKER_JOB_TREE_PATCH_OPERATION_KIND,
                    operation="deleted",
                    relative_path=relative_path,
                    before_content=before.content,
                    before_executable=before.executable,
                    after_content=None,
                    after_executable=None,
                )
            )
        elif (
            before.content != after.content
            or before.executable != after.executable
        ):
            operations.append(
                _PATCH_OPERATION_TYPE(
                    kind=REPOSITORY_WORKER_JOB_TREE_PATCH_OPERATION_KIND,
                    operation="modified",
                    relative_path=relative_path,
                    before_content=before.content,
                    before_executable=before.executable,
                    after_content=after.content,
                    after_executable=after.executable,
                )
            )
    return tuple(operations)


_BUILTIN_DERIVE_OPERATIONS = _derive_operations


def _candidate_bundle_digest(
    candidate_bundle: RepositoryWorkerJobTreeCandidateBundle,
) -> str:
    return _BUILTIN_CANONICAL_DIGEST(
        {
            "files": [
                {
                    "content_bytes": len(item.content),
                    "content_digest": _BUILTIN_CONTENT_DIGEST(item.content),
                    "executable": item.executable,
                    "relative_path": item.relative_path,
                }
                for item in candidate_bundle.files
            ],
            "kind": REPOSITORY_WORKER_JOB_TREE_CANDIDATE_BUNDLE_KIND,
            "schema_version": REPOSITORY_WORKER_JOB_TREE_RECONCILIATION_SCHEMA_VERSION,
        }
    )


_BUILTIN_CANDIDATE_BUNDLE_DIGEST = _candidate_bundle_digest


def _detached_candidate_bundle(
    candidate_bundle: RepositoryWorkerJobTreeCandidateBundle,
) -> RepositoryWorkerJobTreeCandidateBundle:
    if type(candidate_bundle) is not _CANDIDATE_BUNDLE_TYPE:
        raise _InvalidReconciliation
    try:
        files = candidate_bundle.files
        if type(files) is not tuple:
            raise _InvalidReconciliation
        detached = _CANDIDATE_BUNDLE_TYPE(
            files=tuple(
                _SOURCE_FILE_TYPE(
                    relative_path=item.relative_path,
                    content=item.content,
                    executable=item.executable,
                )
                for item in files
                if type(item) is _SOURCE_FILE_TYPE
            )
        )
        if candidate_bundle.files is not files or len(detached.files) != len(files):
            raise _InvalidReconciliation
        return detached
    except (
        AttributeError,
        TypeError,
        UnicodeError,
        ValidationError,
        ValueError,
    ):
        raise _InvalidReconciliation from None


_BUILTIN_DETACHED_CANDIDATE_BUNDLE = _detached_candidate_bundle


def _validate_candidate_policy(
    candidate_bundle: RepositoryWorkerJobTreeCandidateBundle,
    *,
    path_policy: dict[str, list[str]],
    resource_limits: dict[str, int],
) -> None:
    _BUILTIN_VALIDATE_CANDIDATE_FILES(candidate_bundle.files)
    if sum(len(item.content) for item in candidate_bundle.files) > resource_limits[
        "workspace_bytes"
    ]:
        raise _InvalidReconciliation
    for source_file in candidate_bundle.files:
        relative_path = source_file.relative_path
        if (
            not any(
                _BUILTIN_IS_AT_OR_BELOW(relative_path, allowed_path)
                for allowed_path in path_policy["allowed_paths"]
            )
            or any(
                _BUILTIN_IS_AT_OR_BELOW(relative_path, protected_path)
                for protected_path in path_policy["protected_paths"]
            )
            or any(
                _BUILTIN_IS_AT_OR_BELOW(relative_path, excluded_path)
                for excluded_path in (
                    path_policy["generated_paths"] + path_policy["vendor_paths"]
                )
            )
        ):
            raise _InvalidReconciliation


_BUILTIN_VALIDATE_CANDIDATE_POLICY = _validate_candidate_policy


def _validate_source_policy(
    source_bundle: RepositoryWorkerJobTreeSourceBundle,
    *,
    path_policy: dict[str, list[str]],
    resource_limits: dict[str, int],
) -> None:
    """Recheck the detached source against retained exact policy snapshots."""

    if type(source_bundle) is not _SOURCE_BUNDLE_TYPE:
        raise _InvalidReconciliation
    _BUILTIN_SOURCE_BUNDLE_POST_INIT(source_bundle)
    candidate_view = _CANDIDATE_BUNDLE_TYPE(files=source_bundle.files)
    _BUILTIN_VALIDATE_CANDIDATE_POLICY(
        candidate_view,
        path_policy=path_policy,
        resource_limits=resource_limits,
    )


_BUILTIN_VALIDATE_SOURCE_POLICY = _validate_source_policy


def _materialization_receipt_projection(
    receipt: RepositoryWorkerJobTreeMaterializationReceipt,
) -> dict[str, Any]:
    if type(receipt) is not _MATERIALIZATION_RECEIPT_TYPE:
        raise _InvalidReconciliation
    try:
        _BUILTIN_MATERIALIZATION_RECEIPT_POST_INIT(receipt)
        projection = {
            "executable_file_count": receipt.executable_file_count,
            "job_tree_contract_digest": receipt.job_tree_contract_digest,
            "kind": receipt.kind,
            "materialization_scope": receipt.materialization_scope,
            "materialized_file_count": receipt.materialized_file_count,
            "materialized_total_bytes": receipt.materialized_total_bytes,
            "regular_file_count": receipt.regular_file_count,
            "schema_version": receipt.schema_version,
            "source_bundle_digest": receipt.source_bundle_digest,
            "source_file_count": receipt.source_file_count,
            "source_snapshot_digest": receipt.source_snapshot_digest,
            "source_total_bytes": receipt.source_total_bytes,
        }
        if (
            type(projection["kind"]) is not str
            or projection["kind"]
            != REPOSITORY_WORKER_JOB_TREE_MATERIALIZATION_KIND
            or type(projection["schema_version"]) is not int
            or projection["schema_version"]
            != REPOSITORY_WORKER_JOB_TREE_MATERIALIZATION_SCHEMA_VERSION
            or type(projection["materialization_scope"]) is not str
            or projection["materialization_scope"] != MATERIALIZATION_SCOPE
        ):
            raise _InvalidReconciliation
        return projection
    except (AttributeError, TypeError, ValidationError, ValueError):
        raise _InvalidReconciliation from None


_BUILTIN_MATERIALIZATION_RECEIPT_PROJECTION = (
    _materialization_receipt_projection
)


@dataclass(frozen=True, slots=True)
class RepositoryWorkerJobTreeReconciliation:
    """Private patch operations and public digest/count reconciliation evidence."""

    kind: str
    schema_version: int
    reconciliation_scope: str
    source_snapshot_digest: str = field(repr=False)
    job_tree_contract_digest: str = field(repr=False)
    materialization_receipt_digest: str = field(repr=False)
    source_bundle_digest: str = field(repr=False)
    candidate_bundle_digest: str = field(repr=False)
    path_policy_digest: str = field(repr=False)
    resource_limits_digest: str = field(repr=False)
    source_bundle: RepositoryWorkerJobTreeSourceBundle = field(repr=False)
    candidate_bundle: RepositoryWorkerJobTreeCandidateBundle = field(repr=False)
    materialization_receipt: RepositoryWorkerJobTreeMaterializationReceipt = (
        field(repr=False)
    )
    path_policy: dict[str, list[str]] = field(repr=False)
    resource_limits: dict[str, int] = field(repr=False)
    operations: tuple[RepositoryWorkerJobTreePatchOperation, ...] = field(
        repr=False
    )
    source_file_count: int
    source_total_bytes: int
    candidate_file_count: int
    candidate_total_bytes: int
    added_file_count: int
    modified_file_count: int
    deleted_file_count: int

    def __post_init__(self) -> None:
        try:
            if (
                type(self.kind) is not str
                or self.kind != REPOSITORY_WORKER_JOB_TREE_RECONCILIATION_KIND
                or type(self.schema_version) is not int
                or self.schema_version
                != REPOSITORY_WORKER_JOB_TREE_RECONCILIATION_SCHEMA_VERSION
                or type(self.reconciliation_scope) is not str
                or self.reconciliation_scope != RECONCILIATION_SCOPE
                or not all(
                    _BUILTIN_IS_DIGEST(getattr(self, name))
                    for name in (
                        "source_snapshot_digest",
                        "job_tree_contract_digest",
                        "materialization_receipt_digest",
                        "source_bundle_digest",
                        "candidate_bundle_digest",
                        "path_policy_digest",
                        "resource_limits_digest",
                    )
                )
                or type(self.source_bundle) is not _SOURCE_BUNDLE_TYPE
                or type(self.candidate_bundle)
                is not _CANDIDATE_BUNDLE_TYPE
                or type(self.materialization_receipt)
                is not _MATERIALIZATION_RECEIPT_TYPE
                or type(self.operations) is not tuple
                or any(
                    type(operation) is not _PATCH_OPERATION_TYPE
                    for operation in self.operations
                )
            ):
                raise _InvalidReconciliation
            checked_policy = _BUILTIN_PATH_POLICY_SNAPSHOT(self.path_policy)
            checked_limits = _BUILTIN_RESOURCE_LIMITS_SNAPSHOT(
                self.resource_limits
            )
            _BUILTIN_VALIDATE_SOURCE_POLICY(
                self.source_bundle,
                path_policy=checked_policy,
                resource_limits=checked_limits,
            )
            _BUILTIN_VALIDATE_CANDIDATE_POLICY(
                self.candidate_bundle,
                path_policy=checked_policy,
                resource_limits=checked_limits,
            )
            receipt_projection = _BUILTIN_MATERIALIZATION_RECEIPT_PROJECTION(
                self.materialization_receipt
            )
            expected_operations = _BUILTIN_DERIVE_OPERATIONS(
                self.source_bundle,
                self.candidate_bundle,
            )
            if (
                self.operations != expected_operations
                or self.source_bundle_digest
                != _BUILTIN_SOURCE_BUNDLE_DIGEST(self.source_bundle)
                or self.candidate_bundle_digest
                != _BUILTIN_CANDIDATE_BUNDLE_DIGEST(self.candidate_bundle)
                or self.materialization_receipt_digest
                != _BUILTIN_CANONICAL_DIGEST(receipt_projection)
                or self.path_policy_digest
                != _BUILTIN_CANONICAL_DIGEST(checked_policy)
                or self.resource_limits_digest
                != _BUILTIN_CANONICAL_DIGEST(checked_limits)
                or receipt_projection["source_snapshot_digest"]
                != self.source_snapshot_digest
                or receipt_projection["job_tree_contract_digest"]
                != self.job_tree_contract_digest
                or receipt_projection["source_bundle_digest"]
                != self.source_bundle_digest
                or receipt_projection["source_file_count"]
                != len(self.source_bundle.files)
                or receipt_projection["source_total_bytes"]
                != sum(len(item.content) for item in self.source_bundle.files)
                or type(self.source_file_count) is not int
                or self.source_file_count != len(self.source_bundle.files)
                or type(self.source_total_bytes) is not int
                or self.source_total_bytes
                != sum(len(item.content) for item in self.source_bundle.files)
                or type(self.candidate_file_count) is not int
                or self.candidate_file_count != len(self.candidate_bundle.files)
                or type(self.candidate_total_bytes) is not int
                or self.candidate_total_bytes
                != sum(len(item.content) for item in self.candidate_bundle.files)
                or type(self.added_file_count) is not int
                or self.added_file_count
                != sum(item.operation == "added" for item in self.operations)
                or type(self.modified_file_count) is not int
                or self.modified_file_count
                != sum(item.operation == "modified" for item in self.operations)
                or type(self.deleted_file_count) is not int
                or self.deleted_file_count
                != sum(item.operation == "deleted" for item in self.operations)
            ):
                raise _InvalidReconciliation
        except (
            AttributeError,
            TypeError,
            UnicodeError,
            ValidationError,
            ValueError,
        ):
            raise ValidationError(_INVALID_RECONCILIATION_MESSAGE) from None

    @property
    def reconciliation_digest(self) -> str:
        return _BUILTIN_CANONICAL_DIGEST(
            _BUILTIN_RECONCILIATION_PROJECTION(self)
        )

    def to_canonical(self) -> dict[str, Any]:
        return _BUILTIN_RECONCILIATION_PROJECTION(self)

    def to_mapping(self) -> dict[str, Any]:
        mapping = _BUILTIN_RECONCILIATION_PROJECTION(self)
        mapping.update(
            {
                "authority_granted": False,
                "candidate_filesystem_captured": False,
                "dispatch_enabled": False,
                "patch_application_implemented": False,
                "patch_reconciliation_implemented": True,
                "reconciliation_digest": self.reconciliation_digest,
                "worker_execution_permitted": False,
            }
        )
        return mapping


_BUILTIN_RECONCILIATION_POST_INIT = (
    RepositoryWorkerJobTreeReconciliation.__post_init__
)
_RECONCILIATION_TYPE = RepositoryWorkerJobTreeReconciliation


def _reconciliation_projection(
    reconciliation: RepositoryWorkerJobTreeReconciliation,
) -> dict[str, Any]:
    _BUILTIN_RECONCILIATION_POST_INIT(reconciliation)
    return {
        "added_file_count": reconciliation.added_file_count,
        "candidate_bundle_digest": reconciliation.candidate_bundle_digest,
        "candidate_file_count": reconciliation.candidate_file_count,
        "candidate_total_bytes": reconciliation.candidate_total_bytes,
        "deleted_file_count": reconciliation.deleted_file_count,
        "job_tree_contract_digest": reconciliation.job_tree_contract_digest,
        "kind": reconciliation.kind,
        "materialization_receipt_digest": (
            reconciliation.materialization_receipt_digest
        ),
        "modified_file_count": reconciliation.modified_file_count,
        "operations": [
            _BUILTIN_OPERATION_PROJECTION(operation)
            for operation in reconciliation.operations
        ],
        "path_policy_digest": reconciliation.path_policy_digest,
        "reconciliation_scope": reconciliation.reconciliation_scope,
        "resource_limits_digest": reconciliation.resource_limits_digest,
        "schema_version": reconciliation.schema_version,
        "source_bundle_digest": reconciliation.source_bundle_digest,
        "source_file_count": reconciliation.source_file_count,
        "source_snapshot_digest": reconciliation.source_snapshot_digest,
        "source_total_bytes": reconciliation.source_total_bytes,
    }


_BUILTIN_RECONCILIATION_PROJECTION = _reconciliation_projection


def derive_repository_worker_job_tree_reconciliation(
    snapshot: RepositoryWorkerJobTreeSourceSnapshot,
    *,
    contract: RepositoryWorkerJobTreeContract,
    materialization_receipt: RepositoryWorkerJobTreeMaterializationReceipt,
    candidate_bundle: RepositoryWorkerJobTreeCandidateBundle,
    path_policy: dict[str, Any],
    resource_limits: dict[str, Any],
) -> RepositoryWorkerJobTreeReconciliation:
    """Derive private patch operations from exact detached bundles only.

    The caller must later connect the candidate bundle to a descriptor-safe
    post-worker tree reader and independently authorize any review, storage,
    patch application, or promotion.  This pure comparison cannot do so.
    """

    try:
        if (
            type(snapshot) is not _SOURCE_SNAPSHOT_TYPE
            or type(contract) is not _CONTRACT_TYPE
        ):
            raise _InvalidReconciliation
        (
            source_bundle,
            source_snapshot_digest,
            contract_digest,
            _source_root_components,
            _source_root_metadata,
        ) = _BUILTIN_VALIDATED_INPUTS(snapshot, contract)
        checked_policy = _BUILTIN_PATH_POLICY_SNAPSHOT(path_policy)
        checked_limits = _BUILTIN_RESOURCE_LIMITS_SNAPSHOT(resource_limits)
        path_policy_digest = _BUILTIN_CANONICAL_DIGEST(checked_policy)
        resource_limits_digest = _BUILTIN_CANONICAL_DIGEST(checked_limits)
        if (
            path_policy_digest != snapshot.path_policy_digest
            or resource_limits_digest != snapshot.resource_limits_digest
            or path_policy_digest != contract.path_policy_digest
            or resource_limits_digest != contract.resource_limits_digest
        ):
            raise _InvalidReconciliation
        receipt_projection = _BUILTIN_MATERIALIZATION_RECEIPT_PROJECTION(
            materialization_receipt
        )
        materialization_receipt_digest = _BUILTIN_CANONICAL_DIGEST(
            receipt_projection
        )
        if (
            receipt_projection["source_snapshot_digest"]
            != source_snapshot_digest
            or receipt_projection["job_tree_contract_digest"] != contract_digest
            or receipt_projection["source_bundle_digest"]
            != _BUILTIN_SOURCE_BUNDLE_DIGEST(source_bundle)
            or receipt_projection["source_file_count"] != len(source_bundle.files)
            or receipt_projection["source_total_bytes"]
            != sum(len(item.content) for item in source_bundle.files)
        ):
            raise _InvalidReconciliation
        detached_candidate = _BUILTIN_DETACHED_CANDIDATE_BUNDLE(
            candidate_bundle
        )
        _BUILTIN_VALIDATE_CANDIDATE_POLICY(
            detached_candidate,
            path_policy=checked_policy,
            resource_limits=checked_limits,
        )
        operations = _BUILTIN_DERIVE_OPERATIONS(source_bundle, detached_candidate)
        return _RECONCILIATION_TYPE(
            kind=REPOSITORY_WORKER_JOB_TREE_RECONCILIATION_KIND,
            schema_version=REPOSITORY_WORKER_JOB_TREE_RECONCILIATION_SCHEMA_VERSION,
            reconciliation_scope=RECONCILIATION_SCOPE,
            source_snapshot_digest=source_snapshot_digest,
            job_tree_contract_digest=contract_digest,
            materialization_receipt_digest=materialization_receipt_digest,
            source_bundle_digest=_BUILTIN_SOURCE_BUNDLE_DIGEST(source_bundle),
            candidate_bundle_digest=_BUILTIN_CANDIDATE_BUNDLE_DIGEST(
                detached_candidate
            ),
            path_policy_digest=path_policy_digest,
            resource_limits_digest=resource_limits_digest,
            source_bundle=source_bundle,
            candidate_bundle=detached_candidate,
            materialization_receipt=materialization_receipt,
            path_policy=checked_policy,
            resource_limits=checked_limits,
            operations=operations,
            source_file_count=len(source_bundle.files),
            source_total_bytes=sum(len(item.content) for item in source_bundle.files),
            candidate_file_count=len(detached_candidate.files),
            candidate_total_bytes=sum(
                len(item.content) for item in detached_candidate.files
            ),
            added_file_count=sum(item.operation == "added" for item in operations),
            modified_file_count=sum(
                item.operation == "modified" for item in operations),
            deleted_file_count=sum(
                item.operation == "deleted" for item in operations),
        )
    except (
        AttributeError,
        TypeError,
        UnicodeError,
        ValidationError,
        ValueError,
    ):
        raise ValidationError(_INVALID_RECONCILIATION_MESSAGE) from None


__all__ = [
    "RECONCILIATION_SCOPE",
    "REPOSITORY_WORKER_JOB_TREE_CANDIDATE_BUNDLE_KIND",
    "REPOSITORY_WORKER_JOB_TREE_PATCH_OPERATION_KIND",
    "REPOSITORY_WORKER_JOB_TREE_RECONCILIATION_KIND",
    "REPOSITORY_WORKER_JOB_TREE_RECONCILIATION_SCHEMA_VERSION",
    "RepositoryWorkerJobTreeCandidateBundle",
    "RepositoryWorkerJobTreePatchOperation",
    "RepositoryWorkerJobTreeReconciliation",
    "derive_repository_worker_job_tree_reconciliation",
]
