"""Crash-safe filesystem primitives for controller-owned local artifacts.

The helpers in this module do not decide whether an artifact write is
authorized and do not own reconciliation policy.  Callers must persist any
required intent evidence before calling :func:`stage_artifact`, and they remain
responsible for removing staged or published inodes when a later step fails.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import stat
from typing import Literal

from .errors import ConfigurationError, ValidationError


ArtifactIdentity = tuple[int, int]
PublishedArtifactState = Literal["absent", "matches", "unverifiable"]

ARTIFACT_ABSENT: PublishedArtifactState = "absent"
ARTIFACT_MATCHES: PublishedArtifactState = "matches"
ARTIFACT_UNVERIFIABLE: PublishedArtifactState = "unverifiable"


@dataclass(slots=True)
class StagedArtifact:
    """A caller-selected staging path and the inode created there."""

    path: Path
    identity: ArtifactIdentity | None = None
    parent_identity: ArtifactIdentity | None = None
    _parent_descriptor: int | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _artifact_descriptor: int | None = field(
        default=None,
        init=False,
        repr=False,
    )

    def close(self) -> None:
        """Release the parent-directory descriptor retained after staging."""

        descriptor = self._parent_descriptor
        self._parent_descriptor = None
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        artifact_descriptor = self._artifact_descriptor
        self._artifact_descriptor = None
        if artifact_descriptor is not None:
            try:
                os.close(artifact_descriptor)
            except OSError:
                pass

    def __del__(self) -> None:
        self.close()


def stage_artifact(
    path: Path,
    content: bytes,
    *,
    stage: StagedArtifact,
) -> None:
    """Durably stage bytes through one verified parent-directory descriptor."""

    if stage.path.parent != path.parent or stage.path == path:
        raise ConfigurationError("artifact staging path is invalid")
    _validate_entry_name(path.name)
    _validate_entry_name(stage.path.name)

    stage.close()
    parent_descriptor = _open_artifact_directory(path.parent, create=True)
    created = False
    stage.identity = None
    try:
        stage.parent_identity = _descriptor_identity(parent_descriptor)
    except BaseException:
        try:
            os.close(parent_descriptor)
        except OSError:
            pass
        raise
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        if _entry_metadata(parent_descriptor, path.name) is not None:
            raise ValidationError("artifact destination already exists")
        if _entry_metadata(parent_descriptor, stage.path.name) is not None:
            raise ValidationError("artifact staging destination already exists")
        descriptor = os.open(
            stage.path.name,
            flags,
            0o600,
            dir_fd=parent_descriptor,
        )
        created = True
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ConfigurationError("artifact staging entry is invalid")
        stage.identity = (metadata.st_dev, metadata.st_ino)
        # Keep the inode itself leased from creation until the caller has
        # reconciled the action receipt.  In particular, this lets recovery
        # observe an unexpected hard link even when the controller-owned
        # staging name has already been removed.
        stage._artifact_descriptor = descriptor
        descriptor = None
        offset = 0
        while offset < len(content):
            written = os.write(
                stage._artifact_descriptor,
                content[offset:],
            )
            if written <= 0:
                raise ConfigurationError(
                    "artifact staging write did not make progress"
                )
            offset += written
        os.fsync(stage._artifact_descriptor)
        staged_metadata = _entry_metadata(
            parent_descriptor,
            stage.path.name,
        )
        if (
            staged_metadata is None
            or (
                staged_metadata.st_dev,
                staged_metadata.st_ino,
            )
            != stage.identity
            or staged_metadata.st_nlink != 1
        ):
            raise ConfigurationError(
                "artifact staging link count is invalid"
            )
        retained_metadata = os.fstat(stage._artifact_descriptor)
        if (
            (retained_metadata.st_dev, retained_metadata.st_ino)
            != stage.identity
            or retained_metadata.st_nlink != 1
        ):
            raise ConfigurationError(
                "artifact staging descriptor is invalid"
            )
        if not _fsync_open_directory(parent_descriptor):
            raise ConfigurationError(
                "artifact staging namespace sync failed"
            )
        if not _path_directory_has_identity(
            path.parent,
            stage.parent_identity,
        ):
            raise ConfigurationError(
                "artifact parent changed during staging"
            )
        stage._parent_descriptor = parent_descriptor
        parent_descriptor = None
    except BaseException:
        removed = False
        if created and stage.identity is not None:
            try:
                removed = _remove_owned_entry_at(
                    parent_descriptor,
                    stage.path.name,
                    stage.identity,
                )
            except BaseException:
                removed = False
        retained_link_count: int | None = None
        if stage._artifact_descriptor is not None:
            try:
                retained_link_count = os.fstat(
                    stage._artifact_descriptor
                ).st_nlink
            except BaseException:
                pass
        if removed and retained_link_count == 0:
            # The controller name was removed and the retained inode proves
            # that no hard-link alias survives.
            if stage.identity is not None:
                stage.identity = None
            stage.close()
        elif (
            stage.identity is not None
            and stage._artifact_descriptor is not None
        ):
            # Preserve both leases for caller-owned conservative recovery.  A
            # non-zero link count with no known controller name is an unknown
            # external effect and must not be downgraded to a clean failure.
            stage._parent_descriptor = parent_descriptor
            parent_descriptor = None
        else:
            stage.close()
        raise
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if parent_descriptor is not None:
            try:
                os.close(parent_descriptor)
            except OSError:
                pass


def _ensure_artifact_parent(parent: Path) -> None:
    """Create a private directory chain without following any path component."""

    descriptor = _open_artifact_directory(parent, create=True)
    try:
        if not _fsync_open_directory(descriptor):
            raise ConfigurationError(
                "artifact parent namespace sync failed"
            )
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def publish_staged_artifact(
    path: Path,
    *,
    stage: StagedArtifact,
) -> None:
    """Hard-link a staged inode without resolving the parent path twice.

    The parent directory identity captured during staging must still be the
    directory named by ``path.parent``.  Both names are then accessed relative
    to the same held directory descriptor.  A detected namespace change rolls
    back controller-owned names through that descriptor.
    """

    if stage.path.parent != path.parent or stage.path == path:
        raise ConfigurationError("artifact staging path is invalid")
    if stage.identity is None or stage.parent_identity is None:
        raise ConfigurationError("artifact staging identity is unavailable")
    _validate_entry_name(path.name)
    _validate_entry_name(stage.path.name)

    retained_descriptor = stage._parent_descriptor
    retained_artifact_descriptor = stage._artifact_descriptor
    if retained_descriptor is None or retained_artifact_descriptor is None:
        raise ConfigurationError(
            "artifact staging descriptor is unavailable"
        )
    try:
        parent_descriptor = os.dup(retained_descriptor)
    except OSError as exc:
        raise ConfigurationError(
            "artifact staging parent descriptor is invalid"
        ) from exc
    linked = False
    try:
        if (
            _descriptor_identity(parent_descriptor)
            != stage.parent_identity
            or not _path_directory_has_identity(
                path.parent,
                stage.parent_identity,
            )
        ):
            try:
                _remove_owned_entry_at(
                    parent_descriptor,
                    stage.path.name,
                    stage.identity,
                )
            except BaseException:
                pass
            raise ConfigurationError(
                "artifact parent changed before publication"
            )
        retained_metadata = os.fstat(retained_artifact_descriptor)
        if (
            (retained_metadata.st_dev, retained_metadata.st_ino)
            != stage.identity
            or retained_metadata.st_nlink != 1
        ):
            raise ConfigurationError(
                "artifact staging descriptor is invalid"
            )
        staged_metadata = _entry_metadata(
            parent_descriptor,
            stage.path.name,
        )
        if (
            staged_metadata is None
            or not stat.S_ISREG(staged_metadata.st_mode)
            or staged_metadata.st_nlink != 1
            or (
                staged_metadata.st_dev,
                staged_metadata.st_ino,
            )
            != stage.identity
        ):
            raise ConfigurationError(
                "artifact staging entry could not be verified"
            )
        if _entry_metadata(parent_descriptor, path.name) is not None:
            raise ValidationError("artifact destination already exists")
        try:
            os.link(
                stage.path.name,
                path.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise ConfigurationError(
                "staged artifact could not be published safely"
            ) from exc
        linked = True
        if os.fstat(retained_artifact_descriptor).st_nlink != 2:
            raise ConfigurationError(
                "artifact publication link count is invalid"
            )
        published_metadata = _entry_metadata(parent_descriptor, path.name)
        if (
            published_metadata is None
            or not stat.S_ISREG(published_metadata.st_mode)
            or published_metadata.st_nlink != 2
            or (
                published_metadata.st_dev,
                published_metadata.st_ino,
            )
            != stage.identity
        ):
            raise ConfigurationError(
                "published artifact identity could not be verified"
            )
        if not _fsync_open_directory(parent_descriptor):
            raise ConfigurationError(
                "artifact publication namespace sync failed"
            )
        if not _path_directory_has_identity(
            path.parent,
            stage.parent_identity,
        ):
            _rollback_changed_namespace(
                parent_descriptor,
                path.name,
                stage,
            )
            linked = False
            raise ConfigurationError(
                "artifact parent changed during publication"
            )

        # The final name is a hard link to the already-fsynced bytes.  Failure
        # to remove the staging name does not invalidate the published file.
        try:
            os.unlink(stage.path.name, dir_fd=parent_descriptor)
        except OSError:
            pass
        published_metadata = _entry_metadata(parent_descriptor, path.name)
        if (
            published_metadata is None
            or (
                published_metadata.st_dev,
                published_metadata.st_ino,
            )
            != stage.identity
            or published_metadata.st_nlink != 1
        ):
            raise ConfigurationError(
                "artifact publication link count is invalid"
            )
        if os.fstat(retained_artifact_descriptor).st_nlink != 1:
            raise ConfigurationError(
                "artifact publication link count is invalid"
            )
        if not _fsync_open_directory(parent_descriptor):
            raise ConfigurationError(
                "artifact publication namespace sync failed"
            )
        if not _path_directory_has_identity(
            path.parent,
            stage.parent_identity,
        ):
            _rollback_changed_namespace(
                parent_descriptor,
                path.name,
                stage,
            )
            linked = False
            raise ConfigurationError(
                "artifact parent changed during publication"
            )
        # Keep the verified parent descriptor leased to the caller until its
        # action receipt and any recovery path have been reconciled.
    except BaseException:
        if linked:
            try:
                _remove_owned_entry_at(
                    parent_descriptor,
                    path.name,
                    stage.identity,
                )
            except BaseException:
                pass
        raise
    finally:
        try:
            os.close(parent_descriptor)
        except OSError:
            pass


def _rollback_changed_namespace(
    parent_descriptor: int,
    destination_name: str,
    stage: StagedArtifact,
) -> None:
    """Best-effort removal when the pathname no longer names the held parent."""

    try:
        _remove_owned_entry_at(
            parent_descriptor,
            destination_name,
            stage.identity,
        )
    except BaseException:
        pass
    try:
        _remove_owned_entry_at(
            parent_descriptor,
            stage.path.name,
            stage.identity,
        )
    except BaseException:
        pass


def fsync_artifact_parent(path: Path) -> bool:
    """Durably commit the current parent namespace without following links."""

    return _fsync_directory(path.parent)


def _fsync_directory(directory: Path) -> bool:
    """Fsync one safely traversed directory descriptor."""

    try:
        descriptor = _open_artifact_directory(directory, create=False)
    except (ConfigurationError, FileNotFoundError, ValidationError):
        return False
    try:
        return _fsync_open_directory(descriptor)
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _open_artifact_directory(
    directory: Path,
    *,
    create: bool,
) -> int:
    """Open a directory chain one component at a time without following links."""

    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    if directory.is_absolute():
        anchor = directory.anchor
        components = directory.parts[1:]
    else:
        anchor = "."
        components = directory.parts
    try:
        descriptor = os.open(anchor, flags)
    except OSError as exc:
        raise ConfigurationError(
            "artifact parent anchor could not be opened safely"
        ) from exc
    try:
        for component in components:
            if component in ("", "."):
                continue
            if component == "..":
                raise ValidationError(
                    "artifact parent traversal is not allowed"
                )
            try:
                entry_metadata = os.stat(
                    component,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                except FileExistsError as exc:
                    raise ConfigurationError(
                        "artifact parent changed during creation"
                    ) from exc
                except OSError as exc:
                    raise ConfigurationError(
                        "artifact parent could not be created safely"
                    ) from exc
                if not _fsync_open_directory(descriptor):
                    raise ConfigurationError(
                        "artifact parent namespace sync failed"
                    )
                try:
                    entry_metadata = os.stat(
                        component,
                        dir_fd=descriptor,
                        follow_symlinks=False,
                    )
                except OSError as exc:
                    raise ConfigurationError(
                        "artifact parent creation could not be verified"
                    ) from exc
            except OSError as exc:
                raise ConfigurationError(
                    "artifact parent could not be inspected safely"
                ) from exc
            protected_symlink = stat.S_ISLNK(entry_metadata.st_mode)
            if protected_symlink and _descriptor_is_process_writable(
                descriptor
            ):
                raise ValidationError(
                    "artifact parent must not traverse a mutable symlink"
                )
            if (
                not protected_symlink
                and not stat.S_ISDIR(entry_metadata.st_mode)
            ):
                raise ValidationError(
                    "artifact parent must be an ordinary directory"
                )
            try:
                child_descriptor = os.open(
                    component,
                    (
                        flags
                        if not protected_symlink
                        else flags & ~getattr(os, "O_NOFOLLOW", 0)
                    ),
                    dir_fd=descriptor,
                )
            except OSError as exc:
                raise ConfigurationError(
                    "artifact parent could not be opened safely"
                ) from exc
            try:
                opened_metadata = os.fstat(child_descriptor)
            except BaseException as exc:
                try:
                    os.close(child_descriptor)
                except OSError:
                    pass
                if isinstance(exc, OSError):
                    raise ConfigurationError(
                        "artifact parent descriptor could not be verified"
                    ) from exc
                raise
            if protected_symlink:
                try:
                    confirmed_metadata = os.stat(
                        component,
                        dir_fd=descriptor,
                        follow_symlinks=False,
                    )
                except BaseException as exc:
                    try:
                        os.close(child_descriptor)
                    except OSError:
                        pass
                    if isinstance(exc, OSError):
                        raise ConfigurationError(
                            "artifact parent symlink could not be verified"
                        ) from exc
                    raise
                entry_unchanged = (
                    confirmed_metadata.st_dev,
                    confirmed_metadata.st_ino,
                ) == (
                    entry_metadata.st_dev,
                    entry_metadata.st_ino,
                )
            else:
                entry_unchanged = (
                    opened_metadata.st_dev,
                    opened_metadata.st_ino,
                ) == (
                    entry_metadata.st_dev,
                    entry_metadata.st_ino,
                )
            if (
                not stat.S_ISDIR(opened_metadata.st_mode)
                or not entry_unchanged
            ):
                try:
                    os.close(child_descriptor)
                except OSError:
                    pass
                raise ConfigurationError(
                    "artifact parent changed while being opened"
                )
            previous_descriptor = descriptor
            descriptor = child_descriptor
            try:
                os.close(previous_descriptor)
            except OSError:
                pass
        return descriptor
    except BaseException:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _descriptor_is_process_writable(descriptor: int) -> bool:
    """Return whether this process can replace entries in the directory."""

    try:
        return os.access(
            ".",
            os.W_OK,
            dir_fd=descriptor,
            effective_ids=True,
            follow_symlinks=False,
        )
    except (NotImplementedError, OSError):
        # The safe fallback is to reject symlink traversal.
        return True


def _descriptor_identity(descriptor: int) -> ArtifactIdentity:
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        raise ConfigurationError("artifact parent descriptor is invalid")
    return (metadata.st_dev, metadata.st_ino)


def _entry_metadata(
    parent_descriptor: int,
    name: str,
) -> os.stat_result | None:
    try:
        return os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ConfigurationError(
            "artifact entry could not be inspected safely"
        ) from exc


def _fsync_open_directory(descriptor: int) -> bool:
    try:
        os.fsync(descriptor)
    except OSError:
        return False
    return True


def _path_directory_has_identity(
    directory: Path,
    expected_identity: ArtifactIdentity | None,
) -> bool:
    if expected_identity is None:
        return False
    try:
        descriptor = _open_artifact_directory(directory, create=False)
    except (ConfigurationError, FileNotFoundError, ValidationError):
        return False
    try:
        return _descriptor_identity(descriptor) == expected_identity
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _validate_entry_name(name: str) -> None:
    if name in ("", ".", "..") or Path(name).name != name:
        raise ValidationError("artifact entry name is invalid")


def _remove_owned_entry_at(
    parent_descriptor: int,
    name: str,
    expected_identity: ArtifactIdentity | None,
) -> bool:
    try:
        metadata = _entry_metadata(parent_descriptor, name)
    except ConfigurationError:
        return False
    if metadata is None:
        return _fsync_open_directory(parent_descriptor)
    if (
        expected_identity is None
        or not stat.S_ISREG(metadata.st_mode)
        or (metadata.st_dev, metadata.st_ino) != expected_identity
    ):
        return False
    try:
        os.unlink(name, dir_fd=parent_descriptor)
    except OSError:
        return False
    try:
        absent = _entry_metadata(parent_descriptor, name) is None
    except ConfigurationError:
        return False
    return bool(absent and _fsync_open_directory(parent_descriptor))


def published_artifact_state(
    path: Path,
    expected: bytes,
    *,
    expected_identity: ArtifactIdentity | None = None,
    expected_parent_identity: ArtifactIdentity | None = None,
    stage: StagedArtifact | None = None,
) -> PublishedArtifactState:
    """Classify a final name as absent, an exact private file, or uncertain."""

    anchored = stage is not None and stage._parent_descriptor is not None
    if anchored:
        if stage.path.parent != path.parent:
            return ARTIFACT_UNVERIFIABLE
        retained_descriptor = stage._parent_descriptor
        assert retained_descriptor is not None
        try:
            parent_descriptor = os.dup(retained_descriptor)
        except OSError:
            return ARTIFACT_UNVERIFIABLE
    else:
        try:
            parent_descriptor = _open_artifact_directory(
                path.parent,
                create=False,
            )
        except FileNotFoundError:
            return ARTIFACT_ABSENT
        except (ConfigurationError, ValidationError):
            return ARTIFACT_UNVERIFIABLE
    descriptor: int | None = None
    try:
        parent_identity = _descriptor_identity(parent_descriptor)
        if (
            expected_parent_identity is not None
            and parent_identity != expected_parent_identity
        ):
            return ARTIFACT_UNVERIFIABLE
        try:
            entry_metadata = _entry_metadata(
                parent_descriptor,
                path.name,
            )
        except ConfigurationError:
            return ARTIFACT_UNVERIFIABLE
        if entry_metadata is None:
            return (
                ARTIFACT_ABSENT
                if _path_directory_has_identity(
                    path.parent,
                    parent_identity,
                )
                else ARTIFACT_UNVERIFIABLE
            )
        if not stat.S_ISREG(entry_metadata.st_mode):
            return ARTIFACT_UNVERIFIABLE
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(
            path.name,
            flags,
            dir_fd=parent_descriptor,
        )
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            metadata = os.fstat(handle.fileno())
            observed = handle.read(len(expected) + 1)
        if (
            metadata.st_dev != entry_metadata.st_dev
            or metadata.st_ino != entry_metadata.st_ino
            or (
                expected_identity is not None
                and (metadata.st_dev, metadata.st_ino)
                != expected_identity
            )
        ):
            return ARTIFACT_UNVERIFIABLE
        retained_inode_matches = True
        if stage is not None and stage._artifact_descriptor is not None:
            retained_metadata = os.fstat(stage._artifact_descriptor)
            retained_inode_matches = bool(
                (retained_metadata.st_dev, retained_metadata.st_ino)
                == (metadata.st_dev, metadata.st_ino)
                and retained_metadata.st_nlink == 1
            )
        matches = bool(
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_size == len(expected)
            and metadata.st_nlink == 1
            and observed == expected
            and metadata.st_mode & 0o077 == 0
            and retained_inode_matches
            and _path_directory_has_identity(
                path.parent,
                parent_identity,
            )
        )
        return ARTIFACT_MATCHES if matches else ARTIFACT_UNVERIFIABLE
    except OSError:
        return ARTIFACT_UNVERIFIABLE
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            os.close(parent_descriptor)
        except OSError:
            pass


def remove_owned_published_artifact(
    path: Path,
    *,
    staged_identity: ArtifactIdentity | None,
    expected_parent_identity: ArtifactIdentity | None = None,
    stage: StagedArtifact | None = None,
) -> bool:
    """Remove only the staged inode and prove the supplied name is absent."""

    anchored = stage is not None and stage._parent_descriptor is not None
    if anchored:
        if stage.path.parent != path.parent:
            return False
        retained_descriptor = stage._parent_descriptor
        assert retained_descriptor is not None
        try:
            parent_descriptor = os.dup(retained_descriptor)
        except OSError:
            return False
    else:
        try:
            parent_descriptor = _open_artifact_directory(
                path.parent,
                create=False,
            )
        except FileNotFoundError:
            # A name below a parent that was never created is already proven
            # absent only when no earlier parent identity was captured.
            return expected_parent_identity is None
        except (ConfigurationError, ValidationError):
            return False
    try:
        parent_identity = _descriptor_identity(parent_descriptor)
        if (
            expected_parent_identity is not None
            and parent_identity != expected_parent_identity
        ):
            return False
        unexpected_links = False
        if anchored and stage is not None:
            metadata = _entry_metadata(parent_descriptor, path.name)
            if (
                metadata is not None
                and staged_identity is not None
                and (metadata.st_dev, metadata.st_ino) == staged_identity
            ):
                known_link_count = 1
                if path.name != stage.path.name:
                    staged_metadata = _entry_metadata(
                        parent_descriptor,
                        stage.path.name,
                    )
                    if (
                        staged_metadata is not None
                        and (
                            staged_metadata.st_dev,
                            staged_metadata.st_ino,
                        )
                        == staged_identity
                    ):
                        known_link_count += 1
                unexpected_links = metadata.st_nlink > known_link_count
        removed = _remove_owned_entry_at(
            parent_descriptor,
            path.name,
            staged_identity,
        )
        if anchored:
            known_remaining_links = 0
            retained_inode_matches = False
            if stage is not None and stage._artifact_descriptor is not None:
                known_names = {path.name, stage.path.name}
                for name in known_names:
                    candidate = _entry_metadata(parent_descriptor, name)
                    if (
                        candidate is not None
                        and staged_identity is not None
                        and (candidate.st_dev, candidate.st_ino)
                        == staged_identity
                    ):
                        known_remaining_links += 1
                retained_metadata = os.fstat(stage._artifact_descriptor)
                retained_inode_matches = bool(
                    staged_identity is not None
                    and (
                        retained_metadata.st_dev,
                        retained_metadata.st_ino,
                    )
                    == staged_identity
                    and retained_metadata.st_nlink
                    == known_remaining_links
                )
            return bool(
                removed
                and not unexpected_links
                and retained_inode_matches
                and _path_directory_has_identity(
                    path.parent,
                    parent_identity,
                )
            )
        return bool(
            removed
            and _path_directory_has_identity(path.parent, parent_identity)
        )
    finally:
        try:
            os.close(parent_descriptor)
        except OSError:
            pass


__all__ = [
    "ARTIFACT_ABSENT",
    "ARTIFACT_MATCHES",
    "ARTIFACT_UNVERIFIABLE",
    "ArtifactIdentity",
    "PublishedArtifactState",
    "StagedArtifact",
    "fsync_artifact_parent",
    "publish_staged_artifact",
    "published_artifact_state",
    "remove_owned_published_artifact",
    "stage_artifact",
]
