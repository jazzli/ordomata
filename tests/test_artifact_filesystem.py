from __future__ import annotations

import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from ordomata.artifact_filesystem import (
    ARTIFACT_MATCHES,
    ARTIFACT_UNVERIFIABLE,
    StagedArtifact,
    publish_staged_artifact,
    published_artifact_state,
    remove_owned_published_artifact,
    stage_artifact,
)
from ordomata.errors import ConfigurationError, ValidationError


class ArtifactFilesystemTests(unittest.TestCase):
    def test_descriptor_anchored_happy_path_preserves_private_exact_bytes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = (
                Path(temporary) / "nested" / "artifacts" / "candidate.json"
            )
            stage = StagedArtifact(
                destination.with_name(".candidate.json.intent.tmp")
            )
            content = b'{"candidate":"private"}\n'

            stage_artifact(destination, content, stage=stage)

            self.assertIsNotNone(stage.identity)
            self.assertIsNotNone(stage.parent_identity)
            self.assertEqual(stage.path.read_bytes(), content)
            self.assertEqual(
                stat.S_IMODE(stage.path.stat().st_mode),
                0o600,
            )

            publish_staged_artifact(destination, stage=stage)

            self.assertFalse(stage.path.exists())
            self.assertEqual(destination.read_bytes(), content)
            self.assertEqual(
                published_artifact_state(
                    destination,
                    content,
                    expected_identity=stage.identity,
                    expected_parent_identity=stage.parent_identity,
                ),
                ARTIFACT_MATCHES,
            )
            self.assertTrue(
                remove_owned_published_artifact(
                    destination,
                    staged_identity=stage.identity,
                )
            )
            self.assertFalse(destination.exists())

    def test_mutable_parent_symlink_is_rejected_without_outside_write(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root / "outside"
            outside.mkdir()
            redirected_parent = root / "artifacts"
            redirected_parent.symlink_to(outside, target_is_directory=True)
            destination = redirected_parent / "candidate.json"
            stage = StagedArtifact(
                redirected_parent / ".candidate.json.intent.tmp"
            )

            with self.assertRaisesRegex(
                ValidationError,
                "mutable symlink",
            ):
                stage_artifact(destination, b"private", stage=stage)

            self.assertEqual(tuple(outside.iterdir()), ())
            self.assertIsNone(stage.identity)

    def test_parent_swap_before_publication_cleans_held_staging_inode(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            intended = root / "artifacts"
            intended.mkdir()
            relocated = root / "relocated-artifacts"
            outside = root / "outside"
            outside.mkdir()
            destination = intended / "candidate.json"
            stage = StagedArtifact(intended / ".candidate.json.intent.tmp")
            stage_artifact(destination, b"private", stage=stage)

            intended.rename(relocated)
            intended.symlink_to(outside, target_is_directory=True)

            with self.assertRaisesRegex(
                ConfigurationError,
                "parent changed before publication",
            ):
                publish_staged_artifact(destination, stage=stage)

            self.assertFalse((outside / destination.name).exists())
            self.assertFalse((relocated / destination.name).exists())
            self.assertFalse((relocated / stage.path.name).exists())

    def test_parent_swap_during_link_rolls_back_without_outside_write(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            intended = root / "artifacts"
            intended.mkdir()
            relocated = root / "relocated-artifacts"
            outside = root / "outside"
            outside.mkdir()
            destination = intended / "candidate.json"
            stage = StagedArtifact(intended / ".candidate.json.intent.tmp")
            stage_artifact(destination, b"private", stage=stage)
            original_link = os.link

            def swap_parent_then_link(source, target, **kwargs):
                intended.rename(relocated)
                intended.symlink_to(outside, target_is_directory=True)
                return original_link(source, target, **kwargs)

            with (
                patch(
                    "ordomata.artifact_filesystem.os.link",
                    side_effect=swap_parent_then_link,
                ),
                self.assertRaisesRegex(
                    ConfigurationError,
                    "parent changed during publication",
                ),
            ):
                publish_staged_artifact(destination, stage=stage)

            self.assertFalse((outside / destination.name).exists())
            self.assertFalse((relocated / destination.name).exists())
            self.assertFalse((relocated / stage.path.name).exists())

    def test_parent_swap_during_owned_removal_preserves_replacement_file(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            intended = root / "artifacts"
            intended.mkdir()
            relocated = root / "relocated-artifacts"
            outside = root / "outside"
            outside.mkdir()
            destination = intended / "candidate.json"
            stage = StagedArtifact(intended / ".candidate.json.intent.tmp")
            stage_artifact(destination, b"owned", stage=stage)
            publish_staged_artifact(destination, stage=stage)
            replacement = outside / destination.name
            replacement.write_bytes(b"foreign")
            original_unlink = os.unlink

            def swap_parent_then_unlink(name, **kwargs):
                intended.rename(relocated)
                intended.symlink_to(outside, target_is_directory=True)
                return original_unlink(name, **kwargs)

            with patch(
                "ordomata.artifact_filesystem.os.unlink",
                side_effect=swap_parent_then_unlink,
            ):
                removed = remove_owned_published_artifact(
                    destination,
                    staged_identity=stage.identity,
                )

            self.assertFalse(removed)
            self.assertFalse((relocated / destination.name).exists())
            self.assertEqual(replacement.read_bytes(), b"foreign")

    def test_new_hardlink_during_owned_removal_is_not_reported_clean(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "artifacts"
            parent.mkdir()
            destination = parent / "candidate.json"
            escaped_alias = Path(temporary) / "escaped-candidate.json"
            stage = StagedArtifact(parent / ".candidate.json.intent.tmp")
            stage_artifact(destination, b"private", stage=stage)
            publish_staged_artifact(destination, stage=stage)
            original_unlink = os.unlink
            aliased = False

            def alias_then_unlink(name, *args, **kwargs):
                nonlocal aliased
                if not aliased and name == destination.name:
                    os.link(
                        destination,
                        escaped_alias,
                        follow_symlinks=False,
                    )
                    aliased = True
                return original_unlink(name, *args, **kwargs)

            with patch(
                "ordomata.artifact_filesystem.os.unlink",
                new=alias_then_unlink,
            ):
                removed = remove_owned_published_artifact(
                    destination,
                    staged_identity=stage.identity,
                    expected_parent_identity=stage.parent_identity,
                    stage=stage,
                )

            self.assertTrue(aliased)
            self.assertFalse(removed)
            self.assertFalse(destination.exists())
            self.assertEqual(escaped_alias.read_bytes(), b"private")
            stage.close()

    def test_existing_or_unowned_entries_are_never_replaced_or_removed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "artifacts"
            parent.mkdir()
            destination = parent / "candidate.json"
            destination.write_bytes(b"foreign")
            stage = StagedArtifact(parent / ".candidate.json.intent.tmp")

            with self.assertRaisesRegex(
                ValidationError,
                "destination already exists",
            ):
                stage_artifact(destination, b"private", stage=stage)

            self.assertEqual(destination.read_bytes(), b"foreign")
            self.assertFalse(
                remove_owned_published_artifact(
                    destination,
                    staged_identity=(0, 0),
                )
            )
            self.assertEqual(destination.read_bytes(), b"foreign")
            destination.unlink()
            destination.symlink_to(parent / "missing")
            self.assertEqual(
                published_artifact_state(destination, b"private"),
                ARTIFACT_UNVERIFIABLE,
            )
            self.assertFalse(
                remove_owned_published_artifact(
                    destination,
                    staged_identity=(0, 0),
                )
            )
            self.assertTrue(destination.is_symlink())


if __name__ == "__main__":
    unittest.main()
