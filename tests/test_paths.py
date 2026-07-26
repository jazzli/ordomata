from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from ordomata.errors import ConfigurationError
from ordomata.paths import (
    LEGACY_STATE_DIRECTORY_NAME,
    STATE_DIRECTORY_NAME,
    resolve_state_directory_name,
    resolve_state_root,
)


class StatePathTests(unittest.TestCase):
    def test_missing_state_selects_canonical_without_creating_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertEqual(resolve_state_root(root), root / STATE_DIRECTORY_NAME)
            self.assertFalse((root / STATE_DIRECTORY_NAME).exists())
            self.assertFalse((root / LEGACY_STATE_DIRECTORY_NAME).exists())

    def test_canonical_state_wins_when_it_is_the_only_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / STATE_DIRECTORY_NAME).mkdir()
            self.assertEqual(
                resolve_state_directory_name(root), STATE_DIRECTORY_NAME
            )

    def test_legacy_state_is_used_in_place_when_it_is_the_only_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / LEGACY_STATE_DIRECTORY_NAME).mkdir()
            self.assertEqual(
                resolve_state_root(root), root / LEGACY_STATE_DIRECTORY_NAME
            )

    def test_dual_state_roots_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / STATE_DIRECTORY_NAME).mkdir()
            (root / LEGACY_STATE_DIRECTORY_NAME).mkdir()
            with self.assertRaisesRegex(ConfigurationError, "both .ordomata"):
                resolve_state_root(root)

    def test_selected_state_root_must_be_a_real_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / STATE_DIRECTORY_NAME).write_text("not a directory")
            with self.assertRaisesRegex(ConfigurationError, "must be a directory"):
                resolve_state_root(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "outside"
            target.mkdir()
            (root / LEGACY_STATE_DIRECTORY_NAME).symlink_to(
                target, target_is_directory=True
            )
            with self.assertRaisesRegex(ConfigurationError, "must not be a symlink"):
                resolve_state_root(root)


if __name__ == "__main__":
    unittest.main()
