from __future__ import annotations

import re
import tomllib
import unittest
from pathlib import Path

import ordomata


_MARKDOWN_LINK = re.compile(r"(?<!!)\[[^]]+\]\(([^)]+)\)")


class RepositoryHygieneTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(__file__).resolve().parents[1]

    def test_package_version_matches_project_metadata(self) -> None:
        metadata = tomllib.loads((self.root / "pyproject.toml").read_text())

        self.assertEqual(metadata["project"]["version"], ordomata.__version__)

    def test_local_markdown_link_targets_exist_and_stay_in_repository(self) -> None:
        markdown_files = (
            self.root / "README.md",
            self.root / "AGENTS.md",
            *sorted((self.root / "docs").glob("*.md")),
            *sorted((self.root / "fixtures").glob("*.md")),
        )
        failures: list[str] = []

        for path in markdown_files:
            for line_number, line in enumerate(path.read_text().splitlines(), 1):
                for raw_target in _MARKDOWN_LINK.findall(line):
                    target = raw_target.strip().split(maxsplit=1)[0].strip("<>")
                    if target.startswith(("http://", "https://", "mailto:", "#")):
                        continue
                    local_target = target.split("#", 1)[0]
                    if not local_target:
                        continue
                    resolved = (path.parent / local_target).resolve()
                    if not resolved.is_relative_to(self.root):
                        failures.append(
                            f"{path.relative_to(self.root)}:{line_number}: "
                            f"link escapes repository: {target}"
                        )
                    elif not resolved.exists():
                        failures.append(
                            f"{path.relative_to(self.root)}:{line_number}: "
                            f"missing link target: {target}"
                        )

        self.assertEqual(failures, [], "\n".join(failures))
