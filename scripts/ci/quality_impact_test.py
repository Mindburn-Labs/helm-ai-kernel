#!/usr/bin/env python3
"""The PR impact filter must count a deleted file as a change (26-03)."""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import quality  # noqa: E402


def git(repo: pathlib.Path, *args: str) -> None:
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
    subprocess.run(["git", *args], cwd=repo, env=env, check=True, capture_output=True)


class ImpactFilterTest(unittest.TestCase):
    def changed_after(self, change) -> set[str] | None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            git(repo, "init", "-q", "-b", "main")
            (repo / "release").mkdir()
            (repo / "release" / "pins.json").write_text("{}\n")
            (repo / "README.md").write_text("x\n")
            git(repo, "add", "-A")
            git(repo, "commit", "-q", "-m", "base")
            git(repo, "checkout", "-q", "-b", "change")
            change(repo)
            git(repo, "commit", "-q", "-am", "change")
            env = {k: v for k, v in os.environ.items() if k not in ("QUALITY_CHANGED_FILES", "GITHUB_BASE_REF")}
            with mock.patch.object(quality, "ROOT", repo), mock.patch.dict(os.environ, env, clear=True):
                return quality.changed_files()

    def test_deleted_file_is_a_change(self) -> None:
        # A deletion alongside any other edit: the old filter (no D) returned
        # only README.md, so the gate watching release/** was skipped.
        def change(repo: pathlib.Path) -> None:
            git(repo, "rm", "-q", "release/pins.json")
            (repo / "README.md").write_text("y\n")

        files = self.changed_after(change)
        self.assertEqual(files, {"release/pins.json", "README.md"})
        gate = {"id": "console-sidecar-pin", "paths": ["release/**"]}
        self.assertTrue(quality.impacted(gate, files), "a deletion-only change must impact the gate that watches the path")

    def test_modified_file_is_still_a_change(self) -> None:
        files = self.changed_after(lambda repo: (repo / "README.md").write_text("y\n"))
        self.assertEqual(files, {"README.md"})


if __name__ == "__main__":
    unittest.main()
