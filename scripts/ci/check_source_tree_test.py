#!/usr/bin/env python3
"""Exercise checkout integrity against real temporary Git repositories."""
from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import check_source_tree as guard


class SourceTreeTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.git("init", "-q")
        for path in guard.SOURCE_ROOTS:
            self.write(path + "/source.go", "package fixture\n")
        self.write(".gitignore", "**/.gen_tmp/\n")
        self.git("add", ".")

    def git(self, *args: str) -> None:
        subprocess.run(["git", *args], cwd=self.root, capture_output=True, check=True)

    def write(self, name: str, content: str = "package fixture\n") -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def test_indexed_sources_and_generated_output_outside_scope_pass(self) -> None:
        self.write("core/coverage.out", "mode: set\n")
        self.assertEqual(guard.check(self.root), [])

    def test_untracked_and_gitignored_sources_are_refused(self) -> None:
        for name in ("core/pkg/crypto/injected.go",
                     "core/pkg/kernel/.gen_tmp/injected.go",
                     "protocols/untracked\nname.json"):
            with self.subTest(name=name):
                path = self.write(name)
                self.assertEqual(guard.check(self.root), [
                    f"source file is not in the Git index: {name!r}",
                ])
                path.unlink()
                self.assertEqual(guard.check(self.root), [])

    def test_indexing_a_new_source_does_not_need_a_second_manifest(self) -> None:
        self.write("core/pkg/crypto/added.go")
        self.git("add", "core/pkg/crypto/added.go")
        self.assertEqual(guard.check(self.root), [])

    def test_missing_tracked_source_and_missing_directory_are_refused(self) -> None:
        path = self.root / "core/pkg/crypto/source.go"
        path.unlink()
        self.assertEqual(guard.check(self.root), [
            "tracked source file is missing: 'core/pkg/crypto/source.go'",
        ])
        path.parent.rmdir()
        self.assertIn("missing source directory: core/pkg/crypto", guard.check(self.root))

    def test_untracked_symlink_is_refused(self) -> None:
        name = "core/pkg/crypto/injected.go"
        (self.root / name).symlink_to("source.go")
        self.assertIn(f"source file is not in the Git index: {name!r}", guard.check(self.root))

    def test_empty_index_and_git_inventory_failure_are_not_success(self) -> None:
        self.git("rm", "--cached", "-rf", ".")
        self.assertIn("source inventory is empty", guard.check(self.root))
        with mock.patch.object(guard, "ROOT", self.root), \
                mock.patch.object(guard, "check", side_effect=subprocess.CalledProcessError(1, "git")), \
                mock.patch("builtins.print"):
            self.assertEqual(guard.main(), 2)


if __name__ == "__main__":
    unittest.main()
