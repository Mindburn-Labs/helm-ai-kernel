#!/usr/bin/env python3
"""Dependabot coverage checks on temporary repository layouts."""
from __future__ import annotations

import pathlib
import tempfile
import unittest

import yaml

from check_dependency_hygiene import coverage_failures


class DependabotCoverageTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.manifests = [
            "core/go.mod", "tools/new-module/go.mod", "sdk/go/go.mod",
            "sdk/python/pyproject.toml", "sdk/python/requirements-runtime.txt",
            "sdk/ts/package.json", "sdk/rust/Cargo.toml", "sdk/java/pom.xml",
        ]
        for manifest in self.manifests:
            path = self.root / manifest
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()

    def check(self, entries: str, manifests: list[str] | None = None) -> list[str]:
        return coverage_failures(
            self.root, "version: 2\nupdates:\n" + entries,
            self.manifests if manifests is None else manifests,
        )

    def test_singular_quoted_directory(self) -> None:
        self.assertEqual(self.check(
            "  - package-ecosystem: gomod\n    directory: '/core'\n",
            ["core/go.mod"],
        ), [])

    def test_plural_inline_and_block_directories(self) -> None:
        for directories in (
            "    directories: ['/core', '/sdk/go']\n",
            "    directories:\n      - /core\n      - /sdk/go\n",
        ):
            with self.subTest(directories=directories):
                self.assertEqual(self.check(
                    "  - package-ecosystem: gomod\n" + directories,
                    ["core/go.mod", "sdk/go/go.mod"],
                ), [])

    def test_recursive_glob_covers_all_modules_and_sdks(self) -> None:
        entries = "".join(
            f"  - package-ecosystem: {ecosystem}\n    directories: ['**/*']\n"
            for ecosystem in ("gomod", "pip", "npm", "cargo", "maven")
        )
        self.assertEqual(self.check(entries), [])

    def test_single_level_glob_does_not_match_deeper_directory(self) -> None:
        self.assertEqual(self.check(
            "  - package-ecosystem: gomod\n    directories: ['/sdk/*']\n",
            ["sdk/go/go.mod", "tools/new-module/go.mod"],
        ), ["Dependabot does not cover tools/new-module/go.mod (gomod)"])

    def test_new_go_module_and_each_sdk_manifest_are_required(self) -> None:
        failures = self.check("  - package-ecosystem: gomod\n    directory: /core\n")
        self.assertEqual(len(failures), len(self.manifests) - 1)
        for manifest in self.manifests[1:]:
            self.assertTrue(any(manifest in failure for failure in failures))

    def test_wrong_ecosystem_and_comments_do_not_count(self) -> None:
        self.assertEqual(self.check(
            "  - package-ecosystem: npm\n    directory: /core\n"
            "    # directory: /sdk/go\n",
            ["core/go.mod", "sdk/go/go.mod"],
        ), [
            "Dependabot does not cover core/go.mod (gomod)",
            "Dependabot does not cover sdk/go/go.mod (gomod)",
        ])

    def test_other_target_branch_does_not_count(self) -> None:
        self.assertTrue(self.check(
            "  - package-ecosystem: gomod\n    directory: /core\n"
            "    target-branch: maintenance\n", ["core/go.mod"],
        ))

    def test_explicit_default_branch_counts(self) -> None:
        self.assertEqual(self.check(
            "  - package-ecosystem: gomod\n    directory: /core\n"
            "    target-branch: main\n", ["core/go.mod"],
        ), [])

    def test_root_directory(self) -> None:
        self.assertEqual(self.check(
            "  - package-ecosystem: gomod\n    directory: /\n", ["go.mod"],
        ), [])

    def test_invalid_configuration_is_rejected(self) -> None:
        for entries in (
            "  - package-ecosystem: gomod\n",
            "  - package-ecosystem: gomod\n    directories: /core\n",
            "  - package-ecosystem: gomod\n    directories: []\n",
            "  - package-ecosystem: gomod\n    directory: /core\n    directories: ['/core']\n",
            "  - package-ecosystem: gomod\n    directories: ['/../outside']\n",
            "  - package-ecosystem: gomod\n    directories: [\n",
        ):
            with self.subTest(entries=entries), self.assertRaises((ValueError, yaml.YAMLError)):
                self.check(entries)


if __name__ == "__main__":
    unittest.main()
