import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


spec = importlib.util.spec_from_file_location(
    "lint_skill", Path(__file__).with_name("lint_skill.py")
)
lint_skill = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lint_skill)


class ParseFrontmatterTest(unittest.TestCase):
    def test_nested_scalar_lists(self):
        parsed = lint_skill.parse_frontmatter(
            """---
name: example
metadata:
  helm:
    permissions:
      - shell
      - network
  openclaw:
    requires:
      bins:
        - curl
      env:
        - API_TOKEN
---
"""
        )

        self.assertEqual(parsed["metadata"]["helm"]["permissions"], ["shell", "network"])
        self.assertEqual(parsed["metadata"]["openclaw"]["requires"]["bins"], ["curl"])
        self.assertEqual(parsed["metadata"]["openclaw"]["requires"]["env"], ["API_TOKEN"])


class LintTest(unittest.TestCase):
    def test_rejects_invalid_identity_and_missing_memory_access(self):
        with tempfile.TemporaryDirectory() as root:
            skill = Path(root) / "Bad_Name" / "SKILL.md"
            skill.parent.mkdir()
            skill.write_text(
                """---
name: Bad_Name
description: test
version: latest
metadata:
  helm:
    effect_class: read_only
    reversibility: none
    data_boundary: local_only
    permissions:
      - helm.cap.test
    receipts:
      required: true
---
""",
                encoding="utf-8",
            )

            problems = lint_skill.lint(skill)

        self.assertIn("baseline: `name` must be kebab-case", problems)
        self.assertIn("baseline: `version` must be SemVer", problems)
        self.assertIn(
            "helm-cert: missing `metadata.helm.memory_access` block", problems
        )

    def test_cli_handles_help_and_missing_file(self):
        script = Path(__file__).with_name("lint_skill.py")
        help_result = subprocess.run(
            [sys.executable, script, "--help"], capture_output=True, text=True
        )
        missing_result = subprocess.run(
            [sys.executable, script, "/does/not/exist/SKILL.md"],
            capture_output=True,
            text=True,
        )

        self.assertEqual(help_result.returncode, 0)
        self.assertEqual(missing_result.returncode, 1)
        self.assertIn("cannot read file", missing_result.stdout)


if __name__ == "__main__":
    unittest.main()
