import importlib.util
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


if __name__ == "__main__":
    unittest.main()
