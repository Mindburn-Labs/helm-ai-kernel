#!/usr/bin/env python3
"""Guard tag-release provenance and no-fanout workflow invariants."""
from __future__ import annotations

import re
import unittest
from pathlib import Path


WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "release.yml"


class ReleaseWorkflowContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text()

    def job(self, name: str) -> str:
        match = re.search(
            rf"^  {re.escape(name)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
            self.workflow,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(match, f"missing {name} job")
        return match.group("body")  # type: ignore[union-attr]

    def test_tag_release_is_main_only_and_catalog_is_presynced(self) -> None:
        preflight = self.job("release-preflight")
        self.assertIn("needs: version-contract", preflight)
        self.assertIn('tag_commit="$(git rev-parse "${GITHUB_REF}^{commit}")"', preflight)
        self.assertIn("git ls-remote --exit-code origin refs/heads/main", preflight)
        self.assertIn("kernel_blob=\"$(git hash-object --no-filters api/openapi/helm.openapi.yaml)\"", preflight)
        self.assertIn(
            "repos/Mindburn-Labs/contracts-catalog/contents/api/specs/helm.openapi.yaml?ref=main",
            preflight,
        )
        self.assertIn('if [ "$kernel_blob" != "$catalog_blob" ]; then', preflight)
        self.assertIn("needs: release-preflight", self.job("validate"))
        self.assertIn("release-preflight", self.job("github-release"))

    def test_release_never_creates_a_catalog_pr_or_bypasses_tap_policy(self) -> None:
        self.assertNotIn("downstream-fanout:", self.workflow)
        homebrew = self.job("homebrew")
        self.assertNotIn("--admin", homebrew)
        self.assertIn("--auto", homebrew)
        self.assertIn("--delete-branch", homebrew)
        self.assertIn("for attempt in $(seq 1 120); do", homebrew)
        self.assertIn('state="$(gh pr view "$pr"', homebrew)
        self.assertIn("MERGED) exit 0 ;;", homebrew)
        self.assertIn("CLOSED)", homebrew)
        self.assertIn("Timed out waiting for Homebrew PR", homebrew)


if __name__ == "__main__":
    unittest.main()
