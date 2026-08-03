#!/usr/bin/env python3
"""Guard the trusted and untrusted OpenSSF Scorecard workflow lanes."""
from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "scorecard.yml"
WORKFLOW_DOCS = ROOT / ".github" / "workflows" / "README.md"
BEST_PRACTICES = ROOT / "BEST_PRACTICES.md"
BEST_PRACTICES_MAP = ROOT / ".bestpractices.json"
NORMALIZER = ROOT / "scripts" / "ci" / "normalize_scorecard_sarif.py"


class ScorecardWorkflowContractTest(unittest.TestCase):
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

    def test_pull_request_lane_is_read_only_and_artifact_only(self) -> None:
        analysis = self.job("pull-request-analysis")
        self.assertIn("if: github.event_name == 'pull_request'", analysis)
        self.assertIn("permissions:\n      contents: read\n      actions: read", analysis)
        self.assertNotIn("id-token:", analysis)
        self.assertNotIn("security-events:", analysis)
        self.assertIn("publish_results: false", analysis)
        self.assertIn("name: scorecard-pr-results", analysis)
        self.assertNotIn("upload-sarif", analysis)

        evidence = self.job("pull-request-evidence")
        self.assertIn("name: Upload pull request SARIF", evidence)
        self.assertIn("if: github.event_name == 'pull_request'", evidence)
        self.assertIn("needs: pull-request-analysis", evidence)
        self.assertIn("permissions:\n      contents: read", evidence)
        self.assertNotIn("actions:", evidence)
        self.assertNotIn("id-token:", evidence)
        self.assertNotIn("security-events:", evidence)
        self.assertIn("name: scorecard-pr-results", evidence)
        self.assertIn("test -s scorecard-pr-results/results.sarif", evidence)
        self.assertNotIn("upload-sarif", evidence)

    def test_only_default_branch_and_schedule_runs_publish_sarif(self) -> None:
        self.assertIn("  push:\n    branches: [main]", self.workflow)
        trusted = self.job("trusted-analysis")
        self.assertIn(
            "if: github.event_name == 'push' || github.event_name == 'schedule'",
            trusted,
        )
        self.assertIn("contents: read", trusted)
        self.assertIn("actions: read", trusted)
        self.assertIn("id-token: write", trusted)
        self.assertIn("security-events: write", trusted)
        self.assertIn("publish_results: true", trusted)
        self.assertIn("github/codeql-action/upload-sarif", trusted)

    def test_removed_pr_sarif_normalizer_has_no_stale_references(self) -> None:
        self.assertFalse(NORMALIZER.exists())
        for path in (WORKFLOW_DOCS, BEST_PRACTICES, BEST_PRACTICES_MAP):
            self.assertNotIn("normalize_scorecard_sarif.py", path.read_text())


if __name__ == "__main__":
    unittest.main()
