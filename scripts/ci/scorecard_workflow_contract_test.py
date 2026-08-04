#!/usr/bin/env python3
"""Guard the trusted and untrusted OpenSSF Scorecard workflow lanes.

The lanes live in separate files because the OpenSSF results webapp
statically rejects a publishing workflow that defines any job beyond the
trusted scorecard job (observed as a 400 "workflow has a non-scorecard job
with id-token permissions" on every main push while both lanes shared
scorecard.yml).
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "scorecard.yml"
WORKFLOW_PR = ROOT / ".github" / "workflows" / "scorecard-pr.yml"
WORKFLOW_DOCS = ROOT / ".github" / "workflows" / "README.md"
BEST_PRACTICES = ROOT / "BEST_PRACTICES.md"
BEST_PRACTICES_MAP = ROOT / ".bestpractices.json"
NORMALIZER = ROOT / "scripts" / "ci" / "normalize_scorecard_sarif.py"

JOB_PATTERN = r"^  (?P<name>[A-Za-z0-9_-]+):\n"


def jobs_in(text: str) -> list[str]:
    in_jobs = text.split("\njobs:\n", 1)[1]
    return re.findall(JOB_PATTERN, in_jobs, re.MULTILINE)


class ScorecardWorkflowContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.trusted_workflow = WORKFLOW.read_text()
        cls.pr_workflow = WORKFLOW_PR.read_text()

    def job(self, source: str, name: str) -> str:
        match = re.search(
            rf"^  {re.escape(name)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
            source,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(match, f"missing {name} job")
        return match.group("body")  # type: ignore[union-attr]

    def test_pull_request_lane_is_read_only_and_artifact_only(self) -> None:
        analysis = self.job(self.pr_workflow, "pull-request-analysis")
        self.assertIn("if: github.event_name == 'pull_request'", analysis)
        self.assertIn("permissions:\n      contents: read\n      actions: read", analysis)
        self.assertNotIn("id-token:", analysis)
        self.assertNotIn("security-events:", analysis)
        self.assertIn("publish_results: false", analysis)
        self.assertIn("name: scorecard-pr-results", analysis)
        self.assertNotIn("upload-sarif", analysis)

        evidence = self.job(self.pr_workflow, "pull-request-evidence")
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

    def test_pull_request_workflow_never_publishes(self) -> None:
        self.assertNotIn("id-token:", self.pr_workflow)
        self.assertNotIn("publish_results: true", self.pr_workflow)
        self.assertIn("  pull_request:\n    branches: [main]", self.pr_workflow)

    def test_only_default_branch_and_schedule_runs_publish_sarif(self) -> None:
        self.assertIn("  push:\n    branches: [main]", self.trusted_workflow)
        trusted = self.job(self.trusted_workflow, "trusted-analysis")
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

    def test_publishing_workflow_defines_only_the_trusted_job(self) -> None:
        # The OpenSSF results webapp refuses to accept results from a
        # workflow file containing any job besides the scorecard job.
        self.assertEqual(jobs_in(self.trusted_workflow), ["trusted-analysis"])
        self.assertNotIn("pull_request", self.trusted_workflow.split("\njobs:\n", 1)[0])

    def test_removed_pr_sarif_normalizer_has_no_stale_references(self) -> None:
        self.assertFalse(NORMALIZER.exists())
        for path in (WORKFLOW_DOCS, BEST_PRACTICES, BEST_PRACTICES_MAP):
            self.assertNotIn("normalize_scorecard_sarif.py", path.read_text())


if __name__ == "__main__":
    unittest.main()
