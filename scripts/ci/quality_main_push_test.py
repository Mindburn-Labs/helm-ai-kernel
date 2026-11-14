#!/usr/bin/env python3
"""A push to main skips the merge profile only for the exact sha a merge group gated."""

from __future__ import annotations

import os
import pathlib
import sys
import unittest
import unittest.mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import quality  # noqa: E402

SHA = "a" * 40


def env(**values: str) -> dict[str, str]:
    base = {k: v for k, v in os.environ.items() if not k.startswith(("GITHUB_", "HELM_GATED_"))}
    base.update(values)
    return base


class GatedByMergeGroupTest(unittest.TestCase):
    def gated(self, selection: str = "merge", **values: str) -> str | None:
        with unittest.mock.patch.dict(os.environ, env(**values), clear=True):
            return quality.gated_by_merge_group(selection)

    def test_push_with_the_recorded_run_for_this_sha_is_gated(self) -> None:
        self.assertEqual(self.gated(GITHUB_EVENT_NAME="push", GITHUB_SHA=SHA, HELM_GATED_SHA=SHA, HELM_GATED_BY_RUN="42"), "42")

    def test_every_other_case_runs_the_profile(self) -> None:
        cases = {
            "pull request": dict(GITHUB_EVENT_NAME="pull_request", GITHUB_SHA=SHA, HELM_GATED_SHA=SHA, HELM_GATED_BY_RUN="42"),
            "merge group": dict(GITHUB_EVENT_NAME="merge_group", GITHUB_SHA=SHA, HELM_GATED_SHA=SHA, HELM_GATED_BY_RUN="42"),
            "other sha": dict(GITHUB_EVENT_NAME="push", GITHUB_SHA=SHA, HELM_GATED_SHA="b" * 40, HELM_GATED_BY_RUN="42"),
            "no record": dict(GITHUB_EVENT_NAME="push", GITHUB_SHA=SHA),
            "bad run id": dict(GITHUB_EVENT_NAME="push", GITHUB_SHA=SHA, HELM_GATED_SHA=SHA, HELM_GATED_BY_RUN="42; true"),
            "local run": dict(),
        }
        for name, values in cases.items():
            with self.subTest(case=name):
                self.assertIsNone(self.gated(**values))

    def test_only_the_merge_profile_is_skipped(self) -> None:
        self.assertIsNone(self.gated("release", GITHUB_EVENT_NAME="push", GITHUB_SHA=SHA, HELM_GATED_SHA=SHA, HELM_GATED_BY_RUN="42"))


if __name__ == "__main__":
    unittest.main()
