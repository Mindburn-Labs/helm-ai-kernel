#!/usr/bin/env python3
"""gate_base_check.py must hold a change to the merge profile its base defines."""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parent / "gate_base_check.py"


def registry(merge: list[str], extra: list[str] | None = None) -> str:
    ids = sorted(set(merge) | set(extra or []))
    return json.dumps({
        "version": 1,
        "gates": [{"id": gate, "command": f"echo {gate}"} for gate in ids],
        "profiles": {"merge": {"gates": merge}},
    }, indent=2) + "\n"


class GateBaseCheckTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        (self.tmp / "scripts" / "ci").mkdir(parents=True)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "test")
        shutil.copy(SCRIPT, self.tmp / "scripts" / "ci" / "gate_base_check.py")
        self.write("scripts/ci/quality-gates.json", registry(["gosec", "go-test", "deadcode"]))
        self.base = self.commit("base")

    def git(self, *args: str) -> str:
        return subprocess.run(["git", *args], cwd=self.tmp, check=True, capture_output=True, text=True).stdout.strip()

    def write(self, path: str, text: str) -> None:
        (self.tmp / path).write_text(text, encoding="utf-8")

    def commit(self, message: str) -> str:
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD")

    def run_check(self, event: dict | None = None, event_name: str = "push", ci: bool = False) -> subprocess.CompletedProcess[str]:
        env = {k: v for k, v in os.environ.items() if not k.startswith(("GITHUB_", "GATE_BASE_CHECK_"))}
        if ci:
            env["GITHUB_ACTIONS"] = "true"
        if event is not None:
            path = self.tmp.parent / f"{self.tmp.name}-event.json"
            path.write_text(json.dumps(event), encoding="utf-8")
            self.addCleanup(path.unlink)
            env["GITHUB_EVENT_NAME"] = event_name
            env["GITHUB_EVENT_PATH"] = str(path)
        return subprocess.run([sys.executable, "scripts/ci/gate_base_check.py"], cwd=self.tmp, env=env,
                              capture_output=True, text=True)

    def test_an_unchanged_profile_passes(self) -> None:
        result = self.run_check({"before": self.base})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS", result.stdout)

    def test_dropping_a_base_gate_fails(self) -> None:
        self.write("scripts/ci/quality-gates.json", registry(["go-test", "deadcode"], extra=["gosec"]))
        self.commit("drop gosec from merge")
        result = self.run_check({"before": self.base})
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("merge gate gosec", result.stdout)

    def test_deleting_a_base_gate_outright_fails(self) -> None:
        self.write("scripts/ci/quality-gates.json", registry(["go-test", "deadcode"]))
        self.commit("delete gosec")
        self.assertEqual(self.run_check({"before": self.base}).returncode, 1)

    def test_an_acknowledged_removal_passes_and_is_reported(self) -> None:
        self.write("scripts/ci/quality-gates.json", registry(["go-test", "deadcode"]))
        self.write("scripts/ci/gate-removals.json", json.dumps(
            {"removals": [{"gate": "gosec", "reason": "replaced by a stricter scanner"}]}))
        self.commit("drop gosec with a reason")
        result = self.run_check({"before": self.base})
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("replaced by a stricter scanner", result.stdout)

    def test_acknowledging_a_gate_that_still_runs_fails(self) -> None:
        self.write("scripts/ci/gate-removals.json", json.dumps(
            {"removals": [{"gate": "gosec", "reason": "pre-approved"}]}))
        self.commit("acknowledge ahead of time")
        result = self.run_check({"before": self.base})
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("still runs", result.stdout)

    def test_an_acknowledgement_without_a_reason_fails(self) -> None:
        self.write("scripts/ci/quality-gates.json", registry(["go-test", "deadcode"]))
        self.write("scripts/ci/gate-removals.json", json.dumps({"removals": [{"gate": "gosec"}]}))
        self.commit("no reason")
        self.assertEqual(self.run_check({"before": self.base}).returncode, 1)

    def test_the_merge_group_base_comes_from_the_event(self) -> None:
        self.write("scripts/ci/quality-gates.json", registry(["go-test", "deadcode"]))
        self.commit("drop gosec")
        result = self.run_check({"merge_group": {"base_sha": self.base}}, event_name="merge_group")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("merge_group.base_sha", result.stdout)

    def test_the_base_copy_of_the_checker_judges_the_change(self) -> None:
        # The base carries a checker that always fails; a head copy that passes
        # everything must not replace it.
        self.write("scripts/ci/gate_base_check.py", "import sys\nprint('base checker ran')\nsys.exit(7)\n")
        strict = self.commit("base checker")
        shutil.copy(SCRIPT, self.tmp / "scripts" / "ci" / "gate_base_check.py")
        self.commit("head checker")
        result = self.run_check({"before": strict})
        self.assertEqual(result.returncode, 7, result.stdout)
        self.assertIn("base checker ran", result.stdout)

    def test_the_real_base_copy_judges_an_edited_checker(self) -> None:
        # The base copy runs from standard input and must still find the
        # repository: a comment-only edit passes, a dropped gate fails.
        checker = self.tmp / "scripts" / "ci" / "gate_base_check.py"
        checker.write_text(checker.read_text(encoding="utf-8") + "\n# edited in this change\n", encoding="utf-8")
        self.commit("edit the checker")
        result = self.run_check({"before": self.base})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("running the base commit's copy", result.stdout)
        self.assertIn("PASS", result.stdout)

    def test_the_real_base_copy_fails_a_dropped_gate_in_ci(self) -> None:
        checker = self.tmp / "scripts" / "ci" / "gate_base_check.py"
        checker.write_text(checker.read_text(encoding="utf-8") + "\n# edited in this change\n", encoding="utf-8")
        self.write("scripts/ci/quality-gates.json", registry(["go-test", "deadcode"]))
        self.commit("edit the checker and drop gosec")
        result = self.run_check({"merge_group": {"base_sha": self.base}}, event_name="merge_group", ci=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("running the base commit's copy", result.stdout)
        self.assertIn("merge gate gosec", result.stdout)

    def test_a_local_run_without_a_base_reports_not_run(self) -> None:
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("NOT RUN", result.stdout)

    def test_ci_without_a_base_fails(self) -> None:
        result = self.run_check({"merge_group": {}}, event_name="merge_group", ci=True)
        self.assertEqual(result.returncode, 2, result.stdout)

    def test_ci_with_a_base_commit_missing_from_the_checkout_fails(self) -> None:
        # A shallow checkout must not read as a base that defines no gate.
        missing = "0123456789abcdef0123456789abcdef01234567"
        self.write("scripts/ci/quality-gates.json", registry(["go-test", "deadcode"]))
        self.commit("drop gosec")
        result = self.run_check({"merge_group": {"base_sha": missing}}, event_name="merge_group", ci=True)
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("not in this checkout", result.stdout)

    def test_a_local_run_with_a_missing_base_commit_reports_not_run(self) -> None:
        result = self.run_check({"before": "0123456789abcdef0123456789abcdef01234567"})
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("NOT RUN", result.stdout)


if __name__ == "__main__":
    unittest.main()
