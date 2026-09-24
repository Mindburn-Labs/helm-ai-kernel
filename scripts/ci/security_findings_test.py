#!/usr/bin/env python3
"""Known-good and known-bad inputs for the security gates' report handling."""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from collections import Counter

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from security_findings import (  # noqa: E402
    ReportError,
    compare,
    gitleaks_keys,
    gosec_keys,
    govulncheck_called,
    parse_allowlist,
)

SCRIPT = pathlib.Path(__file__).resolve().parent / "security_findings.py"


def gosec_issue(rule: str, filename: str, line: int, source: str) -> dict:
    return {
        "FromLinter": "gosec",
        "Text": f"{rule}: something risky",
        "Pos": {"Filename": filename, "Line": line},
        "SourceLines": [source],
    }


class KeysTest(unittest.TestCase):
    def test_gosec_key_ignores_line_numbers(self) -> None:
        a = gosec_keys({"Issues": [gosec_issue("G304", "/repo/core/pkg/a.go", 10, "os.ReadFile(p)")]}, "/repo")
        b = gosec_keys({"Issues": [gosec_issue("G304", "/repo/core/pkg/a.go", 99, "  os.ReadFile(p)  ")]}, "/repo")
        self.assertEqual(a, b)
        self.assertTrue(a[0].startswith("G304 core/pkg/a.go "))

    def test_gosec_key_changes_with_the_code(self) -> None:
        a = gosec_keys({"Issues": [gosec_issue("G304", "/repo/core/pkg/a.go", 10, "os.ReadFile(p)")]}, "/repo")
        b = gosec_keys({"Issues": [gosec_issue("G304", "/repo/core/pkg/a.go", 10, "os.ReadFile(q)")]}, "/repo")
        self.assertNotEqual(a, b)

    def test_gosec_taint_rules_are_left_out(self) -> None:
        issues = [gosec_issue("G703", "/repo/core/a.go", 1, "x"), gosec_issue("G204", "/repo/core/a.go", 2, "y")]
        self.assertEqual([k.split()[0] for k in gosec_keys({"Issues": issues}, "/repo")], ["G204"])

    def test_gosec_report_without_issues_field_is_an_error(self) -> None:
        with self.assertRaises(ReportError):
            gosec_keys({}, "/repo")

    def test_gitleaks_key_never_contains_the_secret(self) -> None:
        secret = "sk-or-v1-" + "ab" * 32
        keys = gitleaks_keys([{"RuleID": "openrouter-api-key", "File": "x.go", "Secret": secret}])
        self.assertEqual(len(keys), 1)
        self.assertNotIn(secret, keys[0])
        self.assertNotIn("abab", keys[0])

    def test_govulncheck_counts_only_called_symbols(self) -> None:
        stream = "".join(
            json.dumps(m)
            for m in (
                {"config": {"scanner_name": "govulncheck"}},
                {"finding": {"osv": "GO-1", "trace": [{"module": "m"}]}},
                {"finding": {"osv": "GO-2", "trace": [{"module": "m", "package": "m/p"}]}},
                {"finding": {"osv": "GO-3", "trace": [{"module": "m", "package": "m/p", "function": "F"}]}},
            )
        )
        self.assertEqual(govulncheck_called(stream), ["GO-3"])

    def test_govulncheck_empty_output_is_not_a_clean_scan(self) -> None:
        with self.assertRaises(ReportError):
            govulncheck_called("")


class CompareTest(unittest.TestCase):
    def test_same_findings_pass(self) -> None:
        self.assertEqual(compare(Counter(["a", "b"]), Counter(["b", "a"])), ([], []))

    def test_new_finding_fails(self) -> None:
        self.assertEqual(compare(Counter(["a"]), Counter(["a", "b"])), (["b"], []))

    def test_fixed_finding_must_leave_the_allowlist(self) -> None:
        self.assertEqual(compare(Counter(["a", "b"]), Counter(["a"])), ([], ["b"]))

    def test_duplicates_are_counted(self) -> None:
        self.assertEqual(compare(Counter(["a"]), Counter(["a", "a"])), (["a"], []))

    def test_allowlist_comments_are_ignored(self) -> None:
        self.assertEqual(parse_allowlist("# header\n\na\na\n"), Counter({"a": 2}))

    def test_command_line_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            allow = pathlib.Path(tmp, "allow.txt")
            allow.write_text("# frozen\nG304 core/a.go 0123456789ab\n")
            same = pathlib.Path(tmp, "same.txt")
            same.write_text("G304 core/a.go 0123456789ab\n")
            grown = pathlib.Path(tmp, "grown.txt")
            grown.write_text("G304 core/a.go 0123456789ab\nG204 core/b.go ba9876543210\n")
            run = lambda *a: subprocess.run([sys.executable, str(SCRIPT), *a], capture_output=True, text=True)  # noqa: E731
            self.assertEqual(run("compare", str(allow), str(same)).returncode, 0)
            result = run("compare", str(allow), str(grown))
            self.assertEqual(result.returncode, 1)
            self.assertIn("new finding", result.stdout)
            self.assertEqual(run("gosec-keys", str(same), "core").returncode, 2)  # not JSON


if __name__ == "__main__":
    unittest.main()
