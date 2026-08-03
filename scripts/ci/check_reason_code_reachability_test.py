#!/usr/bin/env python3
"""Negative coverage for the reason-code reachability gate.

The gate used to count any line containing `contracts.<Ident>` as an emission,
so a reason code referenced only in a comment, a string literal, or a longer
prefixed identifier silently passed as reachable. These tests run the real
checker against synthetic trees where the only reference is non-code, and
assert the gate still fails — plus the two shapes that must pass.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

CHECKER = pathlib.Path(__file__).resolve().parent / "check_reason_code_reachability.py"

VERDICT_GO = """package contracts

type ReasonCode string

const (
	ReasonEmitted   ReasonCode = "demo/emitted"
	ReasonDocumented ReasonCode = "demo/documented"
)
"""


class ReasonCodeReachabilityTest(unittest.TestCase):
    def run_gate(self, sources: dict[str, str]) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "scripts" / "ci").mkdir(parents=True)
            (root / "core" / "pkg" / "contracts").mkdir(parents=True)
            shutil.copy(CHECKER, root / "scripts" / "ci" / CHECKER.name)
            (root / "core" / "pkg" / "contracts" / "verdict.go").write_text(VERDICT_GO, encoding="utf-8")
            for rel, content in sources.items():
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(root / "scripts" / "ci" / CHECKER.name)],
                capture_output=True,
                text=True,
            )

    def test_comment_only_reference_does_not_count(self):
        result = self.run_gate({
            "core/pkg/kernel/x.go": "package kernel\n\n// ReasonDocumented is returned on stale assumptions.\nvar A = 1\n",
            "core/pkg/kernel/y.go": "package kernel\n\nvar B = contracts.ReasonEmitted\n",
        })
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("ReasonDocumented", result.stdout)

    def test_string_literal_reference_does_not_count(self):
        result = self.run_gate({
            "core/pkg/kernel/x.go": 'package kernel\n\nvar Msg = "contracts.ReasonDocumented happened"\nvar A = contracts.ReasonEmitted\n',
        })
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_prefixed_identifier_does_not_count(self):
        result = self.run_gate({
            "core/pkg/kernel/x.go": "package kernel\n\nvar A = contracts.ReasonEmitted\nvar B = contracts.ReasonDocumentedExtra\n",
        })
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("ReasonDocumented", result.stdout)

    def test_qualified_reference_counts(self):
        result = self.run_gate({
            "core/pkg/kernel/x.go": "package kernel\n\nvar A = contracts.ReasonEmitted\nvar B = contracts.ReasonDocumented\n",
        })
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_bare_reference_inside_contracts_counts(self):
        result = self.run_gate({
            "core/pkg/kernel/x.go": "package kernel\n\nvar A = contracts.ReasonEmitted\n",
            "core/pkg/contracts/other.go": "package contracts\n\nvar B = ReasonDocumented\n",
        })
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
