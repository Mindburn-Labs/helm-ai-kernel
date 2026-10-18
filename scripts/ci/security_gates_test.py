#!/usr/bin/env python3
"""Exercise the govulncheck gate across its process and report boundaries."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parent

FAKE_GO = r'''#!/usr/bin/env python3
import os
import sys

args = sys.argv[1:]
if args[:1] == ["env"]:
    values = {"GOVERSION": "go1.26.9", "GOOS": "linux", "GOARCH": "amd64"}
    for name in args[1:]:
        print(values[name])
elif args[:2] == ["version", "-m"]:
    print(f"{args[2]}: {os.environ.get('TOOL_BUILD_VERSION', 'go1.26.9')}")
    print("\tpath\tgolang.org/x/vuln/cmd/govulncheck")
    print("\tmod\tgolang.org/x/vuln\tv1.3.0\th1:fixture")
    print("\tbuild\tGOOS=linux")
    print("\tbuild\tGOARCH=amd64")
elif args[:2] == ["mod", "tidy"]:
    pass
else:
    sys.exit(f"unexpected Go command: {args}")
'''

FAKE_SCANNER = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

case = os.environ["SCAN_CASE"]
control = Path.cwd().name == "govulncheck-control"
emit = lambda message: print(json.dumps(message), flush=True)
emit({"config": {"protocol_version": "v1.0.0", "scanner_name": "govulncheck",
                 "scanner_version": "v1.3.0", "scan_mode": "source", "scan_level": "symbol"}})
if case == "config-only" and not control:
    sys.exit(0)
if (case == "failed" or case == "one-of-two-failed" and Path.cwd().name == "broken") and not control:
    print("synthetic package load failure", file=sys.stderr)
    sys.exit(1)
if case == "truncated" and not control:
    print('{"SBOM":', end="", flush=True)
    sys.exit(0)
emit({"SBOM": {"go_version": "go1.26.9", "roots": ["example.com/fixture"],
               "modules": [{"path": "example.com/fixture"}]}})
emit({"progress": {"message": "Checking the code against the vulnerabilities..."}})
if control:
    if case != "bad-control":
        emit({"finding": {"osv": "GO-2021-0113", "trace": [{"module": "golang.org/x/text", "function": "Parse"}]}})
elif case == "called":
    emit({"finding": {"osv": "GO-TEST-CALLED", "trace": [{"module": "example.com/fixture", "function": "Vulnerable"}]}})
elif case == "module-only":
    emit({"finding": {"osv": "GO-TEST-IMPORTED", "trace": [{"module": "example.com/fixture"}]}})
elif case == "malformed-finding":
    emit({"finding": {"osv": "GO-TEST-MALFORMED", "trace": []}})
if case == "late-failed" and not control:
    print("synthetic late scanner failure", file=sys.stderr)
    sys.exit(1)
'''


class GovulncheckGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.repo = root / "repo"
        (self.repo / "scripts/ci").mkdir(parents=True)
        (self.repo / "app").mkdir()
        (self.repo / "app/go.mod").write_text("module example.com/fixture\n\ngo 1.26.9\n")
        (self.repo / "app/main.go").write_text("package main\nfunc main() {}\n")
        for name in ("security_gates.sh", "security_findings.py"):
            shutil.copy2(SCRIPTS / name, self.repo / "scripts/ci" / name)
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "app/go.mod", "app/main.go"], check=True)

        fake_bin = root / "bin"
        fake_bin.mkdir()
        fake_go = fake_bin / "go"
        fake_go.write_text(FAKE_GO)
        fake_go.chmod(0o755)
        self.tools = root / "tools"
        for name in ("govulncheck-v1.3.0", "govulncheck-v1.3.0-go1.26.9-linux-amd64"):
            directory = self.tools / name
            directory.mkdir(parents=True)
            scanner = directory / "govulncheck"
            scanner.write_text(FAKE_SCANNER)
            scanner.chmod(0o755)
        self.path = f"{fake_bin}{os.pathsep}{os.environ['PATH']}"

    def run_gate(self, case: str, **extra_env: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update(PATH=self.path, HELM_CI_TOOLS=str(self.tools), SCAN_CASE=case)
        env.update(extra_env)
        return subprocess.run(
            ["bash", "scripts/ci/security_gates.sh", "govulncheck"],
            cwd=self.repo, env=env, text=True, capture_output=True, timeout=30,
        )

    def test_clean_scan_passes(self) -> None:
        result = self.run_gate("clean")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_imported_but_uncalled_vulnerability_passes(self) -> None:
        result = self.run_gate("module-only")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_called_vulnerability_fails(self) -> None:
        result = self.run_gate("called")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("GO-TEST-CALLED", result.stdout + result.stderr)

    def test_package_load_failure_with_config_report_fails(self) -> None:
        result = self.run_gate("failed")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("synthetic package load failure", result.stderr)

    def test_late_nonzero_exit_fails_despite_complete_report(self) -> None:
        result = self.run_gate("late-failed")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_one_failed_module_fails_the_entire_gate(self) -> None:
        broken = self.repo / "broken"
        broken.mkdir()
        (broken / "go.mod").write_text("module example.com/broken\n\ngo 1.26.9\n")
        (broken / "main.go").write_text("package main\nfunc main() {}\n")
        subprocess.run(["git", "-C", str(self.repo), "add", "broken/go.mod", "broken/main.go"], check=True)
        result = self.run_gate("one-of-two-failed")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("1/2 module(s) completed", result.stdout)

    def test_config_only_zero_exit_is_incomplete(self) -> None:
        result = self.run_gate("config-only")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_truncated_json_fails(self) -> None:
        result = self.run_gate("truncated")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_malformed_finding_fails(self) -> None:
        result = self.run_gate("malformed-finding")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_positive_control_must_detect_planted_vulnerability(self) -> None:
        result = self.run_gate("bad-control")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_stale_go_build_cannot_be_reused(self) -> None:
        result = self.run_gate("clean", TOOL_BUILD_VERSION="go1.25.13")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
