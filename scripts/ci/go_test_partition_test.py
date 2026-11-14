#!/usr/bin/env python3
"""Check test dispatch with package inventories and failing discovery commands."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class GoTestPartitionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        scripts = self.root / "scripts/ci"
        scripts.mkdir(parents=True)
        for name in ("go_core_command_tests.sh", "go_module_tests.sh"):
            shutil.copyfile(ROOT / "scripts/ci" / name, scripts / name)
        for module in ("core", "sdk/go", "tools/example"):
            directory = self.root / module
            directory.mkdir(parents=True)
            (directory / "go.mod").write_text("module example.test/" + module + "\n")
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.record = self.root / "calls.jsonl"
        fake = self.bin / "go"
        fake.write_text("""#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
if args == ['list', '-m']:
    if os.environ.get('FAIL_MODULE'):
        sys.exit(int(os.environ['FAIL_MODULE']))
    print('example.test/core')
elif args == ['list', './...']:
    if os.environ.get('FAIL_LIST'):
        sys.exit(int(os.environ['FAIL_LIST']))
    print(os.environ['PACKAGE_INVENTORY'])
elif args and args[0] == 'test':
    with open(os.environ['CALL_RECORD'], 'a') as out:
        out.write(json.dumps({'cwd': str(Path.cwd()), 'args': args, 'gowork': os.environ.get('GOWORK')}) + '\\n')
    sys.exit(int(os.environ.get('FAIL_TEST', '0')))
else:
    sys.exit(99)
""")
        fake.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        CALL_RECORD=str(self.record), PACKAGE_INVENTORY="\n".join([
                            "example.test/core/pkg/guardian", "example.test/core/pkg/store",
                            "example.test/core/cmd/receipt_verify", "example.test/core/cmd/receipt_verify/helper",
                            "example.test/core/cmd/helm-ai-kernel", "example.test/core/cmd/helm-gateway",
                            "example.test/core/integration/new_case", "example.test/core/pkg_extra",
                        ]))

    def run_script(self, name: str, **overrides: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["bash", str(self.root / "scripts/ci" / name)],
                              cwd=self.root, env=dict(self.env, **overrides),
                              text=True, capture_output=True, check=False)

    def calls(self) -> list[dict]:
        return [json.loads(line) for line in self.record.read_text().splitlines()] if self.record.exists() else []

    def test_new_command_and_integration_packages_are_dispatched_once(self) -> None:
        result = self.run_script("go_core_command_tests.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["args"], ["test", "example.test/core/cmd/helm-ai-kernel",
                         "example.test/core/cmd/helm-gateway", "example.test/core/integration/new_case",
                         "example.test/core/pkg_extra", "-count=1"])
        self.assertEqual(calls[0]["gowork"], "off")

    def test_discovery_failure_never_runs_a_partial_inventory(self) -> None:
        for variable in ("FAIL_MODULE", "FAIL_LIST"):
            with self.subTest(variable=variable):
                result = self.run_script("go_core_command_tests.sh", **{variable: "7"})
                self.assertEqual(result.returncode, 7)
                self.assertEqual(self.calls(), [])

    def test_empty_command_inventory_is_not_success(self) -> None:
        result = self.run_script("go_core_command_tests.sh", PACKAGE_INVENTORY="example.test/core/pkg/guardian")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_test_failure_propagates(self) -> None:
        result = self.run_script("go_core_command_tests.sh", FAIL_TEST="9")
        self.assertEqual(result.returncode, 9)

    def test_module_sweep_excludes_only_core(self) -> None:
        result = self.run_script("go_module_tests.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        self.assertEqual([Path(c["cwd"]).relative_to(self.root).as_posix() for c in calls],
                         ["sdk/go", "tools/example"])
        self.assertTrue(all(c["args"] == ["test", "./..."] and c["gowork"] == "off" for c in calls))


if __name__ == "__main__":
    unittest.main()
