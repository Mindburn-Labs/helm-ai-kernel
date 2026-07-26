#!/usr/bin/env python3
"""Guard the one branch that cannot prove itself: absent jsonschema must fail.

The gate previously caught the ImportError and reported a parse-only pass, so a
schema that stopped matching its own registry stayed green for as long as the
package was missing from CI — which was always (HELM-374). Reintroducing that
`except ImportError: return None` would look harmless in review and would be
invisible in a green run, so it is asserted here instead.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

CHECKER = pathlib.Path(__file__).resolve().parent / "check_json_schemas.py"


class JsonSchemaGateFailsClosedTest(unittest.TestCase):
    def run_with_broken_jsonschema(self, shadow: pathlib.Path) -> subprocess.CompletedProcess[str]:
        # Inherit the environment and override only PYTHONPATH: a stripped env
        # loses locale and cert vars and makes this flaky on some runners.
        return subprocess.run(
            [sys.executable, str(CHECKER)],
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": str(shadow)},
        )

    def assert_controlled_failure(self, result: subprocess.CompletedProcess[str]) -> None:
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 1, f"expected failure, got:\n{output}")
        self.assertIn(".github/schema-requirements.txt", output, "the failure must say how to fix it")

    def test_absent_package_is_an_error_not_a_downgraded_pass(self) -> None:
        with tempfile.TemporaryDirectory() as shadow:
            # Shadowing the real package is the only faithful way to reproduce a
            # runner that never installed it.
            (pathlib.Path(shadow) / "jsonschema.py").write_text(
                'raise ImportError("simulated absent package")\n', encoding="utf-8"
            )
            self.assert_controlled_failure(self.run_with_broken_jsonschema(pathlib.Path(shadow)))

    def test_partial_install_fails_before_the_first_schema_is_compiled(self) -> None:
        # Package imports, submodule does not. Checking only the package would
        # let this through and crash mid-walk with a traceback instead.
        with tempfile.TemporaryDirectory() as shadow:
            package = pathlib.Path(shadow) / "jsonschema"
            package.mkdir()
            (package / "__init__.py").write_text("", encoding="utf-8")
            (package / "validators.py").write_text(
                'raise ImportError("simulated partial install")\n', encoding="utf-8"
            )
            result = self.run_with_broken_jsonschema(pathlib.Path(shadow))

        self.assert_controlled_failure(result)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
