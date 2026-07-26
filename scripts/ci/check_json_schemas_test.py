#!/usr/bin/env python3
"""Guard the one branch that cannot prove itself: absent jsonschema must fail.

The gate previously caught the ImportError and reported a parse-only pass, so a
schema that stopped matching its own registry stayed green for as long as the
package was missing from CI — which was always (HELM-374). Reintroducing that
`except ImportError: return None` would look harmless in review and would be
invisible in a green run, so it is asserted here instead.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile
import unittest

CHECKER = pathlib.Path(__file__).resolve().parent / "check_json_schemas.py"


class JsonSchemaGateFailsClosedTest(unittest.TestCase):
    def test_missing_jsonschema_is_an_error_not_a_downgraded_pass(self) -> None:
        with tempfile.TemporaryDirectory() as shadow:
            # Shadowing the real package is the only faithful way to reproduce a
            # runner that never installed it.
            (pathlib.Path(shadow) / "jsonschema.py").write_text(
                'raise ImportError("simulated missing package")\n', encoding="utf-8"
            )
            result = subprocess.run(
                [sys.executable, str(CHECKER)],
                capture_output=True,
                text=True,
                env={"PATH": "/usr/bin:/bin", "PYTHONPATH": shadow},
            )

        self.assertEqual(result.returncode, 1, f"expected failure, got:\n{result.stdout}{result.stderr}")
        self.assertIn("jsonschema package is missing", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
