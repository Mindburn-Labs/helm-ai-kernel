#!/usr/bin/env python3
"""Positive controls for gen_reason_codes.py (HELM-747 s2).

The check must accept the committed tree and reject each way the languages,
the proto and the registry can drift apart.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gen_reason_codes as gen  # noqa: E402


class ReasonCodeGenerationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        for rel in [gen.REGISTRY, gen.PROTO, *gen.OUTPUTS]:
            dst = self.tmp / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(gen.ROOT / rel, dst)

    def edit(self, rel: str, old: str, new: str) -> None:
        path = self.tmp / rel
        text = path.read_text(encoding="utf-8")
        self.assertIn(old, text)
        path.write_text(text.replace(old, new, 1), encoding="utf-8")

    def problems(self) -> list[str]:
        return gen.check(self.tmp)

    def test_committed_tree_is_in_sync(self) -> None:
        self.assertEqual(gen.check(gen.ROOT), [])

    def test_every_language_carries_every_code(self) -> None:
        codes = [c["code"] for c in gen.load_registry(gen.ROOT)]
        for rel, text in gen.render(gen.load_registry(gen.ROOT)).items():
            for code in codes:
                self.assertIn(f'"{code}"', text, f"{rel} lacks {code}")

    def test_hand_edited_output_fails(self) -> None:
        self.edit(gen.OUTPUTS[1], '"POLICY_VIOLATION"', '"POLICY_VIOLATED"')
        self.assertTrue(any("out of date" in p for p in self.problems()))

    def test_new_registry_code_without_regeneration_fails(self) -> None:
        registry = self.tmp / gen.REGISTRY
        data = json.loads(registry.read_text(encoding="utf-8"))
        data["codes"].append({**data["codes"][0], "code": "FIXTURE_NEW_CODE"})
        registry.write_text(json.dumps(data), encoding="utf-8")
        self.assertEqual(len([p for p in self.problems() if "out of date" in p]), len(gen.OUTPUTS))

    def test_proto_enum_value_outside_registry_fails(self) -> None:
        self.edit(gen.PROTO, "  REASON_CODE_PDP_ERROR = 6;\n", "  REASON_CODE_PDP_ERROR = 6;\n  REASON_CODE_NOT_REGISTERED = 99;\n")
        self.assertIn("helm.proto: enum value REASON_CODE_NOT_REGISTERED is not a registry code", self.problems())

    def test_closed_enum_field_without_string_fails(self) -> None:
        # The first `reason_code_text = 6` in helm.proto is PDPResponse's.
        self.edit(gen.PROTO, "  string reason_code_text = 6;\n", "")
        self.assertIn("helm.proto: message PDPResponse has a ReasonCode enum field but no string reason_code_text", self.problems())

    def test_invalid_registry_code_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            gen.render([{"code": "lower_case", "applies_to": ["DENY"], "description": "x"}])
        with self.assertRaises(ValueError):
            gen.render([{"code": "DUP", "applies_to": ["DENY"], "description": "x"}] * 2)


if __name__ == "__main__":
    unittest.main()
