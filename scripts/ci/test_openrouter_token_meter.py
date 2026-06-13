#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import io
import json
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path
from types import SimpleNamespace


SCRIPT = Path(__file__).with_name("openrouter_token_meter.py")
SPEC = importlib.util.spec_from_file_location("openrouter_token_meter", SCRIPT)
meter = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(meter)


class FakeResponse:
    def __init__(self, payload: object) -> None:
        self.payload = payload

    def __enter__(self) -> io.BytesIO:
        return io.BytesIO(json.dumps(self.payload).encode("utf-8"))

    def __exit__(self, *args: object) -> None:
        return None


class OpenRouterTokenMeterTests(unittest.TestCase):
    def test_find_usage_accepts_completion_response_usage(self) -> None:
        payload = {
            "id": "gen-1",
            "usage": {
                "prompt_tokens": 12,
                "completion_tokens": 3,
                "total_tokens": 15,
            },
        }
        self.assertEqual(meter.find_usage(payload), (12, 3, 15))

    def test_find_usage_accepts_generation_stats_shape(self) -> None:
        payload = {
            "data": {
                "tokens_prompt": 10,
                "tokens_completion": 4,
                "tokens_total": 14,
            },
        }
        self.assertEqual(meter.find_usage(payload), (10, 4, 14))

    def test_probe_writes_token_artifacts_from_current_response(self) -> None:
        response = {
            "id": "gen-1",
            "model": "openrouter/test",
            "object": "chat.completion",
            "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            "usage": {
                "prompt_tokens": 8,
                "completion_tokens": 2,
                "total_tokens": 10,
            },
        }

        with tempfile.TemporaryDirectory() as tmp:
            args = SimpleNamespace(
                run="run-1",
                case="helm-integration-openrouter-probe",
                out=tmp,
                model="openrouter/test",
                prompt="Reply ok",
                max_tokens=4,
                min_total=1,
            )
            with mock.patch.dict("os.environ", {"OPENROUTER_API_KEY": "sk-redacted"}), mock.patch(
                "urllib.request.urlopen", return_value=FakeResponse(response)
            ):
                self.assertEqual(meter.cmd_probe(args), 0)

            out = Path(tmp)
            self.assertIn('"total_tokens": 10', (out / "tokens.jsonl").read_text(encoding="utf-8"))
            self.assertIn("Total: `10` tokens", (out / "tokens-report.md").read_text(encoding="utf-8"))
            redacted = json.loads((out / "openrouter-response-redacted.json").read_text(encoding="utf-8"))
            self.assertEqual(redacted["id"], "gen-1")
            self.assertEqual(redacted["choices_count"], 1)
            self.assertNotIn("sk-redacted", json.dumps(redacted))


if __name__ == "__main__":
    unittest.main()
