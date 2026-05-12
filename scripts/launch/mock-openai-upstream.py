#!/usr/bin/env python3
"""Local OpenAI-compatible mock upstream for release smoke tests."""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    server_version = "helm-mock-openai/1.0"

    def log_message(self, fmt: str, *args: object) -> None:
        return

    def _json(self, status: int, payload: dict) -> None:
        data = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path in {"/health", "/healthz"}:
            self._json(200, {"status": "ok", "mode": "local-mock"})
            return
        self._json(404, {"error": {"message": "not found"}})

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0") or "0")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            request = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            self._json(400, {"error": {"message": "invalid json"}})
            return

        if self.path not in {"/v1/chat/completions", "/chat/completions"}:
            self._json(404, {"error": {"message": "unsupported endpoint"}})
            return

        model = request.get("model") or "helm-local-mock"
        self._json(
            200,
            {
                "id": "chatcmpl-helm-local-fixture",
                "object": "chat.completion",
                "created": 1778587200,
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {
                            "role": "assistant",
                            "content": "local fixture response",
                        },
                    }
                ],
                "usage": {
                    "prompt_tokens": 7,
                    "completion_tokens": 3,
                    "total_tokens": 10,
                },
            },
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=19090)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
