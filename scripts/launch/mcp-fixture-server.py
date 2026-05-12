#!/usr/bin/env python3
"""Local stdio-style MCP fixture used by release smoke tests."""

from __future__ import annotations

import argparse
import json
import sys


TOOLS = [
    {
        "name": "local.echo",
        "description": "Echoes public fixture input without side effects.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
            "additionalProperties": False,
        },
    }
]


def emit(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
    sys.stdout.flush()


def self_test() -> None:
    emit({"status": "ok", "tools": TOOLS})


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            emit({"jsonrpc": "2.0", "error": {"code": -32700, "message": "parse error"}})
            continue
        method = request.get("method")
        request_id = request.get("id")
        if method == "initialize":
            emit({"jsonrpc": "2.0", "id": request_id, "result": {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "helm-local-fixture", "version": "1.0.0"}}})
        elif method == "tools/list":
            emit({"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}})
        else:
            emit({"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "method not found"}})


if __name__ == "__main__":
    main()
