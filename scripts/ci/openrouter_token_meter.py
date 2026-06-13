#!/usr/bin/env python3
"""Create redacted OpenRouter token evidence for a CI run.

The API key is read from OPENROUTER_API_KEY and is never printed. The probe
uses the same key type as live completions and records token usage from the
current completion response, avoiding account-level activity windows that are
not tied to the running workflow.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


OPENROUTER_CHAT_COMPLETIONS = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_GENERATION = "https://openrouter.ai/api/v1/generation"
DEFAULT_MODEL = "openai/gpt-4o-mini"


def read_key() -> str:
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key:
        raise SystemExit("OPENROUTER_API_KEY not set")
    return key


def openrouter_headers(key: str) -> dict[str, str]:
    return {
        "Authorization": "Bearer " + key,
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/Mindburn-Labs/helm-ai-kernel",
        "X-Title": "HELM AI Kernel CI Token Probe",
    }


def request_json(url: str, *, key: str, method: str = "GET", body: object | None = None) -> dict[str, Any]:
    data = None
    if body is not None:
        data = json.dumps(body, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=openrouter_headers(key), method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise SystemExit(f"OpenRouter HTTP {exc.code}: {exc.reason}; {detail}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"OpenRouter unreachable: {exc.reason}") from exc
    if not isinstance(payload, dict):
        raise SystemExit("OpenRouter returned a non-object JSON payload")
    return payload


def as_int(value: object) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def usage_from_dict(payload: dict[str, Any]) -> tuple[int, int, int] | None:
    prompt = as_int(
        payload.get("prompt_tokens")
        or payload.get("promptTokens")
        or payload.get("input_tokens")
        or payload.get("inputTokens")
        or payload.get("tokens_prompt")
    )
    completion = as_int(
        payload.get("completion_tokens")
        or payload.get("completionTokens")
        or payload.get("output_tokens")
        or payload.get("outputTokens")
        or payload.get("tokens_completion")
    )
    total = as_int(payload.get("total_tokens") or payload.get("totalTokens") or payload.get("tokens_total"))
    if not total and (prompt or completion):
        total = prompt + completion
    if prompt or completion or total:
        return prompt, completion, total
    return None


def find_usage(payload: object) -> tuple[int, int, int] | None:
    if isinstance(payload, dict):
        direct = usage_from_dict(payload)
        if direct is not None:
            return direct
        for value in payload.values():
            nested = find_usage(value)
            if nested is not None:
                return nested
    elif isinstance(payload, list):
        for item in payload:
            nested = find_usage(item)
            if nested is not None:
                return nested
    return None


def redact_completion(payload: dict[str, Any]) -> dict[str, object]:
    choices = payload.get("choices")
    usage = payload.get("usage")
    return {
        "id": payload.get("id"),
        "model": payload.get("model"),
        "usage": usage if isinstance(usage, dict) else None,
        "choices_count": len(choices) if isinstance(choices, list) else 0,
        "object": payload.get("object"),
    }


def write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def append_jsonl(path: Path, payload: object) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")


def write_report(out_dir: Path, record: dict[str, object]) -> None:
    lines = [
        "# OpenRouter Token Evidence",
        "",
        f"- Run: `{record['run']}`",
        f"- Case: `{record['case']}`",
        f"- Model: `{record['model']}`",
        f"- Total: `{record['total_tokens']}` tokens",
        f"- Prompt: `{record['prompt_tokens']}`",
        f"- Completion: `{record['completion_tokens']}`",
        f"- Accuracy: `{record['accuracy']}`",
        "",
        "Source: current OpenRouter completion response usage for this CI run.",
        "The API key value is not logged or written.",
    ]
    (out_dir / "tokens-report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (out_dir / "tokens-logs.md").write_text(
        "OpenRouter completion usage: "
        f"model={record['model']} "
        f"prompt={record['prompt_tokens']} "
        f"completion={record['completion_tokens']} "
        f"total={record['total_tokens']} "
        f"accuracy={record['accuracy']}\n",
        encoding="utf-8",
    )


def completion_probe(key: str, model: str, prompt: str, max_tokens: int) -> dict[str, Any]:
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
        "max_tokens": max_tokens,
    }
    return request_json(OPENROUTER_CHAT_COMPLETIONS, key=key, method="POST", body=payload)


def generation_usage(key: str, generation_id: object) -> tuple[int, int, int] | None:
    if not generation_id:
        return None
    query = urllib.parse.urlencode({"id": str(generation_id)})
    payload = request_json(f"{OPENROUTER_GENERATION}?{query}", key=key)
    return find_usage(payload)


def cmd_probe(args: argparse.Namespace) -> int:
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    key = read_key()

    completion = completion_probe(key, args.model, args.prompt, args.max_tokens)
    write_json(out_dir / "openrouter-response-redacted.json", redact_completion(completion))

    usage = find_usage(completion)
    accuracy = "completion-response-usage"
    if usage is None:
        usage = generation_usage(key, completion.get("id"))
        accuracy = "generation-stats-usage"
    if usage is None:
        print("::error::OpenRouter response did not include token usage", file=sys.stderr)
        return 1

    prompt_tokens, completion_tokens, total_tokens = usage
    record = {
        "run": args.run,
        "case": args.case,
        "llm": True,
        "model": args.model,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
        "accuracy": accuracy,
    }
    append_jsonl(out_dir / "tokens.jsonl", record)
    write_report(out_dir, record)
    print(
        "[openrouter-token-meter] "
        f"{args.case}: model={args.model} prompt={prompt_tokens} "
        f"completion={completion_tokens} total={total_tokens}"
    )

    if total_tokens < args.min_total:
        print(
            f"::error::OpenRouter token usage below minimum: observed {total_tokens}, required {args.min_total}",
            file=sys.stderr,
        )
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    probe = sub.add_parser("probe")
    probe.add_argument("--run", required=True)
    probe.add_argument("--case", required=True)
    probe.add_argument("--out", required=True)
    probe.add_argument("--model", default=DEFAULT_MODEL)
    probe.add_argument("--prompt", default="Reply with exactly: ok")
    probe.add_argument("--max-tokens", type=int, default=4)
    probe.add_argument("--min-total", type=int, default=1)
    probe.set_defaults(func=cmd_probe)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
