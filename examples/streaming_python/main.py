#!/usr/bin/env python3
"""
HELM Streaming Governance Example (Python)

Demonstrates token-by-token SSE streaming through HELM's governed proxy.
Every streamed completion is governed: the Guardian pipeline evaluates the
request before forwarding, and the response is streamed to the client while
HELM captures the full output for receipt generation.

Prerequisites:
    pip install openai
    helm proxy --upstream https://api.openai.com/v1 &

Usage:
    export OPENAI_API_KEY=sk-...
    python main.py
"""
import os
import sys
import time

from openai import OpenAI, OpenAIError


def streaming_chat(client: OpenAI, prompt: str) -> str:
    """Send a streaming chat completion through the HELM governed proxy.

    Returns the assembled response text.
    """
    stream = client.chat.completions.create(
        model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": prompt},
        ],
        stream=True,
    )

    full_response = ""
    for chunk in stream:
        if chunk.choices and chunk.choices[0].delta.content:
            token = chunk.choices[0].delta.content
            print(token, end="", flush=True)
            full_response += token

    print()  # newline after streamed output
    return full_response


def streaming_with_tools(client: OpenAI) -> str:
    """Demonstrate streaming with tool definitions (governed by HELM).

    When tools are present, HELM evaluates whether the tool is permitted
    by the active policy before forwarding the request upstream.
    """
    stream = client.chat.completions.create(
        model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        messages=[
            {"role": "user", "content": "What is the weather in London?"},
        ],
        tools=[
            {
                "type": "function",
                "function": {
                    "name": "get_weather",
                    "description": "Get current weather for a location",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "location": {"type": "string", "description": "City name"},
                        },
                        "required": ["location"],
                    },
                },
            }
        ],
        stream=True,
    )

    full_response = ""
    tool_calls = []
    for chunk in stream:
        if not chunk.choices:
            continue
        delta = chunk.choices[0].delta
        if delta.content:
            print(delta.content, end="", flush=True)
            full_response += delta.content
        if delta.tool_calls:
            for tc in delta.tool_calls:
                tool_calls.append(tc)

    print()
    if tool_calls:
        print(f"  Tool calls requested: {len(tool_calls)}")
    return full_response


def main() -> None:
    proxy_url = os.getenv("HELM_PROXY_URL", "http://localhost:9090/v1")
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("Error: OPENAI_API_KEY is not set.", file=sys.stderr)
        print("Usage: export OPENAI_API_KEY=sk-... && python main.py", file=sys.stderr)
        sys.exit(1)

    # Point the OpenAI client at the HELM proxy
    client = OpenAI(base_url=proxy_url, api_key=api_key)

    print("=" * 60)
    print("HELM Streaming Governance Example")
    print(f"Proxy: {proxy_url}")
    print("=" * 60)

    # --- Example 1: Basic streaming ---
    print("\n--- Example 1: Basic Streaming ---\n")
    start = time.monotonic()
    try:
        response = streaming_chat(client, "Explain what a proof graph is in 3 sentences.")
        elapsed = time.monotonic() - start
        print(f"\n  Characters: {len(response)}")
        print(f"  Time: {elapsed:.2f}s")
    except OpenAIError as e:
        print(f"\n  Denied or error: {e}")

    # --- Example 2: Streaming with tool calls ---
    print("\n--- Example 2: Streaming with Tool Calls ---\n")
    try:
        streaming_with_tools(client)
    except OpenAIError as e:
        print(f"\n  Denied or error: {e}")
        print("  (This is expected if the tool is not in the HELM allowlist)")

    # --- Governance artifacts ---
    print("\n--- Governance Artifacts ---")
    print()
    print("After streaming, HELM has generated:")
    print("  1. DecisionRecord  - Signed ALLOW/DENY verdict for the request")
    print("  2. Receipt         - Signed binding of input hash -> output hash")
    print("  3. ProofGraph node - Causal DAG entry linking decision to receipt")
    print()
    print("Export evidence:  helm export --evidence ./data/evidence")
    print("Verify receipts:  helm verify ./data/evidence")


if __name__ == "__main__":
    main()
