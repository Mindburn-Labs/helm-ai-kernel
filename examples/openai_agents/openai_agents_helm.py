"""
OpenAI Agents SDK + HELM Integration Example

Routes OpenAI agent API calls through a HELM-governed proxy,
producing cryptographic receipts for every tool call and response.

Prerequisites:
    pip install openai helm

Environment:
    HELM_PROXY_URL  - HELM proxy URL (default: http://localhost:8080)
    OPENAI_API_KEY  - OpenAI API key (forwarded by proxy)
"""

import os
import json
from openai import OpenAI


# --- Configuration ---
HELM_PROXY_URL = os.getenv("HELM_PROXY_URL", "http://localhost:8080")


def create_helm_client():
    """Create an OpenAI client that routes through HELM proxy."""
    return OpenAI(
        base_url=f"{HELM_PROXY_URL}/v1",
        # HELM proxy intercepts all requests, adds governance, forwards to OpenAI
        default_headers={
            "X-Helm-Session": "openai-agents-example",
            "X-Helm-Principal": "agent:openai-sdk",
        },
    )


# --- Tool Definitions ---
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "search_documents",
            "description": "Search internal documents for relevant information",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                    "limit": {"type": "integer", "description": "Max results", "default": 5},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "send_email",
            "description": "Send an email to a recipient",
            "parameters": {
                "type": "object",
                "properties": {
                    "to": {"type": "string", "description": "Recipient email"},
                    "subject": {"type": "string", "description": "Email subject"},
                    "body": {"type": "string", "description": "Email body"},
                },
                "required": ["to", "subject", "body"],
            },
        },
    },
]


def handle_tool_call(name: str, args: dict) -> str:
    """Handle tool calls (stub implementations)."""
    if name == "search_documents":
        return json.dumps({
            "results": [
                {"title": "Q4 Revenue Report", "snippet": "Revenue increased 23% YoY..."},
                {"title": "Product Roadmap", "snippet": "Key initiatives for Q1..."},
            ]
        })
    elif name == "send_email":
        print(f"  📧 [STUB] Would send email to {args['to']}: {args['subject']}")
        return json.dumps({"status": "sent", "message_id": "msg-stub-001"})
    return json.dumps({"error": "unknown tool"})


def run_agent(user_message: str):
    """Run a single agent turn with tool use through HELM proxy."""
    client = create_helm_client()

    messages = [
        {"role": "system", "content": "You are a helpful assistant. Use tools when needed."},
        {"role": "user", "content": user_message},
    ]

    print(f"🤖 Agent processing: {user_message}")
    print(f"   Routing through HELM proxy at {HELM_PROXY_URL}")

    # First API call — may result in tool calls
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=messages,
        tools=TOOLS,
        tool_choice="auto",
    )

    # Handle tool calls loop
    while response.choices[0].message.tool_calls:
        tool_calls = response.choices[0].message.tool_calls
        messages.append(response.choices[0].message)

        for tc in tool_calls:
            print(f"  🔧 Tool call: {tc.function.name}")
            result = handle_tool_call(tc.function.name, json.loads(tc.function.arguments))
            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": result,
            })

        # Follow-up call with tool results — also goes through HELM
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            tools=TOOLS,
        )

    final = response.choices[0].message.content
    print(f"\n✅ Agent response: {final[:150]}...")
    return final


# --- Main ---
if __name__ == "__main__":
    print("🛡️ OpenAI Agents SDK + HELM Integration Example")
    print()

    # Example 1: Simple query (no tool use expected)
    run_agent("What is the capital of France?")

    print("\n" + "=" * 60 + "\n")

    # Example 2: Query that triggers tool use
    run_agent("Search our documents for the Q4 revenue report and summarize the key findings.")

    print(f"\n📦 EvidencePack produced by HELM proxy")
    print(f"   Export: helm export --session openai-agents-example")
    print(f"   Verify: helm verify --bundle ./evidencepack --json")
