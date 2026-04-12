# Examples

This directory contains runnable integration examples for SDK, agent frameworks, and OpenAI-compatible flows.

## 🚀 Agent Hardening Quickstarts

| Framework | What you get | Start here |
|-----------|-------------|------------|
| **DeerFlow** | Governed research pipeline with receipts | [`deerflow/`](deerflow/) |
| **OpenClaw** | Hardened agent actions with proof | [`openclaw/`](openclaw/) |

## SDK Examples

| Example | Language | Description |
|---------|----------|-------------|
| [`go_client`](go_client/) | Go | HELM Go SDK integration |
| [`java_client`](java_client/) | Java | HELM Java SDK integration |
| [`rust_client`](rust_client/) | Rust | HELM Rust SDK integration |

## Framework Integrations

| Example | Framework | Description |
|---------|-----------|-------------|
| [`langgraph`](langgraph/) | LangGraph | Governed LangGraph pipeline |
| [`mcp_client`](mcp_client/) | MCP | Governed MCP tool calls |
| [`openai_agents`](openai_agents/) | OpenAI Agents SDK | Governed OpenAI agents |
| [`ms_agent_framework`](ms_agent_framework/) | Microsoft Agent Framework | Governed MS agents |
| [`orchestration`](orchestration/) | Multi-agent | Orchestrated governed agents |

## Proxy Integrations (base_url rewrite)

| Example | Language | Description |
|---------|----------|-------------|
| [`js_openai_baseurl`](js_openai_baseurl/) | JavaScript | OpenAI SDK with HELM proxy |
| [`python_openai_baseurl`](python_openai_baseurl/) | Python | OpenAI SDK with HELM proxy |
| [`ts_openai_baseurl`](ts_openai_baseurl/) | TypeScript | TypeScript fetch with HELM proxy |

## Streaming Governance (SSE)

| Example | Language | Description |
|---------|----------|-------------|
| [`streaming_python`](streaming_python/) | Python | SSE streaming with per-request governance |
| [`streaming_ts`](streaming_ts/) | TypeScript | SSE streaming with per-request governance |

## Verification

| Example | Description |
|---------|-------------|
| [`receipt_verification`](receipt_verification/) | Verify receipts offline (Python + TS) |
| [`golden`](golden/) | Golden artifact reference |
| [`substrate`](substrate/) | Substrate integration |

Each example folder includes its own `README.md` and entrypoint.
