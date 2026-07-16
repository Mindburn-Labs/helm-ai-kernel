# Codex Starter — Local MCP Fixture

This starter creates an example project and exercises a local MCP endpoint with
`curl`. It does not install configuration into Codex, observe Codex loading a
server, or prove a real Codex client session.

## Quick Start

```bash
helm-ai-kernel init codex ./my-codex-project
cd my-codex-project
echo "OPENAI_API_KEY=sk-..." >> .env
helm-ai-kernel doctor --dir .
helm-ai-kernel mcp serve --transport http
./first-governed-call.sh
```

## Native Client Boundary

`helm-ai-kernel init codex` creates a starter layout; the governed-call script
is a local HTTP fixture, not a Codex client run. `helm-ai-kernel setup codex`
or printed MCP configuration can prove local setup only and deliberately leave
`client_load_observed=false`. A real native-client claim requires a sterile
client home and disposable workspace that loads the configured server and
exercises the configured hook classes or routed MCP call. Direct upstream calls
and unconfigured client actions remain outside that proof.

## What's Included

| File | Purpose |
| --- | --- |
| `helm.yaml` | HELM config for Codex MCP |
| `first-governed-call.sh` | Runnable governed tool call demo |
| `ci-smoke.sh` | CI-compatible smoke test |

The `ci-smoke.sh` script validates generated project files from
`helm-ai-kernel init codex`; it does not require a real OpenAI API key.
