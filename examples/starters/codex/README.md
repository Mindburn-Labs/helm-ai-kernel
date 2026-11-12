# Codex Starter — HELM AI Kernel Governed AI

Get started with HELM AI Kernel governance over OpenAI Codex.

## Quick Start

```bash
helm-ai-kernel init codex ./my-codex-project
cd my-codex-project
helm-ai-kernel doctor
helm-ai-kernel mcp serve --transport http --port 8080
# from the repository root, in another terminal:
bash examples/starters/codex/first-governed-call.sh
```

The MCP server serves HELM's own tool catalog and does not call the provider,
so no API key is needed. `first-governed-call.sh` initializes an MCP session
and lists the tools; it does not call a tool and writes no receipt.

## What's Included

| File | Purpose |
| --- | --- |
| `helm.yaml` | HELM config for Codex MCP |
| `first-governed-call.sh` | Runnable script that opens an MCP session and lists the tools |
| `ci-smoke.sh` | CI-compatible smoke test |

The `ci-smoke.sh` script validates generated project files from
`helm-ai-kernel init codex`; it does not require a real OpenAI API key.
