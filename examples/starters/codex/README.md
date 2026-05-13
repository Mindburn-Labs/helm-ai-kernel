# Codex Starter — HELM AI Kernel Governed AI

Get started with HELM AI Kernel governance over OpenAI Codex.

## Quick Start

```bash
helm-ai-kernel init codex ./my-codex-project
cd my-codex-project
echo "OPENAI_API_KEY=sk-..." >> .env
helm-ai-kernel doctor --dir .
helm-ai-kernel mcp serve --transport http
./first-governed-call.sh
```

## What's Included

| File | Purpose |
| --- | --- |
| `helm.yaml` | HELM config for Codex MCP |
| `first-governed-call.sh` | Runnable governed tool call demo |
| `ci-smoke.sh` | CI-compatible smoke test |

The `ci-smoke.sh` script validates generated project files from
`helm-ai-kernel init codex`; it does not require a real OpenAI API key.
