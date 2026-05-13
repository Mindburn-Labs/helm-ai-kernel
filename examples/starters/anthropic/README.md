# Anthropic Starter — HELM AI Kernel Governed AI

Get started with HELM AI Kernel governance over Anthropic Claude models.

## Quick Start

```bash
helm-ai-kernel init claude ./my-anthropic-project
cd my-anthropic-project
echo "ANTHROPIC_API_KEY=sk-ant-..." >> .env
helm-ai-kernel doctor --dir .
helm-ai-kernel mcp serve --transport http
./first-governed-call.sh
```

## What's Included

| File | Purpose |
| --- | --- |
| `helm.yaml` | HELM config for Anthropic MCP tooling |
| `first-governed-call.sh` | Runnable governed tool call demo |
| `ci-smoke.sh` | CI-compatible smoke test |

The `ci-smoke.sh` script validates generated project files from
`helm-ai-kernel init claude`; it does not require a real Anthropic API key.
