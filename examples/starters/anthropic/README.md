# Anthropic Starter — HELM OSS Governed AI

Get started with HELM OSS governance over Anthropic Claude models.

## Quick Start

```bash
helm init claude ./my-anthropic-project
cd my-anthropic-project
echo "ANTHROPIC_API_KEY=sk-ant-..." >> .env
helm doctor --dir .
helm mcp serve --transport http
./first-governed-call.sh
```

## What's Included

| File | Purpose |
|------|---------|
| `helm.yaml` | HELM config for Anthropic MCP tooling |
| `.env.example` | Required environment variables |
| `first-governed-call.sh` | Runnable governed tool call demo |
| `ci-smoke.sh` | CI-compatible smoke test |
