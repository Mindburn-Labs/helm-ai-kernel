# Codex Starter — HELM OSS Governed AI

Get started with HELM OSS governance over OpenAI Codex.

## Quick Start

```bash
helm init codex ./my-codex-project
cd my-codex-project
echo "OPENAI_API_KEY=sk-..." >> .env
helm doctor --dir .
helm mcp serve --transport http
./first-governed-call.sh
```

## What's Included

| File | Purpose |
|------|---------|
| `helm.yaml` | HELM config for Codex MCP |
| `.env.example` | Required environment variables |
| `first-governed-call.sh` | Runnable governed tool call demo |
| `ci-smoke.sh` | CI-compatible smoke test |
