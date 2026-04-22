# Google ADK Starter — HELM OSS Governed AI

Get started with HELM OSS governance over Google Gemini models.

## Quick Start

```bash
helm init google ./my-google-project
cd my-google-project
echo "GEMINI_API_KEY=..." >> .env
helm doctor --dir .
helm mcp serve --transport http
./first-governed-call.sh
```

## What's Included

| File | Purpose |
|------|---------|
| `helm.yaml` | HELM config for Google ADK/A2A |
| `.env.example` | Required environment variables |
| `first-governed-call.sh` | Runnable governed tool call demo |
| `ci-smoke.sh` | CI-compatible smoke test |
