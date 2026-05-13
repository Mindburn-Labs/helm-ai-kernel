# Google ADK Starter — HELM AI Kernel Governed AI

Get started with HELM AI Kernel governance over Google Gemini models.

## Quick Start

```bash
helm-ai-kernel init google ./my-google-project
cd my-google-project
echo "GEMINI_API_KEY=..." >> .env
helm-ai-kernel doctor --dir .
helm-ai-kernel mcp serve --transport http
./first-governed-call.sh
```

## What's Included

| File | Purpose |
| --- | --- |
| `helm.yaml` | HELM config for Google ADK/A2A |
| `first-governed-call.sh` | Runnable governed tool call demo |
| `ci-smoke.sh` | CI-compatible smoke test |

The `ci-smoke.sh` script validates generated project files from
`helm-ai-kernel init google`; it does not require a real Google API key.
