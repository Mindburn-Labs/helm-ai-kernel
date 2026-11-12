# Google ADK Starter — HELM AI Kernel Governed AI

Get started with HELM AI Kernel governance over Google Gemini models.

## Quick Start

```bash
helm-ai-kernel init google ./my-google-project
cd my-google-project
helm-ai-kernel doctor
helm-ai-kernel mcp serve --transport http --port 8080
# from the repository root, in another terminal:
bash examples/starters/google/first-governed-call.sh
```

The MCP server serves HELM's own tool catalog and does not call the provider,
so no API key is needed. `first-governed-call.sh` initializes an MCP session
and lists the tools; it does not call a tool and writes no receipt.

## What's Included

| File | Purpose |
| --- | --- |
| `helm.yaml` | HELM config for Google ADK/A2A |
| `first-governed-call.sh` | Runnable script that opens an MCP session and lists the tools |
| `ci-smoke.sh` | CI-compatible smoke test |

The `ci-smoke.sh` script validates generated project files from
`helm-ai-kernel init google`; it does not require a real Google API key.
