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
is a local HTTP fixture, not a Codex client run. To inspect Codex project-local
configuration separately, use:

```bash
helm-ai-kernel setup codex --scope project --dry-run --json
```

After an explicit `--yes` setup, its exact configuration checks, signed
lifecycle receipt, and Kernel-only synthetic denial still report
`client_load_observed=false`. A real native-client claim requires a sterile
client home and disposable workspace that load the configured server and
exercise the configured hook classes or routed MCP call; direct upstream calls
and unconfigured client actions remain outside that proof. See the [native
client integration boundary](../../../docs/INTEGRATIONS/native-client-boundary.md).

## What's Included

| File | Purpose |
| --- | --- |
| `helm.yaml` | HELM config for Codex MCP |
| `first-governed-call.sh` | Runnable governed tool call demo |
| `ci-smoke.sh` | CI-compatible smoke test |

The `ci-smoke.sh` script validates generated project files from
`helm-ai-kernel init codex`; it does not require a real OpenAI API key.
