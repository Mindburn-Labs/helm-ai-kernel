---
title: Quickstart
last_reviewed: 2026-07-01
---

# Quickstart

Install HELM AI Kernel, protect a local coding agent, and verify the signed
receipt for a blocked action. This path is local-first: no hosted account, live
model key, production credential, Docker daemon, or private endpoint is required
for the first proof.

## 1. Install HELM

Published macOS CLI:

```bash
brew tap mindburn-labs/tap
brew trust mindburn-labs/tap
brew install helm-ai-kernel
helm-ai-kernel --version
```

Source build:

```bash
git clone https://github.com/Mindburn-Labs/helm-ai-kernel.git
cd helm-ai-kernel
make build
./bin/helm-ai-kernel --version
```

Use `./bin/helm-ai-kernel` for source builds and `helm-ai-kernel` for installed
CLI examples.

## 2. Protect Codex Or Claude Code

For Codex:

```bash
helm-ai-kernel setup codex --yes
```

For Claude Code:

```bash
helm-ai-kernel setup claude-code --yes
```

The setup command defaults to user scope and `~/.helm-ai-kernel`. Project scope
is explicit:

```bash
helm-ai-kernel setup codex --scope project --yes
```

Inspect before writing:

```bash
helm-ai-kernel setup codex --dry-run --json
```

Check or remove the integration:

```bash
helm-ai-kernel setup status codex
helm-ai-kernel setup remove codex --yes
```

Setup writes draft policy and quarantine artifacts only. It does not approve
detected tools.

## 3. Trigger A Denial

Use the protected client and attempt a high-risk tool action such as destructive
shell cleanup. HELM should deny or escalate instead of silently dispatching the
effect.

Hook denials write signed workstation decision receipts under:

```text
~/.helm-ai-kernel/receipts/hooks/
```

## 4. Verify The Receipt

```bash
helm-ai-kernel workstation verify-decision \
  --receipt ~/.helm-ai-kernel/receipts/hooks/<decision>.json
```

The verifier exits `0` only when the decision receipt hash and Ed25519 signature
verify. Tampered receipts return a non-zero exit.

Use the `v0.5.18` release `evidence-pack.tar` when verifying release-bundle
evidence instead of local quickstart receipts.

## 5. Run The Headless Local Proof

Use this when you want the local Kernel API proof path without changing an
agent client config:

```bash
helm-ai-kernel quickstart
```

Machine-readable startup state:

```bash
helm-ai-kernel quickstart --json
```

Useful flags:

| Flag | Purpose |
| --- | --- |
| `--addr 127.0.0.1` | Loopback bind address. Non-loopback binds are rejected. |
| `--port 7714` | Local Kernel port. |
| `--data-dir <dir>` | SQLite, keys, policy, receipts, and EvidencePack location. |
| `--reset` | Remove the quickstart data directory before initialization. |
| `--profile claude|codex|mcp|openai-compatible` | Label the onboarding path. |
| `--dry-run --json` | Prepare startup state without serving. |

## Next Steps

- [Agent Risk Scan](reference/agent-risk-scan.md)
- [Codex integration](INTEGRATIONS/codex.md)
- [Claude Code integration](INTEGRATIONS/claude-code.md)
- [MCP integration](INTEGRATIONS/mcp.md)
- [OpenAI-compatible proxy](INTEGRATIONS/openai_baseurl.md)
- [Verification](VERIFICATION.md)
- [Troubleshooting](TROUBLESHOOTING.md)

## Source Truth

- `core/cmd/helm-ai-kernel/setup_cmd.go`
- `core/cmd/helm-ai-kernel/hook_cmd.go`
- `core/cmd/helm-ai-kernel/quickstart_cmd.go`
- `core/cmd/helm-ai-kernel/local_first_run_routes.go`
- `core/cmd/helm-ai-kernel/workstation_m3_cmd.go`
- `core/cmd/helm-ai-kernel/receipts_cmd.go`
- `core/cmd/helm-ai-kernel/verify_cmd.go`
- `api/openapi/helm.openapi.yaml`
- `scripts/launch/demo-mcp.sh`
- `scripts/launch/demo-openai-proxy.sh`
