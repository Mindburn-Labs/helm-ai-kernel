---
title: Quickstart
last_reviewed: 2026-06-29
---

# Quickstart

This is the shortest public HELM AI Kernel proof path: install or build the
CLI, attach it to Claude Code or Codex, trigger a blocked local tool call, and
verify the signed evidence offline. No account, hosted service, live model key,
Docker daemon, or private endpoint is required.

## Audience

Developers, security reviewers, and integration owners who need one local proof
that HELM sits between an agent request and a side effect.

## Outcome

After this page you should have:

- a local Claude Code or Codex MCP entry;
- a PreToolUse hook where the client supports it;
- draft policy artifacts under `~/.helm-ai-kernel`;
- a local Kernel on `127.0.0.1:7714`;
- a signed `DENY` receipt for a blocked local tool call;
- offline-verifiable receipt or EvidencePack material.

## Source Truth

- `core/cmd/helm-ai-kernel/setup_cmd.go`
- `core/cmd/helm-ai-kernel/hook_cmd.go`
- `core/cmd/helm-ai-kernel/quickstart_cmd.go`
- `core/cmd/helm-ai-kernel/local_first_run_routes.go`
- `core/cmd/helm-ai-kernel/server_cmd.go`
- `core/cmd/helm-ai-kernel/receipts_cmd.go`
- `core/cmd/helm-ai-kernel/verify_cmd.go`
- `release.high_risk.v3.toml`

## 1. Install Or Build

Use the published macOS CLI when evaluating the current release:

```bash
brew tap mindburn-labs/tap
brew trust mindburn-labs/tap
brew install helm-ai-kernel
helm-ai-kernel --version
```

Use a source build when proving the current checkout:

```bash
git clone https://github.com/Mindburn-Labs/helm-ai-kernel.git
cd helm-ai-kernel
make build
./bin/helm-ai-kernel --version
```

## 2. Attach To A Local Coding Agent

For Claude Code:

```bash
helm-ai-kernel setup claude-code --yes
```

For Codex:

```bash
helm-ai-kernel setup codex --yes
```

Inspect the exact file writes before changing local client config:

```bash
helm-ai-kernel setup codex --dry-run --json
```

Setup never approves detected tools. It writes draft policy and quarantine
artifacts only; approvals remain explicit.

## 3. Prove Fail-Closed Behavior

Keep the Kernel terminal open, then ask the local agent to perform a tool action
that the starter policy denies. The expected result is a blocked action and a
signed decision receipt.

Verify the receipt offline:

```bash
helm-ai-kernel workstation verify-decision --receipt ~/.helm-ai-kernel/receipts/hooks/<decision>.json
```

Run the headless API proof path when you do not want to modify a local client:

```bash
helm-ai-kernel quickstart --json
```

The local onboarding API proves health, policy load, signed allow, signed deny,
MCP quarantine, tamper rejection, and EvidencePack export metadata.

## 4. Inspect Receipts

List local receipts while the boundary is running:

```bash
curl 'http://127.0.0.1:7714/api/v1/receipts?limit=20'
```

Tail a receipt stream:

```bash
helm-ai-kernel receipts tail --agent agent.demo.exec --server http://127.0.0.1:7714
```

## 5. Verify Evidence

Verify an exported EvidencePack without network access:

```bash
helm-ai-kernel verify --bundle <pack>
```

Use the `v0.5.18` release `evidence-pack.tar` only when validating the
published release artifact set. Local quickstart proof can use a locally
exported pack from the current checkout instead.

Tampering with a receipt or EvidencePack must fail verification.

## Troubleshooting

| Symptom | First check |
| --- | --- |
| Setup cannot find the client | Run `helm-ai-kernel setup <client> --dry-run --json` and check the reported config path. |
| The local API is unreachable | Confirm the Kernel is listening on `127.0.0.1:7714`. |
| No receipt appears | Check the hook was installed and the attempted tool action crossed the configured policy. |
| Verification fails | Re-export the receipt or EvidencePack and verify the original file before editing it. |

Do not paste provider keys, private prompts, private endpoints, or unredacted
receipts into public issues.
