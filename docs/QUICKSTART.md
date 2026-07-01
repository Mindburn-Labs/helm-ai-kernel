---
title: Quickstart
last_reviewed: 2026-07-01
---

# Quickstart

Run HELM locally and prove the boundary before connecting it to a real agent.
No account or model key is required.

## Install

```bash
brew tap mindburn-labs/tap
brew install helm-ai-kernel
helm-ai-kernel --version
```

From source:

```bash
git clone https://github.com/Mindburn-Labs/helm-ai-kernel.git
cd helm-ai-kernel
make build
./bin/helm-ai-kernel --version
```

## Supported Today

| Surface | Public proof |
| --- | --- |
| Install | `brew install helm-ai-kernel` or `make build` |
| Local proof | `helm-ai-kernel mcp proof --json --out ~/.helm-ai-kernel/proofs` |
| Codex setup | `helm-ai-kernel setup codex --dry-run --json` |
| Claude Code setup | `helm-ai-kernel setup claude-code --dry-run --json` |
| MCP approval loop | `mcp authorize-call`, `mcp approve`, `mcp revoke`, `mcp pending`, `mcp receipts` |
| OpenAI proxy | `helm-ai-kernel proxy --port 9090` |
| Receipts | `helm-ai-kernel mcp receipts --json` and `helm-ai-kernel boundary records --json` |
| Conformance | `helm-ai-kernel conform --level L1 --json` and `--level L2` |
| SDKs | source clients under `sdk/` with local test targets |

## Prove The Boundary

```bash
helm-ai-kernel mcp proof --json --out ~/.helm-ai-kernel/proofs
```

Expected shape:

```json
{
  "schema_version": "helm.mcp.proof/v1",
  "offline_verified": true,
  "scenarios": [
    { "verdict": "ESCALATE", "dispatched": false },
    { "verdict": "DENY", "dispatched": false }
  ]
}
```

Verify the generated EvidencePack offline:

```bash
helm-ai-kernel verify --bundle ~/.helm-ai-kernel/proofs/<run-id>/<run-id> --profile dev-local --json
```

Use the `v0.5.18` release `evidence-pack.tar` from the GitHub release for
release verification instead of a local proof bundle.

## See An Escalation

Ask HELM to authorize a local MCP action before dispatch:

```bash
helm-ai-kernel mcp authorize-call \
  --server-id helm-demo-shell \
  --tool-name pwd
```

Expected client message:

```text
HELM ESCALATE
decision: mcp-boundary-...
reason: unknown MCP server requires approval
receipt: ~/.helm-ai-kernel/receipts/mcp/...
approve:
  helm-ai-kernel mcp approve --server-id helm-demo-shell \
    --tools "pwd" \
    --ttl 15m \
    --reason 'read-only repo inspection for local dev'
```

Nothing runs on `ESCALATE`. The developer either approves the exact scope or
does nothing.

Approve a narrow read-only grant:

```bash
helm-ai-kernel mcp approve \
  --server-id helm-demo-shell \
  --tools "pwd,ls,cat" \
  --ttl 15m \
  --reason "read-only repo inspection for local dev"
```

Then rerun the original action. HELM evaluates again against the approval,
schema, policy, and effect scope. Approval does not silently resume the blocked
action.

Revoke the grant:

```bash
helm-ai-kernel mcp revoke \
  --server-id helm-demo-shell \
  --reason "inspection finished"
```

## Connect A Local Agent

For Claude Code:

```bash
helm-ai-kernel setup claude-code --yes
```

For Codex:

```bash
helm-ai-kernel setup codex --yes
```

Preview writes first:

```bash
helm-ai-kernel setup codex --dry-run --json
```

Setup writes local config and draft policy artifacts. It does not approve
detected tools.

## Inspect

```bash
helm-ai-kernel mcp pending --json
helm-ai-kernel mcp receipts --json
helm-ai-kernel boundary records --verdict ESCALATE --json
```

Keep sensitive prompts, provider keys, endpoints, and unredacted receipts out of
public issues.
