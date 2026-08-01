---
title: Quickstart
last_reviewed: 2026-07-24
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
| CLI chooser | `helm-ai-kernel` or `helm-ai-kernel setup` |
| Local proof | `helm-ai-kernel mcp proof --json --out ~/.helm-ai-kernel/proofs` |
| Codex setup | `helm-ai-kernel setup codex --dry-run --json` |
| Claude Code setup | `helm-ai-kernel setup claude-code --dry-run --json` |
| Cursor / Windsurf / VS Code config | `helm-ai-kernel setup --client cursor --print-config` |
| OpenClaw / Hermes adapters | [tool runtime adapters](INTEGRATIONS/tool-runtime-adapters.md) |
| Framework adapters | [framework adapters](INTEGRATIONS/framework-adapters.md) |
| Skill Packs | `helm-ai-kernel skills search --json` |
| Agent risk scan | `helm-ai-kernel scan --path . --risk-envelope out/risk-envelope.json --preview out/risk-report.md` |
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
helm-ai-kernel verify --bundle ~/.helm-ai-kernel/proofs/<run-id>/evidencepacks/<run-id> --profile dev-local --json
```

When the `v0.7.5` GitHub Release publishes an `evidence-pack.tar`, use that
release asset for release verification instead of a local proof bundle. Until
then, the local proof bundle above is the verifiable path.

For the full public flow, see [HELM Proof Loop](PROOF_LOOP.md).

## See An Escalation

Ask HELM to authorize a local MCP action before dispatch:

```bash
helm-ai-kernel mcp authorize-call \
  --server-id helm-governance \
  --tool-name file_read
```

Every verdict prints the same shape: verdict, decision id, reason, receipt
path, and — where a remediation exists — the exact next-step command.

```text
HELM ESCALATE
decision: mcp-boundary-...
reason: unknown MCP server requires approval
receipt: data/receipts/mcp/...
next:
  helm-ai-kernel mcp approve --server-id helm-governance \
    --tools "file_read" \
    --ttl 15m \
    --reason 'read-only repo inspection for local dev'
```

Nothing runs on `ESCALATE`. The developer either approves the exact scope or
does nothing.

Approve a narrow read-only grant:

```bash
helm-ai-kernel mcp approve \
  --server-id helm-governance \
  --tools "file_read" \
  --ttl 15m \
  --reason "read-only repo inspection for local dev"
```

Then rerun the original action. The approval covers the server and tool, so
the check advances to the next gate: the tool's schema must be pinned so a
server-side schema change cannot silently rewrite what the tool does.

```text
HELM ESCALATE
decision: mcp-boundary-...
reason: MCP tool schema requires approval or pinning
receipt: data/receipts/mcp/...
next:
  helm-ai-kernel mcp authorize-call --server-id helm-governance \
    --tool-name file_read --pinned-schema-hash sha256:...
```

Pin the schema by rerunning with the printed hash:

```bash
helm-ai-kernel mcp authorize-call \
  --server-id helm-governance \
  --tool-name file_read \
  --pinned-schema-hash sha256:...
```

```text
HELM ALLOW
decision: mcp-boundary-...
reason: approved scope, schema pin, and policy checks passed
receipt: data/receipts/mcp/...
```

A call outside the approved scope fails closed with the same shape — receipt
path plus the approval command that would widen the scope:

```text
HELM DENY
decision: mcp-boundary-...
reason: tool is outside the approved scope for this MCP server
receipt: data/receipts/mcp/...
next:
  helm-ai-kernel mcp approve --server-id helm-governance \
    --tools "file_write" --ttl 15m --reason '...'
```

Approval does not silently resume the blocked action: HELM evaluates again
against the approval, schema pin, policy, and effect scope on every call. See
[Deny Reason Codes](guides/deny-reason-codes.md) for what each reason code
means and the step that resolves it.

Revoke the grant:

```bash
helm-ai-kernel mcp revoke \
  --server-id helm-governance \
  --reason "inspection finished"
```

## Connect A Local Agent

See the supported matrix:

```bash
helm-ai-kernel setup --json
```

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
helm-ai-kernel setup --client cursor --print-config
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
