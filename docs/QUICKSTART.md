---
title: Quickstart
last_reviewed: 2026-07-16
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
  "schema_version": "helm.mcp.proof/v4",
  "proof_scope": "complete",
  "offline_verified": true,
  "tamper_rejected": true,
  "complete_positive_and_negative": true,
  "proof_complete": true,
  "negative_cases_no_dispatch": true,
  "dispatch_count": 1,
  "replay_no_redispatch": true,
  "pre_dispatch_bypass_blocked": true,
  "duration_gate_pass": true,
  "scenarios": [
    {
      "scenario_id": "approved_reversible_local_effect",
      "verdict": "ALLOW",
      "dispatched": true,
      "dispatch_count": 1,
      "replay_no_redispatch": true
    },
    { "verdict": "DENY", "dispatched": false }
  ]
}
```

The positive case writes one fixed, reversible file under the proof output
directory through `SafeExecutor`. Its signed execution receipt hashes the exact
exported file bytes. Replaying the same authorized intent returns the same
durably stored receipt envelope without a second dispatch. Every policy receipt
binds exported authorization inputs and the resulting evaluation. Missing or
invalid approvals, schema drift, confused-deputy scope, and the other negative
cases remain at zero dispatch. The command fails unless the complete default
run—including pack seal, offline verification, and a required tamper-negative
check—finishes in under 60 seconds.

The complete run also sends forged, decision-mismatched, and unsigned intents
directly to `SafeExecutor`; all three must fail before the local driver. Those
pre-dispatch outcomes are sealed as evidence, but do not add new policy reason
codes.

Use `--scenario <id>` only to inspect an individual vector: its summary says
`proof_scope: "vector_only"` and `proof_complete: false`. The replay result is
sequential same-effect idempotency, not a concurrency, reordering, or
crash-recovery exactly-once claim.

Verify the generated EvidencePack offline:

```bash
helm-ai-kernel verify --bundle ~/.helm-ai-kernel/proofs/<run-id>/evidencepacks/<run-id> --profile dev-local --json
```

For a tagged release, use its published `evidence-pack.tar` asset for release
verification. The local command above is the reproducible workstation proof
for the installed binary or a source build.

For the full public flow, see [HELM Proof Loop](PROOF_LOOP.md).

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
