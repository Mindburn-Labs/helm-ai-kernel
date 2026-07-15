---
title: Receipts
last_reviewed: 2026-07-14
---

# Receipts

Every governed action should leave a local record. For public HELM, that record
is the proof path: show what was proposed, what HELM decided, why it decided
that, and where the receipt was written.

## What Gets Written

For MCP and boundary decisions, HELM records:

- `decision_id`
- verdict: `ALLOW`, `DENY`, or `ESCALATE`
- reason code
- server id, tool name, and effect scope when available
- receipt path
- approval hint for resolvable escalations
- policy epoch and record hash

Approvals and revocations also write receipts. A later evaluation must fail
closed when an approval is expired, revoked, or outside its server, tool, or
effect scope.

Codex project setup and removal also record signed lifecycle receipts. Their
durable rows retain the canonical receipt envelope; recovery reopens that store
read-only and refuses a missing, malformed, non-canonical, or legacy
index-only envelope. These receipts prove the local lifecycle transaction, not
that a native client opened the generated configuration.

## Inspect Local Receipts

```bash
helm-ai-kernel mcp receipts --json
helm-ai-kernel mcp pending --json
helm-ai-kernel boundary records --json
```

For a single workstation receipt:

```bash
helm-ai-kernel workstation verify-decision \
  --receipt ~/.helm-ai-kernel/receipts/hooks/wpd_<decision>.json
```

For an EvidencePack:

```bash
helm-ai-kernel verify evidence-pack.tar
```

Compatibility form:

```bash
helm-ai-kernel verify --bundle evidence-pack.tar
```

Offline verification is the default. If a pack has no public anchor, HELM
reports that directly; it does not invent one.

## Read A Decision

Start with these fields:

| Field | Meaning |
| --- | --- |
| `decision_id` | The decision to cite when debugging or rerunning |
| `verdict` | `ALLOW`, `DENY`, or `ESCALATE` |
| `reason_code` | Why the boundary returned that verdict |
| `receipt_path` | Local file written for the decision |
| `approval_command` | Scoped command to run when the verdict is `ESCALATE` |
| `record_hash` | Tamper-evidence handle for the boundary record |

An `ESCALATE` receipt is not permission to continue. Approve the exact scope,
then rerun the original action so HELM evaluates it again.

## Export Evidence

Use an EvidencePack when you need to move proof material between machines or
review it later:

```bash
helm-ai-kernel evidence export \
  --receipts ~/.helm-ai-kernel/receipts \
  --out evidence-pack.tar

helm-ai-kernel verify evidence-pack.tar
```

EvidencePacks are portable proof bundles for local review and offline replay.

## Native Client Evidence

Local Codex setup can prove exact HELM-owned configuration, a signed lifecycle
record, and a Kernel-only synthetic denial. It intentionally reports
`client_load_observed=false` until a separate real client session is observed.
Do not use that local result as proof of every Codex action or direct upstream
MCP call. See the [Native Client Integration
Boundary](INTEGRATIONS/native-client-boundary.md) before describing a real
client-session result.

## Release Evidence

Current source release target: `v0.7.2`.

The `v0.7.2` release is complete only after the listed local verification
assets appear on the GitHub release and verify locally.

Check the GitHub release and local verification artifacts together:

- release: `https://github.com/Mindburn-Labs/helm-ai-kernel/releases/tag/v0.7.2`
- v0.7.2 Asset Contract
- `v0.7.2.openvex.json`
- `v0.7.2.json`
