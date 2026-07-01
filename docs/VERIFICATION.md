---
title: Receipts
last_reviewed: 2026-07-01
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

EvidencePacks are portable proof bundles. They are not compliance
certifications, hosted availability claims, or buyer rollout evidence.

## Release Evidence

Current source release target: `v0.5.18`.

The `v0.5.18` release is complete when the GitHub release and local verification
artifacts agree:

- release: `https://github.com/Mindburn-Labs/helm-ai-kernel/releases/tag/v0.5.18`
- v0.5.18 Asset Contract
- `v0.5.18.openvex.json`
- `v0.5.18.json`
