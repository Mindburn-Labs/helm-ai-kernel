---
title: Receipts
last_reviewed: 2026-07-01
---

# Receipts

Every governed action should leave a local record. For public HELM, that record
is the proof path: show what was proposed, what HELM decided, why it decided
that, and where the receipt was written.

<!-- quantum_posture: verification docs mention existing Ed25519 and cosign checks only; this page adds no post-quantum cryptographic control. -->

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

Current source release target: `v0.5.19`:
<https://github.com/Mindburn-Labs/helm-ai-kernel/releases/tag/v0.5.19>. The
release is complete only when the page attaches platform binaries,
`SHA256SUMS.txt`, `sbom.json`, `v0.5.19.openvex.json`,
`release-attestation.json`, `evidence-pack.tar`,
`release.high_risk.v3.toml`, `sample-policy-material.tar`,
`helm-ai-kernel-launchpad-data.tar`, `helm-ai-kernel.mcpb`,
`helm-ai-kernel.rb`, `v0.5.19.json`, `version-status.json`, and matching
`*.cosign.bundle` files for each primary asset.

There is no public GitHub Release object for `v0.4.1`; use `v0.4.0` as the
actual baseline when auditing the `v0.5.0` delta.

## v0.5.19 Asset Contract

The `v0.5.19` release is complete only when it attaches these primary assets:

- `helm-ai-kernel-darwin-amd64`
- `helm-ai-kernel-darwin-arm64`
- `helm-ai-kernel-linux-amd64`
- `helm-ai-kernel-linux-arm64`
- `helm-ai-kernel-windows-amd64.exe`
- `SHA256SUMS.txt`
- `sbom.json`
- `v0.5.19.openvex.json`
- `release-attestation.json`
- `evidence-pack.tar`
- `release.high_risk.v3.toml`
- `sample-policy-material.tar`
- `helm-ai-kernel-launchpad-data.tar`
- `helm-ai-kernel.mcpb`
- `helm-ai-kernel.rb`

`sample-policy-material.tar` must include both
`release.high_risk.v3.toml` and
`reference_packs/eu_ai_act_high_risk.v1.json`. The release workflow signs each
primary asset, including `SHA256SUMS.txt`, with a matching
`*.cosign.bundle`.

If a release also attaches `helm-console-web-*` bundle artifacts, treat them as
release packaging evidence only. They do not imply that Console source code,
hosted Enterprise availability, or customer production access is published from
this kernel repo.

## EvidencePack Contents

An EvidencePack is the portable verification bundle for a HELM-governed run or
release path. A complete pack includes the indexed records needed to verify the
decision chain without trusting the process that produced it:

- prompts or request metadata when the surface records them for the run;
- MCP tool calls, OpenAI-compatible proxy requests, policy decisions, and
  outcomes that crossed the HELM boundary;
- receipt bytes, receipt IDs, decision IDs, output hashes, and reason codes;
- ProofGraph or boundary record roots that bind the decision path;
- signature material and native seal metadata when the pack has been sealed;
- optional external anchor and storage receipts for customer or
  high-assurance profiles.

The verifier checks the archive or directory shape, the indexed file hashes,
the receipt material, root hashes, and available signatures. A demo receipt is
not automatically a complete EvidencePack; use a pack produced by export,
LaunchKit, release artifacts, or an operator-controlled evidence workflow.

## Offline Verification

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
They are not compliance certifications, hosted availability claims, or buyer
rollout evidence.
