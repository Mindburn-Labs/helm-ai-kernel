# Protect Local Coding Agents

This guide shows the local HELM path for Codex or Claude Code-style runs. It
uses local client setup, hook decisions, manifest artifacts, and wrapper
receipts. It does not require private vendor APIs, a hosted account, or a model
provider key.

HELM is not a competing coding agent. It governs selected effects around a
local agent workflow and leaves an offline-verifiable receipt trail.

## Install a local hook

Inspect the writes first:

```bash
helm-ai-kernel setup codex --dry-run --json
helm-ai-kernel setup claude-code --dry-run --json
```

Install the local integration:

```bash
helm-ai-kernel setup codex --yes
helm-ai-kernel setup claude-code --yes
```

Setup writes draft policy and quarantine artifacts. It does not approve tools
or grant operate permissions.

## Prove a denied action

Ask the local agent to perform an action the starter policy denies. The
reference transcript denies the shell target `rm -rf /tmp/helm-risky-cleanup`
before dispatch and writes a signed workstation policy decision receipt.

Verify the receipt:

```bash
helm-ai-kernel workstation verify-decision --receipt ~/.helm-ai-kernel/receipts/hooks/wpd_<decision>.json
```

Expected fields:

```text
verdict:   DENY
reason:    OPERATE_PERMISSIONS_EMPTY
effect:    WORKSTATION_SHELL_COMMAND
signature: true
```

Use the imported-artifact flow below when you want to test workstation
receipts without modifying local client configuration.

## Import a run

```bash
cd helm-ai-kernel/core
go run ./cmd/helm-ai-kernel workstation import \
  --artifacts ../fixtures/workstation/allowed-draft \
  --out /tmp/helm-workstation-run.json
```

View the receipt without reading raw chat history:

```bash
go run ./cmd/helm-ai-kernel workstation view \
  --receipt /tmp/helm-workstation-run.json
```

## Enforce a selected effect

Network egress fails closed under `workstation.observe_draft.v1` because the default allowlist is empty:

```bash
go run ./cmd/helm-ai-kernel workstation enforce \
  --class network \
  --target https://forbidden.example \
  --out /tmp/helm-workstation-network-deny.json
```

The command exits `126` and writes a signed policy decision receipt. Draft workspace edits remain separately allowed:

```bash
go run ./cmd/helm-ai-kernel workstation decide \
  --class file \
  --target docs/example.md \
  --out /tmp/helm-workstation-draft-allow.json
```

## Operator views

```bash
go run ./cmd/helm-ai-kernel workstation denied --input /tmp/helm-workstation-network-deny.json
go run ./cmd/helm-ai-kernel workstation memory --input ../fixtures/workstation/reference/receipts
go run ./cmd/helm-ai-kernel workstation loops --input ../fixtures/workstation/reference/receipts
```

## Agent scope audit

Generate one audit report across MCP tools, filesystem, network, memory, secrets, deploys, payments, loops, and shell:

```bash
go run ./cmd/helm-ai-kernel audit scope \
  --input ../fixtures/workstation/reference/receipts \
  --json

go run ./cmd/helm-ai-kernel audit scope \
  --input /tmp/helm-workstation-run.json,/tmp/helm-workstation-network-deny.json \
  --out /tmp/helm-scope-audit \
  --evidence-pack
```

The report is receipt-scoped. It never claims full desktop, browser, OS, or proprietary hosted-agent control.

## EvidencePack and certification

```bash
go run ./cmd/helm-ai-kernel workstation evidence \
  --receipt /tmp/helm-workstation-run.json \
  --out /tmp/helm-workstation-evidencepack

go run ./cmd/helm-ai-kernel workstation certify \
  --fixtures ../fixtures/workstation \
  --mode high-risk-effect-capable
```

Expected result: deterministic import, signed receipts, denied operate effects, memory effects with TTL/sensitivity, recurring loops with schedule/max runtime/tool scope/expiration, and a sample EvidencePack that can be inspected offline.
