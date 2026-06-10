# Workstation Governance Quickstart

This quickstart shows the local workstation adapter path for Codex or Claude Code-style runs. It uses manifest artifacts and wrapper decisions; it does not require private vendor APIs.

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
