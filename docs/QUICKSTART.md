---
title: Quickstart
---

# Quickstart

This walkthrough uses the public HELM OSS path: install the CLI, start a local boundary, verify an EvidencePack offline, and stream live receipts from an agent.

## 1. Install

```bash
brew install mindburn/tap/helm
```

Source install and Docker remain supported, but Homebrew is the primary public install path.

## 2. Start a Local Boundary

```bash
helm serve --policy ./release.high_risk.v3.toml
```

Expected ready line:

```text
helm-edge-local · listening :7714 · ready
```

The sample policy uses `reference_packs/eu_ai_act_high_risk.v1.json` and stores receipts in `./data/receipts.db`.

## 3. Verify an EvidencePack Offline

```bash
helm verify evidence-pack.tar
```

`helm verify --bundle evidence-pack.tar` is retained for compatibility. Offline verification never contacts Mindburn or Titan services.

## 4. Verify Against Public Proof Metadata

```bash
helm verify evidence-pack.tar --online
```

`--online` first requires offline verification to pass, then checks embedded envelope/root metadata against `HELM_LEDGER_URL` or the public Mindburn proof proxy. If no public anchor exists, offline verification can still pass and the CLI reports `anchor offline`.

## 5. Stream Live Receipts

```bash
helm receipts tail --agent agent.titan.exec
```

The default server is `HELM_URL` or `http://127.0.0.1:7714`.

## Source Build

```bash
git clone https://github.com/Mindburn-Labs/helm-oss.git
cd helm-oss
make build
./bin/helm serve --policy ./release.high_risk.v3.toml
```

## Existing Demo Flow

```bash
./bin/helm onboard --yes
./bin/helm demo organization --template starter --provider mock
./bin/helm export --evidence ./data/evidence --out evidence.tar
./bin/helm verify evidence.tar
```

## Machine-Readable Output

Use JSON output for automation and auditor handoff:

```bash
helm verify evidence-pack.tar --json
cat ./data/evidence/run-report.json
```

## Validation Targets

```bash
make test
make test-all
make crucible
```

These targets cover the kernel package tests, SDK validation, fixture verification, and the retained use-case test runner.

## Existing Client Integration

To put HELM in front of an existing OpenAI-compatible client:

```bash
./bin/helm proxy --upstream https://api.openai.com/v1
```

Then update the client base URL to `http://localhost:8080/v1`.
