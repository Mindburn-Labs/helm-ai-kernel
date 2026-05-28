---
last_reviewed: "2026-05-28"
---

# OpenClaw on HELM

## What this proves
OpenClaw runs through HELM’s fail-closed execution boundary.

```mermaid
flowchart TD
    A[OpenClaw Agent] -->|Request Tool Call| B(HELM AI Kernel)
    B -->|Check Policy| C{Verdict}
    C -->|ALLOW| D[Execute Action]
    C -->|DENY| E[Block & Return Error]
    C -->|ESCALATE| F[Step-Up / Operator Approval]
    D -->|Teardown / Receipt| G[EvidencePack Export]
```

## One-command path
```bash
helm up openclaw
```

## Headless path
```bash
helm-ai-kernel launch openclaw local-container --headless --output json
```

## Source Truth
- Registry source: `registry/launchpad/apps/openclaw.yaml`
- Policy source: `policies/launchpad/apps/openclaw.safe.toml`

## Evidence requirements
- cpi_output
- kernel_verdict
- sandbox_grant
- launch_receipt
- install_receipt
- healthcheck_receipt
- teardown_receipt
- evidence_pack
- evidence_graph
- mcp_quarantine
- mcp_manifest
- model_gateway_broker
- artifact_digest
- cosign_signature
- syft_sbom
- grype_vulnerability_scan

## Verify
```bash
helm-ai-kernel verify --bundle <pack>
```
