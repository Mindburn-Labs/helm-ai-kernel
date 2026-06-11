---
last_reviewed: "2026-06-11"
---

# OpenClaw on HELM

## What this proves
OpenClaw runs through HELM’s fail-closed execution boundary. The launch is driven by a registry-pinned app definition and a safe default-deny policy: HELM installs OpenClaw into a sandboxed local container, gates every tool call through the kernel verdict path, and emits a signed receipt for each lifecycle step, from install and healthcheck to teardown. The run ends with an exported EvidencePack that anyone can verify offline, so an autonomous agent framework operates with the same evidence discipline as the rest of your stack.

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
