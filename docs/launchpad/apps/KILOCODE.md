---
last_reviewed: "2026-05-28"
---

# Kilo Code on HELM

## What this proves
Kilo Code currently has `verify_only` contract evidence. The pinned image and
`kilocode --version` healthcheck are useful smoke proof, but `--version` smoke
checks do not count as live-agent F2 coverage.

```mermaid
flowchart TD
    A[Kilo Code Agent] -->|Request Tool Call| B(HELM AI Kernel)
    B -->|Check Policy| C{Verdict}
    C -->|ALLOW| D[Execute Action]
    C -->|DENY| E[Block & Return Error]
    C -->|ESCALATE| F[Step-Up / Operator Approval]
    D -->|Teardown / Receipt| G[EvidencePack Export]
```

## Contract preflight path
```bash
helm-ai-kernel app preflight kilocode --json
```

## Source Truth
- Registry source: `registry/launchpad/apps/kilocode.yaml`
- Policy source: `policies/launchpad/apps/kilocode.safe.toml`

## Evidence requirements
- cpi_output
- kernel_verdict
- sandbox_grant
- healthcheck_receipt
- evidence_pack
- offline_verify
- evidence_graph
- mcp_quarantine
- mcp_manifest
- artifact_digest
- cosign_signature
- syft_sbom
- grype_vulnerability_scan

## Verify
```bash
helm-ai-kernel verify --bundle <pack>
```
