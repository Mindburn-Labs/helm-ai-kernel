---
title: Signed Receipts for AI Agent Actions
last_reviewed: 2026-06-01
---

# Signed Receipts for AI Agent Actions

HELM AI Kernel documents this search intent with a local, source-backed proof path.

## Audit Receipt Chain

```mermaid
flowchart LR
    Request["LLM action request"] --> Verdict["Boundary verdict"]
    Verdict --> Receipt["Signed receipt"]
    Receipt --> Hash["Receipt hash"]
    Hash --> EvidencePack["EvidencePack"]
    EvidencePack --> Auditor["Auditor verification"]
```

```bash
git clone https://github.com/Mindburn-Labs/helm-ai-kernel.git
cd helm-ai-kernel
make build
bash scripts/launch/demo-proof.sh
```

## Source-Backed Docs

- [Quickstart](../QUICKSTART.md)
- [Execution security model](../EXECUTION_SECURITY_MODEL.md)
- [MCP integration](../INTEGRATIONS/mcp.md)
- [Verification](../VERIFICATION.md)
