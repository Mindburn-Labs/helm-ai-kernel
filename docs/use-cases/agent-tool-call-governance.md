---
title: AI Agent Side-Effect Governance
last_reviewed: 2026-06-01
---

# AI Agent Side-Effect Governance

HELM AI Kernel documents this search intent with a local, source-backed proof path.

## Governance Path

```mermaid
flowchart LR
    Agent["Agent request"] --> Boundary["HELM boundary"]
    Boundary --> Policy["Policy evaluation"]
    Policy --> Verdict["ALLOW, DENY, or ESCALATE"]
    Verdict --> Receipt["Signed receipt"]
    Receipt --> Audit["Audit and replay"]
```

```bash
git clone https://github.com/Mindburn-Labs/helm-ai-kernel.git
cd helm-ai-kernel
make build
bash scripts/launch/demo-local.sh
```

## Source Truth

- [Quickstart](../QUICKSTART.md)
- [Execution security model](../EXECUTION_SECURITY_MODEL.md)
- [MCP integration](../INTEGRATIONS/mcp.md)
- [Verification](../VERIFICATION.md)
