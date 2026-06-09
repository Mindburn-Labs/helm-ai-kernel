---
title: OpenAI-Compatible Execution Boundary
last_reviewed: 2026-06-01
---

# OpenAI-Compatible Execution Boundary

HELM AI Kernel documents this search intent with a local, source-backed proof path.

## Gateway Policy Path

```mermaid
flowchart LR
    Client["OpenAI-compatible client"] --> Proxy["HELM proxy"]
    Proxy --> Policy["Policy and receipt boundary"]
    Policy --> Upstream["Upstream model when allowed"]
    Policy --> Denial["DENY or ESCALATE"]
    Upstream --> Receipt["Receipt metadata"]
    Denial --> Receipt
```

```bash
git clone https://github.com/Mindburn-Labs/helm-ai-kernel.git
cd helm-ai-kernel
make build
bash scripts/launch/demo-openai-proxy.sh
```

## Source Truth

- [Quickstart](../QUICKSTART.md)
- [Execution security model](../EXECUTION_SECURITY_MODEL.md)
- [MCP integration](../INTEGRATIONS/mcp.md)
- [Verification](../VERIFICATION.md)
