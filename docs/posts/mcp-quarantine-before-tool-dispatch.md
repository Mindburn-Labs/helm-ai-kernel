---
title: MCP Quarantine Before Tool Dispatch
last_reviewed: 2026-06-01
---

# MCP Quarantine Before Tool Dispatch

HELM AI Kernel puts a deterministic boundary between agent proposals and side effects. The local proof path shows MCP quarantine, ALLOW/DENY/ESCALATE decisions, signed receipts, and offline verification without requiring signup.

```bash
git clone https://github.com/Mindburn-Labs/helm-ai-kernel.git
cd helm-ai-kernel
make build
bash scripts/launch/demo-mcp.sh
bash scripts/launch/demo-proof.sh
```
