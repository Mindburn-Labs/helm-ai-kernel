---
title: How To Fail Closed on Agent Tool Calls
last_reviewed: 2026-06-01
---

# How To Fail Closed on Agent Tool Calls

HELM AI Kernel puts a deterministic boundary between agent proposals and side effects. The local proof path shows MCP quarantine, ALLOW/DENY/ESCALATE decisions, signed receipts, and offline verification without requiring signup.

```bash
git clone https://github.com/Mindburn-Labs/helm-ai-kernel.git
cd helm-ai-kernel
make build
bash scripts/launch/demo-mcp.sh
bash scripts/launch/demo-proof.sh
```
