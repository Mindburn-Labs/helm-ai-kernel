---
title: How To Fail Closed on Agent Tool Calls
last_reviewed: 2026-06-02
---

# How To Fail Closed on Agent Tool Calls

Failing closed means an agent tool call does not reach a side-effecting tool
unless the boundary has enough authority, identity, schema, and policy context
to approve it. For MCP and AI gateway workflows, that default matters.

HELM AI Kernel demonstrates the pattern locally:

- unknown MCP server: DENY
- unknown MCP tool: DENY
- missing schema pin: DENY or ESCALATE
- schema-pinned fixture call: ALLOW
- dangerous shell fixture: DENY with a signed receipt
- flipped-verdict receipt: verification failure

![HELM MCP quarantine and receipt proof board](../assets/helm-mcp-quarantine-demo.png)

Run the local demos:

```bash
git clone https://github.com/Mindburn-Labs/helm-ai-kernel.git
cd helm-ai-kernel
make build
bash scripts/launch/demo-mcp.sh
bash scripts/launch/demo-proof.sh
```

Use the pattern when integrating agent frameworks, MCP servers, or
OpenAI-compatible clients: intercept before dispatch, bind approval to the
schema and identity you inspected, emit a receipt, and verify the evidence
offline.
