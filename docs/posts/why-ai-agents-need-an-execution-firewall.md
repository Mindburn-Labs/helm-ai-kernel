---
title: Why AI Agents Need an Execution Firewall
last_reviewed: 2026-06-02
---

# Why AI Agents Need an Execution Firewall

AI agents can propose useful work, but tool calls are where proposals become
side effects. A model can ask to read a ticket, draft a reply, call an MCP
tool, export customer data, or run a shell command. Those requests need a
deterministic execution boundary before anything reaches the tool.

HELM AI Kernel is an open-source execution firewall for MCP and AI agents. It
intercepts proposed tool calls, evaluates policy before dispatch, records
ALLOW, DENY, or ESCALATE decisions, and emits signed receipts that can be
verified offline.

## Execution Firewall Flow

```mermaid
flowchart LR
    Agent["AI agent"] --> Proposal["Proposed side effect"]
    Proposal --> Kernel["HELM AI Kernel"]
    Kernel --> Policy["Policy and schema evaluation"]
    Policy --> Verdict["ALLOW, DENY, or ESCALATE"]
    Verdict --> Dispatch["Dispatch only when allowed"]
    Verdict --> Receipt["Signed receipt"]
    Receipt --> Verifier["Offline verification"]
```

![HELM MCP quarantine and receipt proof board](../assets/helm-mcp-quarantine-demo.svg)

The key idea is simple: the agent can propose, but HELM decides whether the
side effect is authorized. Unknown MCP servers and tools fail closed before
fixture dispatch. Schema-pinned calls can be allowed. A DENY decision produces
a receipt, and a flipped-verdict copy fails verification.

Run the local proof path without an account or production credentials:

```bash
git clone https://github.com/Mindburn-Labs/helm-ai-kernel.git
cd helm-ai-kernel
make build
bash scripts/launch/demo-mcp.sh
bash scripts/launch/demo-proof.sh
```

Star the repo if you want to follow the MCP execution-firewall roadmap:
<https://github.com/Mindburn-Labs/helm-ai-kernel>

## Source Truth

- [Quickstart](../QUICKSTART.md)
- [Execution security model](../EXECUTION_SECURITY_MODEL.md)
- [MCP integration](../INTEGRATIONS/mcp.md)
- [Verification](../VERIFICATION.md)
