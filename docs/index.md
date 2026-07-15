---
title: HELM documentation
last_reviewed: 2026-07-15
---

# HELM documentation

Block unsafe AI-agent actions before they run.

HELM sits between an agent and a tool call:

```text
agent/tool requests action
-> HELM evaluates before dispatch
-> ALLOW: action runs
-> DENY: action is blocked
-> ESCALATE: action is blocked and a decision receipt is written
```

Install and open the CLI front door:

```bash
brew tap mindburn-labs/tap
brew install helm-ai-kernel
helm-ai-kernel
```

Then choose one path.

## Start

- [Quickstart](QUICKSTART.md)
- [HELM proof loop](PROOF_LOOP.md)
- [Configure local coding-agent hooks and routed MCP paths](quickstart/workstation-governance.md)
- [Scan agent risk](reference/agent-risk-scan.md)
- [OpenAI proxy](INTEGRATIONS/openai_baseurl.md)
- [Verify receipts](VERIFICATION.md)
- [Native client integration boundary](INTEGRATIONS/native-client-boundary.md)

## Local Client Setup Boundary

Codex setup and printed MCP configuration can record exact local configuration,
but intentionally leave `client_load_observed=false`. They do not prove that
Codex or Claude Code loaded the configuration in a real session. A native
client claim needs a sterile client home and disposable workspace that loads the
configured server, exercises only configured hook classes and routed MCP calls,
and verifies resulting receipts. Direct upstream and unconfigured client paths
remain outside that review.

## More

- [AI security categories](AI_SECURITY_CATEGORIES.md)
- [MCP](INTEGRATIONS/mcp.md)
- [Conformance](CONFORMANCE.md)
- [Troubleshooting](TROUBLESHOOTING.md)
- [CLI](reference/cli.md)
- [HTTP API](reference/http-api.md)
- [SDKs](sdks/00_INDEX.md)
