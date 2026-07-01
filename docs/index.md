---
title: HELM documentation
last_reviewed: 2026-07-01
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
- [Protect local coding agents](quickstart/workstation-governance.md)
- [Scan agent risk](reference/agent-risk-scan.md)
- [OpenAI proxy](INTEGRATIONS/openai_baseurl.md)
- [Verify receipts](VERIFICATION.md)

## More

- [MCP](INTEGRATIONS/mcp.md)
- [Conformance](CONFORMANCE.md)
- [Troubleshooting](TROUBLESHOOTING.md)
- [CLI](reference/cli.md)
- [HTTP API](reference/http-api.md)
- [SDKs](sdks/00_INDEX.md)
