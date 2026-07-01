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

Run the local proof:

```bash
brew tap mindburn-labs/tap
brew install helm-ai-kernel
helm-ai-kernel --version
helm-ai-kernel mcp proof \
  --json \
  --out ~/.helm-ai-kernel/proofs
```

The proof writes a local EvidencePack with no dispatched side effects. It
includes quarantined MCP servers, schema drift, missing approval receipts, and
replay attempts.

## Start

- [Quickstart](QUICKSTART.md)
- [Protect local coding agents](quickstart/workstation-governance.md)
- [OpenAI proxy](INTEGRATIONS/openai_baseurl.md)
- [MCP](INTEGRATIONS/mcp.md)

## Verify

- [Receipts and EvidencePacks](VERIFICATION.md)
- [Conformance](CONFORMANCE.md)
- [Troubleshooting](TROUBLESHOOTING.md)

## Reference

- [CLI](reference/cli.md)
- [HTTP API](reference/http-api.md)
- [SDKs](sdks/00_INDEX.md)
