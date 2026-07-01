---
title: HELM AI Kernel
last_reviewed: 2026-07-01
---

# HELM AI Kernel

HELM AI Kernel is a local execution firewall for AI agents. Put it between an
agent and side-effecting tools, get an `ALLOW`, `DENY`, or `ESCALATE` decision,
and keep a signed receipt that can be verified later.

## Start

| Goal | Start here |
| --- | --- |
| Protect a local coding agent | [Quickstart](QUICKSTART.md) |
| Scan an agent before enforcement | [Agent Risk Scan](reference/agent-risk-scan.md) |
| Understand the model | [How HELM works](HOW_HELM_WORKS.md) |
| Install the CLI | [Installation](DEVELOPER_JOURNEY.md#install) |
| Call the HTTP API | [API introduction](reference/http-api.md) |
| Use an SDK | [SDKs](sdks/00_INDEX.md) |
| Route MCP tools | [MCP integration](INTEGRATIONS/mcp.md) |
| Use an OpenAI-compatible base URL | [OpenAI-compatible proxy](INTEGRATIONS/openai_baseurl.md) |

## First Command

```bash
helm-ai-kernel setup codex --yes
```

For Claude Code:

```bash
helm-ai-kernel setup claude-code --yes
```

Both commands keep the proof local. They write draft policy material, configure
the supported client integration, start the local Kernel path, and leave signed
receipts for blocked actions.

## Main Paths

- [Quickstart](QUICKSTART.md) - first local denial and receipt verification.
- [How HELM works](HOW_HELM_WORKS.md) - local decision path, receipts, and
  verification boundary.
- [Local coding agents](quickstart/workstation-governance.md) - add HELM to a
  developer workstation.
- [Agent Risk Scan](reference/agent-risk-scan.md) - local-first scan,
  anonymized risk envelope, and EvidencePack path.
- [Developer journey](DEVELOPER_JOURNEY.md) - choose the next path after the
  first proof.
- [Claude Code](INTEGRATIONS/claude-code.md) - one-command setup, status,
  remove, and receipt verification.
- [Codex](INTEGRATIONS/codex.md) - user or project-scoped setup for Codex.
- [MCP tools](INTEGRATIONS/mcp.md) - wrap, quarantine, approve, and inspect MCP
  tool calls.
- [OpenAI-compatible proxy](INTEGRATIONS/openai_baseurl.md) - keep an
  OpenAI-shaped client while moving enforcement into HELM.
- [Verification](VERIFICATION.md) - verify receipts and EvidencePacks offline.
- [Troubleshooting](TROUBLESHOOTING.md) - diagnose setup, ports, receipts, and
  policy behavior.

## Capabilities

| Capability | What to read |
| --- | --- |
| Fail-closed execution | [Execution security model](EXECUTION_SECURITY_MODEL.md) |
| MCP quarantine | [MCP tool quarantine](use-cases/mcp-execution-firewall.md) |
| Signed receipts | [Signed receipts](capabilities/signed-receipts.md) |
| EvidencePack verification | [EvidencePack verification](capabilities/evidencepack-verification.md) |
| Agent Risk Scan | [Agent Risk Scan](reference/agent-risk-scan.md) |
| Policy bundles | [Policy bundles](capabilities/policy-bundles.md) |
| OpenAI-compatible proxy | [Proxy integration](INTEGRATIONS/openai_baseurl.md) |

## Reference

- [CLI reference](reference/cli.md)
- [HTTP API reference](reference/http-api.md)
- [SDKs](sdks/00_INDEX.md)
- [JSON schemas](reference/json-schemas.md)
- [Protocols and schemas](reference/protocols-and-schemas.md)
- [Conformance](CONFORMANCE.md)
- [Compatibility](COMPATIBILITY.md)
- [Publishing](PUBLISHING.md)

## Public Boundary

The public docs describe HELM AI Kernel only. They do not claim hosted
Enterprise availability, buyer rollout, regulatory certification, paid account
activation, or broad operating-system control.

## Source Truth

This site is built from source-owned docs in this repository. Runtime behavior
is owned by `core/`, `api/openapi/helm.openapi.yaml`, SDK README files,
examples, and verification tests. If a public claim cannot be tied to those
sources, remove it or qualify it.
