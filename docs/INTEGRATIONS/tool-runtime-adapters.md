---
title: Tool Runtime Adapters
last_reviewed: 2026-07-01
---

# Tool Runtime Adapters

Use tool runtime adapters when the agent runtime proposes a concrete side
effect and your wrapper must ask HELM before dispatch.

## Supported Wrappers

| Runtime | Helper |
| --- | --- |
| OpenClaw | `fromOpenClawSkillCall` |
| Hermes | `fromHermesToolCall` |
| Mastra | `fromMastraToolCall` |
| Browser Use | `fromBrowserUseAction` |
| TinyFish | `fromTinyFishSearch`, `fromTinyFishFetch`, `fromTinyFishBrowserSession`, `fromTinyFishAgentRun` |
| E2B | `fromE2BExecution` |
| Composio | `fromComposioAction` |

## Pattern

```ts
import { preflightAction, fromOpenClawSkillCall } from "@mindburn/helm-tool-wrapper";

const intent = fromOpenClawSkillCall({
  skill: "gmail-send",
  input: { to: "ops@example.invalid", subject: "Draft follow-up" },
  conversation_id: "local-session",
});

const decision = await preflightAction({
  helmUrl: "http://127.0.0.1:7714",
  actionUrn: intent.actionUrn,
  input: intent.input,
  metadata: intent.metadata,
});
```

Dispatch only when the verdict is `ALLOW`. For `DENY` or `ESCALATE`, keep the
runtime blocked and show the receipt details to the developer.

## Runtime Examples

- [OpenClaw](openclaw.md)
- [Hermes](hermes.md)
