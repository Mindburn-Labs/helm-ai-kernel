---
title: Framework Adapters
last_reviewed: 2026-08-05
---

# Framework Adapters

Use the effect gateway when an agent framework already owns the tool-call hook
and the tool's side effect must be governed before it runs.

## Pattern

The TypeScript SDK's `NativeGatewayClient` calls the gateway's native effect
interface (`core/pkg/gateway/mcpserver`). Pass the exact discovered tool name,
the framework's arguments and an explicit target; the gateway decides,
dispatches and records the attempt.

```ts
import { NativeGatewayClient } from "@mindburn/helm-ai-kernel";

const gateway = new NativeGatewayClient({ mcpUrl, episodeToken: getEpisodeToken });
const tools = await gateway.listTools();
const result = await gateway.callEffect({
  toolName: "github_repository_get",
  arguments: { schema: "helm.github.repository.get.v1", branch: "main" },
  target: "github.com/owner/repository",
});
if (result.structuredContent.status === "reconciling") {
  await gateway.getAttempt(result.structuredContent.attempt_id!);
}
```

The client owns no authority. A framework's metadata is never treated as
authority, and a call is made once: keep the returned attempt and read it with
`getAttempt` instead of retrying.

## Removed helpers

The chat-completion helpers (`fromLangGraphToolCall`, `fromCrewAITask`,
`fromOpenAIAgentsToolCall` and twelve others, plus
`createAgentFrameworkAdapter`) were removed. They serialized the tool call as
chat-message text and submitted a chat completion, so nothing evaluated the
named tool or its arguments.
