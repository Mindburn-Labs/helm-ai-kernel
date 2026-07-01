---
title: Framework Adapters
last_reviewed: 2026-07-01
---

# Framework Adapters

Use framework adapters when an agent framework already owns the tool-call hook
and you need to normalize that proposed action before HELM evaluates it.

## Supported Helpers

| Framework | Helper |
| --- | --- |
| LangGraph | `fromLangGraphToolCall` |
| LangChain | `fromLangChainToolCall` |
| CrewAI | `fromCrewAITask` |
| OpenAI Agents SDK | `fromOpenAIAgentsToolCall` |
| AutoGen / AG2 | `fromAutoGenToolCall` |
| Semantic Kernel | `fromSemanticKernelFunctionCall` |
| PydanticAI | `fromPydanticAIToolCall` |
| LlamaIndex | `fromLlamaIndexToolCall` |
| LiteLLM | `fromLiteLLMToolCall` |
| n8n | `fromN8NNodeExecution` |
| Zapier-style webhook | `fromZapierWebhookCall` |
| Raw MCP client | `fromRawMCPToolCall` |

## Pattern

```ts
import { HelmClient, createAgentFrameworkAdapter, fromLangGraphToolCall } from "@mindburn/helm-ai-kernel";

const helm = new HelmClient({ baseUrl: "http://127.0.0.1:7714" });
const adapter = createAgentFrameworkAdapter(helm, {
  model: "helm-governance",
  metadata: { boundary: "local-dev" },
});

const result = await adapter.submit(
  fromLangGraphToolCall({
    id: "call-1",
    name: "repo.read_file",
    args: { path: "README.md" },
  }),
);

console.log(result.governance.receiptId);
```

The adapter prepares the action for HELM. It does not execute the original
tool.
