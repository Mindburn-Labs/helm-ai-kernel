---
title: Framework Adapters
last_reviewed: 2026-08-05
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
| OpenAI Codex | `fromCodexToolCall` |
| Claude Code | `fromClaudeToolCall` |
| Hermes | `fromHermesToolCall` |
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
tool. Named helpers are conveniences, not separate policy lanes: every helper
produces the same `AgentFrameworkAction` and uses the same receipt-bearing HELM
client. Use `fromRawMCPToolCall` for another framework that exposes an MCP tool
call instead of adding a provider-specific authority path.

Named helpers expect the provider's canonical envelope:

- `fromCodexToolCall`: `recipient_name` + `parameters`
- `fromClaudeToolCall`: `tool_name` + `tool_input`
- `fromHermesToolCall`: `tool_name` + `arguments`

If those canonical fields are missing, or alias fields disagree with them, the
helper throws `TypeError` before any HELM request is built.

Source presence is not package-release proof. Before a production integration,
verify the installed SDK version contains the helper, route one allow case and
blocked deny/escalate cases, and verify the resulting receipt offline.
