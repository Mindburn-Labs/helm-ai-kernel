import { describe, expect, it, vi } from "vitest";
import {
  agentFrameworkAdapters,
  buildGovernedToolRequest,
  createAgentFrameworkAdapter,
  fromAutoGenToolCall,
  fromCrewAITask,
  fromLangGraphToolCall,
  fromLangChainToolCall,
  fromLlamaIndexToolCall,
  fromLiteLLMToolCall,
  fromN8NNodeExecution,
  fromOpenAIAgentsToolCall,
  fromPydanticAIToolCall,
  fromRawMCPToolCall,
  fromSemanticKernelFunctionCall,
  fromZapierWebhookCall,
  toOpenAIFunctionTool,
  type HelmGovernanceClient,
} from "./agent-frameworks.js";

describe("agent framework adapters", () => {
  it("catalogs the frameworks tracked against Microsoft AGT coverage", () => {
    expect(agentFrameworkAdapters.map((adapter) => adapter.framework)).toEqual([
      "langchain",
      "langgraph",
      "autogen",
      "crewai",
      "openai-agents",
      "semantic-kernel",
      "pydantic-ai",
      "llamaindex",
      "litellm",
      "n8n",
      "zapier-webhook",
      "raw-mcp",
    ]);
  });

  it("normalizes LangGraph tool calls", () => {
    const action = fromLangGraphToolCall({
      id: "call-lg",
      name: "web.search",
      args: { query: "agent governance toolkit" },
      metadata: { graph: "due-diligence" },
    });

    expect(action).toMatchObject({
      framework: "langgraph",
      toolName: "web.search",
      toolCallId: "call-lg",
      arguments: { query: "agent governance toolkit" },
      metadata: { graph: "due-diligence" },
    });
  });

  it("normalizes CrewAI task calls", () => {
    const action = fromCrewAITask({
      id: "crew-call",
      task: "research-task",
      agent: "researcher",
      tool: { name: "fetch_url", description: "Fetch a URL" },
      input: { url: "https://example.test" },
    });

    expect(action).toMatchObject({
      framework: "crewai",
      toolName: "fetch_url",
      taskId: "research-task",
      agentId: "researcher",
      description: "Fetch a URL",
      arguments: { url: "https://example.test" },
    });
  });

  it("normalizes OpenAI Agents SDK function arguments from JSON", () => {
    const action = fromOpenAIAgentsToolCall({
      id: "call-openai",
      function: {
        name: "file.write",
        arguments: '{"path":"/tmp/out.txt","content":"ok"}',
      },
    });

    expect(action).toMatchObject({
      framework: "openai-agents",
      toolName: "file.write",
      toolCallId: "call-openai",
      arguments: { path: "/tmp/out.txt", content: "ok" },
    });
  });

  it("normalizes PydanticAI and LlamaIndex variants", () => {
    expect(
      fromPydanticAIToolCall({
        tool_call_id: "pd-call",
        tool_name: "lookup_customer",
        args: '{"customer_id":"cus_123"}',
        agent: "support-agent",
      }),
    ).toMatchObject({
      framework: "pydantic-ai",
      toolName: "lookup_customer",
      toolCallId: "pd-call",
      agentId: "support-agent",
      arguments: { customer_id: "cus_123" },
    });

    expect(
      fromLlamaIndexToolCall({
        id: "llama-call",
        toolName: "retrieve_context",
        kwargs: ["policy", "evidence"],
      }),
    ).toMatchObject({
      framework: "llamaindex",
      toolName: "retrieve_context",
      toolCallId: "llama-call",
      arguments: { items: ["policy", "evidence"] },
    });
  });

  it("normalizes the 2026 framework middleware set into pre-dispatch actions", () => {
    expect(
      fromLangChainToolCall({
        id: "lc-call",
        name: "retriever.lookup",
        args: { q: "boundary" },
        runId: "run-lc",
      }),
    ).toMatchObject({
      framework: "langchain",
      toolName: "retriever.lookup",
      runId: "run-lc",
    });

    expect(
      fromAutoGenToolCall({
        id: "ag-call",
        tool: "shell.exec",
        args: { command: "make test" },
        agent: "coder",
      }),
    ).toMatchObject({ framework: "autogen", toolName: "shell.exec", agentId: "coder" });

    expect(
      fromSemanticKernelFunctionCall({
        pluginName: "Files",
        functionName: "Write",
        arguments: { path: "/tmp/out" },
      }),
    ).toMatchObject({ framework: "semantic-kernel", toolName: "Files.Write" });

    expect(
      fromLiteLLMToolCall({
        function: { name: "db.query", arguments: "{}" },
        model: "gpt-4.1",
      }),
    ).toMatchObject({ framework: "litellm", toolName: "db.query" });

    expect(
      fromN8NNodeExecution({
        id: "n8n-node",
        node: "http.request",
        parameters: { url: "https://example.test" },
        workflowId: "wf-1",
      }),
    ).toMatchObject({ framework: "n8n", toolName: "http.request", runId: "wf-1" });

    expect(
      fromZapierWebhookCall({
        id: "zap-call",
        action: "crm.update",
        payload: { id: "lead-1" },
        zapId: "zap-1",
      }),
    ).toMatchObject({ framework: "zapier-webhook", toolName: "crm.update", runId: "zap-1" });

    expect(
      fromRawMCPToolCall({
        id: "mcp-call",
        serverId: "srv-1",
        toolName: "files.read",
        args: { path: "/tmp/a" },
        scopes: ["tools.call"],
      }),
    ).toMatchObject({ framework: "raw-mcp", toolName: "files.read", agentId: "srv-1" });
  });

  it("builds an OpenAI-compatible HELM request with the original action in the policy prompt", () => {
    const action = fromOpenAIAgentsToolCall({
      id: "call-openai",
      function: {
        name: "shell.exec",
        arguments: { command: "npm test" },
      },
    });

    const request = buildGovernedToolRequest(action, {
      model: "helm-governance",
    });

    expect(request.model).toBe("helm-governance");
    expect(request.temperature).toBe(0);
    expect(request.tools?.[0]._function?.name).toBe("shell_exec");
    expect(request.messages[1].content).toContain(
      '"framework": "openai-agents"',
    );
    expect(request.messages[1].content).toContain('"tool_name": "shell.exec"');
  });

  it("submits through the receipt-bearing client path", async () => {
    const client = {
      chatCompletionsWithReceipt: vi.fn().mockResolvedValue({
        response: { id: "chatcmpl-1" },
        governance: {
          receiptId: "receipt-1",
          status: "APPROVED",
          outputHash: "hash",
          lamportClock: 1,
          reasonCode: "ALLOW",
          decisionId: "decision-1",
          proofGraphNode: "node-1",
          signature: "sig",
          toolCalls: 1,
        },
      }),
    } satisfies HelmGovernanceClient;

    const adapter = createAgentFrameworkAdapter(client, {
      model: "helm-governance",
      metadata: { environment: "test" },
    });
    const result = await adapter.submit(
      fromLangGraphToolCall({
        name: "search",
        args: { q: "helm" },
        metadata: { run: "r1" },
      }),
    );

    expect(client.chatCompletionsWithReceipt).toHaveBeenCalledTimes(1);
    expect(result.governance.receiptId).toBe("receipt-1");
    expect(result.action.metadata).toEqual({ environment: "test", run: "r1" });
  });

  it("rejects framework events without a tool name", () => {
    expect(() =>
      fromLangGraphToolCall({ args: { query: "missing tool" } }),
    ).toThrow("langgraph adapter requires a tool name");
  });

  it("keeps original tool name in metadata while sanitizing OpenAI function names", () => {
    const tool = toOpenAIFunctionTool(
      fromOpenAIAgentsToolCall({
        function: {
          name: "browser.open/url",
          arguments: {},
        },
      }),
    );

    expect(tool._function?.name).toBe("browser_open_url");
  });
});
