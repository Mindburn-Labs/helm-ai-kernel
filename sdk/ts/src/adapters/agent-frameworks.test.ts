import { describe, expect, it, vi } from "vitest";
import {
  agentFrameworkAdapters,
  buildGovernedToolRequest,
  createAgentFrameworkAdapter,
  fromCrewAITask,
  fromLangGraphToolCall,
  fromLlamaIndexToolCall,
  fromOpenAIAgentsToolCall,
  fromPydanticAIToolCall,
  toOpenAIFunctionTool,
  type HelmGovernanceClient,
} from "./agent-frameworks.js";

describe("agent framework adapters", () => {
  it("catalogs the frameworks tracked against Microsoft AGT coverage", () => {
    expect(agentFrameworkAdapters.map((adapter) => adapter.framework)).toEqual([
      "langgraph",
      "crewai",
      "openai-agents",
      "pydantic-ai",
      "llamaindex",
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
