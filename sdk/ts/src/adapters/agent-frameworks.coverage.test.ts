import { describe, expect, it, vi } from "vitest";
import {
  createAgentFrameworkAdapter,
  fromLangGraphToolCall,
  fromLlamaIndexToolCall,
  fromN8NNodeExecution,
  fromOpenAIAgentsToolCall,
  fromSemanticKernelFunctionCall,
  fromZapierWebhookCall,
  fromRawMCPToolCall,
  toOpenAIFunctionTool,
  type HelmGovernanceClient,
} from "./agent-frameworks.js";

describe("agent framework adapter coverage branches", () => {
  it("normalizes fallback argument shapes", () => {
    expect(fromOpenAIAgentsToolCall({ name: "tool", arguments: "not json" }).arguments).toEqual({ value: "not json" });
    expect(fromOpenAIAgentsToolCall({ name: "tool", arguments: "" }).arguments).toEqual({});
    expect(fromOpenAIAgentsToolCall({ name: "tool", arguments: [1, 2] }).arguments).toEqual({ items: [1, 2] });
    expect(fromOpenAIAgentsToolCall({ name: "tool", arguments: 7 }).arguments).toEqual({ value: 7 });
    expect(fromSemanticKernelFunctionCall({ pluginName: "files", functionName: "read", arguments: {} }).toolName).toBe("files.read");
    expect(fromSemanticKernelFunctionCall({ functionName: "read", arguments: {} }).toolName).toBe("read");
    expect(fromLlamaIndexToolCall({ tool_name: "search", input: null }).arguments).toEqual({});
    expect(fromN8NNodeExecution({ name: "http", input: { url: "https://example.test" } }).toolName).toBe("http");
    expect(fromZapierWebhookCall({ tool: "zap", payload: { id: 1 } }).toolName).toBe("zap");
  });

  it("throws on missing and unnormalizable tool names", () => {
    expect(() => fromLangGraphToolCall({ args: {} })).toThrow("requires a tool name");
    expect(() => toOpenAIFunctionTool({
      framework: "raw-mcp",
      toolName: "   ",
      arguments: {},
    })).toThrow("normalizes to an empty");
  });

  it("builds and submits with default option merging", async () => {
    const response = { response: { id: "chatcmpl", choices: [] }, governance: { receiptId: "r1" } };
    const client: HelmGovernanceClient = {
      chatCompletionsWithReceipt: vi.fn(async () => response as any),
    };
    const adapter = createAgentFrameworkAdapter(client, {
      model: "gpt-default",
      policyPrompt: "default policy",
      temperature: 0.1,
      maxTokens: 128,
      metadata: { defaulted: true },
    });
    const action = fromRawMCPToolCall({
      serverId: "srv",
      name: "file.read",
      args: { path: "/tmp/a" },
      scopes: ["fs:read"],
      metadata: { call: "one" },
    });

    const request = adapter.buildRequest(action);
    expect(request.model).toBe("gpt-default");
    expect(request.messages[1].content).toContain("file.read");

    const result = await adapter.submit(action, { model: "gpt-override", temperature: 0.2 });
    expect(result.request.model).toBe("gpt-override");
    expect(result.action.metadata).toMatchObject({ defaulted: true, call: "one" });
    expect(client.chatCompletionsWithReceipt).toHaveBeenCalledOnce();
  });
});
