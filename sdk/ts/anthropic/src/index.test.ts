import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  HelmAnthropicGovernor,
  HelmToolDenyError,
} from "./index.js";
import type {
  ClaudeToolUseBlock,
  ToolCallReceipt,
  ToolCallDenial,
} from "./index.js";

// ── Test helpers ────────────────────────────────────────────────

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function governanceApproval(toolName: string, args: Record<string, unknown>): Response {
  return jsonResponse({
    id: `chatcmpl-${Date.now()}`,
    object: "chat.completion",
    created: Date.now(),
    model: "helm-governance",
    choices: [
      {
        index: 0,
        message: {
          role: "assistant",
          content: null,
          tool_calls: [
            {
              id: `call_${Date.now()}`,
              type: "function",
              function: { name: toolName, arguments: JSON.stringify(args) },
            },
          ],
        },
        finish_reason: "tool_calls",
      },
    ],
  });
}

function governanceDenial(reason: string): Response {
  return jsonResponse({
    id: `chatcmpl-${Date.now()}`,
    object: "chat.completion",
    created: Date.now(),
    model: "helm-governance",
    choices: [
      {
        index: 0,
        message: { role: "assistant", content: reason },
        finish_reason: "stop",
      },
    ],
  });
}

function toolUseBlock(name: string, input: Record<string, unknown>): ClaudeToolUseBlock {
  return {
    type: "tool_use",
    id: `toolu_${Date.now()}`,
    name,
    input,
  };
}

// ── Tests ───────────────────────────────────────────────────────

describe("HelmAnthropicGovernor", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  describe("construction", () => {
    it("applies default config", () => {
      const gov = new HelmAnthropicGovernor({ baseUrl: "http://localhost:8080" });
      // No throw. Internal defaults are tested via behaviour below.
      expect(gov.getReceipts()).toEqual([]);
    });

    it("accepts principal override", () => {
      const gov = new HelmAnthropicGovernor({
        baseUrl: "http://localhost:8080",
        principal: "my-agent",
      });
      expect(gov.getReceipts()).toEqual([]);
    });
  });

  describe("governToolUse — approval path", () => {
    it("returns a receipt and records it when HELM approves", async () => {
      fetchMock.mockResolvedValueOnce(governanceApproval("file_read", { path: "/etc/hosts" }));

      const gov = new HelmAnthropicGovernor({ baseUrl: "http://localhost:8080" });
      const block = toolUseBlock("file_read", { path: "/etc/hosts" });
      const receipt = await gov.governToolUse(block);

      expect(receipt).not.toBeNull();
      expect(receipt!.toolName).toBe("file_read");
      expect(receipt!.toolUseId).toBe(block.id);
      expect(receipt!.status === "APPROVED" || receipt!.status === "PENDING").toBe(true);
      expect(gov.getReceipts()).toHaveLength(1);
    });

    it("invokes onReceipt callback with the receipt", async () => {
      fetchMock.mockResolvedValueOnce(governanceApproval("file_read", { path: "/x" }));
      const received: ToolCallReceipt[] = [];
      const gov = new HelmAnthropicGovernor({
        baseUrl: "http://localhost:8080",
        onReceipt: (r) => received.push(r),
      });
      await gov.governToolUse(toolUseBlock("file_read", { path: "/x" }));
      expect(received).toHaveLength(1);
      expect(received[0].toolName).toBe("file_read");
    });
  });

  describe("governToolUse — fail-closed path", () => {
    it("throws HelmToolDenyError when HELM returns a deny", async () => {
      fetchMock.mockResolvedValueOnce(governanceDenial("blocked by policy"));
      const gov = new HelmAnthropicGovernor({ baseUrl: "http://localhost:8080" });

      await expect(
        gov.governToolUse(toolUseBlock("shell_exec", { cmd: "rm -rf /" }))
      ).rejects.toBeInstanceOf(HelmToolDenyError);
    });

    it("throws HelmToolDenyError when HELM is unreachable and failClosed=true", async () => {
      fetchMock.mockRejectedValueOnce(new Error("ECONNREFUSED"));
      const gov = new HelmAnthropicGovernor({
        baseUrl: "http://localhost:19999",
        failClosed: true,
      });
      await expect(
        gov.governToolUse(toolUseBlock("search_web", { q: "x" }))
      ).rejects.toBeInstanceOf(HelmToolDenyError);
    });

    it("does not throw when HELM is unreachable and failClosed=false", async () => {
      fetchMock.mockRejectedValueOnce(new Error("ECONNREFUSED"));
      const gov = new HelmAnthropicGovernor({
        baseUrl: "http://localhost:19999",
        failClosed: false,
      });
      // Permissive open path — no throw. Receipt may be null.
      const result = await gov.governToolUse(toolUseBlock("search_web", { q: "x" }));
      expect(result === null || typeof result === "object").toBe(true);
    });

    it("invokes onDeny callback before throwing", async () => {
      fetchMock.mockResolvedValueOnce(governanceDenial("blocked"));
      const deniedSpy = vi.fn<(d: ToolCallDenial) => void>();
      const gov = new HelmAnthropicGovernor({
        baseUrl: "http://localhost:8080",
        onDeny: deniedSpy,
      });
      await expect(
        gov.governToolUse(toolUseBlock("shell_exec", {}))
      ).rejects.toBeInstanceOf(HelmToolDenyError);
      expect(deniedSpy).toHaveBeenCalledTimes(1);
      expect(deniedSpy.mock.calls[0][0].toolName).toBe("shell_exec");
    });
  });

  describe("receipts chain", () => {
    it("preserves Lamport monotonicity across successive approvals", async () => {
      fetchMock
        .mockResolvedValueOnce(governanceApproval("tool_a", {}))
        .mockResolvedValueOnce(governanceApproval("tool_b", {}))
        .mockResolvedValueOnce(governanceApproval("tool_c", {}));

      const gov = new HelmAnthropicGovernor({ baseUrl: "http://localhost:8080" });
      await gov.governToolUse(toolUseBlock("tool_a", {}));
      await gov.governToolUse(toolUseBlock("tool_b", {}));
      await gov.governToolUse(toolUseBlock("tool_c", {}));

      const rs = gov.getReceipts();
      expect(rs).toHaveLength(3);
      expect(rs[0].lamportClock).toBeLessThan(rs[1].lamportClock);
      expect(rs[1].lamportClock).toBeLessThan(rs[2].lamportClock);
    });

    it("clearReceipts empties the chain without losing Lamport monotonicity for future calls", async () => {
      fetchMock
        .mockResolvedValueOnce(governanceApproval("tool_a", {}))
        .mockResolvedValueOnce(governanceApproval("tool_b", {}));

      const gov = new HelmAnthropicGovernor({ baseUrl: "http://localhost:8080" });
      await gov.governToolUse(toolUseBlock("tool_a", {}));
      const firstClock = gov.getReceipts()[0].lamportClock;

      gov.clearReceipts();
      expect(gov.getReceipts()).toEqual([]);

      await gov.governToolUse(toolUseBlock("tool_b", {}));
      expect(gov.getReceipts()).toHaveLength(1);
      // New receipt's clock must be strictly greater than the cleared one.
      expect(gov.getReceipts()[0].lamportClock).toBeGreaterThan(firstClock);
    });
  });

  describe("collectReceipts=false", () => {
    it("still runs governance but does not store receipts", async () => {
      fetchMock.mockResolvedValueOnce(governanceApproval("tool_a", {}));
      const gov = new HelmAnthropicGovernor({
        baseUrl: "http://localhost:8080",
        collectReceipts: false,
      });
      const r = await gov.governToolUse(toolUseBlock("tool_a", {}));
      expect(r).not.toBeNull();
      expect(gov.getReceipts()).toEqual([]);
    });
  });
});

describe("HelmToolDenyError", () => {
  it("is a proper Error subclass with denial payload", () => {
    const denial: ToolCallDenial = {
      toolName: "shell_exec",
      toolUseId: "toolu_x",
      args: {},
      reasonCode: "DENY_POLICY_VIOLATION",
      message: "blocked",
    };
    const err = new HelmToolDenyError(denial);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("HelmToolDenyError");
    expect(err.denial).toBe(denial);
    expect(err.message).toContain("shell_exec");
    expect(err.message).toContain("DENY_POLICY_VIOLATION");
  });
});
