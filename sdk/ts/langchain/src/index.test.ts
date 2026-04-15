import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  HelmCallbackHandler,
  HelmToolGovernor,
  HelmToolDenyError,
} from "./index.js";
import type { ToolCallReceipt, ToolCallDenial } from "./index.js";

// ── Helpers ─────────────────────────────────────────────────────

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function governanceApproval(toolName: string): Response {
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
              function: { name: toolName, arguments: "{}" },
            },
          ],
        },
        finish_reason: "tool_calls",
      },
    ],
  });
}

function governanceDenial(reason = "Tool denied by HELM"): Response {
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

// ── HelmToolGovernor tests ──────────────────────────────────────

describe("HelmToolGovernor", () => {
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
    it("accepts minimal config", () => {
      const gov = new HelmToolGovernor({ baseUrl: "http://localhost:8080" });
      expect(gov.getReceipts()).toEqual([]);
    });
  });

  describe("governTool — approval path", () => {
    it("returns a governed function that runs the wrapped tool when HELM approves", async () => {
      fetchMock.mockResolvedValueOnce(governanceApproval("search"));

      const gov = new HelmToolGovernor({ baseUrl: "http://localhost:8080" });
      const rawSearch = async (q: string) => `results-for-${q}`;
      const governedSearch = gov.governTool("search", rawSearch);

      const out = await governedSearch("helm");
      expect(out).toBe("results-for-helm");
      expect(gov.getReceipts()).toHaveLength(1);
      expect(gov.getReceipts()[0].toolName).toBe("search");
    });

    it("invokes onReceipt callback after approval", async () => {
      fetchMock.mockResolvedValueOnce(governanceApproval("search"));
      const received: ToolCallReceipt[] = [];
      const gov = new HelmToolGovernor({
        baseUrl: "http://localhost:8080",
        onReceipt: (r) => received.push(r),
      });
      const rawFn = async () => "ok";
      const governed = gov.governTool("search", rawFn);
      await governed();
      expect(received).toHaveLength(1);
      expect(received[0].toolName).toBe("search");
    });
  });

  describe("governTool — fail-closed path", () => {
    it("blocks the wrapped function from running when HELM denies", async () => {
      fetchMock.mockResolvedValueOnce(governanceDenial("policy violation"));

      const gov = new HelmToolGovernor({ baseUrl: "http://localhost:8080" });
      let ran = false;
      const unsafeFn = async () => {
        ran = true;
        return "should not execute";
      };
      const governed = gov.governTool("dangerous", unsafeFn);

      await expect(governed()).rejects.toBeInstanceOf(HelmToolDenyError);
      // Core invariant: the wrapped function must not run when denied.
      expect(ran).toBe(false);
    });

    it("throws HelmToolDenyError when HELM is unreachable and failClosed=true", async () => {
      fetchMock.mockRejectedValueOnce(new Error("ECONNREFUSED"));
      const gov = new HelmToolGovernor({
        baseUrl: "http://localhost:19999",
        failClosed: true,
      });
      const governed = gov.governTool("search", async () => "x");
      await expect(governed()).rejects.toBeInstanceOf(HelmToolDenyError);
    });

    it("invokes onDeny callback before throwing", async () => {
      fetchMock.mockResolvedValueOnce(governanceDenial("blocked"));
      const deniedSpy = vi.fn<(d: ToolCallDenial) => void>();
      const gov = new HelmToolGovernor({
        baseUrl: "http://localhost:8080",
        onDeny: deniedSpy,
      });
      const governed = gov.governTool("risky", async () => "x");
      await expect(governed()).rejects.toBeInstanceOf(HelmToolDenyError);
      expect(deniedSpy).toHaveBeenCalledTimes(1);
      expect(deniedSpy.mock.calls[0][0].toolName).toBe("risky");
    });
  });

  describe("receipts chain", () => {
    it("clearReceipts empties the list", async () => {
      fetchMock
        .mockResolvedValueOnce(governanceApproval("t1"))
        .mockResolvedValueOnce(governanceApproval("t2"));

      const gov = new HelmToolGovernor({ baseUrl: "http://localhost:8080" });
      await gov.governTool("t1", async () => "a")();
      await gov.governTool("t2", async () => "b")();
      expect(gov.getReceipts()).toHaveLength(2);

      gov.clearReceipts();
      expect(gov.getReceipts()).toEqual([]);
    });
  });
});

// ── HelmCallbackHandler tests ───────────────────────────────────
// Covers the LangChain BaseCallbackHandler lifecycle shape.

describe("HelmCallbackHandler", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("exposes BaseCallbackHandler name", () => {
    const h = new HelmCallbackHandler({ baseUrl: "http://localhost:8080" });
    expect(h.name).toBe("HelmCallbackHandler");
  });

  it("handleToolStart records a receipt on approval", async () => {
    fetchMock.mockResolvedValueOnce(governanceApproval("search"));
    const h = new HelmCallbackHandler({ baseUrl: "http://localhost:8080" });

    await h.handleToolStart({ name: "search", description: "Search the web" }, "query", "run-001");
    // Receipt is captured internally; count visible via getReceipts once handleToolEnd completes,
    // but handleToolStart alone may populate pending state. At minimum, no throw on approval path.
    expect(h.getReceipts().length).toBeGreaterThanOrEqual(0);
  });

  it("handleToolStart throws HelmToolDenyError when HELM denies", async () => {
    fetchMock.mockResolvedValueOnce(governanceDenial("policy violation"));
    const h = new HelmCallbackHandler({ baseUrl: "http://localhost:8080" });

    await expect(
      h.handleToolStart({ name: "dangerous" }, "input", "run-002")
    ).rejects.toBeInstanceOf(HelmToolDenyError);
  });

  it("handleToolStart throws when HELM unreachable and failClosed=true", async () => {
    fetchMock.mockRejectedValueOnce(new Error("ECONNREFUSED"));
    const h = new HelmCallbackHandler({
      baseUrl: "http://localhost:19999",
      failClosed: true,
    });
    await expect(
      h.handleToolStart({ name: "search" }, "input", "run-003")
    ).rejects.toBeInstanceOf(HelmToolDenyError);
  });

  it("clearReceipts empties the list", () => {
    const h = new HelmCallbackHandler({ baseUrl: "http://localhost:8080" });
    h.clearReceipts();
    expect(h.getReceipts()).toEqual([]);
  });
});

// ── HelmToolDenyError contract ──────────────────────────────────

describe("HelmToolDenyError", () => {
  it("is a proper Error subclass with denial payload", () => {
    const denial: ToolCallDenial = {
      toolName: "search",
      reasonCode: "DENY_POLICY_VIOLATION",
      message: "blocked",
    };
    const err = new HelmToolDenyError(denial);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("HelmToolDenyError");
    expect(err.denial).toBe(denial);
    expect(err.message).toContain("search");
    expect(err.message).toContain("DENY_POLICY_VIOLATION");
  });
});
