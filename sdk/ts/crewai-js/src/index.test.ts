import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { HelmCrewGovernor, HelmTaskDenyError } from "./index.js";
import type { TaskReceipt, TaskDenial } from "./index.js";

// ── Helpers ─────────────────────────────────────────────────────

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function governanceApproval(taskName: string): Response {
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
              function: { name: taskName, arguments: "{}" },
            },
          ],
        },
        finish_reason: "tool_calls",
      },
    ],
  });
}

function governanceDenial(reason = "Task denied by HELM"): Response {
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

// ── Tests ───────────────────────────────────────────────────────

describe("HelmCrewGovernor", () => {
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
      const gov = new HelmCrewGovernor({ baseUrl: "http://localhost:8080" });
      expect(gov.getReceipts()).toEqual([]);
    });

    it("accepts principal override", () => {
      const gov = new HelmCrewGovernor({
        baseUrl: "http://localhost:8080",
        principal: "research-crew-1",
      });
      expect(gov.getReceipts()).toEqual([]);
    });
  });

  describe("governTask — approval path", () => {
    it("executes the wrapped task and records a receipt when HELM approves", async () => {
      fetchMock.mockResolvedValueOnce(governanceApproval("research"));
      const gov = new HelmCrewGovernor({ baseUrl: "http://localhost:8080" });

      const result = await gov.governTask("research", async () => ({ data: "ok" }));
      expect(result).toEqual({ data: "ok" });
      expect(gov.getReceipts()).toHaveLength(1);
      expect(gov.getReceipts()[0].taskName).toBe("research");
    });

    it("passes context through to governance and still runs task", async () => {
      fetchMock.mockResolvedValueOnce(governanceApproval("summarize"));
      const gov = new HelmCrewGovernor({ baseUrl: "http://localhost:8080" });

      const out = await gov.governTask(
        "summarize",
        async () => "summary",
        { documentId: "doc-42" }
      );
      expect(out).toBe("summary");
      expect(fetchMock).toHaveBeenCalledTimes(1);

      // Inspect the request body — the context payload should contain our field.
      const args = fetchMock.mock.calls[0];
      const init = args[1] as RequestInit;
      const bodyText = init.body as string;
      expect(bodyText).toContain("doc-42");
    });

    it("invokes onReceipt after approved task", async () => {
      fetchMock.mockResolvedValueOnce(governanceApproval("research"));
      const received: TaskReceipt[] = [];
      const gov = new HelmCrewGovernor({
        baseUrl: "http://localhost:8080",
        onReceipt: (r) => received.push(r),
      });
      await gov.governTask("research", async () => "ok");
      expect(received).toHaveLength(1);
      expect(received[0].taskName).toBe("research");
    });
  });

  describe("governTask — fail-closed path", () => {
    it("throws HelmTaskDenyError when HELM denies the task", async () => {
      fetchMock.mockResolvedValueOnce(governanceDenial("policy violation"));
      const gov = new HelmCrewGovernor({ baseUrl: "http://localhost:8080" });

      let executorRan = false;
      await expect(
        gov.governTask("risky", async () => {
          executorRan = true;
          return "should not run";
        })
      ).rejects.toBeInstanceOf(HelmTaskDenyError);

      // Critical invariant: the executor must NOT run when HELM denies.
      expect(executorRan).toBe(false);
    });

    it("throws HelmTaskDenyError when HELM is unreachable and failClosed=true", async () => {
      fetchMock.mockRejectedValueOnce(new Error("ECONNREFUSED"));
      const gov = new HelmCrewGovernor({
        baseUrl: "http://localhost:19999",
        failClosed: true,
      });
      await expect(
        gov.governTask("research", async () => "x")
      ).rejects.toBeInstanceOf(HelmTaskDenyError);
    });

    it("invokes onDeny callback before throwing", async () => {
      fetchMock.mockResolvedValueOnce(governanceDenial("blocked"));
      const deniedSpy = vi.fn<(d: TaskDenial) => void>();
      const gov = new HelmCrewGovernor({
        baseUrl: "http://localhost:8080",
        onDeny: deniedSpy,
      });
      await expect(
        gov.governTask("risky", async () => "x")
      ).rejects.toBeInstanceOf(HelmTaskDenyError);
      expect(deniedSpy).toHaveBeenCalledTimes(1);
      expect(deniedSpy.mock.calls[0][0].taskName).toBe("risky");
    });
  });

  describe("receipts chain", () => {
    it("clearReceipts empties the list", async () => {
      fetchMock
        .mockResolvedValueOnce(governanceApproval("t1"))
        .mockResolvedValueOnce(governanceApproval("t2"));

      const gov = new HelmCrewGovernor({ baseUrl: "http://localhost:8080" });
      await gov.governTask("t1", async () => "a");
      await gov.governTask("t2", async () => "b");
      expect(gov.getReceipts()).toHaveLength(2);

      gov.clearReceipts();
      expect(gov.getReceipts()).toEqual([]);
    });
  });
});

describe("HelmTaskDenyError", () => {
  it("is a proper Error subclass with denial payload", () => {
    const denial: TaskDenial = {
      taskName: "risky",
      reasonCode: "DENY_POLICY_VIOLATION",
      message: "blocked",
    };
    const err = new HelmTaskDenyError(denial);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("HelmTaskDenyError");
    expect(err.denial).toBe(denial);
    expect(err.message).toContain("risky");
    expect(err.message).toContain("DENY_POLICY_VIOLATION");
  });
});
