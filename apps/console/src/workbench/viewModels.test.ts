import { describe, expect, it } from "vitest";
import { buildOperatorTasks, buildWorkbenchSnapshot, parseGovernedCommand } from "./viewModels";
import type { Capability } from "./types";
import type { ConsoleBootstrap, Receipt } from "../api/client";

const bootstrap: ConsoleBootstrap = {
  version: { version: "0.5.1", commit: "test", build_time: "2026-05-05T00:00:00Z" },
  workspace: { organization: "local", project: "default", environment: "test", mode: "self-hosted" },
  health: { kernel: "ready", policy: "ready", store: "ready", conformance: "ready" },
  counts: { receipts: 1, pending_approvals: 0, open_incidents: 0, mcp_tools: 1 },
  receipts: [],
  conformance: { level: "L2", status: "pass" },
  mcp: { authorization: "active", scopes: [] },
};

const receipt: Receipt = {
  receipt_id: "rcpt_escalate",
  status: "escalate",
  effect_id: "HTTP_POST",
  lamport_clock: 1,
  metadata: { action: "HTTP_POST", resource: "https://example.test/hook" },
};

function capability(status: Capability["readState"]["status"], message?: string): Capability {
  return {
    id: "approvals",
    label: "Approval ceremonies",
    group: "Core",
    status,
    sourceEndpoint: "GET /api/v1/approvals",
    readState: { status, source: "GET /api/v1/approvals", message },
    actions: [],
    records: [],
  };
}

describe("workbench view models", () => {
  it("turns unauthorized access into the first operator task", () => {
    const tasks = buildOperatorTasks({
      bootstrap: null,
      receipts: [],
      capabilities: [],
      accessState: "unauthorized",
      error: "admin key missing",
      streamState: "unauthorized",
    });

    expect(tasks[0]).toMatchObject({
      id: "access-required",
      severity: "high",
      route: "settings",
      source: "HELM_ADMIN_API_KEY",
    });
  });

  it("derives receipt tasks and condenses unavailable APIs into diagnostics", () => {
    const tasks = buildOperatorTasks({
      bootstrap,
      receipts: [receipt],
      capabilities: [capability("unavailable", "approval backend down")],
      accessState: "authorized",
      error: null,
      streamState: "live",
    });

    expect(tasks.map((task) => task.title)).toContain("Escalated action: HTTP_POST");
    expect(tasks.map((task) => task.title)).not.toContain("Approval ceremonies unavailable");

    const snapshot = buildWorkbenchSnapshot({
      bootstrap,
      receipts: [receipt],
      capabilities: [capability("unavailable", "approval backend down")],
      accessState: "authorized",
      error: null,
      streamState: "live",
      command: null,
    });
    expect(snapshot.healthSummary.label).toBe("1 route needs attention");
    expect(snapshot.diagnostics[0]).toMatchObject({
      label: "Approval ceremonies",
      message: "approval backend down",
      source: "GET /api/v1/approvals",
    });
  });

  it("emits no synthetic clear task when live inputs have no work", () => {
    const tasks = buildOperatorTasks({
      bootstrap,
      receipts: [],
      capabilities: [capability("empty")],
      accessState: "authorized",
      error: null,
      streamState: "live",
    });

    expect(tasks).toEqual([]);
  });

  it("maps slash shortcuts into governed command modes", () => {
    expect(parseGovernedCommand("/replay latest").mode).toBe("replay");
    expect(parseGovernedCommand("/approve").mode).toBe("approve");
    expect(parseGovernedCommand("HTTP_POST https://example.test/hook")).toMatchObject({
      mode: "evaluate",
      parsedAction: "HTTP_POST",
      parsedResource: "https://example.test/hook",
    });
  });
});
