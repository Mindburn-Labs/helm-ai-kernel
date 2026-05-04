import { render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { describe, expect, it, vi } from "vitest";
import { App } from "./App";

vi.mock("./api/client", () => ({
  loadBootstrap: async () => ({
    version: { version: "0.4.0", commit: "test", build_time: "2026-05-05T00:00:00Z" },
    workspace: { organization: "local", project: "default", environment: "production", mode: "self-hosted" },
    health: { kernel: "ready", policy: "ready", store: "ready", conformance: "pending" },
    counts: { receipts: 1, pending_approvals: 0, open_incidents: 0, mcp_tools: 2 },
    receipts: [
      {
        receipt_id: "rcpt_test",
        decision_id: "dec_test",
        effect_id: "LLM_INFERENCE",
        status: "allow",
        timestamp: "2026-05-05T00:00:00Z",
        executor_id: "operator@local",
        blob_hash: "sha256:abc",
        output_hash: "sha256:def",
        signature: "sig",
        lamport_clock: 1,
        metadata: { action: "LLM_INFERENCE", resource: "gpt-4.1-mini" },
      },
    ],
    conformance: { level: "L2", status: "pass", report_id: "conf_test" },
    mcp: { authorization: "active", scopes: ["tools:filesystem.read"] },
  }),
  loadReceipts: async () => [],
  evaluateIntent: async () => undefined,
  watchReceipts: () => () => undefined,
}));

describe("HELM Console", () => {
  it("renders the command shell with live receipt primitives", async () => {
    render(<App />);
    expect(await screen.findByRole("heading", { name: "Governance command" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Intent → Policy → Decision → Receipt → Evidence" })).toBeInTheDocument();
    expect(screen.getAllByText("rcpt_test").length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: /Evaluate intent/i })).toBeInTheDocument();
  });
});
