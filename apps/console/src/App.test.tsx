import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";

const apiMock = vi.hoisted(() => ({
  loadBootstrap: vi.fn(),
  loadReceipts: vi.fn(),
  evaluateIntent: vi.fn(),
  runPublicDemo: vi.fn(),
  verifyPublicDemoReceipt: vi.fn(),
  tamperPublicDemoReceipt: vi.fn(),
  replayVerifyCurrentEvidence: vi.fn(),
  watchReceipts: vi.fn(),
  getConsoleAdminKey: vi.fn(() => window.sessionStorage.getItem("helm.console.admin_api_key") ?? ""),
  setConsoleAdminKey: vi.fn((value: string) => {
    if (value.trim() === "") {
      window.sessionStorage.removeItem("helm.console.admin_api_key");
      return;
    }
    window.sessionStorage.setItem("helm.console.admin_api_key", value.trim());
  }),
  hasConsoleAdminKey: vi.fn(() => (window.sessionStorage.getItem("helm.console.admin_api_key") ?? "").trim() !== ""),
  isUnauthorizedError: vi.fn((error: unknown) => {
    if (typeof error !== "object" || error === null || !("status" in error)) return false;
    const status = Number((error as { readonly status?: unknown }).status);
    return status === 401 || status === 403;
  }),
}));

vi.mock("./api/client", () => apiMock);
vi.mock("@copilotkit/react-core/v2/styles.css", () => ({}));
vi.mock("@copilotkit/react-core", () => ({
  CopilotKit: ({ children }: { readonly children: ReactNode }) => children,
}));
vi.mock("@copilotkit/react-core/v2/headless", () => ({
  useComponent: vi.fn(),
  useFrontendTool: vi.fn(),
}));
vi.mock("@copilotkit/react-core/v2", () => ({
  useRenderTool: vi.fn(),
}));

import { App } from "./App";

function bootstrapFixture() {
  return {
    version: { version: "0.5.0", commit: "test", build_time: "2026-05-05T00:00:00Z" },
    workspace: { organization: "local", project: "default", environment: "production", mode: "self-hosted" },
    health: { kernel: "ready", policy: "ready", store: "ready", conformance: "pending" },
    counts: { receipts: 3, pending_approvals: 0, open_incidents: 0, mcp_tools: 2 },
    receipts: [
      {
        receipt_id: "rcpt_verified",
        decision_id: "dec_verified",
        effect_id: "FILE_READ",
        status: "allow",
        timestamp: "2026-05-05T00:02:00Z",
        executor_id: "operator@local",
        blob_hash: "sha256:verified-blob",
        output_hash: "sha256:verified-output",
        signature: "sig",
        lamport_clock: 3,
        metadata: { action: "FILE_READ", resource: "/tmp/report.txt", verification_status: "PASS" },
      },
      {
        receipt_id: "rcpt_test",
        decision_id: "dec_test",
        effect_id: "LLM_INFERENCE",
        status: "allow",
        timestamp: "2026-05-05T00:01:00Z",
        executor_id: "operator@local",
        blob_hash: "sha256:abc",
        output_hash: "sha256:def",
        signature: "sig",
        lamport_clock: 2,
        metadata: { action: "LLM_INFERENCE", resource: "gpt-4.1-mini" },
      },
      {
        receipt_id: "rcpt_review",
        decision_id: "dec_review",
        effect_id: "HTTP_POST",
        status: "escalate",
        timestamp: "2026-05-05T00:00:00Z",
        executor_id: "auditor@local",
        lamport_clock: 1,
        metadata: { action: "HTTP_POST", resource: "https://example.test/hook" },
      },
    ],
    conformance: { level: "L2", status: "pass", report_id: "conf_test" },
    mcp: { authorization: "active", scopes: ["tools:filesystem.read"] },
  };
}

describe("HELM Console", () => {
  afterEach(() => {
    cleanup();
  });

  beforeEach(() => {
    window.localStorage.clear();
    window.sessionStorage.clear();
    document.documentElement.removeAttribute("data-density");
    vi.clearAllMocks();
    apiMock.loadBootstrap.mockResolvedValue(bootstrapFixture());
    apiMock.loadReceipts.mockResolvedValue([]);
    apiMock.evaluateIntent.mockResolvedValue(undefined);
    apiMock.runPublicDemo.mockResolvedValue({
      action_id: "export_customer_list",
      selected_action: "Export customer list",
      active_policy: { policy_id: "agent_tool_call_boundary" },
      verdict: "DENY",
      reason_code: "MISSING_REQUIREMENT",
      receipt: {
        receipt_id: "rcpt_demo",
        decision_id: "dec_demo",
        effect_id: "demo.export_customer_list",
        status: "DENY",
        timestamp: "2026-05-05T00:03:00Z",
        executor_id: "demo.agent@helm-ai-kernel",
        output_hash: "sha256:demo",
        signature: "sig",
        lamport_clock: 4,
        metadata: { action_id: "export_customer_list", source: "public.demo" },
      },
      proof_refs: { decision_id: "dec_demo", receipt_id: "rcpt_demo", receipt_hash: "sha256:receipt" },
      verification_hint: "/api/demo/verify",
      sandbox_label: "HELM AI Kernel public sandbox - no external side effects",
      helm_ai_kernel_version: "0.5.0",
    });
    apiMock.verifyPublicDemoReceipt.mockResolvedValue({
      valid: true,
      signature_valid: true,
      hash_matches: true,
      reason: "signature and receipt hash verified",
      receipt_hash: "sha256:receipt",
      expected_receipt_hash: "sha256:receipt",
    });
    apiMock.tamperPublicDemoReceipt.mockResolvedValue({
      valid: false,
      signature_valid: false,
      hash_matches: false,
      reason: "signature verification failed",
      receipt_hash: "sha256:tampered",
      expected_receipt_hash: "sha256:receipt",
      original_hash: "sha256:receipt",
      tampered_hash: "sha256:tampered",
    });
    apiMock.replayVerifyCurrentEvidence.mockResolvedValue({ verdict: "PASS", checks: { replay: "PASS" } });
    apiMock.watchReceipts.mockReturnValue(() => undefined);
  });

  it("renders the command shell with live receipt primitives", async () => {
    render(<App />);
    expect(await screen.findByRole("heading", { name: "Governance command" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Agent tool call boundary" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Intent → Policy → Decision → Receipt → Evidence" })).toBeInTheDocument();
    expect(screen.getAllByText("rcpt_test").length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: /Evaluate intent/i })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "MCP quarantine" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Sandbox grants" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Evidence export" })).toBeInTheDocument();
  });

  it("runs the public proof workflow and shows tamper failure", async () => {
    render(<App />);
    expect(await screen.findByRole("heading", { name: "Agent tool call boundary" })).toBeInTheDocument();
    expect(screen.getByText("Agent tool call")).toBeInTheDocument();
    expect(screen.getByText("Tamper fails")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("sample action"), { target: { value: "export_customer_list" } });
    fireEvent.click(screen.getByRole("button", { name: "Run scenario" }));

    await waitFor(() => expect(apiMock.runPublicDemo).toHaveBeenCalledWith("export_customer_list"));
    expect(await screen.findByText("MISSING_REQUIREMENT")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Verify receipt" }));
    await waitFor(() => expect(apiMock.verifyPublicDemoReceipt).toHaveBeenCalledWith(
      expect.objectContaining({ receipt_id: "rcpt_demo" }),
      "sha256:receipt",
    ));
    expect(await screen.findByText(/valid · signature and receipt hash verified/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Tamper" }));
    await waitFor(() => expect(apiMock.tamperPublicDemoReceipt).toHaveBeenCalledWith(
      expect.objectContaining({ receipt_id: "rcpt_demo" }),
      "sha256:receipt",
    ));
    expect(await screen.findByText(/invalid · sha256:tampered/i)).toBeInTheDocument();
  });

  it("does not report hashes or signatures as verified without explicit verification metadata", async () => {
    render(<App />);

    const table = await screen.findByRole("table", { name: "Receipt stream" });
    const pendingButton = within(table).getByRole("button", { name: "Select receipt rcpt_test" });
    const pendingRow = pendingButton.closest("tr");
    if (!(pendingRow instanceof HTMLElement)) throw new Error("Pending receipt row not found");
    expect(within(pendingRow).getByLabelText("PENDING. Verification has not completed.")).toBeInTheDocument();
    expect(within(pendingRow).queryByLabelText("VERIFIED. Signature, manifest, or source chain verified.")).not.toBeInTheDocument();

    const verifiedButton = within(table).getByRole("button", { name: "Select receipt rcpt_verified" });
    const verifiedRow = verifiedButton.closest("tr");
    if (!(verifiedRow instanceof HTMLElement)) throw new Error("Verified receipt row not found");
    expect(within(verifiedRow).getByLabelText("VERIFIED. Signature, manifest, or source chain verified.")).toBeInTheDocument();
  });

  it("selects receipts through a semantic table action", async () => {
    render(<App />);

    const table = await screen.findByRole("table", { name: "Receipt stream" });
    const selectReceipt = within(table).getByRole("button", { name: "Select receipt rcpt_test" });

    fireEvent.click(selectReceipt);

    expect(screen.getByRole("heading", { name: "rcpt_test" })).toBeInTheDocument();
    expect(screen.getByText("present; verification pending")).toBeInTheDocument();
  });

  it("shows an explicit protected API access state", async () => {
    apiMock.loadBootstrap.mockRejectedValueOnce({ status: 401 });

    render(<App />);

    expect(await screen.findByRole("heading", { name: "Console access required" })).toBeInTheDocument();
    expect(screen.getAllByText(/Protected Console APIs require HELM_ADMIN_API_KEY/i).length).toBeGreaterThan(0);

    fireEvent.change(screen.getByLabelText("admin key"), { target: { value: "test-admin-key" } });
    fireEvent.click(screen.getByRole("button", { name: "Use key" }));

    await waitFor(() => expect(apiMock.setConsoleAdminKey).toHaveBeenCalledWith("test-admin-key"));
  });

  it("only exposes controls that perform a local action", async () => {
    render(<App />);
    expect(await screen.findByRole("heading", { name: "Governance command" })).toBeInTheDocument();

    expect(screen.queryByRole("button", { name: /Filters/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Approve/i })).not.toBeInTheDocument();
    expect(screen.getByLabelText("Workspace environment")).toHaveTextContent("local · production");
    expect(screen.queryByRole("button", { name: /local · production/i })).not.toBeInTheDocument();

    const comfortable = screen.getByRole("button", { name: "Comfortable" });
    expect(comfortable).toHaveAttribute("aria-pressed", "false");
    fireEvent.click(comfortable);
    await waitFor(() => expect(document.documentElement).toHaveAttribute("data-density", "comfortable"));
    expect(comfortable).toHaveAttribute("aria-pressed", "true");
  });
});
