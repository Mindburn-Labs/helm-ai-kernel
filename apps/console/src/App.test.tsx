import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";

const apiMock = vi.hoisted(() => ({
  loadBootstrap: vi.fn(),
  loadReceipts: vi.fn(),
  loadReceiptDetail: vi.fn(),
  evaluateIntent: vi.fn(),
  runPublicDemo: vi.fn(),
  verifyPublicDemoReceipt: vi.fn(),
  tamperPublicDemoReceipt: vi.fn(),
  replayVerifyCurrentEvidence: vi.fn(),
  replayVerifyEvidence: vi.fn(),
  watchReceipts: vi.fn(),
  loadConsoleDiagnostics: vi.fn(),
  loadConsoleSurfaceCatalog: vi.fn(),
  loadConsoleSurface: vi.fn(),
  loadEndpoint: vi.fn(),
  listApprovals: vi.fn(),
  createApproval: vi.fn(),
  createApprovalWebAuthnChallenge: vi.fn(),
  assertApprovalWebAuthn: vi.fn(),
  transitionApproval: vi.fn(),
  listMcpRegistry: vi.fn(),
  loadMcpCapabilities: vi.fn(),
  scanMcpRegistry: vi.fn(),
  approveMcpRegistry: vi.fn(),
  approveMcpServer: vi.fn(),
  revokeMcpServer: vi.fn(),
  listMcpAuthProfiles: vi.fn(),
  updateMcpAuthProfile: vi.fn(),
  authorizeMcpCall: vi.fn(),
  listSandboxProfiles: vi.fn(),
  listSandboxGrants: vi.fn(),
  createSandboxGrant: vi.fn(),
  verifySandboxGrant: vi.fn(),
  preflightSandboxGrant: vi.fn(),
  inspectSandboxRuntime: vi.fn(),
  listAgentIdentities: vi.fn(),
  loadAuthzHealth: vi.fn(),
  checkAuthz: vi.fn(),
  listAuthzSnapshots: vi.fn(),
  listBudgets: vi.fn(),
  updateBudget: vi.fn(),
  listBoundaryRecords: vi.fn(),
  loadBoundaryStatus: vi.fn(),
  loadBoundaryCapabilities: vi.fn(),
  listBoundaryCheckpoints: vi.fn(),
  createBoundaryCheckpoint: vi.fn(),
  verifyBoundaryRecord: vi.fn(),
  verifyBoundaryCheckpoint: vi.fn(),
  listEvidenceEnvelopes: vi.fn(),
  createEvidenceEnvelope: vi.fn(),
  loadEvidenceEnvelopePayload: vi.fn(),
  verifyEvidenceEnvelope: vi.fn(),
  exportEvidence: vi.fn(),
  verifyEvidenceBundleBase64: vi.fn(),
  listProofgraphSessions: vi.fn(),
  loadProofgraphSessionReceipts: vi.fn(),
  loadProofgraphReceipt: vi.fn(),
  listVerificationScopes: vi.fn(),
  createVerificationScope: vi.fn(),
  loadVerificationScope: vi.fn(),
  verifyVerificationScope: vi.fn(),
  listConformanceReports: vi.fn(),
  listConformanceVectors: vi.fn(),
  loadConformanceNegative: vi.fn(),
  runConformance: vi.fn(),
  listHarnessTraces: vi.fn(),
  createHarnessTrace: vi.fn(),
  loadHarnessTrace: vi.fn(),
  verifyHarnessTrace: vi.fn(),
  listPlanTransactions: vi.fn(),
  createPlanTransaction: vi.fn(),
  loadPlanTransaction: vi.fn(),
  verifyPlanTransaction: vi.fn(),
  listHarnessChangeContracts: vi.fn(),
  createHarnessChangeContract: vi.fn(),
  loadHarnessChangeContract: vi.fn(),
  approveHarnessChangeContract: vi.fn(),
  verifyHarnessChangeContract: vi.fn(),
  verifyGUIActionReceipt: vi.fn(),
  loadCoexistenceCapabilities: vi.fn(),
  loadTelemetryOtelConfig: vi.fn(),
  exportTelemetry: vi.fn(),
  addTrustKey: vi.fn(),
  revokeTrustKey: vi.fn(),
  listLaunchpadApps: vi.fn(),
  listLaunchpadSubstrates: vi.fn(),
  loadLaunchpadMatrix: vi.fn(),
  planLaunchpad: vi.fn(),
  launchLaunchpad: vi.fn(),
  listLaunchpadRuns: vi.fn(),
  createLaunchpadRuntimeRun: vi.fn(),
  loadLaunchpadRunDetail: vi.fn(),
  loadLaunchpadRunEvents: vi.fn(),
  loadLaunchpadRunReceipts: vi.fn(),
  loadLaunchpadRunLogs: vi.fn(),
  exportLaunchpadRunEvidence: vi.fn(),
  simulateLaunchpadPolicy: vi.fn(),
  inspectLaunchpadSandbox: vi.fn(),
  loadLaunchpadMcpThreatReviews: vi.fn(),
  approveLaunchpadMcpTools: vi.fn(),
  teardownLaunchpadRuntimeRun: vi.fn(),
  listLaunchpadSecretGrants: vi.fn(),
  bindLaunchpadSecretGrant: vi.fn(),
  loadLaunchpadRun: vi.fn(),
  repairLaunchpadRun: vi.fn(),
  deleteLaunchpadRun: vi.fn(),
  getConsoleAdminKey: vi.fn(() => window.sessionStorage.getItem("helm.console.admin_api_key") ?? ""),
  setConsoleAdminKey: vi.fn((value: string) => {
    if (value.trim() === "") {
      window.sessionStorage.removeItem("helm.console.admin_api_key");
      return;
    }
    window.sessionStorage.setItem("helm.console.admin_api_key", value.trim());
  }),
  hasConsoleAdminKey: vi.fn(() => (window.sessionStorage.getItem("helm.console.admin_api_key") ?? "").trim() !== ""),
  getConsoleTenantID: vi.fn(() => window.sessionStorage.getItem("helm.console.tenant_id") ?? "default"),
  setConsoleTenantID: vi.fn((value: string) => {
    if (value.trim() === "") {
      window.sessionStorage.removeItem("helm.console.tenant_id");
      return;
    }
    window.sessionStorage.setItem("helm.console.tenant_id", value.trim());
  }),
  isUnauthorizedError: vi.fn((error: unknown) => {
    if (typeof error !== "object" || error === null || !("status" in error)) return false;
    const status = Number((error as { readonly status?: unknown }).status);
    return status === 401 || status === 403;
  }),
}));

vi.mock("./api/client", () => apiMock);
vi.mock("@copilotkit/react-core/v2/styles.css", () => ({}));
vi.mock("@copilotkit/react-core/v2", () => ({
  CopilotKitProvider: ({ children }: { readonly children: ReactNode }) => children,
  useComponent: vi.fn(),
  useFrontendTool: vi.fn(),
  useRenderTool: vi.fn(),
}));

import { App, mergeReceipts } from "./App";

type ReceiptFixture = ReturnType<typeof bootstrapFixture>["receipts"][number];

function receiptFixture(id: string, lamport_clock: number): ReceiptFixture {
  return {
    receipt_id: id,
    decision_id: `dec_${id}`,
    effect_id: "LLM_INFERENCE",
    status: "allow",
    timestamp: "2026-05-05T00:00:00Z",
    executor_id: "operator@local",
    lamport_clock,
    metadata: { action: "LLM_INFERENCE", resource: id },
  };
}

function bootstrapFixture() {
  return {
    version: { version: "0.5.1", commit: "test", build_time: "2026-05-05T00:00:00Z" },
    workspace: { organization: "local", project: "default", environment: "production", mode: "self-hosted" },
    health: { kernel: "ready", policy: "ready", store: "ready", conformance: "ready" },
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

function launchpadAppFixture() {
  return {
    id: "openclaw",
    app_id: "openclaw",
    name: "OpenClaw",
    availability: "oss_supported",
    version: "0.1.0",
    oci_ref: "ghcr.io/mindburn-labs/openclaw@sha256:abc",
    immutable_digest: "sha256:abc",
    oss_supported: true,
    required_secrets: ["model_gateway"],
    model_gateway_env: ["OPENROUTER_API_KEY"],
    declared_capabilities: ["filesystem.read", "mcp.tools"],
    mcp_servers: [{ id: "openclaw-tools", unknown_server_policy: "quarantine", unknown_tool_policy: "quarantine", schema_pin_required: true }],
    filesystem_needs: ["/workspace read-only", "/tmp/helm-runs read-write"],
    network_needs: ["api.openai.com:443", "github.com:443"],
    policy_ref: "oss.default.deny-by-default",
    status: {
      state: "ready",
      verdict: "ALLOW",
      summary: "Ready to compile LaunchPlan.",
      missing_secrets: [],
      quarantined_mcp: 1,
      last_evidence_pack: "evp_openclaw",
      offline_verifiable: true,
    },
  };
}

function launchpadRunDetailFixture() {
  return {
    run: {
      launch_id: "run_1",
      run_id: "run_1",
      app_id: "openclaw",
      substrate_id: "local-container",
      state: "RUNNING",
      kernel_verdict: "ALLOW",
      plan_hash: "sha256:plan",
      secret_grant_refs: ["rcp_secret"],
      sandbox_grant_refs: ["sha256:sandbox"],
      evidence_pack_refs: ["evp_openclaw"],
    },
    instance: {
      run_id: "run_1",
      app_id: "openclaw",
      substrate_id: "local-container",
      launchplan_hash: "sha256:plan",
      state: "RUNNING",
      verdict: "ALLOW",
      runtime: "local-container",
      active_grants: ["sha256:sandbox"],
      receipts: ["rcp_launch", "rcp_healthcheck"],
      evidencepack_ref: "evp_openclaw",
      evidencepack_refs: ["evp_openclaw"],
      offline_verify_command: "helm evidence verify ./openclaw.evidencepack --offline",
      offline_verification_ready: true,
      local_verification_status: "passed",
    },
    gates: [{
      id: "launchplan.compile",
      group: "LaunchPlan",
      label: "Compile LaunchPlan",
      verdict: "ALLOW",
      proof_status: "proven",
      summary: "LaunchPlan was compiled before runtime.",
      receipt_refs: ["rcp_launch"],
    }],
    events: [{
      id: "run_1:launch_receipt_emitted",
      run_id: "run_1",
      stage: "launch_receipt_emitted",
      label: "Launch receipt emitted",
      verdict: "ALLOW",
      proof_status: "proven",
      human_summary: "Launch receipt was emitted.",
      receipt_ref: "rcp_launch",
    }],
  };
}

describe("HELM Console workbench", () => {
  afterEach(() => {
    cleanup();
  });

  beforeEach(() => {
    window.localStorage.clear();
    window.sessionStorage.clear();
    vi.clearAllMocks();
    apiMock.loadBootstrap.mockResolvedValue(bootstrapFixture());
    apiMock.loadReceipts.mockResolvedValue([]);
    apiMock.loadReceiptDetail.mockResolvedValue(receiptFixture("rcpt_lookup", 7));
    apiMock.evaluateIntent.mockResolvedValue(undefined);
    apiMock.loadConsoleDiagnostics.mockResolvedValue({ status: "ready" });
    apiMock.loadConsoleSurfaceCatalog.mockResolvedValue({ surfaces: [] });
    apiMock.loadConsoleSurface.mockResolvedValue({
      id: "actions",
      status: "available",
      source: "test",
      generated_at: "2026-05-05T00:00:00Z",
      records: [{ id: "LLM_INFERENCE", effect: "E1", risk: "low", status: "active" }],
    });
    apiMock.loadEndpoint.mockResolvedValue({ status: 200, ok: true, data: { records: [] } });
    apiMock.listApprovals.mockResolvedValue({ approvals: [] });
    apiMock.createApproval.mockResolvedValue({ ok: true });
    apiMock.createApprovalWebAuthnChallenge.mockResolvedValue({ challenge_id: "challenge_1" });
    apiMock.assertApprovalWebAuthn.mockResolvedValue({ ok: true });
    apiMock.transitionApproval.mockResolvedValue({ ok: true });
    apiMock.listMcpRegistry.mockResolvedValue({
      servers: [{ server_id: "filesystem", state: "quarantined", risk: "medium", approval_receipt_id: "rcpt_test" }],
    });
    apiMock.loadMcpCapabilities.mockResolvedValue({ tools: [{ name: "filesystem.read", server_id: "filesystem", risk: "low", scope: "tools:filesystem.read" }] });
    apiMock.scanMcpRegistry.mockResolvedValue({ scan_id: "scan_1" });
    apiMock.approveMcpRegistry.mockResolvedValue({ ok: true });
    apiMock.approveMcpServer.mockResolvedValue({ ok: true });
    apiMock.revokeMcpServer.mockResolvedValue({ ok: true });
    apiMock.listMcpAuthProfiles.mockResolvedValue({ profiles: [] });
    apiMock.updateMcpAuthProfile.mockResolvedValue({ ok: true });
    apiMock.authorizeMcpCall.mockResolvedValue({ allowed: true });
    apiMock.listSandboxProfiles.mockResolvedValue({ profiles: [] });
    apiMock.listSandboxGrants.mockResolvedValue({ grants: [] });
    apiMock.createSandboxGrant.mockResolvedValue({ grant_id: "grant_1" });
    apiMock.verifySandboxGrant.mockResolvedValue({ valid: true });
    apiMock.preflightSandboxGrant.mockResolvedValue({ allowed: true });
    apiMock.inspectSandboxRuntime.mockResolvedValue({ profiles: [] });
    apiMock.listAgentIdentities.mockResolvedValue({ agents: [] });
    apiMock.loadAuthzHealth.mockResolvedValue({ status: "ready" });
    apiMock.checkAuthz.mockResolvedValue({ result: "allow" });
    apiMock.listAuthzSnapshots.mockResolvedValue({ snapshots: [] });
    apiMock.listBudgets.mockResolvedValue({ budgets: [] });
    apiMock.updateBudget.mockResolvedValue({ ok: true });
    apiMock.listBoundaryRecords.mockResolvedValue({ records: [] });
    apiMock.loadBoundaryStatus.mockResolvedValue({ status: "ready" });
    apiMock.loadBoundaryCapabilities.mockResolvedValue({ capabilities: [] });
    apiMock.listBoundaryCheckpoints.mockResolvedValue({ checkpoints: [] });
    apiMock.createBoundaryCheckpoint.mockResolvedValue({ checkpoint_id: "chk_1" });
    apiMock.verifyBoundaryRecord.mockResolvedValue({ valid: true });
    apiMock.verifyBoundaryCheckpoint.mockResolvedValue({ valid: true });
    apiMock.listEvidenceEnvelopes.mockResolvedValue({ envelopes: [] });
    apiMock.createEvidenceEnvelope.mockResolvedValue({ manifest_id: "manifest_1" });
    apiMock.loadEvidenceEnvelopePayload.mockResolvedValue({ payload: {} });
    apiMock.verifyEvidenceEnvelope.mockResolvedValue({ valid: true });
    apiMock.exportEvidence.mockResolvedValue({ bytes: 512, content_type: "application/octet-stream" });
    apiMock.verifyEvidenceBundleBase64.mockResolvedValue({ valid: true });
    apiMock.listProofgraphSessions.mockResolvedValue({ sessions: [] });
    apiMock.loadProofgraphSessionReceipts.mockResolvedValue({ receipts: [] });
    apiMock.loadProofgraphReceipt.mockResolvedValue({ receipt: receiptFixture("rcpt_proof", 8) });
    apiMock.listVerificationScopes.mockResolvedValue({ scopes: [] });
    apiMock.createVerificationScope.mockResolvedValue({ verification_scope_id: "scope_1" });
    apiMock.loadVerificationScope.mockResolvedValue({ verification_scope_id: "scope_1" });
    apiMock.verifyVerificationScope.mockResolvedValue({ valid: true });
    apiMock.replayVerifyEvidence.mockResolvedValue({ verdict: "PASS" });
    apiMock.listConformanceReports.mockResolvedValue({ reports: [] });
    apiMock.listConformanceVectors.mockResolvedValue({ vectors: [] });
    apiMock.loadConformanceNegative.mockResolvedValue({ gates: [] });
    apiMock.runConformance.mockResolvedValue({ report_id: "conf_test" });
    apiMock.listHarnessTraces.mockResolvedValue({ traces: [] });
    apiMock.createHarnessTrace.mockResolvedValue({ trace_id: "trace_1" });
    apiMock.loadHarnessTrace.mockResolvedValue({ trace_id: "trace_1" });
    apiMock.verifyHarnessTrace.mockResolvedValue({ valid: true });
    apiMock.listPlanTransactions.mockResolvedValue({ transactions: [] });
    apiMock.createPlanTransaction.mockResolvedValue({ plan_transaction_id: "ptx_1" });
    apiMock.loadPlanTransaction.mockResolvedValue({ plan_transaction_id: "ptx_1" });
    apiMock.verifyPlanTransaction.mockResolvedValue({ valid: true });
    apiMock.listHarnessChangeContracts.mockResolvedValue({ contracts: [] });
    apiMock.createHarnessChangeContract.mockResolvedValue({ change_contract_id: "hcc_1" });
    apiMock.loadHarnessChangeContract.mockResolvedValue({ change_contract_id: "hcc_1" });
    apiMock.approveHarnessChangeContract.mockResolvedValue({ approved: true });
    apiMock.verifyHarnessChangeContract.mockResolvedValue({ valid: true });
    apiMock.verifyGUIActionReceipt.mockResolvedValue({ valid: true });
    apiMock.loadCoexistenceCapabilities.mockResolvedValue({ mode: "export-only" });
    apiMock.loadTelemetryOtelConfig.mockResolvedValue({ endpoint: "disabled" });
    apiMock.exportTelemetry.mockResolvedValue({ ok: true });
    apiMock.addTrustKey.mockResolvedValue({ ok: true });
    apiMock.revokeTrustKey.mockResolvedValue({ ok: true });
    apiMock.listLaunchpadApps.mockResolvedValue([launchpadAppFixture()]);
    apiMock.listLaunchpadSubstrates.mockResolvedValue([{ id: "local-container", name: "Local container", kind: "local-container", availability: "available" }]);
    apiMock.loadLaunchpadMatrix.mockResolvedValue([{ app_id: "openclaw", substrate_id: "local-container", launchable: true, verdict: "ALLOW", reason: "OSS supported", availability: "available" }]);
    apiMock.planLaunchpad.mockResolvedValue({ launch_id: "plan_1", app_id: "openclaw", substrate_id: "local-container", state: "PLANNED", kernel_verdict: "ALLOW", reason: "LaunchPlan compiled.", plan_hash: "sha256:plan" });
    apiMock.launchLaunchpad.mockResolvedValue({ launch_id: "launch_1" });
    apiMock.listLaunchpadRuns.mockResolvedValue({ runs: [{ launch_id: "run_1", app_id: "openclaw", substrate_id: "local-container", state: "RUNNING", kernel_verdict: "ALLOW", plan_hash: "sha256:plan", evidence_pack_refs: ["evp_openclaw"] }] });
    apiMock.createLaunchpadRuntimeRun.mockResolvedValue(launchpadRunDetailFixture());
    apiMock.loadLaunchpadRunDetail.mockResolvedValue(launchpadRunDetailFixture());
    apiMock.loadLaunchpadRunEvents.mockResolvedValue({ events: launchpadRunDetailFixture().events });
    apiMock.loadLaunchpadRunReceipts.mockResolvedValue({ receipts: ["rcp_launch", "rcp_healthcheck"], proof_status: "proven", cli_equivalent: "helm run receipts run_1" });
    apiMock.loadLaunchpadRunLogs.mockResolvedValue({ log: "launchpad state RUNNING verdict ALLOW", proof_status: "proven", cli_equivalent: "helm run logs run_1" });
    apiMock.exportLaunchpadRunEvidence.mockResolvedValue({ evidencepack_ref: "evp_openclaw", offline_verify_command: "helm evidence verify ./openclaw.evidencepack --offline", proof_status: "proven" });
    apiMock.simulateLaunchpadPolicy.mockResolvedValue({ app_id: "openclaw", verdict: "ALLOW", plain_english: "Deny by default with scoped grants.", structured: {}, diff: [], raw: {}, proof_status: "proven", cli_equivalent: "helm policy simulate openclaw" });
    apiMock.inspectLaunchpadSandbox.mockResolvedValue({ sandbox_grant: { backend_profile: "local-container", runtime: "local-container", runtime_version: "local", image_digest: "sha256:abc", filesystem_preopens: ["/workspace read-only"], network_policy: ["api.openai.com:443"], env: ["OPENROUTER_API_KEY"], resource_limits: {}, policy_epoch: "sha256:plan", grant_hash: "sha256:sandbox", proof_status: "proven" }, cli_equivalent: "helm sandbox inspect run_1" });
    apiMock.loadLaunchpadMcpThreatReviews.mockResolvedValue({ threat_reviews: [{ server_id: "openclaw-tools", app_id: "openclaw", transport: "stdio", endpoint: "stdio://openclaw-tools", package_source: "ghcr.io/mindburn-labs/openclaw", digest: "sha256:abc", signature: "cosign://openclaw", tools: [{ name: "read_file", side_effect_class: "T0", filesystem_needs: ["workspace:read"], network_needs: [], secret_needs: [], approval_state: "quarantined" }, { name: "execute_shell", side_effect_class: "T2", filesystem_needs: ["workspace:write"], network_needs: ["deny-by-default"], secret_needs: [], approval_state: "quarantined" }], unknown_tools: true, state: "quarantined", risk_class: "T1", proof_status: "proven", summary: "Unknown tools remain quarantined.", cli_equivalent: "helm mcp quarantine" }] });
    apiMock.approveLaunchpadMcpTools.mockResolvedValue({ approval: { receipt_id: "rcp_mcp_approval" } });
    apiMock.teardownLaunchpadRuntimeRun.mockResolvedValue({ ...launchpadRunDetailFixture(), instance: { ...launchpadRunDetailFixture().instance, state: "DELETED" } });
    apiMock.listLaunchpadSecretGrants.mockResolvedValue({ secrets: [{ name: "model_gateway", value_env: "OPENROUTER_API_KEY", present: true, scope: "runtime env", grant_mode: "env-backed", launch_impact: "required" }] });
    apiMock.bindLaunchpadSecretGrant.mockResolvedValue({ ok: true });
    apiMock.loadLaunchpadRun.mockResolvedValue({ launch_id: "launch_1" });
    apiMock.repairLaunchpadRun.mockResolvedValue({ ok: true });
    apiMock.deleteLaunchpadRun.mockResolvedValue({ launch_id: "launch_1", status: "deleted" });
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
      helm_ai_kernel_version: "0.5.1",
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

  it("renders the universal Launch-first Console navigation", async () => {
    render(<App />);
    expect(await screen.findByRole("heading", { name: "Launch / Run Timeline" })).toBeInTheDocument();
    expect(screen.getByText("OpenClaw")).toBeInTheDocument();
    expect(screen.getByText("Ready to compile LaunchPlan.")).toBeInTheDocument();

    const nav = screen.getAllByLabelText("Primary flows")[0];
    for (const label of ["Launch", "Runs", "MCP Firewall", "Policies", "Secrets", "Sandbox", "Evidence", "Receipts", "Registry", "Settings"]) {
      expect(within(nav).getByRole("button", { name: label })).toBeInTheDocument();
    }
    expect(within(nav).queryByRole("button", { name: /Workbench/i })).not.toBeInTheDocument();
    expect(within(nav).queryByRole("button", { name: /Capabilities/i })).not.toBeInTheDocument();
    expect(within(nav).queryByRole("button", { name: /^Approvals$/i })).not.toBeInTheDocument();
  });

  it("evaluates a governed command and refreshes receipts", async () => {
    render(<App />);
    fireEvent.click((await screen.findAllByRole("button", { name: /HELM/i }))[0]);
    expect(await screen.findByRole("heading", { name: "Governed agent cockpit" })).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Command"), { target: { value: "HTTP_POST https://example.test/hook" } });
    fireEvent.click(screen.getByRole("button", { name: /^Run$/i }));

    await waitFor(() => expect(apiMock.evaluateIntent).toHaveBeenCalledWith(expect.objectContaining({
      action: "HTTP_POST",
      resource: "https://example.test/hook",
    })));
  });

  it("opens MCP Firewall from primary navigation", async () => {
    render(<App />);
    fireEvent.click((await screen.findAllByRole("button", { name: "MCP Firewall" }))[0]);
    expect(await screen.findByRole("heading", { name: "Threat reviews" })).toBeInTheDocument();
    expect(screen.getByText("openclaw-tools")).toBeInTheDocument();
    expect(screen.getByText("read_file")).toBeInTheDocument();
    expect(screen.getByText("execute_shell")).toBeInTheDocument();
    expect(screen.getByText("T2")).toBeInTheDocument();
    expect(screen.getAllByText(/HELM AI cannot authorize this side effect/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText("quarantined").length).toBeGreaterThan(0);
  });

  it("blocks launch when an AppSpec secret is missing and shows one exact fix", async () => {
    apiMock.listLaunchpadApps.mockResolvedValueOnce([{
      ...launchpadAppFixture(),
      status: {
        state: "needs_secret",
        verdict: "ESCALATE",
        reason_code: "ERR_LAUNCHPAD_REQUIRED_SECRET_MISSING",
        summary: "Required secret grant is missing; launch will not start a container.",
        missing_secrets: ["OPENROUTER_API_KEY"],
        quarantined_mcp: 1,
        offline_verifiable: false,
      },
    }]);
    apiMock.loadLaunchpadMatrix.mockResolvedValueOnce([{ app_id: "openclaw", substrate_id: "local-container", launchable: false, verdict: "ESCALATE", reason: "Required secret grant is missing.", availability: "available" }]);
    apiMock.listLaunchpadSecretGrants.mockResolvedValueOnce({ secrets: [{ name: "model_gateway", value_env: "OPENROUTER_API_KEY", present: false, scope: "runtime env", grant_mode: "env-backed", launch_impact: "blocks launch" }] });

    render(<App />);
    const card = (await screen.findByText("OpenClaw")).closest("article");
    expect(card).toBeTruthy();
    expect(within(card as HTMLElement).getByText("Missing secret blocks launch")).toBeInTheDocument();
    expect(within(card as HTMLElement).getByText("helm secret set model_gateway --provider env --value-env OPENROUTER_API_KEY")).toBeInTheDocument();
    expect(within(card as HTMLElement).getByRole("button", { name: /^Launch$/i })).toBeDisabled();
  });

  it("shows the HELM AI assistant as non-authoritative", async () => {
    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: /Open HELM AI Kernel assistant/i }));

    expect(await screen.findByLabelText("HELM AI authority boundary")).toBeInTheDocument();
    expect(screen.getByText("Can: explain, draft, summarize, and simulate.")).toBeInTheDocument();
    expect(screen.getByText("Cannot: approve, weaken, bypass, launch, inject secrets, or delete evidence.")).toBeInTheDocument();
  });

  it("shows fail-closed unavailable work instead of fixture fallback", async () => {
    apiMock.listLaunchpadApps.mockRejectedValueOnce(new Error("launchpad backend down"));
    render(<App />);
    expect(await screen.findByText(/launchpad backend down/i)).toBeInTheDocument();
    expect(screen.getByText("Launchpad API unavailable. No fallback demo data was invented.")).toBeInTheDocument();
    expect(screen.queryByText(/fixture/i)).not.toBeInTheDocument();
  });

  it("opens a receipt in the single right drawer with pending verification", async () => {
    render(<App />);
    const search = await screen.findByPlaceholderText("Search or run command");
    fireEvent.change(search, { target: { value: "rcpt_test" } });
    fireEvent.click(await screen.findByRole("option", { name: /rcpt_test/i }));

    expect(screen.getByRole("heading", { name: "rcpt_test" })).toBeInTheDocument();
    expect(screen.getByText("present; verification pending")).toBeInTheDocument();
    expect(screen.getByText("Raw receipt").closest("details")).not.toHaveAttribute("open");
  });

  it("shows an explicit protected API access state", async () => {
    apiMock.loadBootstrap.mockRejectedValueOnce({ status: 401 });
    render(<App />);

    fireEvent.click((await screen.findAllByRole("button", { name: /HELM/i }))[0]);
    expect(await screen.findByText("Admin key required")).toBeInTheDocument();
    expect(screen.getAllByText(/Protected Console APIs require HELM_ADMIN_API_KEY/i).length).toBeGreaterThan(0);

    fireEvent.click((await screen.findAllByRole("button", { name: /^Settings$/i }))[0]);
    fireEvent.change(await screen.findByLabelText("HELM admin API key"), { target: { value: "test-admin-key" } });
    fireEvent.click(screen.getByRole("button", { name: "Use key" }));

    await waitFor(() => expect(apiMock.setConsoleAdminKey).toHaveBeenCalledWith("test-admin-key"));
  });

  it("keeps the proof demo out of primary Console surfaces", async () => {
    render(<App />);
    expect(await screen.findByRole("heading", { name: "Launch / Run Timeline" })).toBeInTheDocument();
    expect(screen.queryByText("Developer / Sandbox Lab (sample only)")).not.toBeInTheDocument();
    const nav = screen.getAllByLabelText("Primary flows")[0];
    expect(within(nav).queryByRole("button", { name: /Capabilities/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Agent tool call boundary" })).not.toBeInTheDocument();
  });
});

describe("mergeReceipts", () => {
  it("inserts a single streamed receipt into descending lamport order", () => {
    const current = [receiptFixture("rcpt_5", 5), receiptFixture("rcpt_3", 3), receiptFixture("rcpt_1", 1)];
    const merged = mergeReceipts(current, [receiptFixture("rcpt_4", 4)]);
    expect(merged.map((receipt) => receipt.receipt_id)).toEqual(["rcpt_5", "rcpt_4", "rcpt_3", "rcpt_1"]);
  });

  it("replaces an existing streamed receipt without duplicating it", () => {
    const current = [receiptFixture("rcpt_5", 5), receiptFixture("rcpt_3", 3), receiptFixture("rcpt_1", 1)];
    const replacement = { ...receiptFixture("rcpt_3", 6), status: "deny" };
    const merged = mergeReceipts(current, [replacement]);
    expect(merged.map((receipt) => receipt.receipt_id)).toEqual(["rcpt_3", "rcpt_5", "rcpt_1"]);
    expect(merged[0]).toMatchObject({ receipt_id: "rcpt_3", status: "deny" });
  });

  it("preserves the 200 receipt cap on streamed inserts", () => {
    const current = Array.from({ length: 200 }, (_, index) => receiptFixture(`rcpt_${200 - index}`, 200 - index));
    const merged = mergeReceipts(current, [receiptFixture("rcpt_new", 250)]);
    expect(merged).toHaveLength(200);
    expect(merged[0]?.receipt_id).toBe("rcpt_new");
    expect(merged.at(-1)?.receipt_id).toBe("rcpt_2");
  });

  it("falls back to batch merge behavior for unsorted inputs", () => {
    const current = [receiptFixture("rcpt_1", 1), receiptFixture("rcpt_5", 5)];
    const merged = mergeReceipts(current, [receiptFixture("rcpt_3", 3)]);
    expect(merged.map((receipt) => receipt.receipt_id)).toEqual(["rcpt_5", "rcpt_3", "rcpt_1"]);
  });
});
