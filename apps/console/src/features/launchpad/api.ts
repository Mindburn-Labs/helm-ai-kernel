import {
  bindLaunchpadSecretGrant,
  approveLaunchpadMcpTools,
  createLaunchpadRuntimeRun,
  deleteLaunchpadRun,
  exportLaunchpadRunEvidence,
  inspectLaunchpadSandbox,
  launchLaunchpad,
  listLaunchpadApps,
  loadLaunchpadMcpThreatReviews,
  listLaunchpadRuns,
  listLaunchpadSecretGrants,
  listLaunchpadSubstrates,
  loadLaunchpadRunLogs,
  loadLaunchpadRunReceipts,
  loadLaunchpadRunDetail,
  loadLaunchpadMatrix,
  planLaunchpad,
  repairLaunchpadRun,
  simulateLaunchpadPolicy,
  teardownLaunchpadRuntimeRun,
} from "../../api/client";
import type {
  LaunchpadSecretGrant,
  LaunchpadApp,
  LaunchpadMatrixCell,
  MCPThreatReview,
  PolicySimulation,
  LaunchpadPlanResponse,
  LaunchpadRun,
  LaunchpadRunDetail,
  LaunchpadSubstrate,
  SandboxGrantView,
} from "./types";

export const launchpadApi = {
  async apps(): Promise<LaunchpadApp[]> {
    return [...await listLaunchpadApps()] as LaunchpadApp[];
  },
  async substrates(): Promise<LaunchpadSubstrate[]> {
    return [...await listLaunchpadSubstrates()] as LaunchpadSubstrate[];
  },
  async matrix(): Promise<LaunchpadMatrixCell[]> {
    return [...await loadLaunchpadMatrix()] as LaunchpadMatrixCell[];
  },
  async runs(): Promise<LaunchpadRun[]> {
    const body = await listLaunchpadRuns();
    if (typeof body === "object" && body !== null && "runs" in body && Array.isArray((body as { runs?: unknown }).runs)) {
      return [...((body as { runs: LaunchpadRun[] }).runs)];
    }
    return [];
  },
  plan(appId: string, substrateId: string): Promise<LaunchpadPlanResponse> {
    return planLaunchpad(appId, substrateId) as Promise<LaunchpadPlanResponse>;
  },
  run(appId: string, substrateId: string): Promise<LaunchpadRunDetail> {
    return createLaunchpadRuntimeRun(appId, substrateId) as unknown as Promise<LaunchpadRunDetail>;
  },
  detail(runId: string): Promise<LaunchpadRunDetail> {
    return loadLaunchpadRunDetail(runId) as unknown as Promise<LaunchpadRunDetail>;
  },
  receipts(runId: string): Promise<{ receipts?: string[]; proof_status?: string; cli_equivalent?: string }> {
    return loadLaunchpadRunReceipts(runId) as Promise<{ receipts?: string[]; proof_status?: string; cli_equivalent?: string }>;
  },
  logs(runId: string): Promise<{ log?: string; proof_status?: string; cli_equivalent?: string }> {
    return loadLaunchpadRunLogs(runId) as Promise<{ log?: string; proof_status?: string; cli_equivalent?: string }>;
  },
  exportEvidence(runId: string): Promise<{ evidencepack_ref?: string; offline_verify_command?: string; proof_status?: string; cli_equivalent?: string }> {
    return exportLaunchpadRunEvidence(runId) as Promise<{ evidencepack_ref?: string; offline_verify_command?: string; proof_status?: string; cli_equivalent?: string }>;
  },
  simulatePolicy(appId: string, substrateId: string): Promise<PolicySimulation> {
    return simulateLaunchpadPolicy(appId, substrateId) as Promise<PolicySimulation>;
  },
  sandbox(runId: string): Promise<{ sandbox_grant?: SandboxGrantView; cli_equivalent?: string }> {
    return inspectLaunchpadSandbox(runId) as Promise<{ sandbox_grant?: SandboxGrantView; cli_equivalent?: string }>;
  },
  async mcpThreatReviews(): Promise<MCPThreatReview[]> {
    const body = await loadLaunchpadMcpThreatReviews();
    if (typeof body === "object" && body !== null && "threat_reviews" in body && Array.isArray((body as { threat_reviews?: unknown }).threat_reviews)) {
      return [...((body as { threat_reviews: MCPThreatReview[] }).threat_reviews)];
    }
    if (typeof body === "object" && body !== null && "reviews" in body && Array.isArray((body as { reviews?: unknown }).reviews)) {
      return [...((body as { reviews: MCPThreatReview[] }).reviews)];
    }
    return [];
  },
  approveMcp(body: { server_id: string; tools: string[]; ttl: string; reason: string; approver?: string }): Promise<unknown> {
    return approveLaunchpadMcpTools(body);
  },
  launch(appId: string, substrateId: string): Promise<LaunchpadRun> {
    return launchLaunchpad(appId, substrateId) as Promise<LaunchpadRun>;
  },
  repair(launchId: string): Promise<unknown> {
    return repairLaunchpadRun(launchId);
  },
  delete(launchId: string): Promise<LaunchpadRun> {
    return deleteLaunchpadRun(launchId) as Promise<LaunchpadRun>;
  },
  teardown(runId: string): Promise<LaunchpadRunDetail> {
    return teardownLaunchpadRuntimeRun(runId) as unknown as Promise<LaunchpadRunDetail>;
  },
  async secrets(): Promise<LaunchpadSecretGrant[]> {
    const body = await listLaunchpadSecretGrants();
    if (typeof body === "object" && body !== null && "secrets" in body && Array.isArray((body as { secrets?: unknown }).secrets)) {
      return [...((body as { secrets: LaunchpadSecretGrant[] }).secrets)];
    }
    return [];
  },
  bindSecret(body: { name: string; provider: string; value_env: string }): Promise<unknown> {
    return bindLaunchpadSecretGrant(body);
  },
};
