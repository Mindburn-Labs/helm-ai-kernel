import { WorkspaceContext } from "../types/domain";
import { asJsonBody, requestJson } from "./http";
import {
  ApprovalRecord,
  ExportBundle,
  PolicyDraft,
  PolicyVersion,
  PublicVerificationResponse,
  ReplayManifest,
  RunRecord,
  ScheduledTaskRecord,
  SimulationRecord,
  StudioWorkspaceRecord,
  ToolSurfaceGraph,
} from "./types";

function mapStudioWorkspace(workspace: StudioWorkspaceRecord): WorkspaceContext {
  return {
    id: workspace.id,
    name: workspace.name,
    mode: workspace.mode,
    profile: workspace.profile,
    status: workspace.status,
    createdAt: workspace.created_at,
    updatedAt: workspace.updated_at,
    source: "studio",
  };
}

export const studioApi = {
  async listWorkspaces(): Promise<WorkspaceContext[]> {
    const response = await requestJson<{
      workspaces: StudioWorkspaceRecord[];
      count: number;
    }>("/api/v1/workspaces");
    return response.workspaces.map(mapStudioWorkspace);
  },

  async getWorkspace(workspaceId: string): Promise<WorkspaceContext> {
    const response = await requestJson<StudioWorkspaceRecord>(
      `/api/v1/workspaces/${workspaceId}`,
    );
    return mapStudioWorkspace(response);
  },

  async createWorkspace(input: {
    name: string;
    mode: string;
    profile: string;
    runtimeTemplateId?: string;
  }): Promise<WorkspaceContext> {
    const response = await requestJson<StudioWorkspaceRecord>(
      "/api/v1/workspaces",
      asJsonBody({
        name: input.name,
        mode: input.mode,
        profile: input.profile,
        runtime_template_id: input.runtimeTemplateId,
      }),
    );
    return mapStudioWorkspace(response);
  },

  submitRun(input: {
    workspaceId: string;
    templateId?: string;
    plan?: Record<string, unknown>;
  }): Promise<RunRecord> {
    return requestJson(
      `/api/v1/workspaces/${input.workspaceId}/runs`,
      asJsonBody({
        workspace_id: input.workspaceId,
        template_id: input.templateId,
        plan: input.plan,
      }),
    );
  },

  async listRuns(workspaceId: string): Promise<RunRecord[]> {
    const response = await requestJson<{ runs: RunRecord[] }>(
      `/api/v1/workspaces/${workspaceId}/runs`,
    );
    return response.runs;
  },

  getRun(workspaceId: string, runId: string): Promise<RunRecord> {
    return requestJson(`/api/v1/workspaces/${workspaceId}/runs/${runId}`);
  },

  async listRunReceipts(workspaceId: string, runId: string) {
    const response = await requestJson<{ receipts: RunRecord['receipts']; count: number }>(
      `/api/v1/workspaces/${workspaceId}/runs/${runId}/receipts`,
    );
    return Array.isArray(response.receipts) ? response.receipts : [];
  },

  async listApprovals(workspaceId: string): Promise<ApprovalRecord[]> {
    const response = await requestJson<{ approvals: ApprovalRecord[] }>(
      `/api/v1/workspaces/${workspaceId}/approvals`,
    );
    return response.approvals;
  },

  getApproval(workspaceId: string, approvalId: string): Promise<ApprovalRecord> {
    return requestJson(`/api/v1/workspaces/${workspaceId}/approvals/${approvalId}`);
  },

  resolveApproval(input: {
    workspaceId: string;
    approvalId: string;
    decision: "APPROVE" | "DENY";
    reason?: string;
    approverId: string;
  }): Promise<ApprovalRecord> {
    return requestJson(
      `/api/v1/workspaces/${input.workspaceId}/approvals/${input.approvalId}/resolve`,
      asJsonBody({
        decision: input.decision,
        reason: input.reason,
        approver_id: input.approverId,
      }),
    );
  },

  async listToolSurfaces(workspaceId: string): Promise<ToolSurfaceGraph[]> {
    const response = await requestJson<{ graphs: ToolSurfaceGraph[] }>(
      `/api/v1/workspaces/${workspaceId}/tools`,
    );
    return response.graphs.map((graph) => ({
      ...graph,
      nodes: Array.isArray(graph.nodes) ? graph.nodes : [],
      edges: Array.isArray(graph.edges) ? graph.edges : [],
    }));
  },

  importToolSurface(input: {
    workspaceId: string;
    sourceType: string;
    sourceUri?: string;
    manifest: Array<Record<string, unknown>>;
  }): Promise<ToolSurfaceGraph> {
    return requestJson(
      `/api/v1/workspaces/${input.workspaceId}/tools/import`,
      asJsonBody({
        source_type: input.sourceType,
        source_uri: input.sourceUri,
        manifest: input.manifest,
      }),
    );
  },

  draftPolicy(input: {
    workspaceId: string;
    toolSurfaceId: string;
    objective: string;
    constraints: string[];
    modelAdapter?: string;
  }): Promise<PolicyDraft> {
    return requestJson(
      `/api/v1/workspaces/${input.workspaceId}/policy/draft`,
      asJsonBody({
        tool_surface_id: input.toolSurfaceId,
        objective: input.objective,
        constraints: input.constraints,
        model_adapter: input.modelAdapter,
      }),
    );
  },

  compilePolicy(workspaceId: string, draftId: string): Promise<PolicyVersion> {
    return requestJson(
      `/api/v1/workspaces/${workspaceId}/policy/compile`,
      asJsonBody({ draft_id: draftId }),
    );
  },

  activatePolicy(workspaceId: string, versionId: string): Promise<PolicyVersion> {
    return requestJson(
      `/api/v1/workspaces/${workspaceId}/policy/activate`,
      asJsonBody({ version_id: versionId }),
    );
  },

  getActivePolicy(workspaceId: string): Promise<PolicyVersion> {
    return requestJson(`/api/v1/workspaces/${workspaceId}/policy/active`);
  },

  async listSimulations(workspaceId: string): Promise<SimulationRecord[]> {
    const response = await requestJson<{ simulations: SimulationRecord[] }>(
      `/api/v1/workspaces/${workspaceId}/simulations`,
    );
    return response.simulations;
  },

  submitSimulation(input: {
    workspaceId: string;
    templateId: string;
    scope: string;
  }): Promise<SimulationRecord> {
    return requestJson(
      `/api/v1/workspaces/${input.workspaceId}/simulations`,
      asJsonBody({
        template_id: input.templateId,
        scope: input.scope,
      }),
    );
  },

  generateExport(workspaceId: string): Promise<ExportBundle> {
    return requestJson(
      `/api/v1/workspaces/${workspaceId}/export`,
      asJsonBody({}),
    );
  },

  async listPublicReplays(): Promise<ReplayManifest[]> {
    const response = await requestJson<{ replays: ReplayManifest[] }>("/api/v1/replays");
    return response.replays;
  },

  getReplay(replayId: string): Promise<ReplayManifest> {
    return requestJson(`/api/v1/replays/${replayId}`);
  },

  verifyReceipt(receipt: NonNullable<RunRecord['receipts']>[number]): Promise<PublicVerificationResponse> {
    return requestJson("/api/v1/verify", asJsonBody({ receipt }));
  },

  // ── Task endpoints ──────────────────────────────────────

  async listTasks(workspaceId: string): Promise<ScheduledTaskRecord[]> {
    const response = await requestJson<{ tasks: ScheduledTaskRecord[]; count: number }>(
      `/api/v1/workspaces/${workspaceId}/tasks`,
    );
    return response.tasks ?? [];
  },

  getTask(workspaceId: string, taskId: string): Promise<ScheduledTaskRecord> {
    return requestJson(`/api/v1/workspaces/${workspaceId}/tasks/${taskId}`);
  },

  createTask(input: {
    workspaceId: string;
    templateId?: string;
    label: string;
    plan?: Record<string, unknown>;
    cronExpr?: string;
    scheduledAt?: string;
    maxRetries?: number;
    effectClass?: string;
    policyHash?: string;
  }): Promise<ScheduledTaskRecord> {
    return requestJson(
      `/api/v1/workspaces/${input.workspaceId}/tasks`,
      asJsonBody({
        template_id: input.templateId,
        label: input.label,
        plan: input.plan,
        cron_expr: input.cronExpr,
        scheduled_at: input.scheduledAt,
        max_retries: input.maxRetries,
        effect_class: input.effectClass,
        policy_hash: input.policyHash,
      }),
    );
  },

  pauseTask(workspaceId: string, taskId: string): Promise<ScheduledTaskRecord> {
    return requestJson(
      `/api/v1/workspaces/${workspaceId}/tasks/${taskId}/pause`,
      asJsonBody({}),
    );
  },

  resumeTask(workspaceId: string, taskId: string): Promise<ScheduledTaskRecord> {
    return requestJson(
      `/api/v1/workspaces/${workspaceId}/tasks/${taskId}/resume`,
      asJsonBody({}),
    );
  },

  cancelTask(workspaceId: string, taskId: string): Promise<ScheduledTaskRecord> {
    return requestJson(
      `/api/v1/workspaces/${workspaceId}/tasks/${taskId}/cancel`,
      asJsonBody({}),
    );
  },
};
