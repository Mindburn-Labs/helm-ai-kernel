import { WorkspaceContext } from "../types/domain";
import { asJsonBody, requestJson } from "./http";
import {
  ApprovalRecord,
  ControlplaneSession,
  ControlplaneWorkspaceSummary,
  ExportBundle,
  FrontendChatResponse,
  GoalEnvelope,
  PolicyDraft,
  PolicyVersion,
  PublicApprovalResponse,
  PublicEvidenceResponse,
  PublicVerificationResponse,
  ReplayManifest,
  ResearchFeedEvent,
  ResearchMissionRecord,
  ResearchOverrideRecord,
  ResearchPublicationRecord,
  ResearchRunRecord,
  ResearchSourceRecord,
  RunRecord,
  ScheduledTaskRecord,
  SimulationRecord,
  StudioWorkspaceRecord,
  ToolSurfaceGraph,
} from "./types";

function mapControlplaneWorkspace(
  workspace: ControlplaneWorkspaceSummary,
): WorkspaceContext {
  return {
    id: workspace.id,
    name: workspace.name,
    slug: workspace.slug,
    edition: workspace.edition,
    offerCode: workspace.offer_code,
    source: "controlplane",
  };
}

// Studio-workspace mapper. Ported from studio.ts during Phase 5 — the
// `/api/v1/workspaces/*` paths are now served by controlplane (Phase 4
// studio package), so "studio workspaces" are simply the controlplane's
// v1-prefixed workspace records.
function mapStudioWorkspace(
  workspace: StudioWorkspaceRecord,
): WorkspaceContext {
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

export const controlplaneApi = {
  getSession(): Promise<ControlplaneSession> {
    return requestJson<ControlplaneSession>("/api/session");
  },

  async listWorkspaces(): Promise<WorkspaceContext[]> {
    const response = await requestJson<{ workspaces: ControlplaneWorkspaceSummary[] }>(
      "/api/workspaces",
    );
    return response.workspaces.map(mapControlplaneWorkspace);
  },

  async createWorkspace(input: {
    name: string;
    slug: string;
    edition: string;
    offerCode: string;
    plan: string;
  }): Promise<WorkspaceContext> {
    const workspace = await requestJson<ControlplaneWorkspaceSummary>(
      "/api/workspaces",
      asJsonBody(input),
    );
    return mapControlplaneWorkspace(workspace);
  },

  async provisionWorkspace(input: {
    tenantId: string;
    workspaceName: string;
    edition: string;
    offerCode: string;
    plan: string;
  }): Promise<{ workspace_id?: string; status: string; tenant_id: string }> {
    return requestJson("/api/bootstrap/workspace", asJsonBody({
      tenant_id: input.tenantId,
      workspace_name: input.workspaceName,
      edition: input.edition,
      offer_code: input.offerCode,
      plan: input.plan,
    }));
  },

  sendChat(input: {
    message: string;
    conversationId: string;
    orgId?: string;
    history: Array<{ role: string; content: string }>;
  }): Promise<FrontendChatResponse> {
    return requestJson("/api/chat", asJsonBody({
      message: input.message,
      conversation_id: input.conversationId,
      org_id: input.orgId,
      history: input.history,
    }));
  },

  getActiveGoal(): Promise<GoalEnvelope> {
    return requestJson("/api/goals/active");
  },

  advanceGoal(goalId: string): Promise<GoalEnvelope> {
    return requestJson("/api/goals/advance", asJsonBody({ goal_id: goalId }));
  },

  approveGoalBlocker(goalId: string, blockerId: string): Promise<GoalEnvelope> {
    return requestJson(
      "/api/goals/approve",
      asJsonBody({ goal_id: goalId, blocker_id: blockerId }),
    );
  },

  getPublicVerification(receiptId: string): Promise<PublicVerificationResponse> {
    return requestJson(`/api/public/verify/${receiptId}`);
  },

  getPublicEvidence(bundleId: string): Promise<PublicEvidenceResponse> {
    return requestJson(`/api/public/evidence/${bundleId}`);
  },

  getPublicApproval(approvalId: string): Promise<PublicApprovalResponse> {
    return requestJson(`/api/public/approval/${approvalId}`);
  },

  async listResearchMissions(workspaceId: string): Promise<ResearchMissionRecord[]> {
    const query = workspaceId ? `?workspace_id=${encodeURIComponent(workspaceId)}` : "";
    const response = await requestJson<{ missions: ResearchMissionRecord[] }>(`/api/org/research/missions${query}`);
    return response.missions;
  },

  createResearchMission(input: {
    workspaceId: string;
    title: string;
    thesis: string;
    mode: string;
    missionClass: string;
    publicationClass: string;
    topics?: string[];
    querySeeds?: string[];
  }): Promise<ResearchMissionRecord> {
    return requestJson(
      "/api/org/research/missions",
      asJsonBody({
        workspace_id: input.workspaceId,
        mission: {
          title: input.title,
          thesis: input.thesis,
          mode: input.mode,
          class: input.missionClass,
          publication_class: input.publicationClass,
          topics: input.topics,
          query_seeds: input.querySeeds,
          trigger: {
            type: "manual",
            triggered_at: new Date().toISOString(),
          },
          created_at: new Date().toISOString(),
        },
      }),
    );
  },

  async listResearchRuns(workspaceId: string): Promise<ResearchRunRecord[]> {
    const query = workspaceId ? `?workspace_id=${encodeURIComponent(workspaceId)}` : "";
    const response = await requestJson<{ runs: ResearchRunRecord[] }>(`/api/org/research/runs${query}`);
    return response.runs;
  },

  async listResearchSources(workspaceId: string): Promise<ResearchSourceRecord[]> {
    const query = workspaceId ? `?workspace_id=${encodeURIComponent(workspaceId)}` : "";
    const response = await requestJson<{ sources: ResearchSourceRecord[] }>(`/api/org/research/sources${query}`);
    return response.sources;
  },

  async listResearchPublications(workspaceId: string): Promise<ResearchPublicationRecord[]> {
    const query = workspaceId ? `?workspace_id=${encodeURIComponent(workspaceId)}` : "";
    const response = await requestJson<{ publications: ResearchPublicationRecord[] }>(
      `/api/org/research/publications${query}`,
    );
    return response.publications;
  },

  async listResearchOverrides(workspaceId: string): Promise<ResearchOverrideRecord[]> {
    const query = workspaceId ? `?workspace_id=${encodeURIComponent(workspaceId)}` : "";
    const response = await requestJson<{ overrides: ResearchOverrideRecord[] }>(
      `/api/org/research/overrides${query}`,
    );
    return response.overrides;
  },

  async listResearchFeed(workspaceId: string, limit = 40): Promise<ResearchFeedEvent[]> {
    const params = new URLSearchParams();
    if (workspaceId) params.set("workspace_id", workspaceId);
    params.set("limit", String(limit));
    const response = await requestJson<{ items: ResearchFeedEvent[] }>(
      `/api/org/research/feed?${params.toString()}`,
    );
    return response.items;
  },

  cancelResearchMission(workspaceId: string, missionId: string): Promise<void> {
    return requestJson(
      `/api/org/research/missions/${encodeURIComponent(missionId)}/cancel`,
      {
        method: "POST",
        body: JSON.stringify({ workspace_id: workspaceId }),
        headers: { "Content-Type": "application/json" },
      },
    );
  },

  resolveResearchOverride(
    workspaceId: string,
    overrideId: string,
    decision: string,
    notes: string,
  ): Promise<void> {
    return requestJson(
      `/api/org/research/overrides/${encodeURIComponent(overrideId)}/resolve`,
      asJsonBody({ workspace_id: workspaceId, decision, notes }),
    );
  },

  // ──────────────────────────────────────────────────────────────
  // Studio-scoped methods (ported from studio.ts during Phase 5).
  //
  // All target /api/v1/workspaces/* paths which are served by the
  // controlplane's studio package (Phase 4). studio.ts is removed;
  // these methods are the canonical access path for workspace-scoped
  // Studio operations.
  // ──────────────────────────────────────────────────────────────

  async listStudioWorkspaces(): Promise<WorkspaceContext[]> {
    const response = await requestJson<{
      workspaces: StudioWorkspaceRecord[];
      count: number;
    }>("/api/v1/workspaces");
    return response.workspaces.map(mapStudioWorkspace);
  },

  async getStudioWorkspace(workspaceId: string): Promise<WorkspaceContext> {
    const response = await requestJson<StudioWorkspaceRecord>(
      `/api/v1/workspaces/${workspaceId}`,
    );
    return mapStudioWorkspace(response);
  },

  async createStudioWorkspace(input: {
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

  // Runs
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

  // Approvals
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

  // Tool surfaces
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

  // Policy
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

  // Simulations
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

  // Exports
  generateExport(workspaceId: string): Promise<ExportBundle> {
    return requestJson(
      `/api/v1/workspaces/${workspaceId}/export`,
      asJsonBody({}),
    );
  },

  // Replays
  async listPublicReplays(): Promise<ReplayManifest[]> {
    const response = await requestJson<{ replays: ReplayManifest[] }>("/api/v1/replays");
    return response.replays;
  },

  getReplay(replayId: string): Promise<ReplayManifest> {
    return requestJson(`/api/v1/replays/${replayId}`);
  },

  // Receipt verification
  verifyReceipt(receipt: NonNullable<RunRecord['receipts']>[number]): Promise<PublicVerificationResponse> {
    return requestJson("/api/v1/verify", asJsonBody({ receipt }));
  },

  // Scheduled tasks
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
