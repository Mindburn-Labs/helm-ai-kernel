import { WorkspaceContext } from "../types/domain";
import { asJsonBody, requestJson } from "./http";
import {
  ControlplaneSession,
  ControlplaneWorkspaceSummary,
  FrontendChatResponse,
  GoalEnvelope,
  PublicApprovalResponse,
  PublicEvidenceResponse,
  PublicVerificationResponse,
  ResearchFeedEvent,
  ResearchMissionRecord,
  ResearchOverrideRecord,
  ResearchPublicationRecord,
  ResearchRunRecord,
  ResearchSourceRecord,
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
};
