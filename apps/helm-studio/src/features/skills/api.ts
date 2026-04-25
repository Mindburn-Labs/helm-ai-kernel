// Feature-scoped API client for the skills feature.
// Uses requestJson / asJsonBody directly for workspace-scoped skills and candidate endpoints.
import { asJsonBody, requestJson } from '../../api/http';
import type { InstalledSkill, SkillCandidate } from './types';

export const skillsApi = {
  listInstalled(
    workspaceId: string,
  ): Promise<{ skills: InstalledSkill[]; count: number }> {
    return requestJson(`/api/v1/workspaces/${workspaceId}/skills`);
  },

  listCandidates(
    workspaceId: string,
    params?: { queueStatus?: string },
  ): Promise<{ candidates: SkillCandidate[]; count: number }> {
    const qs = new URLSearchParams();
    if (params?.queueStatus) qs.set('queue_status', params.queueStatus);
    const query = qs.toString();
    return requestJson(
      `/api/v1/workspaces/${workspaceId}/skills/candidates${query ? `?${query}` : ''}`,
    );
  },

  getCandidate(workspaceId: string, candidateId: string): Promise<SkillCandidate> {
    return requestJson(
      `/api/v1/workspaces/${workspaceId}/skills/candidates/${candidateId}`,
    );
  },

  promoteCandidate(workspaceId: string, candidateId: string): Promise<InstalledSkill> {
    return requestJson(
      `/api/v1/workspaces/${workspaceId}/skills/candidates/${candidateId}/promote`,
      asJsonBody({}),
    );
  },

  rejectCandidate(workspaceId: string, candidateId: string, reason: string): Promise<void> {
    return requestJson(
      `/api/v1/workspaces/${workspaceId}/skills/candidates/${candidateId}/reject`,
      asJsonBody({ reason }),
    );
  },
};
