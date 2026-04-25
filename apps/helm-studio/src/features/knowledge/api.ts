// Feature-scoped API client for the knowledge feature.
// Uses requestJson / asJsonBody for workspace-scoped LKS and CKS knowledge claim endpoints.
import { asJsonBody, requestJson } from '../../api/http';
import type { KnowledgeClaim, PromoteClaimRequest } from './types';

export const knowledgeApi = {
  listLksClaims(
    workspaceId: string,
    params?: { status?: string },
  ): Promise<{ claims: KnowledgeClaim[]; count: number }> {
    const qs = new URLSearchParams();
    if (params?.status) qs.set('status', params.status);
    const query = qs.toString();
    return requestJson(
      `/api/v1/workspaces/${workspaceId}/knowledge/lks${query ? `?${query}` : ''}`,
    );
  },

  listCksClaims(
    workspaceId: string,
    params?: { status?: string },
  ): Promise<{ claims: KnowledgeClaim[]; count: number }> {
    const qs = new URLSearchParams();
    if (params?.status) qs.set('status', params.status);
    const query = qs.toString();
    return requestJson(
      `/api/v1/workspaces/${workspaceId}/knowledge/cks${query ? `?${query}` : ''}`,
    );
  },

  promoteClaim(
    workspaceId: string,
    claimId: string,
    request: PromoteClaimRequest,
  ): Promise<KnowledgeClaim> {
    return requestJson(
      `/api/v1/workspaces/${workspaceId}/knowledge/${claimId}/promote`,
      asJsonBody(request),
    );
  },

  rejectClaim(workspaceId: string, claimId: string, reason: string): Promise<KnowledgeClaim> {
    return requestJson(
      `/api/v1/workspaces/${workspaceId}/knowledge/${claimId}/reject`,
      asJsonBody({ reason }),
    );
  },
};
