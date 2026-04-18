// Feature-scoped API client for the approvals feature.
// Uses requestJson / asJsonBody directly for workspace-scoped approval endpoints.
import { asJsonBody, requestJson } from '../../api/http';
import type { ApprovalCeremony, CompleteCeremonyRequest } from './types';

export const approvalsApi = {
  listCeremonies(
    workspaceId: string,
    params?: { status?: string },
  ): Promise<{ ceremonies: ApprovalCeremony[]; count: number }> {
    const qs = new URLSearchParams();
    if (params?.status) qs.set('status', params.status);
    const query = qs.toString();
    return requestJson(
      `/api/v1/workspaces/${workspaceId}/approvals${query ? `?${query}` : ''}`,
    );
  },

  getCeremony(workspaceId: string, ceremonyId: string): Promise<ApprovalCeremony> {
    return requestJson(`/api/v1/workspaces/${workspaceId}/approvals/${ceremonyId}`);
  },

  resolveCeremony(
    workspaceId: string,
    ceremonyId: string,
    request: CompleteCeremonyRequest,
  ): Promise<ApprovalCeremony> {
    return requestJson(
      `/api/v1/workspaces/${workspaceId}/approvals/${ceremonyId}/resolve`,
      asJsonBody(request),
    );
  },
};
