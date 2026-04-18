// Feature-scoped API client for the evidence feature.
// Uses requestJson / asJsonBody for workspace-scoped evidence pack and export endpoints.
import { asJsonBody, requestJson } from '../../api/http';
import type { CreateExportRequest, EvidenceExportJob } from './types';

export const evidenceApi = {
  listPacks(
    workspaceId: string,
    params?: { status?: string },
  ): Promise<{ packs: EvidenceExportJob[]; count: number }> {
    const qs = new URLSearchParams();
    if (params?.status) qs.set('status', params.status);
    const query = qs.toString();
    return requestJson(
      `/api/v1/workspaces/${workspaceId}/evidence/packs${query ? `?${query}` : ''}`,
    );
  },

  startExport(
    workspaceId: string,
    request: CreateExportRequest,
  ): Promise<EvidenceExportJob> {
    return requestJson(
      `/api/v1/workspaces/${workspaceId}/evidence/export`,
      asJsonBody(request),
    );
  },

  getReplay(workspaceId: string, replayId: string): Promise<unknown> {
    return requestJson(
      `/api/v1/workspaces/${workspaceId}/evidence/replay/${replayId}`,
    );
  },
};
