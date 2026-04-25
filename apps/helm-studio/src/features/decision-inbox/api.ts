// Feature-scoped API client for the action inbox feature.
// Uses requestJson / asJsonBody directly for workspace-scoped action endpoints.
import { asJsonBody, requestJson } from '../../api/http';
import type { ActionProposalRecord, ProposalDecision } from './types';

export const actionsApi = {
  listProposals(
    workspaceId: string,
    params?: {
      status?: string;
      risk_class?: string;
      program_id?: string;
      limit?: number;
    },
  ): Promise<{ proposals: ActionProposalRecord[]; count: number }> {
    const qs = new URLSearchParams();
    if (params?.status) qs.set('status', params.status);
    if (params?.risk_class) qs.set('risk_class', params.risk_class);
    if (params?.program_id) qs.set('program_id', params.program_id);
    if (params?.limit) qs.set('limit', String(params.limit));
    const query = qs.toString();
    return requestJson(
      `/api/v1/workspaces/${workspaceId}/actions${query ? `?${query}` : ''}`,
    );
  },

  getProposal(
    workspaceId: string,
    proposalId: string,
  ): Promise<ActionProposalRecord> {
    return requestJson(
      `/api/v1/workspaces/${workspaceId}/actions/${proposalId}`,
    );
  },

  decide(
    workspaceId: string,
    proposalId: string,
    decision: ProposalDecision,
    reason?: string,
  ): Promise<void> {
    return requestJson(
      `/api/v1/workspaces/${workspaceId}/actions/${proposalId}/decide`,
      asJsonBody({ decision, reason }),
    );
  },

  batchDecide(
    workspaceId: string,
    proposalIds: string[],
    decision: ProposalDecision,
    reason?: string,
  ): Promise<void> {
    return requestJson(
      `/api/v1/workspaces/${workspaceId}/actions/batch-decide`,
      asJsonBody({ proposal_ids: proposalIds, decision, reason }),
    );
  },
};
