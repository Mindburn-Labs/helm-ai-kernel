import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { actionsApi } from './api';
import type { ProposalDecision } from './types';

// ─── Query key factory ───────────────────────────────────────────────────────

const KEYS = {
  proposals: (workspaceId: string) =>
    ['actions', 'proposals', workspaceId] as const,
  proposal: (workspaceId: string, id: string) =>
    ['actions', 'proposal', workspaceId, id] as const,
};

// ─── Queries ─────────────────────────────────────────────────────────────────

export function useActionProposals(
  workspaceId: string,
  filters?: { status?: string; risk_class?: string; program_id?: string },
) {
  return useQuery({
    queryKey: [...KEYS.proposals(workspaceId), filters],
    enabled: Boolean(workspaceId),
    queryFn: () => actionsApi.listProposals(workspaceId, filters),
    refetchInterval: 5_000, // Fast polling for inbox
  });
}

export function useActionProposal(workspaceId: string, proposalId: string) {
  return useQuery({
    queryKey: KEYS.proposal(workspaceId, proposalId),
    enabled: Boolean(workspaceId) && Boolean(proposalId),
    queryFn: () => actionsApi.getProposal(workspaceId, proposalId),
  });
}

// ─── Mutations ───────────────────────────────────────────────────────────────

export function useDecideAction(workspaceId: string) {
  const qc = useQueryClient();

  return useMutation({
    mutationFn: ({
      proposalId,
      decision,
      reason,
    }: {
      proposalId: string;
      decision: ProposalDecision;
      reason?: string;
    }) => actionsApi.decide(workspaceId, proposalId, decision, reason),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: KEYS.proposals(workspaceId) });
    },
  });
}

export function useBatchDecide(workspaceId: string) {
  const qc = useQueryClient();

  return useMutation({
    mutationFn: ({
      proposalIds,
      decision,
      reason,
    }: {
      proposalIds: string[];
      decision: ProposalDecision;
      reason?: string;
    }) => actionsApi.batchDecide(workspaceId, proposalIds, decision, reason),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: KEYS.proposals(workspaceId) });
    },
  });
}
