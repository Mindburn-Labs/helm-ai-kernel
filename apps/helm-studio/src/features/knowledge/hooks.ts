import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { knowledgeApi } from './api';
import type { PromoteClaimRequest } from './types';

// ─── Query key factory ───────────────────────────────────────────────────────

const KEYS = {
  lks: (workspaceId: string) => ['knowledge', 'lks', workspaceId] as const,
  cks: (workspaceId: string) => ['knowledge', 'cks', workspaceId] as const,
  claim: (workspaceId: string, storeClass: string, id: string) =>
    ['knowledge', 'claim', workspaceId, storeClass, id] as const,
};

// ─── Queries ─────────────────────────────────────────────────────────────────

export function useLksClaims(workspaceId: string, filters?: { status?: string }) {
  return useQuery({
    queryKey: [...KEYS.lks(workspaceId), filters],
    enabled: Boolean(workspaceId),
    queryFn: () => knowledgeApi.listLksClaims(workspaceId, filters),
  });
}

export function useCksClaims(workspaceId: string, filters?: { status?: string }) {
  return useQuery({
    queryKey: [...KEYS.cks(workspaceId), filters],
    enabled: Boolean(workspaceId),
    queryFn: () => knowledgeApi.listCksClaims(workspaceId, filters),
  });
}

// ─── Mutations ───────────────────────────────────────────────────────────────

export function usePromoteClaim(workspaceId: string) {
  const qc = useQueryClient();

  return useMutation({
    mutationFn: ({
      claimId,
      request,
    }: {
      claimId: string;
      request: PromoteClaimRequest;
    }) => knowledgeApi.promoteClaim(workspaceId, claimId, request),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: KEYS.lks(workspaceId) });
      await qc.invalidateQueries({ queryKey: KEYS.cks(workspaceId) });
    },
  });
}

export function useRejectClaim(workspaceId: string) {
  const qc = useQueryClient();

  return useMutation({
    mutationFn: ({
      claimId,
      reason,
    }: {
      claimId: string;
      reason: string;
    }) => knowledgeApi.rejectClaim(workspaceId, claimId, reason),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: KEYS.lks(workspaceId) });
      await qc.invalidateQueries({ queryKey: KEYS.cks(workspaceId) });
    },
  });
}
