import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { approvalsApi } from './api';
import type { CompleteCeremonyRequest } from './types';

// ─── Query key factory ───────────────────────────────────────────────────────

const KEYS = {
  ceremonies: (workspaceId: string) =>
    ['approvals', 'ceremonies', workspaceId] as const,
  ceremony: (workspaceId: string, id: string) =>
    ['approvals', 'ceremony', workspaceId, id] as const,
};

// ─── Queries ─────────────────────────────────────────────────────────────────

export function useApprovals(
  workspaceId: string,
  filters?: { status?: string },
) {
  return useQuery({
    queryKey: [...KEYS.ceremonies(workspaceId), filters],
    enabled: Boolean(workspaceId),
    queryFn: () => approvalsApi.listCeremonies(workspaceId, filters),
    refetchInterval: 5_000,
  });
}

export function useApprovalCeremony(workspaceId: string, ceremonyId: string) {
  return useQuery({
    queryKey: KEYS.ceremony(workspaceId, ceremonyId),
    enabled: Boolean(workspaceId) && Boolean(ceremonyId),
    queryFn: () => approvalsApi.getCeremony(workspaceId, ceremonyId),
  });
}

// ─── Mutations ───────────────────────────────────────────────────────────────

export function useResolveCeremony(workspaceId: string) {
  const qc = useQueryClient();

  return useMutation({
    mutationFn: ({
      ceremonyId,
      request,
    }: {
      ceremonyId: string;
      request: CompleteCeremonyRequest;
    }) => approvalsApi.resolveCeremony(workspaceId, ceremonyId, request),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: KEYS.ceremonies(workspaceId) });
    },
  });
}
