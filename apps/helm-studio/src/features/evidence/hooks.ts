import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { evidenceApi } from './api';
import type { CreateExportRequest } from './types';

// ─── Query key factory ───────────────────────────────────────────────────────

const KEYS = {
  packs: (workspaceId: string) => ['evidence', 'packs', workspaceId] as const,
  replay: (workspaceId: string, id: string) =>
    ['evidence', 'replay', workspaceId, id] as const,
};

// ─── Queries ─────────────────────────────────────────────────────────────────

export function useEvidencePacks(
  workspaceId: string,
  filters?: { status?: string },
) {
  return useQuery({
    queryKey: [...KEYS.packs(workspaceId), filters],
    enabled: Boolean(workspaceId),
    queryFn: () => evidenceApi.listPacks(workspaceId, filters),
    refetchInterval: 8_000,
  });
}

export function useEvidenceReplay(workspaceId: string, replayId: string) {
  return useQuery({
    queryKey: KEYS.replay(workspaceId, replayId),
    enabled: Boolean(workspaceId) && Boolean(replayId),
    queryFn: () => evidenceApi.getReplay(workspaceId, replayId),
  });
}

// ─── Mutations ───────────────────────────────────────────────────────────────

export function useStartExport(workspaceId: string) {
  const qc = useQueryClient();

  return useMutation({
    mutationFn: (request: CreateExportRequest) =>
      evidenceApi.startExport(workspaceId, request),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: KEYS.packs(workspaceId) });
    },
  });
}
