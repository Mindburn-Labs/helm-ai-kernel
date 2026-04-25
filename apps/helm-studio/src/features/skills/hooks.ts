import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { skillsApi } from './api';

// ─── Query key factory ───────────────────────────────────────────────────────

const KEYS = {
  installed: (workspaceId: string) =>
    ['skills', 'installed', workspaceId] as const,
  candidates: (workspaceId: string) =>
    ['skills', 'candidates', workspaceId] as const,
  candidate: (workspaceId: string, id: string) =>
    ['skills', 'candidate', workspaceId, id] as const,
};

// ─── Queries ─────────────────────────────────────────────────────────────────

export function useInstalledSkills(workspaceId: string) {
  return useQuery({
    queryKey: KEYS.installed(workspaceId),
    enabled: Boolean(workspaceId),
    queryFn: () => skillsApi.listInstalled(workspaceId),
  });
}

export function useSkillCandidates(
  workspaceId: string,
  filters?: { queueStatus?: string },
) {
  return useQuery({
    queryKey: [...KEYS.candidates(workspaceId), filters],
    enabled: Boolean(workspaceId),
    queryFn: () => skillsApi.listCandidates(workspaceId, filters),
    refetchInterval: 10_000,
  });
}

export function useSkillCandidate(workspaceId: string, candidateId: string) {
  return useQuery({
    queryKey: KEYS.candidate(workspaceId, candidateId),
    enabled: Boolean(workspaceId) && Boolean(candidateId),
    queryFn: () => skillsApi.getCandidate(workspaceId, candidateId),
  });
}

// ─── Mutations ───────────────────────────────────────────────────────────────

export function usePromoteCandidate(workspaceId: string) {
  const qc = useQueryClient();

  return useMutation({
    mutationFn: (candidateId: string) =>
      skillsApi.promoteCandidate(workspaceId, candidateId),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: KEYS.candidates(workspaceId) });
      await qc.invalidateQueries({ queryKey: KEYS.installed(workspaceId) });
    },
  });
}

export function useRejectCandidate(workspaceId: string) {
  const qc = useQueryClient();

  return useMutation({
    mutationFn: ({ candidateId, reason }: { candidateId: string; reason: string }) =>
      skillsApi.rejectCandidate(workspaceId, candidateId, reason),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: KEYS.candidates(workspaceId) });
    },
  });
}
