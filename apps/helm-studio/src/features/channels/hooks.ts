import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { channelsApi } from './api';

// ─── Query key factory ───────────────────────────────────────────────────────

const KEYS = {
  sessions: (workspaceId: string) =>
    ['channels', 'sessions', workspaceId] as const,
  session: (workspaceId: string, id: string) =>
    ['channels', 'session', workspaceId, id] as const,
};

// ─── Queries ─────────────────────────────────────────────────────────────────

export function useChannelSessions(
  workspaceId: string,
  filters?: { channel?: string; status?: string },
) {
  return useQuery({
    queryKey: [...KEYS.sessions(workspaceId), filters],
    enabled: Boolean(workspaceId),
    queryFn: () => channelsApi.listSessions(workspaceId, filters),
    refetchInterval: 10_000,
  });
}

// ─── Mutations ───────────────────────────────────────────────────────────────

export function useReplyToSession(workspaceId: string) {
  const qc = useQueryClient();

  return useMutation({
    mutationFn: ({ sessionId, text }: { sessionId: string; text: string }) =>
      channelsApi.replyToSession(workspaceId, sessionId, text),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: KEYS.sessions(workspaceId) });
    },
  });
}

export function useQuarantineSession(workspaceId: string) {
  const qc = useQueryClient();

  return useMutation({
    mutationFn: ({ sessionId, reason }: { sessionId: string; reason: string }) =>
      channelsApi.quarantineSession(workspaceId, sessionId, reason),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: KEYS.sessions(workspaceId) });
    },
  });
}
