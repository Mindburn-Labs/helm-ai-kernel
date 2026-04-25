// Feature-scoped API client for the channels feature.
// Uses requestJson / asJsonBody for workspace-scoped channel session endpoints.
import { asJsonBody, requestJson } from '../../api/http';
import type { ChannelSession } from './types';

export const channelsApi = {
  listChannels(workspaceId: string): Promise<{ channels: string[] }> {
    return requestJson(`/api/v1/workspaces/${workspaceId}/channels`);
  },

  listSessions(
    workspaceId: string,
    params?: { channel?: string; status?: string },
  ): Promise<{ sessions: ChannelSession[]; count: number }> {
    const qs = new URLSearchParams();
    if (params?.channel) qs.set('channel', params.channel);
    if (params?.status) qs.set('status', params.status);
    const query = qs.toString();
    return requestJson(
      `/api/v1/workspaces/${workspaceId}/channels/sessions${query ? `?${query}` : ''}`,
    );
  },

  replyToSession(workspaceId: string, sessionId: string, text: string): Promise<void> {
    return requestJson(
      `/api/v1/workspaces/${workspaceId}/channels/${sessionId}/reply`,
      asJsonBody({ text }),
    );
  },

  quarantineSession(workspaceId: string, sessionId: string, reason: string): Promise<ChannelSession> {
    return requestJson(
      `/api/v1/workspaces/${workspaceId}/channels/${sessionId}/quarantine`,
      asJsonBody({ reason }),
    );
  },
};
