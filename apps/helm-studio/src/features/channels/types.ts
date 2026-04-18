export type ChannelType = 'slack' | 'telegram' | 'lark';
export type SessionStatus = 'active' | 'quarantined' | 'closed';

export interface ChannelSession {
  id: string;
  workspaceId: string;
  channel: ChannelType;
  senderId: string;
  threadId?: string;
  status: SessionStatus;
  createdAt: string;
}

export interface SuspiciousInputRecord {
  sessionId: string;
  inputHash: string;
  detectedAt: string;
  reason: string;
}
