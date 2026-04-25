export interface ApprovalCeremony {
  id: string;
  workspaceId: string;
  intentHash: string;
  uiSummaryHash: string;
  timelockMs: number;
  requiredAction: string;
  reasonCodeOptions: string[];
  challengeHash: string;
  responseHash: string;
  status: 'pending' | 'in_progress' | 'completed' | 'expired';
  signerPrincipal: string;
  completedAtMs: number | null;
}

export interface StartCeremonyRequest {
  intentHash: string;
  uiSummaryHash: string;
  timelockMs: number;
  requiredAction: string;
  reasonCodeOptions: string[];
  signerPrincipal: string;
}

export interface CompleteCeremonyRequest {
  challengeHash: string;
  responseHash: string;
  reasonCode: string;
}
