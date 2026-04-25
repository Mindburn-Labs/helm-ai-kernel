export type RiskClass = 'R0' | 'R1' | 'R2' | 'R3';
export type PolicyVerdict = 'ALLOW' | 'DENY' | 'ESCALATE' | 'HELD';
export type ProposalStatus =
  | 'PROPOSED'
  | 'APPROVED'
  | 'IN_PROGRESS'
  | 'COMPLETED'
  | 'REJECTED'
  | 'DEFERRED';
export type ProposalDecision = 'APPROVE' | 'DENY' | 'DEFER';

export interface ActionProposalRecord {
  id: string;
  workspace_id: string;
  effect_type: string;
  connector_id: string;
  tool_name: string;
  summary: string;
  risk_class: RiskClass;
  policy_verdict: PolicyVerdict;
  status: ProposalStatus;
  priority: number;
  source_signal_id?: string;
  program_id?: string;
  person_ids?: string[];
  employee_id?: string;
  manager_employee_id?: string;
  draft_artifact?: DraftArtifactRecord;
  context_slice?: ContextSliceRecord;
  receipt_lineage?: string[];
  params?: Record<string, unknown>;
  expires_at?: string;
  created_at: string;
  decided_at?: string;
}

export interface DraftArtifactRecord {
  id: string;
  proposal_id: string;
  artifact_type: string;
  content_hash: string;
  body_markdown?: string;
  metadata?: Record<string, unknown>;
  created_at: string;
}

export interface ContextSliceRecord {
  id: string;
  proposal_id: string;
  signal_ids: string[];
  reasoning_hash: string;
  model_run_id?: string;
  confidence?: number;
  created_at: string;
}
