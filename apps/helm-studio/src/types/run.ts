// Run Object Model - Canonical type definitions for HELM runs
// A "Run" represents the full lifecycle of an autonomous action

export type RunStage = 
  | 'proposal_created'
  | 'decision_pending'
  | 'decision_signed'
  | 'intent_issued'
  | 'execution_started'
  | 'effects_applied'
  | 'receipt_committed'
  | 'evidence_packed'
  | 'run_complete'
  | 'run_failed'
  | 'run_blocked';

export type RunStatus = 'pending' | 'active' | 'complete' | 'failed' | 'blocked';

export type StageStatus = 'pending' | 'in_progress' | 'complete' | 'failed' | 'skipped';

export interface RunStageData {
  stage: RunStage;
  status: StageStatus;
  timestamp?: string;
  hash?: string;
  actor?: string;
  metadata?: Record<string, unknown>;
}

export interface Proposal {
  proposal_id: string;
  kind: string;
  intent: string;
  scope: string;
  created_at: string;
  hash?: string;
}

export interface Decision {
  decision_id: string;
  proposal_id: string;
  verdict: 'PERMIT' | 'DENY' | 'PENDING' | 'ESCALATE';
  rationale?: string;
  signed_at: string;
  signer: string;
  signature?: string;
}

export interface ExecutionIntent {
  intent_id: string;
  decision_id: string;
  effect_digest_hash?: string;
  issued_at: string;
  expires_at: string;
  allowed_tool: string;
}

export interface Effect {
  effect_id: string;
  tool_name: string;
  status: 'pending' | 'executed' | 'failed' | 'rolled_back';
  started_at?: string;
  completed_at?: string;
  output?: unknown;
}

export interface Receipt {
  receipt_id: string;
  decision_id: string;
  effect_id: string;
  status: 'SUCCESS' | 'FAILURE' | 'PARTIAL';
  timestamp: string;
  blob_hash?: string;
  executor_id: string;
}

export interface EvidencePack {
  pack_id: string;
  run_id: string;
  artifacts: string[];
  sealed_at: string;
  hash: string;
}

// The canonical Run type - spine of all displays
export interface Run {
  run_id: string;
  status: RunStatus;
  created_at: string;
  updated_at: string;
  
  // Timeline stages
  current_stage: RunStage;
  stages: RunStageData[];
  
  // Core objects
  proposal?: Proposal;
  decision?: Decision;
  intent?: ExecutionIntent;
  effects: Effect[];
  receipt?: Receipt;
  evidence_pack?: EvidencePack;
  
  // Correlation
  correlation_id?: string;
  parent_run_id?: string;
  
  // Error info
  error?: {
    code: string;
    message: string;
    stage: RunStage;
  };
  
  // Provenance
  provenance?: Provenance;
}

export interface Provenance {
  actor_id: string;
  session_id: string;
  timestamp: string;
  method: 'interactive' | 'automation' | 'recovery';
  role_snapshot: string;
  device_fingerprint?: string;
}

// Factory function to create an empty partial run
export function createPartialRun(runId: string): Run {
  return {
    run_id: runId,
    status: 'pending',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    current_stage: 'proposal_created',
    stages: [{
      stage: 'proposal_created',
      status: 'pending',
    }],
    effects: [],
  };
}

// Helper to get stage display info
export function getStageDisplayInfo(stage: RunStage): { label: string; icon: string; color: string } {
  const stageMap: Record<RunStage, { label: string; icon: string; color: string }> = {
    'proposal_created': { label: 'Proposal', icon: '📝', color: 'text-blue-400' },
    'decision_pending': { label: 'Awaiting Decision', icon: '⏳', color: 'text-yellow-400' },
    'decision_signed': { label: 'Decision Signed', icon: '✅', color: 'text-green-400' },
    'intent_issued': { label: 'Intent Issued', icon: '🎯', color: 'text-purple-400' },
    'execution_started': { label: 'Executing', icon: '⚙️', color: 'text-orange-400' },
    'effects_applied': { label: 'Effects Applied', icon: '💫', color: 'text-teal-400' },
    'receipt_committed': { label: 'Receipt Committed', icon: '📋', color: 'text-green-400' },
    'evidence_packed': { label: 'Evidence Packed', icon: '📦', color: 'text-indigo-400' },
    'run_complete': { label: 'Complete', icon: '✓', color: 'text-green-500' },
    'run_failed': { label: 'Failed', icon: '✗', color: 'text-red-500' },
    'run_blocked': { label: 'Blocked', icon: '🚫', color: 'text-red-400' },
  };
  return stageMap[stage];
}

// ──────────────────────────────────────────────────────────────
// Autonomy Lifecycle — matches Go contracts
// ──────────────────────────────────────────────────────────────

/**
 * AutonomyRunStage is the lifecycle stage of an autonomous run.
 * Maps to contracts.AutonomyRunStage in Go.
 */
export type AutonomyRunStage =
  | 'SENSING'
  | 'PLANNING'
  | 'GATING'
  | 'EXECUTING'
  | 'VERIFYING'
  | 'DONE'
  | 'FAILED'
  | 'BLOCKED';

/** Execution lane for grouping concurrent runs. */
export type Lane = 'RESEARCH' | 'BUILD' | 'GTM' | 'OPS' | 'COMPLIANCE';

/** Lane aggregate state. */
export interface LaneState {
  lane: Lane;
  active_runs: number;
  progress_pct: number;
  next_action: string;
  last_verification: string;
  status: 'active' | 'idle' | 'blocked';
  blocked_count: number;
}

// ──────────────────────────────────────────────────────────────
// DecisionRequest — matches Go contracts.DecisionRequest
// ──────────────────────────────────────────────────────────────

export type DecisionRequestKind =
  | 'APPROVAL'
  | 'POLICY_CHOICE'
  | 'CLARIFICATION'
  | 'SPENDING'
  | 'IRREVERSIBLE'
  | 'SENSITIVE_POLICY'
  | 'NAMING';

export type DecisionRequestStatus = 'PENDING' | 'RESOLVED' | 'EXPIRED' | 'SKIPPED';

export type DecisionPriority = 'URGENT' | 'HIGH' | 'NORMAL' | 'LOW';

export interface DecisionImpactPreview {
  diff_summary: string;
  risk_delta: string;
  budget_delta_cents: number;
}

export interface DecisionOption {
  id: string;
  label: string;
  description?: string;
  impact_preview?: DecisionImpactPreview;
  is_default?: boolean;
  is_skip?: boolean;
  is_something_else?: boolean;
}

export interface DecisionRequest {
  request_id: string;
  kind: DecisionRequestKind;
  title: string;
  description?: string;
  options: DecisionOption[];
  impact_preview?: DecisionImpactPreview;
  run_id?: string;
  priority: DecisionPriority;
  status: DecisionRequestStatus;
  skip_allowed: boolean;
  created_at: string;
  expires_at?: string;
  resolved_option_id?: string;
  resolved_by?: string;
  resolved_at?: string;
  freeform_response?: string;
}

// ──────────────────────────────────────────────────────────────
// GlobalAutonomyState — matches Go contracts.GlobalAutonomyState
// ──────────────────────────────────────────────────────────────

export type GlobalMode = 'RUNNING' | 'PAUSED' | 'FROZEN' | 'ISLANDED';
export type SchedulerState = 'AWAKE' | 'SLEEPING';
export type RiskLevel = 'NORMAL' | 'ELEVATED' | 'HIGH' | 'CRITICAL';

export interface NowNextNeed {
  now: string;
  next: string;
  need_you: string;
}

export interface RunSummaryProjection {
  run_id: string;
  status: string;
  current_stage: AutonomyRunStage;
  lane: Lane;
  progress_pct: number;
  next_action: string;
  last_verification: string;
  started_at: string;
  updated_at: string;
  blocked_by?: string;
}

export interface BudgetSummary {
  envelope_cents: number;
  burn_cents: number;
  burn_rate: number;
  runway_hours?: number;
}

export interface Anomaly {
  id: string;
  type: string;
  severity: string;
  description: string;
  detected_at: string;
}

export interface Initiative {
  id: string;
  title: string;
  progress_pct: number;
  active_runs: number;
}

export interface GlobalAutonomyState {
  org_id: string;
  posture: string;
  global_mode: GlobalMode;
  scheduler_state: SchedulerState;
  summary: NowNextNeed;
  active_initiatives: Initiative[];
  active_runs: RunSummaryProjection[];
  blockers_queue: DecisionRequest[];
  budget: BudgetSummary;
  risk_level: RiskLevel;
  anomalies: Anomaly[];
  computed_at: string;
}

// Display helpers for autonomy stages
export function getAutonomyStageDisplay(stage: AutonomyRunStage): { label: string; icon: string; color: string } {
  const map: Record<AutonomyRunStage, { label: string; icon: string; color: string }> = {
    'SENSING':   { label: 'Sensing',   icon: '👁', color: 'var(--color-blue-400)' },
    'PLANNING':  { label: 'Planning',  icon: '🗺', color: 'var(--color-purple-400)' },
    'GATING':    { label: 'Gating',    icon: '🚧', color: 'var(--color-yellow-400)' },
    'EXECUTING': { label: 'Executing', icon: '⚙️', color: 'var(--color-orange-400)' },
    'VERIFYING': { label: 'Verifying', icon: '🔍', color: 'var(--color-teal-400)' },
    'DONE':      { label: 'Done',      icon: '✓',  color: 'var(--color-green-500)' },
    'FAILED':    { label: 'Failed',    icon: '✗',  color: 'var(--color-red-500)' },
    'BLOCKED':   { label: 'Blocked',   icon: '🚫', color: 'var(--color-red-400)' },
  };
  return map[stage];
}

export function getLaneDisplay(lane: Lane): { label: string; icon: string } {
  const map: Record<Lane, { label: string; icon: string }> = {
    'RESEARCH':   { label: 'Research',   icon: '🔬' },
    'BUILD':      { label: 'Build',      icon: '🔨' },
    'GTM':        { label: 'Go-to-Market', icon: '🚀' },
    'OPS':        { label: 'Operations', icon: '⚙️' },
    'COMPLIANCE': { label: 'Compliance', icon: '📋' },
  };
  return map[lane];
}

// ──────────────────────────────────────────────────────────────
// CapabilityDiff — matches Go contracts.CapabilityDiff
// ──────────────────────────────────────────────────────────────

export type DiffCategory = 'CAPABILITY' | 'CONTROL' | 'WORKFLOW' | 'DATA' | 'BUDGET' | 'POSTURE';
export type DiffSeverity = 'INFO' | 'WARN' | 'CRITICAL';

export interface CapabilityDiff {
  diff_id: string;
  op_kind: string;
  category: DiffCategory;
  severity: DiffSeverity;
  title: string;
  description: string;
  before?: string;
  after?: string;
  node_ref?: string;   // canvas node ID for highlighting
  run_id?: string;
  timestamp: string;
}

// ──────────────────────────────────────────────────────────────
// Control — for POST /api/autonomy/control
// ──────────────────────────────────────────────────────────────

export type ControlAction = 'PAUSE' | 'RUN' | 'FREEZE' | 'ISLAND';

export interface ControlResponse {
  previous_mode: string;
  new_mode: string;
}

