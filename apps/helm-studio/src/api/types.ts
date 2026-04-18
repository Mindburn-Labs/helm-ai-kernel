import { WorkspaceContext } from "../types/domain";

export interface ControlplaneSession {
  principal_id: string;
  tenant_id: string;
  workspace_id?: string;
  edition: string;
  deployment_mode: string;
  account_lifecycle: string;
  offer_code: string;
}

export interface ControlplaneWorkspaceSummary {
  id: string;
  name: string;
  slug?: string;
  edition?: string;
  offer_code?: string;
}

export interface ResearchMissionTrigger {
  type: string;
  label?: string;
  schedule?: string;
  source_ref?: string;
  reason?: string;
  triggered_by?: string;
  triggered_at: string;
}

export interface ResearchMissionSpec {
  mission_id: string;
  title: string;
  thesis: string;
  mode: string;
  class: string;
  publication_class: string;
  topics?: string[];
  query_seeds?: string[];
  named_domains?: string[];
  keywords?: string[];
  primary_model?: string;
  verification_model?: string;
  editor_model?: string;
  max_budget_tokens?: number;
  max_budget_cents?: number;
  trigger: ResearchMissionTrigger;
  created_at: string;
}

export interface ResearchWorkNode {
  id: string;
  role: string;
  title: string;
  purpose: string;
  depends_on?: string[];
  deadline_sec?: number;
  retry_class?: string;
  required: boolean;
  publish_impact?: string;
}

export interface ResearchWorkGraph {
  mission_id: string;
  version: string;
  nodes: ResearchWorkNode[];
  edges: Array<{ from: string; to: string; kind: string }>;
}

export interface ResearchMissionRecord {
  workspace_id: string;
  mission: ResearchMissionSpec;
  work_graph: ResearchWorkGraph;
  status: string;
  latest_run_id?: string;
  next_trigger_at?: string;
  legacy_import?: boolean;
  created_at: string;
  updated_at: string;
}

export interface ResearchTaskLease {
  lease_id: string;
  mission_id: string;
  node_id: string;
  role: string;
  assignee: string;
  lease_class?: string;
  deadline_at: string;
  retry_count: number;
  escalation_at?: string;
}

export interface ResearchSourceSnapshot {
  source_id: string;
  mission_id: string;
  url: string;
  canonical_url?: string;
  title?: string;
  content_hash: string;
  snapshot_hash?: string;
  dom_manifest_hash?: string;
  pdf_manifest_hash?: string;
  captured_at: string;
  published_at?: string;
  language?: string;
  provider?: string;
  freshness_score?: number;
  primary: boolean;
  metadata?: Record<string, unknown>;
  provenance_status: string;
}

export interface ResearchTracePack {
  mission: ResearchMissionSpec;
  work_graph: ResearchWorkGraph;
  sources?: ResearchSourceSnapshot[];
  claims?: Array<Record<string, unknown>>;
  model_runs?: Array<Record<string, unknown>>;
  tool_runs?: Array<Record<string, unknown>>;
  drafts?: Array<Record<string, unknown>>;
  scores?: Array<Record<string, unknown>>;
  conflicts?: Array<Record<string, unknown>>;
  metadata?: Record<string, unknown>;
}

export interface ResearchEvidencePack {
  pack_id: string;
  mission_id: string;
  trace_hash: string;
  sealed_at: string;
}

export interface ResearchRunRecord {
  run_id: string;
  workspace_id: string;
  mission_id: string;
  status: string;
  publication_id?: string;
  policy_decision?: string;
  reason_codes?: string[];
  token_spend?: number;
  cent_spend?: number;
  trace: ResearchTracePack;
  leases?: ResearchTaskLease[];
  evidence_pack?: ResearchEvidencePack;
  legacy_import?: boolean;
  created_at: string;
  started_at?: string;
  completed_at?: string;
}

export interface ResearchSourceRecord {
  workspace_id: string;
  snapshot: ResearchSourceSnapshot;
  claim_count: number;
  contradiction_count: number;
  legacy_import?: boolean;
  created_at: string;
}

export interface ResearchPromotionReceipt {
  receipt_id: string;
  mission_id: string;
  publication_id: string;
  publication_state: string;
  evidence_pack_hash: string;
  requested_model?: string;
  actual_model?: string;
  fallback_used: boolean;
  policy_decision: string;
  reason_codes?: string[];
  signer?: string;
  manifest_hash: string;
  created_at: string;
}

export interface ResearchPublicationBodyMeta {
  slug?: string;
  abstract?: string;
  body_markdown?: string;
  body_html?: string;
  authors?: string[];
  links?: Record<string, string>;
  cover_image_url?: string;
  publication_type?: string;
}

export interface ResearchPublicationRecord {
  workspace_id: string;
  record: {
    publication_id: string;
    mission_id: string;
    class: string;
    state: string;
    title: string;
    slug?: string;
    thesis?: string;
    abstract?: string;
    body_hash?: string;
    evidence_pack_hash?: string;
    promotion_receipt?: string;
    version: number;
    supersedes?: string;
    superseded_by?: string;
    published_at?: string;
    metadata?: ResearchPublicationBodyMeta & Record<string, unknown>;
  };
  receipt?: ResearchPromotionReceipt;
  legacy_import?: boolean;
  created_at: string;
  updated_at: string;
}

export interface ResearchOverrideRecord {
  id: string;
  workspace_id: string;
  mission_id?: string;
  publication_id?: string;
  reason: string;
  status: string;
  requested_by?: string;
  requested_at: string;
  resolved_at?: string;
  metadata?: Record<string, unknown>;
}

export interface ResearchFeedEvent {
  id: string;
  workspace_id: string;
  mission_id?: string;
  run_id?: string;
  publication_id?: string;
  event_type: string;
  title: string;
  detail: string;
  why?: string;
  changed?: string;
  evidence_added?: string[];
  confidence_delta?: number;
  blockers?: string[];
  publication_impact?: string;
  payload?: Record<string, unknown>;
  created_at: string;
}

export interface StudioWorkspaceRecord {
  id: string;
  tenant_id?: string;
  name: string;
  mode?: string;
  profile?: string;
  status?: string;
  runtime_template_id?: string;
  active_policy_hash?: string;
  ttl_seconds?: number;
  expires_at?: string;
  created_at?: string;
  updated_at?: string;
}

export interface ReceiptRecord {
  receipt_hash: string;
  receipt_type: string;
  run_id: string;
  workspace_id: string;
  timestamp: string;
  lamport_clock: number;
  verdict?: string;
  reason_code?: string;
  effect_class?: string;
  tool_id?: string;
  payload: Record<string, unknown> | null;
  signature: string;
  parent_receipt_id?: string;
  canonical_bytes?: unknown;
}

export interface RunRecord {
  id: string;
  workspace_id: string;
  template_id?: string;
  plan_hash: string;
  policy_hash: string;
  status: string;
  verdict?: string;
  reason_code?: string;
  effect_class?: string;
  evidence_pack_hash?: string;
  replay_manifest_id?: string;
  plan?: Record<string, unknown>;
  receipts?: ReceiptRecord[];
  events?: Array<{ id: string; event_type: string; created_at: string }>;
  created_at: string;
  started_at?: string;
  completed_at?: string;
}

export interface ApprovalRecord {
  id: string;
  run_id: string;
  workspace_id: string;
  intent_hash: string;
  summary_hash: string;
  policy_hash: string;
  effect_class: string;
  action_summary: string;
  risk_summary: string;
  approval_level: string;
  status: string;
  min_hold_seconds: number;
  timelock_seconds: number;
  approvals?: Array<Record<string, unknown>>;
  created_at: string;
  expires_at: string;
  resolved_at?: string;
}

export interface ToolSurfaceGraph {
  id: string;
  workspace_id: string;
  source_type: string;
  source_uri?: string;
  schema_hash: string;
  contract_hash: string;
  node_count: number;
  nodes: Array<Record<string, unknown>>;
  edges?: Array<Record<string, unknown>>;
  created_at: string;
}

export interface PolicyDraft {
  id: string;
  workspace_id: string;
  status: string;
  tool_surface_id: string;
  objective: string;
  constraints?: string[];
  p0_ceilings?: Record<string, unknown>;
  p1_bundle?: Record<string, unknown>;
  p2_overlay?: Record<string, unknown>;
  approval_routes?: Record<string, unknown>;
  explanation?: string;
  warnings?: string[];
  model_adapter?: string;
  created_at: string;
}

export interface PolicyVersion {
  id: string;
  workspace_id: string;
  draft_id?: string;
  version: number;
  compiled_bundle_hash: string;
  compiled_bundle: Record<string, unknown>;
  status: string;
  activated_at?: string;
  created_at: string;
}

export interface SimulationRecord {
  id: string;
  workspace_id: string;
  template_id: string;
  scope: string;
  status: string;
  expected_verdict?: string;
  actual_verdict?: string;
  policy_rule_hits?: string[];
  run_id?: string;
  created_at: string;
  completed_at?: string;
}

export interface ScheduledTaskRecord {
  id: string;
  workspace_id: string;
  template_id: string;
  label: string;
  plan?: Record<string, unknown>;
  cron_expr?: string;
  scheduled_at: string;
  status: string;
  last_run_id?: string;
  last_run_verdict?: string;
  run_count: number;
  max_retries: number;
  effect_class?: string;
  policy_hash?: string;
  created_at: string;
  updated_at: string;
  paused_at?: string;
  cancelled_at?: string;
}

export interface ReplayManifest {
  id: string;
  run_id: string;
  workspace_id: string;
  evidence_pack_hash: string;
  proofgraph_root?: string;
  public_safe: boolean;
  status: string;
  created_at: string;
}

export interface ExportBundle {
  id: string;
  workspace_id: string;
  manifest_hash: string;
  policy_hash: string;
  status: string;
  manifest?: Record<string, unknown>;
  created_at: string;
}

export interface PublicVerificationReceipt {
  id?: string;
  action?: string;
  actor?: string;
  timestamp?: string;
  hash?: string;
  epoch?: number;
  signatureValid?: boolean;
}

export interface PublicVerificationResponse {
  receipt?: PublicVerificationReceipt;
}

export interface FrontendChatMetadata {
  intent?: string;
  confidence?: number;
  reasoning?: string;
  goal_id?: string;
  goal_phase?: string;
  goal_status?: string;
}

export interface FrontendChatResponse {
  id: string;
  role: string;
  content: string;
  timestamp: string;
  metadata?: FrontendChatMetadata;
}

export interface GoalPlanTask {
  id: string;
  description: string;
  status: string;
  depends_on?: string[];
  receipt_ref?: string;
}

export interface GoalBlocker {
  id: string;
  kind: string;
  detail: string;
}

export interface GoalRecord {
  id: string;
  user_prompt: string;
  phase: string;
  outcomes: string[];
  plan_dag: GoalPlanTask[];
  blockers?: GoalBlocker[];
  created_at: string;
  updated_at: string;
  org_id?: string;
  genome_hash?: string;
  status_line: string;
  metadata?: Record<string, unknown>;
}

export interface GoalEnvelope {
  goal: GoalRecord | null;
}

export interface PublicEvidenceResponse {
  valid?: boolean;
  evidence?: {
    id: string;
    title: string;
    status: string;
    hash: string;
    created_at: string;
  };
}

export interface PublicApprovalResponse {
  id: string;
  title: string;
  status: string;
  hash?: string;
  created_at?: string;
}

export interface WorkspaceListEnvelope {
  workspaces: WorkspaceContext[];
}
