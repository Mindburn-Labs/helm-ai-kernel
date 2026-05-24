export type LaunchpadVerdict = "ALLOW" | "DENY" | "ESCALATE";
export type LaunchpadUserState =
  | "available"
  | "needs_setup"
  | "upgrade_required"
  | "enterprise_controlled"
  | "blocked"
  | "unsupported"
  | string;

export interface LaunchpadEntitlementDecision {
  action: string;
  allowed: boolean;
  required_capability?: string;
  reason?: string;
  upgrade_reason?: string;
  fixture_only?: boolean;
}

export type LaunchpadState =
  | "PLANNED"
  | "VALIDATED"
  | "ESCALATED"
  | "DENIED"
  | "PROVISIONING"
  | "INSTALLING"
  | "STARTING"
  | "HEALTHCHECKING"
  | "RUNNING"
  | "REPAIR_REQUIRED"
  | "TEARING_DOWN"
  | "DELETED"
  | "FAILED";

export interface LaunchpadApp {
  id: string;
  app_id?: string;
  name: string;
  availability: string;
  version?: string;
  oci_ref?: string;
  immutable_digest?: string;
  oss_supported?: boolean;
  redistribution?: string;
  install_strategy?: string;
  required_secrets?: string[];
  model_gateway_env?: string[];
  declared_capabilities?: string[];
  mcp_servers?: LaunchpadMcpServer[];
  filesystem_needs?: string[];
  network_needs?: string[];
  healthcheck?: Array<Record<string, unknown>>;
  teardown_recipe?: Record<string, unknown>;
  evidence_profile?: string[];
  risk_class?: string;
  policy_ref?: string;
  status?: LaunchpadAppStatus;
  blocked_reason?: string;
  user_state?: LaunchpadUserState;
  required_capability?: string;
  upgrade_reason?: string;
  entitlement_decision?: LaunchpadEntitlementDecision;
  action_states?: Record<string, LaunchpadEntitlementDecision>;
}

export type LaunchpadImportState = "IMPORTED" | "PREFLIGHTED" | "PROMOTABLE" | "BLOCKED" | "LAUNCHED" | "TORN_DOWN" | string;

export interface LaunchpadImportRequest {
  repo_url: string;
  ref?: string;
  desired_target?: string;
}

export interface SourceSnapshot {
  repo_url: string;
  provider: string;
  owner?: string;
  repo?: string;
  ref?: string;
  commit?: string;
  license_spdx?: string;
  license_state: string;
  fetched_at?: string;
  files: SourceFileSummary[];
  api_source?: string;
}

export interface SourceFileSummary {
  path: string;
  kind: string;
  size?: number;
  sha?: string;
  language?: string;
  content?: string;
}

export interface CapabilityGraph {
  capabilities: string[];
  modules: DetectedModule[];
  frameworks: DetectedFramework[];
  secrets: SecretContract[];
  oauth: OAuthRequirement[];
  ports: number[];
  build_signals: string[];
  runtime_signals: string[];
  policy_signals: string[];
  security_signals: string[];
  adapter_matches: AdapterMatch[];
  confidence: number;
  confidence_reason: string;
}

export interface DetectedModule {
  path: string;
  kind: string;
  manifests: string[];
  entrypoints?: string[];
  build_strategy?: string;
}

export interface DetectedFramework {
  id: string;
  name: string;
  confidence: number;
  evidence: string[];
}

export interface SecretContract {
  name: string;
  source: string;
  required: boolean;
  reason?: string;
  targets?: string[];
}

export interface OAuthRequirement {
  provider: string;
  scopes?: string[];
  source: string;
}

export interface AdapterMatch {
  adapter_id: string;
  confidence: number;
  evidence: string[];
}

export interface BuildStrategy {
  strategy: string;
  confidence: number;
  reason: string;
  commands?: string[][];
  manifest_sources?: string[];
}

export interface TargetPlan {
  target_id: string;
  kind: string;
  substrate_id?: string;
  deployable: boolean;
  requires_approval: boolean;
  commands?: string[][];
  artifacts?: string[];
  secrets_backend?: string;
  healthcheck?: Record<string, string>;
  rollback?: string[];
  risk: string;
  reason: string;
}

export interface GeneratedAppSpecCandidate {
  candidate_id: string;
  trusted: boolean;
  app_spec: LaunchpadApp;
  promotion_requirements: string[];
}

export interface LaunchRecipe {
  import_id: string;
  generated_at?: string;
  detection_order: string[];
  build_strategy: BuildStrategy;
  target_plans: TargetPlan[];
  generated_app_specs: GeneratedAppSpecCandidate[];
  promotion_state: string;
  promotion_requirements: string[];
  cli_equivalent: string;
}

export interface ImportEvidenceLedger {
  status: string;
  receipt_refs?: string[];
  evidence_pack_refs?: string[];
  sbom_ref?: string;
  vulnerability_scan_ref?: string;
  provenance_ref?: string;
  license_ref?: string;
  policy_refs?: string[];
  offline_verify_command?: string;
}

export interface PreflightCheck {
  id: string;
  status: string;
  summary: string;
  evidence_ref?: string;
  fix_actions?: string[];
}

export interface ImportPreflightResult {
  import_id: string;
  status: string;
  checks: PreflightCheck[];
  blocked_reasons?: string[];
  evidence_ledger: ImportEvidenceLedger;
}

export interface LaunchpadImportRecord {
  id: string;
  state: LaunchpadImportState;
  created_at?: string;
  updated_at?: string;
  request: LaunchpadImportRequest;
  source_snapshot: SourceSnapshot;
  capability_graph: CapabilityGraph;
  launch_recipe: LaunchRecipe;
  preflight?: ImportPreflightResult;
  evidence_ledger: ImportEvidenceLedger;
}

export interface LaunchpadAppStatus {
  state: string;
  verdict: LaunchpadVerdict;
  reason_code?: string;
  summary: string;
  missing_secrets?: string[];
  quarantined_mcp?: number;
  last_evidence_pack?: string;
  offline_verifiable?: boolean;
}

export interface LaunchpadMcpServer {
  id: string;
  transport?: string;
  risk_class?: string;
  unknown_server_policy: string;
  unknown_tool_policy: string;
  schema_pin_required: boolean;
}

export interface LaunchpadSubstrate {
  id: string;
  name: string;
  kind: string;
  availability: string;
  default_dry_run?: boolean;
  blocked_reason?: string;
}

export interface LaunchpadMatrixCell {
  app_id: string;
  substrate_id: string;
  launchable: boolean;
  verdict: LaunchpadVerdict;
  reason: string;
  availability: string;
  user_state?: LaunchpadUserState;
  required_capability?: string;
  upgrade_reason?: string;
  entitlement_decision?: LaunchpadEntitlementDecision;
}

export interface LaunchpadPlanResponse {
  launch_id: string;
  app_id: string;
  substrate_id: string;
  state: LaunchpadState;
  kernel_verdict: LaunchpadVerdict;
  reason: string;
  reason_code?: string;
  plan_hash: string;
  evidence_refs?: string[];
  receipts?: LaunchpadReceiptRef[];
  matrix_cell?: LaunchpadMatrixCell;
}

export interface LaunchpadRun {
  launch_id?: string;
  id?: string;
  run_id?: string;
  app_id: string;
  substrate_id: string;
  state: LaunchpadState;
  kernel_verdict: LaunchpadVerdict;
  reason_code?: string;
  reason?: string;
  plan_hash?: string;
  receipt_refs?: LaunchpadReceiptRef[] | Record<string, unknown>[];
  install_receipt_refs?: string[];
  launch_receipt_refs?: string[];
  start_receipt_refs?: string[];
  secret_grant_refs?: string[];
  sandbox_grant_refs?: string[];
  mcp_refs?: string[];
  healthcheck_receipt_refs?: string[];
  teardown_receipt_refs?: string[];
  evidence_pack_refs?: string[];
  teardown_receipt_ref?: string;
  verification_command?: string;
  teardown_command?: string;
  runtime_handles?: Record<string, unknown>;
}

export interface LaunchpadReceiptRef {
  type: string;
  ref: string;
}

export interface GateResult {
  id: string;
  group: string;
  label: string;
  verdict: LaunchpadVerdict;
  reason_code?: string;
  proof_status: "proven" | "unproven" | "blocked" | string;
  summary: string;
  why?: string;
  receipt_refs?: string[];
  proofgraph_node?: string;
  evidence_refs?: string[];
  raw_detail_ref?: string;
  raw_proof_ref?: string;
  required?: boolean;
  receipt_required?: boolean;
  actionable_error?: string;
  fix_actions?: FixAction[];
  cli_equivalent?: string;
}

export interface RunEvent {
  id: string;
  run_id: string;
  stage: string;
  label: string;
  verdict: LaunchpadVerdict;
  reason_code?: string;
  proof_status: "proven" | "unproven" | "blocked" | string;
  human_summary: string;
  why?: string;
  receipt_ref?: string;
  proofgraph_node?: string;
  evidence_refs?: string[];
  raw_payload_ref?: string;
  receipt_required?: boolean;
  actionable_error?: string;
  fix_actions?: FixAction[];
  cli_equivalent?: string;
}

export interface RuntimeInstance {
  run_id: string;
  container_id?: string;
  launchplan_hash?: string;
  state: LaunchpadState;
  verdict: LaunchpadVerdict;
  app_id: string;
  substrate_id: string;
  runtime: string;
  active_grants?: string[];
  receipts?: string[];
  evidencepack_ref?: string;
  evidencepack_refs?: string[];
  offline_verify_command?: string;
  teardown_command?: string;
  runtime_handles?: Record<string, string>;
  local_verification_status?: string;
  offline_verification_ready?: boolean;
  sandbox_grant?: SandboxGrantView;
  cli_equivalent?: string;
}

export interface LaunchpadRunDetail {
  run: LaunchpadRun;
  instance: RuntimeInstance;
  gates: GateResult[];
  events: RunEvent[];
}

export interface LaunchpadSecretGrant {
  name: string;
  provider?: string;
  value_env?: string;
  present: boolean;
  scope: string;
  grant_mode: string;
  grant_hash?: string;
  launch_impact: string;
}

export interface FixAction {
  label: string;
  cli: string;
  description?: string;
}

export interface SandboxGrantView {
  backend_profile: string;
  runtime: string;
  runtime_version: string;
  image_digest?: string;
  filesystem_preopens: string[];
  network_policy: string[];
  env: string[];
  resource_limits: Record<string, string>;
  policy_epoch: string;
  grant_hash?: string;
  proof_status: string;
}

export interface MCPToolThreat {
  name: string;
  side_effect_class: string;
  filesystem_needs?: string[];
  network_needs?: string[];
  secret_needs?: string[];
  risk_class?: string;
  approval_state: string;
  dispatch_receipt?: string;
}

export interface MCPThreatReview {
  server_id: string;
  app_id: string;
  transport?: string;
  endpoint?: string;
  package_source?: string;
  publisher?: string;
  digest?: string;
  signature?: string;
  tools: MCPToolThreat[];
  unknown_tools: boolean;
  state: string;
  risk_class?: string;
  policy_hash?: string;
  approval_receipt?: string;
  last_dispatch_receipt?: string;
  proof_status: string;
  summary: string;
  fix_actions?: FixAction[];
  cli_equivalent?: string;
}

export interface PolicySimulation {
  app_id: string;
  verdict: LaunchpadVerdict;
  reason_code?: string;
  plain_english: string;
  structured: Record<string, unknown>;
  diff: string[];
  raw: Record<string, unknown>;
  receipt_ref?: string;
  proof_status: string;
  fix_actions?: FixAction[];
  cli_equivalent?: string;
}
