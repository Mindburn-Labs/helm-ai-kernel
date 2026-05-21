export type LaunchpadVerdict = "ALLOW" | "DENY" | "ESCALATE";
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
