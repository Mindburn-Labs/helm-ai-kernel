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
  name: string;
  availability: string;
  redistribution?: string;
  install_strategy?: string;
  required_secrets?: string[];
  risk_class?: string;
  blocked_reason?: string;
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
  plan_hash: string;
  evidence_refs?: string[];
  receipts?: LaunchpadReceiptRef[];
  matrix_cell?: LaunchpadMatrixCell;
}

export interface LaunchpadRun {
  launch_id?: string;
  id?: string;
  app_id: string;
  substrate_id: string;
  state: LaunchpadState;
  kernel_verdict: LaunchpadVerdict;
  reason?: string;
  plan_hash?: string;
  receipt_refs?: LaunchpadReceiptRef[];
  evidence_pack_refs?: string[];
  teardown_receipt_ref?: string;
}

export interface LaunchpadReceiptRef {
  type: string;
  ref: string;
}
