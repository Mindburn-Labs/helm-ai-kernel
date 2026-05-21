import type { AdminActionValues, AdminFieldConfig } from "../admin/surfaces";

export type FlowRoute =
  | "launch"
  | "apps"
  | "runs"
  | "policies"
  | "mcp"
  | "secrets"
  | "evidence"
  | "receipts"
  | "sandbox"
  | "registry"
  | "settings"
  | "developer"
  | "workbench"
  | "work"
  | "ledger"
  | "capabilities"
  | "launchpad";

export type CommandMode = "evaluate" | "verify" | "replay" | "approve" | "inspect" | "launch";
export type CommandSource = "composer" | "quick_action" | "search" | "drawer";

export interface GovernedCommand {
  readonly id: string;
  readonly text: string;
  readonly mode: CommandMode;
  readonly principal?: string;
  readonly parsedAction?: string;
  readonly parsedResource?: string;
  readonly source: CommandSource;
}

export type TimelineStepState = "waiting" | "running" | "blocked" | "complete" | "failed" | "unsupported";

export interface TaskTimelineStep {
  readonly id: string;
  readonly label: string;
  readonly state: TimelineStepState;
  readonly summary: string;
  readonly sourceEndpoint?: string;
  readonly receiptRefs: readonly string[];
  readonly artifactRefs: readonly string[];
  readonly action?: WorkbenchAction;
}

export type TaskSeverity = "high" | "medium" | "low";
export type TaskKind = "access" | "approval" | "connector" | "sandbox" | "ledger" | "evidence" | "runtime" | "launch";
export type ReadStatus = "loading" | "ready" | "empty" | "unavailable" | "unauthorized" | "unsupported";
export type CapabilityGroup = "Core" | "Connectors" | "Runtime" | "Policy" | "Proof" | "Developer";

export interface ReadState {
  readonly status: ReadStatus;
  readonly source: string;
  readonly message?: string;
  readonly count?: number;
}

export interface WorkbenchAction {
  readonly id: string;
  readonly label: string;
  readonly method: string;
  readonly endpoint: string;
  readonly fields: readonly AdminFieldConfig[];
  readonly risk: string;
  readonly disabledReason?: string;
  readonly refreshTargets: readonly string[];
  readonly run: (values: AdminActionValues) => Promise<unknown>;
}

export interface OperatorTask {
  readonly id: string;
  readonly kind: TaskKind;
  readonly severity: TaskSeverity;
  readonly title: string;
  readonly summary: string;
  readonly state: string;
  readonly source: string;
  readonly primaryAction: WorkbenchAction | null;
  readonly actionLabel: string;
  readonly relatedReceiptIds: readonly string[];
  readonly route: FlowRoute;
}

export interface RecordSummary {
  readonly id: string;
  readonly label: string;
  readonly state: string;
  readonly facts: readonly string[];
  readonly receiptRefs: readonly string[];
  readonly source: string;
  readonly raw: Record<string, unknown>;
}

export interface Capability {
  readonly id: string;
  readonly label: string;
  readonly group: CapabilityGroup;
  readonly status: ReadStatus;
  readonly sourceEndpoint: string;
  readonly readState: ReadState;
  readonly actions: readonly WorkbenchAction[];
  readonly records: readonly RecordSummary[];
  readonly unsupportedReason?: string;
  readonly raw?: unknown;
}

export interface HealthSummary {
  readonly state: "ready" | "degraded" | "unauthorized" | "unavailable" | "loading";
  readonly label: string;
  readonly message: string;
  readonly unavailableCount: number;
}

export interface QuickAction {
  readonly id: string;
  readonly label: string;
  readonly hint: string;
  readonly command: string;
  readonly mode: CommandMode;
  readonly route?: FlowRoute;
  readonly capabilityId?: string;
}

export interface LatestProof {
  readonly label: string;
  readonly state: string;
  readonly action: string;
  readonly resource: string;
  readonly receiptId?: string;
}

export interface WorkbenchDiagnostic {
  readonly id: string;
  readonly label: string;
  readonly state: ReadStatus | "error";
  readonly message: string;
  readonly source: string;
  readonly route: FlowRoute;
}

export interface WorkbenchSnapshot {
  readonly healthSummary: HealthSummary;
  readonly quickActions: readonly QuickAction[];
  readonly activeTimeline: readonly TaskTimelineStep[];
  readonly attentionCount: number;
  readonly latestProof: LatestProof;
  readonly diagnostics: readonly WorkbenchDiagnostic[];
}
