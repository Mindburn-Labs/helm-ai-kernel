export type Density = "compact" | "comfortable";
export type Mode = "oss" | "commercial" | "shared";
export type Intensity = "active" | "historical" | "muted";

export type VerdictState = "allow" | "deny" | "escalate" | "pending";
export type VerificationState = "verified" | "pending" | "failed" | "exported" | "expired" | "unavailable";
export type RiskState = "low" | "medium" | "high" | "critical";
export type EnvironmentState = "local" | "dev" | "staging" | "production" | "enterprise";
export type LifecycleState = "draft" | "testing" | "ready" | "pending_approval" | "deployed" | "deprecated" | "blocked" | "failed_test";
export type PermissionState = "allowed" | "read_only" | "second_reviewer_required" | "admin_required" | "denied";
export type CitationType =
  | "receipt"
  | "evidence_pack"
  | "evidence_artifact"
  | "policy"
  | "policy_version"
  | "action"
  | "agent"
  | "connector"
  | "approval"
  | "replay_run"
  | "audit_export"
  | "log_entry"
  | "docs"
  | "schema"
  | "cli_output";
export type AssistantRunState =
  | "idle"
  | "queued"
  | "retrieving_context"
  | "reading_sources"
  | "calling_tool"
  | "waiting_for_tool_result"
  | "verifying_evidence"
  | "generating_answer"
  | "binding_citations"
  | "complete"
  | "stopped"
  | "regenerating"
  | "failed"
  | "insufficient_context"
  | "permission_limited";
export type ToolCallState =
  | "proposed"
  | "pending_confirmation"
  | "running"
  | "succeeded"
  | "failed"
  | "cancelled"
  | "denied_by_policy"
  | "escalated"
  | "permission_denied"
  | "unavailable_in_oss"
  | "commercial_only"
  | "mock_only";

export type HelmSemanticState =
  | VerdictState
  | VerificationState
  | RiskState
  | EnvironmentState
  | LifecycleState
  | PermissionState
  | AssistantRunState
  | ToolCallState
  | "historical"
  | "selected"
  | "live";

export type RailState = "allow" | "deny" | "escalate" | "verified" | "pending" | "failed" | "historical" | "selected" | "live";
export type IconTone = "allow" | "deny" | "escalate" | "verified" | "pending" | "muted" | "critical" | "info";

export interface SemanticSpec<TState extends string> {
  readonly state: TState;
  readonly label: string;
  readonly tone: IconTone;
  readonly rail: RailState;
  readonly description: string;
  readonly cssVar: string;
}

export const VERDICT_SEMANTICS = {
  allow: {
    state: "allow",
    label: "ALLOW",
    tone: "allow",
    rail: "allow",
    description: "Policy permitted the requested effect.",
    cssVar: "--helm-verdict-allow",
  },
  deny: {
    state: "deny",
    label: "DENY",
    tone: "deny",
    rail: "deny",
    description: "Policy blocked the requested effect.",
    cssVar: "--helm-verdict-deny",
  },
  escalate: {
    state: "escalate",
    label: "ESCALATE",
    tone: "escalate",
    rail: "escalate",
    description: "Policy requires human review before effect.",
    cssVar: "--helm-verdict-escalate",
  },
  pending: {
    state: "pending",
    label: "PENDING",
    tone: "pending",
    rail: "pending",
    description: "Decision is awaiting evaluation or review.",
    cssVar: "--helm-verdict-pending",
  },
} satisfies Record<VerdictState, SemanticSpec<VerdictState>>;

export const VERIFICATION_SEMANTICS = {
  verified: {
    state: "verified",
    label: "VERIFIED",
    tone: "verified",
    rail: "verified",
    description: "Signature, manifest, or source chain verified.",
    cssVar: "--helm-proof-verified",
  },
  pending: {
    state: "pending",
    label: "PENDING",
    tone: "pending",
    rail: "pending",
    description: "Verification has not completed.",
    cssVar: "--helm-verdict-pending",
  },
  failed: {
    state: "failed",
    label: "FAILED",
    tone: "deny",
    rail: "failed",
    description: "Verification failed or hash mismatched.",
    cssVar: "--helm-verdict-failed",
  },
  exported: {
    state: "exported",
    label: "EXPORTED",
    tone: "verified",
    rail: "verified",
    description: "Evidence or audit package has been exported.",
    cssVar: "--helm-proof-hash",
  },
  expired: {
    state: "expired",
    label: "EXPIRED",
    tone: "muted",
    rail: "historical",
    description: "Evidence is outside retention.",
    cssVar: "--helm-text-muted",
  },
  unavailable: {
    state: "unavailable",
    label: "UNAVAILABLE",
    tone: "muted",
    rail: "historical",
    description: "Evidence is missing or inaccessible.",
    cssVar: "--helm-text-muted",
  },
} satisfies Record<VerificationState, SemanticSpec<VerificationState>>;

export const RISK_SEMANTICS = {
  low: { state: "low", label: "LOW", tone: "verified", rail: "allow", description: "Low operational risk.", cssVar: "--helm-risk-low" },
  medium: { state: "medium", label: "MEDIUM", tone: "escalate", rail: "escalate", description: "Moderate operational risk.", cssVar: "--helm-risk-medium" },
  high: { state: "high", label: "HIGH", tone: "escalate", rail: "escalate", description: "High operational risk.", cssVar: "--helm-risk-high" },
  critical: { state: "critical", label: "CRITICAL", tone: "critical", rail: "deny", description: "Critical production risk.", cssVar: "--helm-risk-critical" },
} satisfies Record<RiskState, SemanticSpec<RiskState>>;

export const ENVIRONMENT_SEMANTICS = {
  local: { state: "local", label: "LOCAL", tone: "muted", rail: "historical", description: "Local OSS environment.", cssVar: "--helm-env-local" },
  dev: { state: "dev", label: "DEV", tone: "info", rail: "selected", description: "Development environment.", cssVar: "--helm-env-dev" },
  staging: { state: "staging", label: "STAGING", tone: "escalate", rail: "escalate", description: "Staging environment.", cssVar: "--helm-env-staging" },
  production: { state: "production", label: "PRODUCTION", tone: "critical", rail: "deny", description: "Production environment.", cssVar: "--helm-env-production" },
  enterprise: { state: "enterprise", label: "ENTERPRISE", tone: "info", rail: "selected", description: "Commercial enterprise environment.", cssVar: "--helm-env-enterprise" },
} satisfies Record<EnvironmentState, SemanticSpec<EnvironmentState>>;

export const LIFECYCLE_SEMANTICS = {
  draft: { state: "draft", label: "DRAFT", tone: "muted", rail: "historical", description: "Editable policy draft.", cssVar: "--helm-text-muted" },
  testing: { state: "testing", label: "TESTING", tone: "info", rail: "selected", description: "Policy is in test evaluation.", cssVar: "--helm-env-dev" },
  ready: { state: "ready", label: "READY", tone: "verified", rail: "verified", description: "Ready for deployment.", cssVar: "--helm-proof-verified" },
  pending_approval: { state: "pending_approval", label: "PENDING APPROVAL", tone: "escalate", rail: "escalate", description: "Awaiting governance approval.", cssVar: "--helm-verdict-escalate" },
  deployed: { state: "deployed", label: "DEPLOYED", tone: "verified", rail: "allow", description: "Policy deployed to environment.", cssVar: "--helm-verdict-allow" },
  deprecated: { state: "deprecated", label: "DEPRECATED", tone: "muted", rail: "historical", description: "Retained for history only.", cssVar: "--helm-text-muted" },
  blocked: { state: "blocked", label: "BLOCKED", tone: "deny", rail: "deny", description: "Deployment is blocked.", cssVar: "--helm-verdict-deny" },
  failed_test: { state: "failed_test", label: "FAILED TEST", tone: "deny", rail: "failed", description: "Policy test failed.", cssVar: "--helm-verdict-failed" },
} satisfies Record<LifecycleState, SemanticSpec<LifecycleState>>;

export const PERMISSION_SEMANTICS = {
  allowed: { state: "allowed", label: "CAN APPROVE", tone: "verified", rail: "allow", description: "User can execute this action.", cssVar: "--helm-verdict-allow" },
  read_only: { state: "read_only", label: "READ ONLY", tone: "muted", rail: "historical", description: "User can inspect only.", cssVar: "--helm-text-muted" },
  second_reviewer_required: { state: "second_reviewer_required", label: "SECOND REVIEWER", tone: "escalate", rail: "escalate", description: "Requires another reviewer.", cssVar: "--helm-verdict-escalate" },
  admin_required: { state: "admin_required", label: "ADMIN REQUIRED", tone: "critical", rail: "deny", description: "Admin permission is required.", cssVar: "--helm-risk-critical" },
  denied: { state: "denied", label: "DENIED", tone: "deny", rail: "deny", description: "User cannot access this action.", cssVar: "--helm-verdict-deny" },
} satisfies Record<PermissionState, SemanticSpec<PermissionState>>;

export const ASSISTANT_RUN_SEMANTICS: Record<AssistantRunState, SemanticSpec<AssistantRunState>> = {
  idle: semantic("idle", "IDLE", "muted", "historical", "No active run.", "--helm-text-muted"),
  queued: semantic("queued", "QUEUED", "pending", "pending", "Run is queued.", "--helm-verdict-pending"),
  retrieving_context: semantic("retrieving_context", "RETRIEVING CONTEXT", "info", "selected", "Collecting scoped sources.", "--helm-proof-hash"),
  reading_sources: semantic("reading_sources", "READING SOURCES", "info", "selected", "Reading source records.", "--helm-proof-hash"),
  calling_tool: semantic("calling_tool", "CALLING TOOL", "escalate", "escalate", "Running visible tool call.", "--helm-verdict-escalate"),
  waiting_for_tool_result: semantic("waiting_for_tool_result", "WAITING FOR TOOL", "pending", "pending", "Awaiting tool result.", "--helm-verdict-pending"),
  verifying_evidence: semantic("verifying_evidence", "VERIFYING EVIDENCE", "verified", "verified", "Checking receipt and manifest integrity.", "--helm-proof-verified"),
  generating_answer: semantic("generating_answer", "GENERATING ANSWER", "info", "selected", "Writing source-backed answer.", "--helm-proof-hash"),
  binding_citations: semantic("binding_citations", "BINDING CITATIONS", "verified", "verified", "Attaching source references.", "--helm-proof-verified"),
  complete: semantic("complete", "COMPLETE", "verified", "verified", "Answer complete.", "--helm-proof-verified"),
  stopped: semantic("stopped", "STOPPED", "muted", "historical", "Generation stopped by user.", "--helm-text-muted"),
  regenerating: semantic("regenerating", "REGENERATING", "info", "selected", "Creating a new answer version.", "--helm-proof-hash"),
  failed: semantic("failed", "FAILED", "deny", "failed", "Assistant run failed.", "--helm-verdict-failed"),
  insufficient_context: semantic("insufficient_context", "INSUFFICIENT CONTEXT", "escalate", "escalate", "Selected evidence cannot answer the question.", "--helm-verdict-escalate"),
  permission_limited: semantic("permission_limited", "PERMISSION LIMITED", "escalate", "escalate", "Some sources are excluded by role.", "--helm-verdict-escalate"),
};

export const TOOL_CALL_SEMANTICS: Record<ToolCallState, SemanticSpec<ToolCallState>> = {
  proposed: semantic("proposed", "PROPOSED", "info", "selected", "Tool call is proposed.", "--helm-proof-hash"),
  pending_confirmation: semantic("pending_confirmation", "PENDING CONFIRMATION", "escalate", "escalate", "Awaiting explicit user confirmation.", "--helm-verdict-escalate"),
  running: semantic("running", "RUNNING", "info", "live", "Tool call is running.", "--helm-proof-hash"),
  succeeded: semantic("succeeded", "SUCCEEDED", "verified", "allow", "Tool call completed.", "--helm-verdict-allow"),
  failed: semantic("failed", "FAILED", "deny", "failed", "Tool call failed.", "--helm-verdict-failed"),
  cancelled: semantic("cancelled", "CANCELLED", "muted", "historical", "Tool call was cancelled.", "--helm-text-muted"),
  denied_by_policy: semantic("denied_by_policy", "DENIED BY POLICY", "deny", "deny", "HELM policy denied execution.", "--helm-verdict-deny"),
  escalated: semantic("escalated", "ESCALATED", "escalate", "escalate", "HELM policy escalated execution.", "--helm-verdict-escalate"),
  permission_denied: semantic("permission_denied", "PERMISSION DENIED", "deny", "deny", "User lacks required permission.", "--helm-verdict-deny"),
  unavailable_in_oss: semantic("unavailable_in_oss", "UNAVAILABLE IN OSS", "muted", "historical", "Commercial-only capability.", "--helm-text-muted"),
  commercial_only: semantic("commercial_only", "COMMERCIAL ONLY", "info", "selected", "Requires HELM AI Enterprise.", "--helm-env-enterprise"),
  mock_only: semantic("mock_only", "MOCK ONLY", "escalate", "escalate", "Demo-only result.", "--helm-verdict-escalate"),
};

function semantic<TState extends string>(
  state: TState,
  label: string,
  tone: IconTone,
  rail: RailState,
  description: string,
  cssVar: string,
): SemanticSpec<TState> {
  return { state, label, tone, rail, description, cssVar };
}

export function railForState(state: HelmSemanticState): RailState {
  if (state in VERDICT_SEMANTICS) return VERDICT_SEMANTICS[state as VerdictState].rail;
  if (state in VERIFICATION_SEMANTICS) return VERIFICATION_SEMANTICS[state as VerificationState].rail;
  if (state in RISK_SEMANTICS) return RISK_SEMANTICS[state as RiskState].rail;
  if (state in ENVIRONMENT_SEMANTICS) return ENVIRONMENT_SEMANTICS[state as EnvironmentState].rail;
  if (state in LIFECYCLE_SEMANTICS) return LIFECYCLE_SEMANTICS[state as LifecycleState].rail;
  if (state in PERMISSION_SEMANTICS) return PERMISSION_SEMANTICS[state as PermissionState].rail;
  if (state in ASSISTANT_RUN_SEMANTICS) return ASSISTANT_RUN_SEMANTICS[state as AssistantRunState].rail;
  if (state in TOOL_CALL_SEMANTICS) return TOOL_CALL_SEMANTICS[state as ToolCallState].rail;
  if (state === "historical" || state === "selected" || state === "live") return state;
  return "historical";
}

export function labelForState(state: HelmSemanticState): string {
  const groups: readonly Record<string, SemanticSpec<string>>[] = [
    VERDICT_SEMANTICS,
    VERIFICATION_SEMANTICS,
    RISK_SEMANTICS,
    ENVIRONMENT_SEMANTICS,
    LIFECYCLE_SEMANTICS,
    PERMISSION_SEMANTICS,
    ASSISTANT_RUN_SEMANTICS,
    TOOL_CALL_SEMANTICS,
  ];
  for (const group of groups) {
    const match = group[state];
    if (match) return match.label;
  }
  return state.toUpperCase();
}

export function assertNever(value: never): never {
  throw new Error(`Unhandled value: ${String(value)}`);
}
