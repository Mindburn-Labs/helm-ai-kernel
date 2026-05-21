import type { AdminRecord, AdminResult, ConsoleBootstrap, Receipt } from "../api/client";
import type { AdminActionConfig, AdminSurfaceConfig } from "../admin/surfaces";
import type {
  Capability,
  CapabilityGroup,
  CommandMode,
  CommandSource,
  FlowRoute,
  GovernedCommand,
  OperatorTask,
  QuickAction,
  ReadState,
  RecordSummary,
  TaskSeverity,
  TaskTimelineStep,
  WorkbenchAction,
  WorkbenchDiagnostic,
  WorkbenchSnapshot,
} from "./types";

export interface CapabilitySnapshot {
  readonly config: AdminSurfaceConfig;
  readonly data: AdminResult | null;
  readonly records: readonly AdminRecord[];
  readonly readState: ReadState;
}

export interface TaskModelInput {
  readonly bootstrap: ConsoleBootstrap | null;
  readonly receipts: readonly Receipt[];
  readonly capabilities: readonly Capability[];
  readonly accessState: "unknown" | "authorized" | "unauthorized";
  readonly error: string | null;
  readonly streamState: string;
}

export interface WorkbenchSnapshotInput extends TaskModelInput {
  readonly command: GovernedCommand | null;
  readonly busy?: boolean;
  readonly replayStatus?: string;
}

const ID_KEYS = [
  "id",
  "receipt_id",
  "approval_id",
  "server_id",
  "grant_id",
  "manifest_id",
  "report_id",
  "snapshot_id",
  "budget_id",
  "record_id",
  "checkpoint_id",
  "launch_id",
  "scope_id",
  "trace_id",
  "transaction_id",
  "change_id",
  "key_id",
  "operation_id",
  "name",
] as const;

const STATE_KEYS = ["state", "status", "verdict", "result", "authorized", "available", "valid"] as const;
const RECEIPT_KEYS = ["receipt_id", "receipt_ref", "approval_receipt_id", "evidence_receipt_id", "decision_receipt_id"] as const;

const GROUP_BY_SURFACE: Record<string, CapabilityGroup> = {
  overview: "Core",
  agents: "Core",
  actions: "Core",
  approvals: "Core",
  policies: "Policy",
  boundary: "Runtime",
  mcp: "Connectors",
  connectors: "Connectors",
  sandbox: "Runtime",
  authz: "Policy",
  budgets: "Policy",
  receipts: "Proof",
  evidence: "Proof",
  replay: "Proof",
  conformance: "Proof",
  proofgraph: "Proof",
  audit: "Proof",
  launchpad: "Runtime",
  trust: "Policy",
  harness: "Developer",
  telemetry: "Developer",
  coexistence: "Developer",
  diagnostics: "Developer",
  developer: "Developer",
  settings: "Core",
};

const METHOD_BY_ACTION_ID: readonly [RegExp, string][] = [
  [/^(list|read|load)/i, "GET"],
  [/^(update)/i, "PUT"],
  [/^(verify|create|run|scan|approve|revoke|authorize|transition|assert|export|preflight|inspect)/i, "POST"],
];

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function receiptKey(receipt: Receipt): string {
  return receipt.receipt_id ?? `${receipt.decision_id ?? "decision"}-${receipt.lamport_clock ?? "pending"}`;
}

export function receiptAction(receipt: Receipt | undefined | null): string {
  return String(receipt?.metadata?.action ?? receipt?.metadata?.action_id ?? receipt?.effect_id ?? "waiting");
}

export function receiptResource(receipt: Receipt | undefined | null): string {
  return String(receipt?.metadata?.resource ?? receipt?.metadata?.source ?? "no governed action yet");
}

export function shortId(value: unknown): string {
  const text = String(value ?? "");
  if (!text) return "not emitted";
  return text.length > 24 ? `${text.slice(0, 12)}...${text.slice(-7)}` : text;
}

export function normalizeState(value: unknown, fallback = "unknown"): string {
  if (value === undefined || value === null || value === "") return fallback;
  return String(value).toLowerCase();
}

export function formatFact(value: unknown): string {
  if (value === undefined || value === null || value === "") return "not emitted";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return `${value.length} item${value.length === 1 ? "" : "s"}`;
  if (isRecord(value)) return `${Object.keys(value).length} field${Object.keys(value).length === 1 ? "" : "s"}`;
  return String(value);
}

export function recordIdentity(record: Record<string, unknown>, fallback: string): string {
  for (const key of ID_KEYS) {
    const value = record[key];
    if (typeof value === "string" && value.trim() !== "") return value;
    if (typeof value === "number") return String(value);
  }
  return fallback;
}

export function summarizeRecord(record: AdminRecord, source: string, index: number): RecordSummary {
  const id = recordIdentity(record, `${source}-${index + 1}`);
  const stateKey = STATE_KEYS.find((key) => record[key] !== undefined);
  const state = normalizeState(stateKey ? record[stateKey] : undefined, "record");
  const factKeys = Object.keys(record)
    .filter((key) => !ID_KEYS.includes(key as (typeof ID_KEYS)[number]) && !STATE_KEYS.includes(key as (typeof STATE_KEYS)[number]))
    .slice(0, 4);
  const facts = factKeys.map((key) => `${key}: ${formatFact(record[key])}`);
  const receiptRefs = RECEIPT_KEYS.flatMap((key) => {
    const value = record[key];
    return typeof value === "string" && value.trim() !== "" ? [value] : [];
  });
  return { id, label: shortId(id), state, facts, receiptRefs, source, raw: record };
}

export function recordsFromResult(data: AdminResult): readonly AdminRecord[] {
  if (Array.isArray(data)) return data.filter(isRecord);
  if (!isRecord(data)) return [];
  for (const key of [
    "records",
    "items",
    "approvals",
    "servers",
    "registry",
    "grants",
    "profiles",
    "snapshots",
    "budgets",
    "envelopes",
    "manifests",
    "reports",
    "vectors",
    "tools",
    "capabilities",
    "checkpoints",
    "agents",
    "identities",
    "runs",
    "sessions",
    "scopes",
    "traces",
    "transactions",
    "changes",
    "contracts",
    "routes",
    "stores",
    "surfaces",
    "matrix",
    "apps",
    "substrates",
  ]) {
    const value = data[key];
    if (Array.isArray(value)) return value.filter(isRecord);
  }
  return Object.entries(data).map(([key, value]) => ({ key, value: formatFact(value) }));
}

export function buildRecordSummaries(data: AdminResult, source: string): readonly RecordSummary[] {
  return recordsFromResult(data).map((record, index) => summarizeRecord(record, source, index));
}

export function actionToWorkbenchAction(config: AdminSurfaceConfig, action: AdminActionConfig): WorkbenchAction {
  const method = METHOD_BY_ACTION_ID.find(([pattern]) => pattern.test(action.id))?.[1] ?? (action.fields?.length ? "POST" : "GET");
  return {
    id: `${config.id}:${action.id}`,
    label: action.label,
    method,
    endpoint: config.source,
    fields: action.fields ?? [],
    risk: action.description,
    disabledReason: action.disabledReason,
    refreshTargets: action.refreshAfter ? [config.id] : [],
    run: action.run,
  };
}

export function buildCapabilities(snapshots: readonly CapabilitySnapshot[]): readonly Capability[] {
  return snapshots.map((snapshot) => {
    const actions = (snapshot.config.actions ?? []).map((action) => actionToWorkbenchAction(snapshot.config, action));
    const records = snapshot.records.map((record, index) => summarizeRecord(record, snapshot.config.source, index));
    const status = snapshot.readState.status === "ready" && records.length === 0 ? "empty" : snapshot.readState.status;
    return {
      id: snapshot.config.id,
      label: snapshot.config.title,
      group: GROUP_BY_SURFACE[snapshot.config.id] ?? "Developer",
      status,
      sourceEndpoint: snapshot.config.source,
      readState: { ...snapshot.readState, status },
      actions,
      records,
      raw: snapshot.data,
      unsupportedReason: actions.length === 0 ? "Unsupported by current OSS API: no mutation route is exposed for this capability." : undefined,
    };
  });
}

function taskSeverityFromState(state: string): TaskSeverity {
  const normalized = state.toLowerCase();
  if (normalized.includes("unauthorized") || normalized.includes("deny") || normalized.includes("failed") || normalized.includes("blocked")) return "high";
  if (normalized.includes("pending") || normalized.includes("quarantine") || normalized.includes("escalate") || normalized.includes("unavailable")) return "medium";
  return "low";
}

function kindForCapability(id: string): OperatorTask["kind"] {
  if (id === "approvals") return "approval";
  if (id === "mcp" || id === "connectors") return "connector";
  if (id === "sandbox") return "sandbox";
  if (id === "launchpad") return "launch";
  if (id === "receipts" || id === "evidence" || id === "replay" || id === "conformance" || id === "audit" || id === "proofgraph") return "evidence";
  if (id === "budgets" || id === "authz" || id === "trust" || id === "boundary") return "runtime";
  return "runtime";
}

function routeForCapabilityTask(id: string): FlowRoute {
  if (id === "mcp" || id === "connectors") return "mcp";
  if (id === "sandbox") return "sandbox";
  if (id === "approvals" || id === "authz" || id === "budgets" || id === "policies" || id === "trust") return "policies";
  if (id === "receipts") return "receipts";
  if (id === "evidence" || id === "replay" || id === "conformance" || id === "audit" || id === "boundary" || id === "proofgraph") return "evidence";
  if (id === "launchpad") return "launch";
  if (id === "settings" || id === "diagnostics") return "settings";
  return "registry";
}

function taskForConcerningRecord(capability: Capability): OperatorTask | null {
  if (capability.status !== "ready" && capability.status !== "empty") return null;
  const concerning = capability.records.find((record) => {
    const state = record.state.toLowerCase();
    return state.includes("pending") || state.includes("quarantine") || state.includes("deny") || state.includes("failed") || state.includes("blocked") || state.includes("escalate");
  });
  if (!concerning) return null;
  return {
    id: `capability-${capability.id}-${concerning.id}`,
    kind: kindForCapability(capability.id),
    severity: taskSeverityFromState(concerning.state),
    title: `${capability.label}: ${concerning.label}`,
    source: capability.sourceEndpoint,
    state: concerning.state,
    summary: concerning.facts[0] ?? `${capability.records.length} live record${capability.records.length === 1 ? "" : "s"}`,
    primaryAction: capability.actions[0] ?? null,
    actionLabel: capability.actions[0]?.label ?? "Inspect",
    relatedReceiptIds: concerning.receiptRefs,
    route: routeForCapabilityTask(capability.id),
  };
}

export function buildOperatorTasks(input: TaskModelInput): readonly OperatorTask[] {
  const tasks: OperatorTask[] = [];

  if (input.accessState === "unauthorized") {
    tasks.push({
      id: "access-required",
      kind: "access",
      severity: "high",
      title: "Admin access required",
      source: "HELM_ADMIN_API_KEY",
      state: "unauthorized",
      summary: input.error ?? "Protected admin routes require a session key.",
      primaryAction: null,
      actionLabel: "Open settings",
      relatedReceiptIds: [],
      route: "settings",
    });
  } else if (input.error) {
    tasks.push({
      id: "console-api-unavailable",
      kind: "runtime",
      severity: "medium",
      title: "Console API unavailable",
      source: "GET /api/v1/console/bootstrap",
      state: "unavailable",
      summary: input.error,
      primaryAction: null,
      actionLabel: "Open diagnostics",
      relatedReceiptIds: [],
      route: "settings",
    });
  }

  if (input.bootstrap?.counts.pending_approvals && input.bootstrap.counts.pending_approvals > 0) {
    tasks.push({
      id: "pending-approvals",
      kind: "approval",
      severity: "high",
      title: `${input.bootstrap.counts.pending_approvals} approval${input.bootstrap.counts.pending_approvals === 1 ? "" : "s"} waiting`,
      source: "GET /api/v1/console/bootstrap",
      state: "pending",
      summary: "Human authorization is required before governed work can continue.",
      primaryAction: null,
      actionLabel: "Review",
      relatedReceiptIds: [],
      route: "work",
    });
  }

  for (const receipt of input.receipts.slice(0, 24)) {
    const state = normalizeState(receipt.status, "pending");
    if (state.includes("deny") || state.includes("escalate") || state.includes("failed")) {
      tasks.push({
        id: `receipt-${receiptKey(receipt)}`,
        kind: "ledger",
        severity: state.includes("escalate") || state.includes("failed") ? "high" : "medium",
        title: `${state.includes("deny") ? "Denied" : state.includes("failed") ? "Failed" : "Escalated"} action: ${receiptAction(receipt)}`,
        source: "GET /api/v1/receipts",
        state,
        summary: receiptResource(receipt),
        primaryAction: null,
        actionLabel: "Open proof",
        relatedReceiptIds: receipt.receipt_id ? [receipt.receipt_id] : [],
        route: "ledger",
      });
    }
  }

  for (const capability of input.capabilities) {
    const task = taskForConcerningRecord(capability);
    if (task) tasks.push(task);
  }

  const severityRank: Record<TaskSeverity, number> = { high: 0, medium: 1, low: 2 };
  return tasks.sort((a, b) => severityRank[a.severity] - severityRank[b.severity] || a.title.localeCompare(b.title));
}

export function parseGovernedCommand(text: string, source: CommandSource = "composer", principal?: string): GovernedCommand {
  const trimmed = text.trim();
  const [first = "", ...rest] = trimmed.split(/\s+/);
  const slash = first.startsWith("/") ? first.slice(1).toLowerCase() : "";
  const modeBySlash: Record<string, CommandMode> = {
    approve: "approve",
    approvals: "approve",
    receipt: "verify",
    verify: "verify",
    replay: "replay",
    mcp: "inspect",
    sandbox: "inspect",
    inspect: "inspect",
    launch: "launch",
  };
  const mode = slash ? modeBySlash[slash] ?? "evaluate" : "evaluate";
  const payload = slash ? rest : [first, ...rest].filter(Boolean);
  const [parsedAction = "LLM_INFERENCE", ...resourceParts] = payload;
  return {
    id: `command-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    text: trimmed,
    mode,
    principal,
    parsedAction: mode === "evaluate" ? parsedAction : undefined,
    parsedResource: mode === "evaluate" ? resourceParts.join(" ") || "unspecified" : payload.join(" ") || undefined,
    source,
  };
}

function diagnosticFromCapability(capability: Capability): WorkbenchDiagnostic | null {
  if (capability.readState.status !== "unavailable" && capability.readState.status !== "unauthorized") return null;
  return {
    id: `diagnostic-${capability.id}`,
    label: capability.label,
    state: capability.readState.status,
    message: capability.readState.message ?? "Backing API did not return a usable response.",
    source: capability.sourceEndpoint,
    route: routeForCapabilityTask(capability.id),
  };
}

function buildDiagnostics(input: TaskModelInput): readonly WorkbenchDiagnostic[] {
  const diagnostics: WorkbenchDiagnostic[] = [];
  if (input.error) {
    diagnostics.push({
      id: "diagnostic-console-bootstrap",
      label: input.accessState === "unauthorized" ? "Admin access" : "Console bootstrap",
      state: input.accessState === "unauthorized" ? "unauthorized" : "error",
      message: input.error,
      source: input.accessState === "unauthorized" ? "HELM_ADMIN_API_KEY" : "GET /api/v1/console/bootstrap",
      route: input.accessState === "unauthorized" ? "settings" : "workbench",
    });
  }
  for (const capability of input.capabilities) {
    const diagnostic = diagnosticFromCapability(capability);
    if (diagnostic) diagnostics.push(diagnostic);
  }
  return diagnostics;
}

function healthSummary(input: TaskModelInput, diagnostics: readonly WorkbenchDiagnostic[]): WorkbenchSnapshot["healthSummary"] {
  if (input.accessState === "unauthorized") {
    return {
      state: "unauthorized",
      label: "Admin key required",
      message: input.error ?? "Protected admin routes need a valid session key.",
      unavailableCount: diagnostics.length,
    };
  }
  if (input.error && !input.bootstrap) {
    return {
      state: "unavailable",
      label: "Console API unavailable",
      message: input.error,
      unavailableCount: diagnostics.length,
    };
  }
  if (!input.bootstrap && input.accessState === "unknown") {
    return {
      state: "loading",
      label: "Connecting",
      message: "Reading the live HELM kernel state.",
      unavailableCount: diagnostics.length,
    };
  }
  if (diagnostics.length > 0) {
    return {
      state: "degraded",
      label: `${diagnostics.length} route${diagnostics.length === 1 ? "" : "s"} ${diagnostics.length === 1 ? "needs" : "need"} attention`,
      message: "Core work can continue; diagnostics are available on demand.",
      unavailableCount: diagnostics.length,
    };
  }
  return {
    state: "ready",
    label: "Ready",
    message: "HELM is connected and no capability read is currently failing.",
    unavailableCount: 0,
  };
}

function latestProof(receipts: readonly Receipt[]): WorkbenchSnapshot["latestProof"] {
  const receipt = receipts[0];
  if (!receipt) {
    return {
      label: "No proof emitted yet",
      state: "waiting",
      action: "Evaluate governed intent",
      resource: "The next receipt will appear here.",
    };
  }
  return {
    label: shortId(receipt.receipt_id),
    state: normalizeState(receipt.status, "pending"),
    action: receiptAction(receipt),
    resource: receiptResource(receipt),
    receiptId: receipt.receipt_id,
  };
}

function quickActions(input: TaskModelInput): readonly QuickAction[] {
  const hasReceipt = input.receipts.length > 0;
  const mcp = input.capabilities.find((capability) => capability.id === "mcp");
  const sandbox = input.capabilities.find((capability) => capability.id === "sandbox");
  const approvalCount = input.bootstrap?.counts.pending_approvals ?? input.capabilities.find((capability) => capability.id === "approvals")?.records.length ?? 0;
  return [
    {
      id: "evaluate-intent",
      label: "Evaluate intent",
      hint: "Run policy before side effects.",
      command: "LLM_INFERENCE gpt-4.1-mini",
      mode: "evaluate",
      route: "workbench",
    },
    {
      id: "review-approvals",
      label: approvalCount > 0 ? `Review ${approvalCount} approval${approvalCount === 1 ? "" : "s"}` : "Review approvals",
      hint: "Human handoff queue.",
      command: "/approve",
      mode: "approve",
      route: "work",
      capabilityId: "approvals",
    },
    {
      id: "verify-latest",
      label: "Verify latest receipt",
      hint: hasReceipt ? "Open proof drawer." : "Waiting for a receipt.",
      command: "/receipt latest",
      mode: "verify",
      route: "ledger",
    },
    {
      id: "replay-evidence",
      label: "Replay evidence",
      hint: hasReceipt ? "Check reproducibility." : "Needs a receipt first.",
      command: "/replay latest",
      mode: "replay",
      route: "evidence",
    },
    {
      id: "scan-mcp",
      label: "Scan MCP",
      hint: mcp?.status === "unavailable" ? "API unavailable" : "Quarantine before approval.",
      command: "/mcp scan",
      mode: "inspect",
      route: "mcp",
      capabilityId: "mcp",
    },
    {
      id: "inspect-sandbox",
      label: "Inspect sandbox",
      hint: sandbox?.status === "unavailable" ? "API unavailable" : "Runtime grants and profiles.",
      command: "/sandbox inspect",
      mode: "inspect",
      route: "sandbox",
      capabilityId: "sandbox",
    },
    {
      id: "open-launchpad",
      label: "Open Launchpad",
      hint: "Plan, launch, repair, teardown.",
      command: "/launch",
      mode: "launch",
      route: "launch",
    },
  ];
}

function stateForReceipt(receipt: Receipt | null): "waiting" | "complete" | "blocked" | "failed" {
  if (!receipt) return "waiting";
  const state = normalizeState(receipt.status, "pending");
  if (state.includes("deny") || state.includes("blocked")) return "blocked";
  if (state.includes("fail")) return "failed";
  return "complete";
}

function buildTimeline(input: WorkbenchSnapshotInput): readonly TaskTimelineStep[] {
  const receipt = input.receipts[0] ?? null;
  const receiptRefs = receipt?.receipt_id ? [receipt.receipt_id] : [];
  const hasCommand = Boolean(input.command?.text);
  const policyFailed = Boolean(input.error);
  const unauthorized = input.accessState === "unauthorized";
  const receiptState = stateForReceipt(receipt);
  const pendingApprovals = input.bootstrap?.counts.pending_approvals ?? 0;
  const replayStatus = input.replayStatus ?? "not checked";

  return [
    {
      id: "intent",
      label: "Intent",
      state: input.busy ? "running" : hasCommand || receipt ? "complete" : "waiting",
      summary: input.command?.text || receiptAction(receipt) || "Type or choose one governed action.",
      sourceEndpoint: "POST /api/v1/evaluate",
      receiptRefs: [],
      artifactRefs: [],
    },
    {
      id: "policy",
      label: "Policy",
      state: unauthorized ? "blocked" : policyFailed ? "failed" : receipt || hasCommand ? "complete" : "waiting",
      summary: unauthorized ? "Admin key required." : policyFailed ? input.error ?? "Policy read failed." : input.bootstrap?.health.policy ?? "Waiting for evaluation.",
      sourceEndpoint: "GET /api/v1/console/bootstrap",
      receiptRefs: [],
      artifactRefs: [],
    },
    {
      id: "decision",
      label: "Decision",
      state: receiptState,
      summary: receipt ? `${normalizeState(receipt.status, "pending")} for ${receiptAction(receipt)}` : "No decision receipt yet.",
      sourceEndpoint: "GET /api/v1/receipts",
      receiptRefs,
      artifactRefs: [],
    },
    {
      id: "approval",
      label: "Approval",
      state: pendingApprovals > 0 || receiptState === "blocked" ? "blocked" : receipt ? "complete" : "waiting",
      summary: pendingApprovals > 0 ? `${pendingApprovals} approval${pendingApprovals === 1 ? "" : "s"} waiting.` : "No human handoff required by the latest receipt.",
      sourceEndpoint: "GET /api/v1/approvals",
      receiptRefs,
      artifactRefs: [],
    },
    {
      id: "receipt",
      label: "Receipt",
      state: receipt ? "complete" : "waiting",
      summary: receipt ? shortId(receipt.receipt_id) : "Receipt will be sealed after evaluation.",
      sourceEndpoint: "GET /api/v1/receipts",
      receiptRefs,
      artifactRefs: receipt?.blob_hash ? [receipt.blob_hash] : [],
    },
    {
      id: "evidence",
      label: "Evidence",
      state: receipt?.signature || receipt?.blob_hash || receipt?.output_hash ? "complete" : receipt ? "unsupported" : "waiting",
      summary: receipt?.signature ? "Signature present." : receipt ? "Evidence fields are partial on this receipt." : "No evidence artifact yet.",
      sourceEndpoint: "GET /api/v1/evidence/envelopes",
      receiptRefs,
      artifactRefs: [receipt?.blob_hash, receipt?.output_hash].filter((value): value is string => Boolean(value)),
    },
    {
      id: "replay",
      label: "Replay",
      state: replayStatus === "checking" ? "running" : replayStatus === "not checked" ? "waiting" : replayStatus.toLowerCase().includes("fail") ? "failed" : "complete",
      summary: replayStatus,
      sourceEndpoint: "POST /api/v1/replay/verify",
      receiptRefs,
      artifactRefs: [],
    },
  ];
}

export function buildWorkbenchSnapshot(input: WorkbenchSnapshotInput): WorkbenchSnapshot {
  const tasks = buildOperatorTasks(input);
  const diagnostics = buildDiagnostics(input);
  return {
    healthSummary: healthSummary(input, diagnostics),
    quickActions: quickActions(input),
    activeTimeline: buildTimeline(input),
    attentionCount: tasks.filter((task) => task.severity === "high" || task.severity === "medium").length,
    latestProof: latestProof(input.receipts),
    diagnostics,
  };
}

export function routeForCapability(id: string): FlowRoute {
  return routeForCapabilityTask(id);
}
