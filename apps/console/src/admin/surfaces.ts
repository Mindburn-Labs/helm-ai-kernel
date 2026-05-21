import {
  addTrustKey,
  approveMcpRegistry,
  approveMcpServer,
  approveHarnessChangeContract,
  assertApprovalWebAuthn,
  authorizeMcpCall,
  checkAuthz,
  createApproval,
  createApprovalWebAuthnChallenge,
  createBoundaryCheckpoint,
  createEvidenceEnvelope,
  createHarnessChangeContract,
  createHarnessTrace,
  createPlanTransaction,
  createSandboxGrant,
  createVerificationScope,
  deleteLaunchpadRun,
  exportEvidence,
  exportTelemetry,
  inspectSandboxRuntime,
  listAgentIdentities,
  listApprovals,
  listAuthzSnapshots,
  listBoundaryCheckpoints,
  listBoundaryRecords,
  listBudgets,
  listConformanceReports,
  listConformanceVectors,
  listEvidenceEnvelopes,
  listHarnessChangeContracts,
  listHarnessTraces,
  listLaunchpadApps,
  listLaunchpadSubstrates,
  listMcpAuthProfiles,
  listMcpRegistry,
  listPlanTransactions,
  listProofgraphSessions,
  listSandboxGrants,
  listSandboxProfiles,
  listVerificationScopes,
  loadAuthzHealth,
  loadBootstrap,
  loadBoundaryCapabilities,
  loadBoundaryStatus,
  loadCoexistenceCapabilities,
  loadConformanceNegative,
  loadConsoleDiagnostics,
  loadConsoleSurface,
  loadConsoleSurfaceCatalog,
  loadMcpCapabilities,
  loadEvidenceEnvelopePayload,
  loadHarnessChangeContract,
  loadHarnessTrace,
  loadLaunchpadMatrix,
  loadLaunchpadRun,
  loadPlanTransaction,
  loadProofgraphReceipt,
  loadProofgraphSessionReceipts,
  loadReceiptDetail,
  loadTelemetryOtelConfig,
  loadVerificationScope,
  launchLaunchpad,
  planLaunchpad,
  preflightSandboxGrant,
  replayVerifyEvidence,
  repairLaunchpadRun,
  revokeMcpServer,
  revokeTrustKey,
  runConformance,
  scanMcpRegistry,
  transitionApproval,
  updateBudget,
  updateMcpAuthProfile,
  verifyBoundaryCheckpoint,
  verifyBoundaryRecord,
  verifyEvidenceBundleBase64,
  verifyEvidenceEnvelope,
  verifyGUIActionReceipt,
  verifyHarnessChangeContract,
  verifyHarnessTrace,
  verifyPlanTransaction,
  verifySandboxGrant,
  verifyVerificationScope,
  type AdminRecord,
  type AdminResult,
  type ConsoleBootstrap,
  type ConsoleDiagnostics,
} from "../api/client";

export type AdminFieldKind = "text" | "textarea" | "select";

export interface AdminActionValues {
  readonly [key: string]: string;
}

export interface AdminFieldConfig {
  readonly id: string;
  readonly label: string;
  readonly kind?: AdminFieldKind;
  readonly placeholder?: string;
  readonly defaultValue?: string;
  readonly options?: readonly string[];
  readonly required?: boolean;
}

export interface AdminActionConfig {
  readonly id: string;
  readonly label: string;
  readonly description: string;
  readonly fields?: readonly AdminFieldConfig[];
  readonly run: (values: AdminActionValues) => Promise<AdminResult>;
  readonly refreshAfter?: boolean;
  readonly disabledReason?: string;
}

export interface AdminColumnConfig {
  readonly key: string;
  readonly label: string;
  readonly priority?: "primary" | "secondary" | "meta";
}

export interface AdminSurfaceConfig {
  readonly id: string;
  readonly title: string;
  readonly eyebrow: string;
  readonly body: string;
  readonly source: string;
  readonly read: () => Promise<AdminResult>;
  readonly rows: (data: AdminResult) => readonly AdminRecord[];
  readonly columns: readonly AdminColumnConfig[];
  readonly detailTitle: string;
  readonly emptyTitle: string;
  readonly emptyBody: string;
  readonly actions?: readonly AdminActionConfig[];
}

const jsonField = (
  values: AdminActionValues,
  key: string,
  fallback: unknown = {},
): unknown => {
  const raw = values[key]?.trim();
  if (!raw) return fallback;
  try {
    return JSON.parse(raw) as unknown;
  } catch (error) {
    throw new Error(`${key} must be valid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
};

const requiredValue = (values: AdminActionValues, key: string): string => {
  const value = values[key]?.trim();
  if (!value) throw new Error(`${key} is required`);
  return value;
};

const optionalValue = (values: AdminActionValues, key: string): string | undefined => {
  const value = values[key]?.trim();
  return value || undefined;
};

const numberValue = (values: AdminActionValues, key: string): number | undefined => {
  const value = optionalValue(values, key);
  if (!value) return undefined;
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) throw new Error(`${key} must be numeric`);
  return numeric;
};

const csvValue = (values: AdminActionValues, key: string): readonly string[] | undefined => {
  const value = optionalValue(values, key);
  if (!value) return undefined;
  return value.split(",").map((item) => item.trim()).filter(Boolean);
};

const compact = (record: AdminRecord): AdminRecord => {
  const entries = Object.entries(record).filter(([, value]) => {
    if (value === undefined || value === null) return false;
    if (typeof value === "string") return value.trim() !== "";
    if (Array.isArray(value)) return value.length > 0;
    return true;
  });
  return Object.fromEntries(entries);
};

const isRecord = (value: unknown): value is AdminRecord => {
  return typeof value === "object" && value !== null && !Array.isArray(value);
};

const asRecord = (value: unknown): AdminRecord => {
  if (isRecord(value)) return value;
  return { value };
};

const findArray = (data: AdminResult, keys: readonly string[]): readonly unknown[] | null => {
  if (Array.isArray(data)) return data;
  if (!isRecord(data)) return null;
  for (const key of keys) {
    const value = data[key];
    if (Array.isArray(value)) return value;
  }
  return null;
};

const rowsFrom = (...keys: readonly string[]) => (data: AdminResult): readonly AdminRecord[] => {
  const records = findArray(data, keys);
  if (records) return records.map(asRecord);
  if (isRecord(data) && Array.isArray(data.records)) return data.records.map(asRecord);
  if (isRecord(data) && Array.isArray(data.items)) return data.items.map(asRecord);
  return objectRows(data);
};

const objectRows = (data: AdminResult): readonly AdminRecord[] => {
  if (!isRecord(data)) return data === undefined ? [] : [{ key: "value", value: String(data) }];
  return Object.entries(data).map(([key, value]) => ({
    key,
    value: summarize(value),
    type: Array.isArray(value) ? "list" : typeof value,
  }));
};

const summarize = (value: unknown): string => {
  if (value === undefined || value === null) return "none";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (Array.isArray(value)) return `${value.length} item${value.length === 1 ? "" : "s"}`;
  if (isRecord(value)) return `${Object.keys(value).length} field${Object.keys(value).length === 1 ? "" : "s"}`;
  return String(value);
};

const bootstrapRows = (data: AdminResult): readonly AdminRecord[] => {
  const bootstrap = data as ConsoleBootstrap;
  if (!bootstrap?.version || !bootstrap?.counts) return objectRows(data);
  return [
    {
      module: "Kernel",
      state: bootstrap.health.kernel,
      value: bootstrap.version.version,
      source: bootstrap.version.commit,
    },
    {
      module: "Policy",
      state: bootstrap.health.policy,
      value: bootstrap.workspace.mode,
      source: bootstrap.workspace.environment,
    },
    {
      module: "Receipts",
      state: "available",
      value: bootstrap.counts.receipts,
      source: "receipt store",
    },
    {
      module: "Approvals",
      state: bootstrap.counts.pending_approvals > 0 ? "pending" : "clear",
      value: bootstrap.counts.pending_approvals,
      source: "approval ceremonies",
    },
    {
      module: "MCP",
      state: bootstrap.mcp.authorization,
      value: bootstrap.counts.mcp_tools,
      source: bootstrap.mcp.scopes.join(", ") || "no scopes",
    },
    {
      module: "Conformance",
      state: bootstrap.conformance.status,
      value: bootstrap.conformance.level,
      source: bootstrap.conformance.report_id ?? "no report",
    },
  ];
};

const diagnosticsRows = (data: AdminResult): readonly AdminRecord[] => {
  const diagnostics = data as ConsoleDiagnostics;
  if (!diagnostics?.stores) return objectRows(data);
  return [
    ...diagnostics.stores.map((store) => ({
      id: store.id,
      label: store.label,
      status: store.status,
      backend: store.backend,
      source: store.source ?? store.path ?? "runtime",
      detail: store.detail ?? "",
    })),
    {
      id: "route_coverage",
      label: "Route coverage",
      status: `${diagnostics.routes.length} routes`,
      backend: "runtime registry",
      source: "/api/v1/console/diagnostics",
      detail: `${diagnostics.routes.filter((route) => route.ui_coverage === "wired").length} wired`,
    },
  ];
};

const loadSurface = (surface: string) => () => loadConsoleSurface(surface);

const bodyFromJson = (values: AdminActionValues, key = "body_json"): AdminRecord => {
  const parsed = jsonField(values, key, {});
  if (!isRecord(parsed)) throw new Error(`${key} must be a JSON object`);
  return parsed;
};

const commonJsonField: AdminFieldConfig = {
  id: "body_json",
  label: "Request body JSON",
  kind: "textarea",
  placeholder: '{"metadata":{}}',
  defaultValue: "{}",
};

export const ADMIN_SURFACES: Record<string, AdminSurfaceConfig> = {
  overview: {
    id: "overview",
    title: "Control plane overview",
    eyebrow: "Workspace",
    body: "Live kernel health, policy state, receipt counts, approval backlog, MCP posture, and conformance level.",
    source: "GET /api/v1/console/bootstrap",
    read: loadBootstrap,
    rows: bootstrapRows,
    columns: [
      { key: "module", label: "Module", priority: "primary" },
      { key: "state", label: "State" },
      { key: "value", label: "Value" },
      { key: "source", label: "Source", priority: "meta" },
    ],
    detailTitle: "Module snapshot",
    emptyTitle: "Bootstrap returned no modules",
    emptyBody: "The console did not receive kernel bootstrap data. Check the API process and admin credentials.",
  },
  agents: {
    id: "agents",
    title: "Agent identities",
    eyebrow: "Identity",
    body: "Non-human principals known to the execution boundary, with tenant and posture metadata from the OSS API.",
    source: "GET /api/v1/identity/agents",
    read: listAgentIdentities,
    rows: rowsFrom("agents", "identities"),
    columns: [
      { key: "agent_id", label: "Agent", priority: "primary" },
      { key: "tenant_id", label: "Tenant" },
      { key: "status", label: "State" },
      { key: "public_key_hash", label: "Key hash", priority: "meta" },
    ],
    detailTitle: "Agent identity",
    emptyTitle: "No agent identities",
    emptyBody: "The boundary registry returned no agent identities for this tenant.",
  },
  actions: {
    id: "actions",
    title: "Action catalog",
    eyebrow: "Governed effects",
    body: "Readable action/effect inventory from the console surface contract. Mutations are disabled because the OSS API does not expose action management routes.",
    source: "GET /api/v1/console/surfaces/actions",
    read: loadSurface("actions"),
    rows: rowsFrom("records", "actions"),
    columns: [
      { key: "id", label: "Action", priority: "primary" },
      { key: "effect", label: "Effect" },
      { key: "risk", label: "Risk" },
      { key: "status", label: "State" },
    ],
    detailTitle: "Action contract",
    emptyTitle: "No action catalog",
    emptyBody: "No action records are available from the current console surface.",
  },
  approvals: {
    id: "approvals",
    title: "Approval ceremonies",
    eyebrow: "Human-in-the-loop",
    body: "Create approval ceremonies, issue WebAuthn challenges, assert passkey evidence, and transition ceremonies when policy allows it.",
    source: "GET/POST /api/v1/approvals",
    read: listApprovals,
    rows: rowsFrom("approvals", "ceremonies"),
    columns: [
      { key: "approval_id", label: "Approval", priority: "primary" },
      { key: "subject", label: "Subject" },
      { key: "status", label: "State" },
      { key: "receipt_id", label: "Receipt", priority: "meta" },
    ],
    detailTitle: "Approval ceremony",
    emptyTitle: "No approval ceremonies",
    emptyBody: "There are no pending or completed approval ceremonies for this tenant.",
    actions: [
      {
        id: "create-approval",
        label: "Create ceremony",
        description: "Open a cryptographic approval ceremony for a governed action.",
        refreshAfter: true,
        fields: [
          { id: "approval_id", label: "Approval ID", placeholder: "approval-..." },
          { id: "subject", label: "Subject", required: true, placeholder: "principal or request subject" },
          { id: "action", label: "Action", required: true, placeholder: "refund.approve" },
          { id: "resource", label: "Resource", placeholder: "ticket/123" },
          { id: "requested_by", label: "Requested by", placeholder: "agent or operator id" },
          { id: "quorum", label: "Quorum", placeholder: "1" },
          commonJsonField,
        ],
        run: (values) => createApproval(compact({
          approval_id: optionalValue(values, "approval_id"),
          subject: requiredValue(values, "subject"),
          action: requiredValue(values, "action"),
          resource: optionalValue(values, "resource"),
          requested_by: optionalValue(values, "requested_by"),
          quorum: numberValue(values, "quorum"),
          metadata: jsonField(values, "body_json", {}),
        })),
      },
      {
        id: "webauthn-challenge",
        label: "Create WebAuthn challenge",
        description: "Generate a passkey challenge for an existing ceremony.",
        fields: [
          { id: "approval_id", label: "Approval ID", required: true },
          { id: "actor_id", label: "Actor ID", placeholder: "operator id" },
          { id: "ttl_ms", label: "TTL ms", placeholder: "300000" },
        ],
        run: (values) => createApprovalWebAuthnChallenge(requiredValue(values, "approval_id"), compact({
          actor_id: optionalValue(values, "actor_id"),
          ttl_ms: numberValue(values, "ttl_ms"),
        })),
      },
      {
        id: "assert-webauthn",
        label: "Assert WebAuthn",
        description: "Submit passkey assertion material for a ceremony challenge.",
        refreshAfter: true,
        fields: [
          { id: "approval_id", label: "Approval ID", required: true },
          { id: "challenge_id", label: "Challenge ID", required: true },
          { id: "actor_id", label: "Actor ID", required: true },
          { id: "assertion_json", label: "Assertion JSON", kind: "textarea", required: true, defaultValue: "{}" },
        ],
        run: (values) => assertApprovalWebAuthn(requiredValue(values, "approval_id"), compact({
          challenge_id: requiredValue(values, "challenge_id"),
          actor_id: requiredValue(values, "actor_id"),
          assertion: jsonField(values, "assertion_json", {}),
        })),
      },
      {
        id: "transition-approval",
        label: "Transition ceremony",
        description: "Approve, deny, escalate, or revoke when the backend allows that transition.",
        refreshAfter: true,
        fields: [
          { id: "approval_id", label: "Approval ID", required: true },
          { id: "transition", label: "Transition", kind: "select", required: true, options: ["approve", "deny", "escalate", "revoke"] },
          { id: "actor_id", label: "Actor ID", required: true },
          { id: "reason", label: "Reason", placeholder: "policy reason" },
        ],
        run: (values) => transitionApproval(requiredValue(values, "approval_id"), requiredValue(values, "transition"), compact({
          actor_id: requiredValue(values, "actor_id"),
          reason: optionalValue(values, "reason"),
        })),
      },
    ],
  },
  policies: {
    id: "policies",
    title: "Policy posture",
    eyebrow: "Policy",
    body: "Read-only policy posture from the console surface. Policy authoring is intentionally not exposed through the OSS admin API.",
    source: "GET /api/v1/console/surfaces/policies",
    read: loadSurface("policies"),
    rows: rowsFrom("records", "policies"),
    columns: [
      { key: "id", label: "Policy", priority: "primary" },
      { key: "kind", label: "Kind" },
      { key: "status", label: "State" },
      { key: "source", label: "Source", priority: "meta" },
    ],
    detailTitle: "Policy record",
    emptyTitle: "No policy surface",
    emptyBody: "The current API did not expose policy posture records.",
  },
  boundary: {
    id: "boundary",
    title: "Boundary records",
    eyebrow: "Execution boundary",
    body: "Browse sealed boundary records, verify records, and create or verify checkpoints against the existing boundary API.",
    source: "GET /api/v1/boundary/records",
    read: listBoundaryRecords,
    rows: rowsFrom("records", "boundary_records"),
    columns: [
      { key: "record_id", label: "Record", priority: "primary" },
      { key: "subject", label: "Subject" },
      { key: "status", label: "State" },
      { key: "record_hash", label: "Hash", priority: "meta" },
    ],
    detailTitle: "Boundary record",
    emptyTitle: "No boundary records",
    emptyBody: "No sealed boundary records are available for this tenant.",
    actions: [
      {
        id: "boundary-status",
        label: "Read status",
        description: "Read boundary runtime status, component posture, and checkpoint state.",
        run: () => loadBoundaryStatus(),
      },
      {
        id: "boundary-capabilities",
        label: "Read capabilities",
        description: "Read boundary capability declarations and public route bindings.",
        run: () => loadBoundaryCapabilities(),
      },
      {
        id: "verify-record",
        label: "Verify record",
        description: "Verify a sealed boundary record by ID.",
        fields: [{ id: "record_id", label: "Record ID", required: true }],
        run: (values) => verifyBoundaryRecord(requiredValue(values, "record_id")),
      },
      {
        id: "list-checkpoints",
        label: "List checkpoints",
        description: "Read sealed boundary checkpoints.",
        run: () => listBoundaryCheckpoints(),
      },
      {
        id: "create-checkpoint",
        label: "Create checkpoint",
        description: "Create a boundary checkpoint from the supplied API body.",
        refreshAfter: true,
        fields: [commonJsonField],
        run: (values) => createBoundaryCheckpoint(bodyFromJson(values)),
      },
      {
        id: "verify-checkpoint",
        label: "Verify checkpoint",
        description: "Verify a sealed boundary checkpoint.",
        fields: [{ id: "checkpoint_id", label: "Checkpoint ID", required: true }],
        run: (values) => verifyBoundaryCheckpoint(requiredValue(values, "checkpoint_id")),
      },
    ],
  },
  mcp: {
    id: "mcp",
    title: "MCP registry",
    eyebrow: "Connectors",
    body: "Review quarantined and approved MCP servers, scan tool bundles, approve or revoke servers, manage auth profiles, and test call authorization.",
    source: "GET /api/v1/mcp/registry",
    read: listMcpRegistry,
    rows: rowsFrom("servers", "registry", "records"),
    columns: [
      { key: "server_id", label: "Server", priority: "primary" },
      { key: "state", label: "State" },
      { key: "risk", label: "Risk" },
      { key: "approval_receipt_id", label: "Receipt", priority: "meta" },
    ],
    detailTitle: "MCP server",
    emptyTitle: "No MCP registry records",
    emptyBody: "No MCP servers have been discovered, quarantined, or approved yet.",
    actions: [
      {
        id: "scan-mcp",
        label: "Scan registry",
        description: "Scan and quarantine an MCP server or tool bundle.",
        refreshAfter: true,
        fields: [commonJsonField],
        run: (values) => scanMcpRegistry(bodyFromJson(values)),
      },
      {
        id: "approve-registry",
        label: "Approve via body",
        description: "Approve a quarantined server with the registry-level route.",
        refreshAfter: true,
        fields: [commonJsonField],
        run: (values) => approveMcpRegistry(bodyFromJson(values)),
      },
      {
        id: "approve-server",
        label: "Approve server",
        description: "Approve a server by path ID and receipt metadata.",
        refreshAfter: true,
        fields: [
          { id: "server_id", label: "Server ID", required: true },
          commonJsonField,
        ],
        run: (values) => approveMcpServer(requiredValue(values, "server_id"), bodyFromJson(values)),
      },
      {
        id: "revoke-server",
        label: "Revoke server",
        description: "Revoke a previously approved MCP server.",
        refreshAfter: true,
        fields: [
          { id: "server_id", label: "Server ID", required: true },
          commonJsonField,
        ],
        run: (values) => revokeMcpServer(requiredValue(values, "server_id"), bodyFromJson(values)),
      },
      {
        id: "auth-profiles",
        label: "List auth profiles",
        description: "Read MCP OAuth authorization profiles.",
        run: () => listMcpAuthProfiles(),
      },
      {
        id: "update-auth-profile",
        label: "Update auth profile",
        description: "Create or replace an MCP auth profile by ID.",
        fields: [
          { id: "profile_id", label: "Profile ID", required: true },
          commonJsonField,
        ],
        run: (values) => updateMcpAuthProfile(requiredValue(values, "profile_id"), bodyFromJson(values)),
      },
      {
        id: "authorize-call",
        label: "Authorize call",
        description: "Run the MCP tools/call authorization tester.",
        fields: [commonJsonField],
        run: (values) => authorizeMcpCall(bodyFromJson(values)),
      },
    ],
  },
  sandbox: {
    id: "sandbox",
    title: "Sandbox grants",
    eyebrow: "Runtime isolation",
    body: "Inspect profiles and grants, create sealed grants, verify grant signatures, preflight permissions, and inspect runtime posture.",
    source: "GET /api/v1/sandbox/grants",
    read: listSandboxGrants,
    rows: rowsFrom("grants", "records"),
    columns: [
      { key: "grant_id", label: "Grant", priority: "primary" },
      { key: "runtime", label: "Runtime" },
      { key: "state", label: "State" },
      { key: "receipt_id", label: "Receipt", priority: "meta" },
    ],
    detailTitle: "Sandbox grant",
    emptyTitle: "No sandbox grants",
    emptyBody: "No sealed runtime grants have been created for this tenant.",
    actions: [
      {
        id: "profiles",
        label: "List profiles",
        description: "Read built-in sandbox backend profiles.",
        run: () => listSandboxProfiles(),
      },
      {
        id: "create-grant",
        label: "Create grant",
        description: "Create a sealed sandbox grant from the supplied API body.",
        refreshAfter: true,
        fields: [commonJsonField],
        run: (values) => createSandboxGrant(bodyFromJson(values)),
      },
      {
        id: "verify-grant",
        label: "Verify grant",
        description: "Verify a sealed sandbox grant before execution.",
        fields: [{ id: "grant_id", label: "Grant ID", required: true }],
        run: (values) => verifySandboxGrant(requiredValue(values, "grant_id")),
      },
      {
        id: "preflight-grant",
        label: "Preflight",
        description: "Check a requested sandbox execution against grant constraints.",
        fields: [commonJsonField],
        run: (values) => preflightSandboxGrant(bodyFromJson(values)),
      },
      {
        id: "inspect-runtime",
        label: "Inspect runtime",
        description: "Inspect sandbox backend profiles or a specific grant.",
        fields: [
          { id: "runtime", label: "Runtime", placeholder: "firecracker" },
          { id: "grant_id", label: "Grant ID" },
        ],
        run: (values) => inspectSandboxRuntime(optionalValue(values, "runtime"), optionalValue(values, "grant_id")),
      },
    ],
  },
  authz: {
    id: "authz",
    title: "Authorization snapshots",
    eyebrow: "Authz",
    body: "List sealed ReBAC/PDP snapshots and run authorization checks that seal relationship evidence.",
    source: "GET /api/v1/authz/snapshots",
    read: listAuthzSnapshots,
    rows: rowsFrom("snapshots", "records"),
    columns: [
      { key: "snapshot_id", label: "Snapshot", priority: "primary" },
      { key: "subject", label: "Subject" },
      { key: "result", label: "Result" },
      { key: "snapshot_hash", label: "Hash", priority: "meta" },
    ],
    detailTitle: "Authorization snapshot",
    emptyTitle: "No authorization snapshots",
    emptyBody: "No authz checks have sealed snapshots for this tenant.",
    actions: [
      {
        id: "authz-health",
        label: "Read health",
        description: "Read ReBAC/PDP health.",
        run: () => loadAuthzHealth(),
      },
      {
        id: "authz-check",
        label: "Run check",
        description: "Evaluate authorization and seal a relationship snapshot.",
        refreshAfter: true,
        fields: [commonJsonField],
        run: (values) => checkAuthz(bodyFromJson(values)),
      },
    ],
  },
  budgets: {
    id: "budgets",
    title: "Budget ceilings",
    eyebrow: "Budgets",
    body: "Read and update budget and velocity ceilings through the public OSS admin API.",
    source: "GET/PUT /api/v1/budgets",
    read: listBudgets,
    rows: rowsFrom("budgets", "ceilings", "records"),
    columns: [
      { key: "budget_id", label: "Budget", priority: "primary" },
      { key: "scope", label: "Scope" },
      { key: "ceiling", label: "Ceiling" },
      { key: "receipt_id", label: "Receipt", priority: "meta" },
    ],
    detailTitle: "Budget ceiling",
    emptyTitle: "No budget ceilings",
    emptyBody: "No budget ceilings are configured for this tenant.",
    actions: [
      {
        id: "update-budget",
        label: "Update ceiling",
        description: "Create or replace a budget ceiling by ID.",
        refreshAfter: true,
        fields: [
          { id: "budget_id", label: "Budget ID", required: true },
          commonJsonField,
        ],
        run: (values) => updateBudget(requiredValue(values, "budget_id"), bodyFromJson(values)),
      },
    ],
  },
  connectors: {
    id: "connectors",
    title: "Governed connector capabilities",
    eyebrow: "MCP tools",
    body: "Read governed MCP tool capabilities from the runtime gateway and test per-call authorization through the admin route.",
    source: "GET /mcp/v1/capabilities",
    read: loadMcpCapabilities,
    rows: rowsFrom("tools", "capabilities", "records"),
    columns: [
      { key: "name", label: "Tool", priority: "primary" },
      { key: "server_id", label: "Server" },
      { key: "risk", label: "Risk" },
      { key: "scope", label: "Scope", priority: "meta" },
    ],
    detailTitle: "Connector capability",
    emptyTitle: "No connector capabilities",
    emptyBody: "The MCP runtime did not expose any governed capabilities.",
    actions: [
      {
        id: "authorize-call",
        label: "Authorize call",
        description: "Run the MCP tools/call authorization tester.",
        fields: [commonJsonField],
        run: (values) => authorizeMcpCall(bodyFromJson(values)),
      },
    ],
  },
  evidence: {
    id: "evidence",
    title: "Evidence envelopes",
    eyebrow: "Evidence",
    body: "Browse envelope manifests, create envelopes, verify manifests, export evidence bundles, and verify uploaded bundles.",
    source: "GET /api/v1/evidence/envelopes",
    read: listEvidenceEnvelopes,
    rows: rowsFrom("envelopes", "manifests", "records"),
    columns: [
      { key: "manifest_id", label: "Manifest", priority: "primary" },
      { key: "state", label: "State" },
      { key: "artifact_count", label: "Artifacts" },
      { key: "receipt_id", label: "Receipt", priority: "meta" },
    ],
    detailTitle: "Evidence manifest",
    emptyTitle: "No evidence envelopes",
    emptyBody: "No envelope manifests are available for this tenant.",
    actions: [
      {
        id: "create-envelope",
        label: "Create envelope",
        description: "Create an evidence envelope manifest from an API request body.",
        refreshAfter: true,
        fields: [commonJsonField],
        run: (values) => createEvidenceEnvelope(bodyFromJson(values)),
      },
      {
        id: "verify-envelope",
        label: "Verify envelope",
        description: "Verify an evidence envelope manifest.",
        fields: [
          { id: "manifest_id", label: "Manifest ID", required: true },
          commonJsonField,
        ],
        run: (values) => verifyEvidenceEnvelope(requiredValue(values, "manifest_id"), bodyFromJson(values)),
      },
      {
        id: "load-envelope-payload",
        label: "Load payload",
        description: "Load an evidence envelope payload by manifest ID.",
        fields: [{ id: "manifest_id", label: "Manifest ID", required: true }],
        run: (values) => loadEvidenceEnvelopePayload(requiredValue(values, "manifest_id")),
      },
      {
        id: "list-verification-scopes",
        label: "List scopes",
        description: "Read evidence verification scopes.",
        run: () => listVerificationScopes(),
      },
      {
        id: "create-verification-scope",
        label: "Create scope",
        description: "Create a verification scope from the supplied request body.",
        refreshAfter: true,
        fields: [commonJsonField],
        run: (values) => createVerificationScope(bodyFromJson(values)),
      },
      {
        id: "load-verification-scope",
        label: "Load scope",
        description: "Load a verification scope by ID.",
        fields: [{ id: "scope_id", label: "Scope ID", required: true }],
        run: (values) => loadVerificationScope(requiredValue(values, "scope_id")),
      },
      {
        id: "verify-verification-scope",
        label: "Verify scope",
        description: "Verify a saved verification scope.",
        fields: [{ id: "scope_id", label: "Scope ID", required: true }],
        run: (values) => verifyVerificationScope(requiredValue(values, "scope_id")),
      },
      {
        id: "export-evidence",
        label: "Export bundle",
        description: "Export a DSSE/JWS evidence bundle. The result reports byte count and content type.",
        fields: [commonJsonField],
        run: (values) => exportEvidence(bodyFromJson(values)),
      },
      {
        id: "verify-bundle",
        label: "Verify bundle",
        description: "Verify an evidence bundle pasted as base64.",
        fields: [{ id: "bundle_base64", label: "Bundle base64", kind: "textarea", required: true }],
        run: (values) => verifyEvidenceBundleBase64(requiredValue(values, "bundle_base64")),
      },
    ],
  },
  replay: {
    id: "replay",
    title: "Replay verification",
    eyebrow: "Replay",
    body: "Run replay verification against an evidence bundle or request body and inspect recent evidence manifests.",
    source: "POST /api/v1/replay/verify",
    read: listEvidenceEnvelopes,
    rows: rowsFrom("envelopes", "manifests", "records"),
    columns: [
      { key: "manifest_id", label: "Manifest", priority: "primary" },
      { key: "state", label: "State" },
      { key: "receipt_id", label: "Receipt" },
      { key: "created_at", label: "Created", priority: "meta" },
    ],
    detailTitle: "Replay evidence",
    emptyTitle: "No replay evidence",
    emptyBody: "No envelope manifests are available to replay from this tenant.",
    actions: [
      {
        id: "replay-verify",
        label: "Verify replay",
        description: "Run replay verification with the supplied request body.",
        fields: [commonJsonField],
        run: (values) => replayVerifyEvidence(bodyFromJson(values)),
      },
    ],
  },
  conformance: {
    id: "conformance",
    title: "Conformance reports",
    eyebrow: "Conformance",
    body: "Run conformance, browse reports, inspect vectors, and read negative gates exposed by the OSS API.",
    source: "GET /api/v1/conformance/reports",
    read: listConformanceReports,
    rows: rowsFrom("reports", "records"),
    columns: [
      { key: "report_id", label: "Report", priority: "primary" },
      { key: "level", label: "Level" },
      { key: "status", label: "State" },
      { key: "created_at", label: "Created", priority: "meta" },
    ],
    detailTitle: "Conformance report",
    emptyTitle: "No conformance reports",
    emptyBody: "No conformance reports are available yet. Run conformance to create one.",
    actions: [
      {
        id: "run-conformance",
        label: "Run conformance",
        description: "Run conformance with the supplied request body.",
        refreshAfter: true,
        fields: [commonJsonField],
        run: (values) => runConformance(bodyFromJson(values)),
      },
      {
        id: "list-vectors",
        label: "List vectors",
        description: "Read conformance vector catalog.",
        run: () => listConformanceVectors(),
      },
      {
        id: "negative-gates",
        label: "Negative gates",
        description: "Read negative conformance gates.",
        run: () => loadConformanceNegative(),
      },
    ],
  },
  proofgraph: {
    id: "proofgraph",
    title: "ProofGraph sessions",
    eyebrow: "ProofGraph",
    body: "Browse proof sessions, load receipt chains by session, and resolve receipts by hash through the runtime proofgraph routes.",
    source: "GET /api/v1/proofgraph/sessions",
    read: listProofgraphSessions,
    rows: rowsFrom("sessions", "records", "items"),
    columns: [
      { key: "session_id", label: "Session", priority: "primary" },
      { key: "receipt_count", label: "Receipts" },
      { key: "status", label: "State" },
      { key: "updated_at", label: "Updated", priority: "meta" },
    ],
    detailTitle: "ProofGraph session",
    emptyTitle: "No proof sessions",
    emptyBody: "No ProofGraph sessions are available for this tenant.",
    actions: [
      {
        id: "session-receipts",
        label: "Load session receipts",
        description: "Fetch receipts attached to a ProofGraph session.",
        fields: [{ id: "session_id", label: "Session ID", required: true }],
        run: (values) => loadProofgraphSessionReceipts(requiredValue(values, "session_id")),
      },
      {
        id: "receipt-by-hash",
        label: "Load receipt hash",
        description: "Resolve a receipt through the ProofGraph receipt hash route.",
        fields: [{ id: "receipt_hash", label: "Receipt hash", required: true }],
        run: (values) => loadProofgraphReceipt(requiredValue(values, "receipt_hash")),
      },
    ],
  },
  harness: {
    id: "harness",
    title: "Harness engineering",
    eyebrow: "Harness",
    body: "Manage harness traces, plan transactions, change contracts, approvals, verification, and GUI receipt checks.",
    source: "GET /api/v1/harness/change-contracts",
    read: listHarnessChangeContracts,
    rows: rowsFrom("changes", "contracts", "records", "items"),
    columns: [
      { key: "change_id", label: "Change", priority: "primary" },
      { key: "state", label: "State" },
      { key: "risk", label: "Risk" },
      { key: "receipt_ref", label: "Receipt", priority: "meta" },
    ],
    detailTitle: "Harness change",
    emptyTitle: "No harness changes",
    emptyBody: "No harness change contracts have been recorded for this tenant.",
    actions: [
      {
        id: "list-traces",
        label: "List traces",
        description: "Read telemetry harness traces.",
        run: () => listHarnessTraces(),
      },
      {
        id: "create-trace",
        label: "Create trace",
        description: "Create a harness trace from JSON.",
        fields: [commonJsonField],
        refreshAfter: true,
        run: (values) => createHarnessTrace(bodyFromJson(values)),
      },
      {
        id: "load-trace",
        label: "Load trace",
        description: "Load a harness trace by ID.",
        fields: [{ id: "trace_id", label: "Trace ID", required: true }],
        run: (values) => loadHarnessTrace(requiredValue(values, "trace_id")),
      },
      {
        id: "verify-trace",
        label: "Verify trace",
        description: "Verify a harness trace by ID.",
        fields: [{ id: "trace_id", label: "Trace ID", required: true }],
        run: (values) => verifyHarnessTrace(requiredValue(values, "trace_id")),
      },
      {
        id: "list-plan-transactions",
        label: "List plans",
        description: "Read plan transactions.",
        run: () => listPlanTransactions(),
      },
      {
        id: "create-plan-transaction",
        label: "Create plan",
        description: "Create a plan transaction from JSON.",
        fields: [commonJsonField],
        refreshAfter: true,
        run: (values) => createPlanTransaction(bodyFromJson(values)),
      },
      {
        id: "load-plan-transaction",
        label: "Load plan",
        description: "Load a plan transaction by ID.",
        fields: [{ id: "transaction_id", label: "Transaction ID", required: true }],
        run: (values) => loadPlanTransaction(requiredValue(values, "transaction_id")),
      },
      {
        id: "verify-plan-transaction",
        label: "Verify plan",
        description: "Verify a plan transaction.",
        fields: [{ id: "transaction_id", label: "Transaction ID", required: true }],
        run: (values) => verifyPlanTransaction(requiredValue(values, "transaction_id")),
      },
      {
        id: "create-change",
        label: "Create change",
        description: "Create a harness change contract from JSON.",
        fields: [commonJsonField],
        refreshAfter: true,
        run: (values) => createHarnessChangeContract(bodyFromJson(values)),
      },
      {
        id: "load-change",
        label: "Load change",
        description: "Load a harness change contract by ID.",
        fields: [{ id: "change_id", label: "Change ID", required: true }],
        run: (values) => loadHarnessChangeContract(requiredValue(values, "change_id")),
      },
      {
        id: "approve-change",
        label: "Approve change",
        description: "Approve a harness change contract with receipt evidence.",
        fields: [
          { id: "change_id", label: "Change ID", required: true },
          commonJsonField,
        ],
        refreshAfter: true,
        run: (values) => approveHarnessChangeContract(requiredValue(values, "change_id"), bodyFromJson(values)),
      },
      {
        id: "verify-change",
        label: "Verify change",
        description: "Verify a harness change contract.",
        fields: [{ id: "change_id", label: "Change ID", required: true }],
        run: (values) => verifyHarnessChangeContract(requiredValue(values, "change_id")),
      },
      {
        id: "verify-gui-receipt",
        label: "Verify GUI receipt",
        description: "Verify a GUI action receipt from JSON.",
        fields: [commonJsonField],
        run: (values) => verifyGUIActionReceipt(bodyFromJson(values)),
      },
    ],
  },
  launchpad: {
    id: "launchpad",
    title: "Launchpad runtime",
    eyebrow: "Launchpad",
    body: "Read app/substrate matrix and run governed plan, launch, repair, status, and teardown operations from the same API client as the rest of Console.",
    source: "GET /api/v1/launchpad/matrix",
    read: loadLaunchpadMatrix,
    rows: rowsFrom("matrix", "records", "items"),
    columns: [
      { key: "app_id", label: "App", priority: "primary" },
      { key: "substrate_id", label: "Substrate" },
      { key: "verdict", label: "Verdict" },
      { key: "reason", label: "Reason", priority: "meta" },
    ],
    detailTitle: "Launchpad matrix cell",
    emptyTitle: "No Launchpad matrix",
    emptyBody: "The Launchpad API returned no app/substrate cells.",
    actions: [
      {
        id: "list-apps",
        label: "List apps",
        description: "Read Launchpad app specs.",
        run: () => listLaunchpadApps(),
      },
      {
        id: "list-substrates",
        label: "List substrates",
        description: "Read Launchpad substrate specs.",
        run: () => listLaunchpadSubstrates(),
      },
      {
        id: "plan-launch",
        label: "Plan",
        description: "Compile a Launchpad plan without starting side effects.",
        fields: [
          { id: "app_id", label: "App ID", required: true },
          { id: "substrate_id", label: "Substrate ID", required: true },
        ],
        run: (values) => planLaunchpad(requiredValue(values, "app_id"), requiredValue(values, "substrate_id")),
      },
      {
        id: "start-launch",
        label: "Launch",
        description: "Start a governed Launchpad run.",
        fields: [
          { id: "app_id", label: "App ID", required: true },
          { id: "substrate_id", label: "Substrate ID", required: true },
        ],
        refreshAfter: true,
        run: (values) => launchLaunchpad(requiredValue(values, "app_id"), requiredValue(values, "substrate_id")),
      },
      {
        id: "load-launch",
        label: "Load run",
        description: "Read a Launchpad run by ID.",
        fields: [{ id: "launch_id", label: "Launch ID", required: true }],
        run: (values) => loadLaunchpadRun(requiredValue(values, "launch_id")),
      },
      {
        id: "repair-launch",
        label: "Repair",
        description: "Build a deterministic repair plan.",
        fields: [{ id: "launch_id", label: "Launch ID", required: true }],
        run: (values) => repairLaunchpadRun(requiredValue(values, "launch_id")),
      },
      {
        id: "delete-launch",
        label: "Teardown",
        description: "Record Launchpad teardown for a run.",
        fields: [{ id: "launch_id", label: "Launch ID", required: true }],
        refreshAfter: true,
        run: (values) => deleteLaunchpadRun(requiredValue(values, "launch_id")),
      },
    ],
  },
  trust: {
    id: "trust",
    title: "Trust keys",
    eyebrow: "Trust",
    body: "Add or revoke trust keys through the OSS admin API. The diagnostics panel shows the current backend persistence mode.",
    source: "POST /api/v1/trust/keys/add",
    read: loadSurface("trust"),
    rows: rowsFrom("records", "routes"),
    columns: [
      { key: "operation_id", label: "Operation", priority: "primary" },
      { key: "method", label: "Method" },
      { key: "path", label: "Path" },
      { key: "ui_coverage", label: "Coverage", priority: "meta" },
    ],
    detailTitle: "Trust route",
    emptyTitle: "No trust route metadata",
    emptyBody: "Trust key routes are mutation-only in this OSS runtime.",
    actions: [
      {
        id: "add-trust-key",
        label: "Add key",
        description: "Add a tenant trust key. Public key must be Ed25519 hex.",
        fields: [
          { id: "tenant_id", label: "Tenant ID", required: true },
          { id: "key_id", label: "Key ID", required: true },
          { id: "public_key", label: "Public key hex", required: true },
        ],
        run: (values) => addTrustKey({
          tenant_id: requiredValue(values, "tenant_id"),
          key_id: requiredValue(values, "key_id"),
          public_key: requiredValue(values, "public_key"),
        }),
      },
      {
        id: "revoke-trust-key",
        label: "Revoke key",
        description: "Revoke a tenant trust key.",
        fields: [
          { id: "tenant_id", label: "Tenant ID", required: true },
          { id: "key_id", label: "Key ID", required: true },
        ],
        run: (values) => revokeTrustKey({
          tenant_id: requiredValue(values, "tenant_id"),
          key_id: requiredValue(values, "key_id"),
        }),
      },
    ],
  },
  audit: {
    id: "audit",
    title: "Audit receipts",
    eyebrow: "Audit",
    body: "Searchable receipts remain in the receipts stream; this audit view focuses on receipt detail lookup and boundary checkpoints.",
    source: "GET /api/v1/boundary/checkpoints",
    read: listBoundaryCheckpoints,
    rows: rowsFrom("checkpoints", "records"),
    columns: [
      { key: "checkpoint_id", label: "Checkpoint", priority: "primary" },
      { key: "record_id", label: "Record" },
      { key: "status", label: "State" },
      { key: "receipt_id", label: "Receipt", priority: "meta" },
    ],
    detailTitle: "Audit checkpoint",
    emptyTitle: "No audit checkpoints",
    emptyBody: "No boundary checkpoints are available. Use Receipts for raw receipt search.",
    actions: [
      {
        id: "receipt-detail",
        label: "Load receipt detail",
        description: "Fetch a receipt by ID without fabricating fallback data.",
        fields: [{ id: "receipt_id", label: "Receipt ID", required: true }],
        run: (values) => loadReceiptDetail(requiredValue(values, "receipt_id")),
      },
    ],
  },
  telemetry: {
    id: "telemetry",
    title: "Telemetry configuration",
    eyebrow: "Telemetry",
    body: "Read non-authoritative OTel GenAI export configuration and send explicit telemetry export events.",
    source: "GET /api/v1/telemetry/otel/config",
    read: loadTelemetryOtelConfig,
    rows: objectRows,
    columns: [
      { key: "key", label: "Setting", priority: "primary" },
      { key: "value", label: "Value" },
      { key: "type", label: "Type", priority: "meta" },
    ],
    detailTitle: "Telemetry setting",
    emptyTitle: "No telemetry config",
    emptyBody: "The telemetry config route returned no fields.",
    actions: [
      {
        id: "export-telemetry",
        label: "Export event",
        description: "Export a non-authoritative telemetry event.",
        fields: [commonJsonField],
        run: (values) => exportTelemetry(bodyFromJson(values)),
      },
    ],
  },
  coexistence: {
    id: "coexistence",
    title: "Coexistence manifest",
    eyebrow: "Coexistence",
    body: "Read scanner and gateway coexistence capabilities used to keep HELM explicit about what it governs and what it only observes.",
    source: "GET /api/v1/coexistence/capabilities",
    read: loadCoexistenceCapabilities,
    rows: objectRows,
    columns: [
      { key: "key", label: "Capability", priority: "primary" },
      { key: "value", label: "Value" },
      { key: "type", label: "Type", priority: "meta" },
    ],
    detailTitle: "Coexistence capability",
    emptyTitle: "No coexistence manifest",
    emptyBody: "The coexistence capability route returned no fields.",
  },
  diagnostics: {
    id: "diagnostics",
    title: "Runtime diagnostics",
    eyebrow: "Diagnostics",
    body: "Redacted runtime, store, route, access, and UI coverage truth from the served backend.",
    source: "GET /api/v1/console/diagnostics",
    read: loadConsoleDiagnostics,
    rows: diagnosticsRows,
    columns: [
      { key: "label", label: "Subsystem", priority: "primary" },
      { key: "status", label: "State" },
      { key: "backend", label: "Backend" },
      { key: "source", label: "Source", priority: "meta" },
    ],
    detailTitle: "Diagnostic",
    emptyTitle: "No diagnostics",
    emptyBody: "The diagnostics route returned no runtime records.",
    actions: [
      {
        id: "surface-catalog",
        label: "Load surfaces",
        description: "Read backend-declared surface and route coverage metadata.",
        run: () => loadConsoleSurfaceCatalog(),
      },
    ],
  },
  developer: {
    id: "developer",
    title: "Developer contract",
    eyebrow: "Developer",
    body: "Developer-facing runtime contract exposed by the console surface. Unsupported operations remain read-only.",
    source: "GET /api/v1/console/surfaces/developer",
    read: loadSurface("developer"),
    rows: rowsFrom("records", "routes", "tools"),
    columns: [
      { key: "id", label: "Item", priority: "primary" },
      { key: "status", label: "State" },
      { key: "method", label: "Method" },
      { key: "path", label: "Path", priority: "meta" },
    ],
    detailTitle: "Developer record",
    emptyTitle: "No developer records",
    emptyBody: "The developer console surface returned no records.",
  },
  settings: {
    id: "settings",
    title: "Console settings",
    eyebrow: "Settings",
    body: "Runtime settings exposed by the console contract. Secret and policy management remains outside this OSS frontend.",
    source: "GET /api/v1/console/surfaces/settings",
    read: loadSurface("settings"),
    rows: rowsFrom("records", "settings"),
    columns: [
      { key: "id", label: "Setting", priority: "primary" },
      { key: "status", label: "State" },
      { key: "value", label: "Value" },
      { key: "source", label: "Source", priority: "meta" },
    ],
    detailTitle: "Setting",
    emptyTitle: "No settings records",
    emptyBody: "The settings console surface returned no records.",
  },
};
