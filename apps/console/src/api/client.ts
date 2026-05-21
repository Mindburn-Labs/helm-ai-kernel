import createClient from "openapi-fetch";
import { appendSseChunk, createSseFrameBuffer } from "../sse";
import type { paths } from "./schema";

export interface Receipt {
  readonly receipt_id?: string;
  readonly decision_id?: string;
  readonly effect_id?: string;
  readonly status?: string;
  readonly blob_hash?: string;
  readonly output_hash?: string;
  readonly timestamp?: string;
  readonly executor_id?: string;
  readonly metadata?: Record<string, unknown>;
  readonly signature?: string;
  readonly prev_hash?: string;
  readonly lamport_clock?: number;
  readonly args_hash?: string;
}

export interface ConsoleBootstrap {
  readonly version: {
    readonly version: string;
    readonly commit: string;
    readonly build_time: string;
    readonly go_version?: string;
  };
  readonly workspace: {
    readonly organization: string;
    readonly project: string;
    readonly environment: string;
    readonly mode: string;
  };
  readonly health: {
    readonly kernel: string;
    readonly policy: string;
    readonly store: string;
    readonly conformance: string;
  };
  readonly counts: {
    readonly receipts: number;
    readonly pending_approvals: number;
    readonly open_incidents: number;
    readonly mcp_tools: number;
  };
  readonly receipts: readonly Receipt[];
  readonly conformance: {
    readonly level: string;
    readonly status: string;
    readonly report_id?: string;
  };
  readonly mcp: {
    readonly authorization: string;
    readonly scopes: readonly string[];
  };
}

export interface DecisionRequest {
  readonly principal: string;
  readonly action: string;
  readonly resource: string;
  readonly context?: Record<string, unknown>;
}

export interface VerificationResult {
  readonly verdict?: string;
  readonly checks?: Record<string, string>;
  readonly errors?: readonly string[];
}

export interface DemoRunResult {
  readonly action_id: string;
  readonly selected_action: string;
  readonly active_policy: Record<string, unknown>;
  readonly verdict: string;
  readonly reason_code: string;
  readonly reason?: string;
  readonly receipt: Receipt;
  readonly proof_refs: Record<string, string>;
  readonly verification_hint: string;
  readonly sandbox_label: string;
  readonly helm_ai_kernel_version: string;
}

export interface DemoVerifyResult {
  readonly valid: boolean;
  readonly signature_valid?: boolean;
  readonly hash_matches?: boolean;
  readonly reason: string;
  readonly verified_fields?: readonly string[];
  readonly receipt_hash?: string;
  readonly expected_receipt_hash?: string;
  readonly original_hash?: string;
  readonly tampered_hash?: string;
}

export interface ConsoleSurfaceState {
  readonly id: string;
  readonly status: string;
  readonly source: string;
  readonly generated_at: string;
  readonly summary?: Record<string, unknown>;
  readonly records?: readonly Record<string, unknown>[];
}

export interface ConsoleRouteDiagnostic {
  readonly method: string;
  readonly path: string;
  readonly mux_pattern: string;
  readonly auth: string;
  readonly rate_limit: string;
  readonly contract_status: string;
  readonly operation_id: string;
  readonly owner: string;
  readonly group: string;
  readonly ui_coverage: "wired" | "developer-only" | "unsupported" | "missing" | string;
  readonly unsupported_reason?: string;
}

export interface ConsoleSurfaceRef {
  readonly id: string;
  readonly label?: string;
  readonly group?: string;
  readonly source: string;
  readonly auth?: string;
  readonly contract_status?: string;
  readonly status?: string;
  readonly unsupported_reason?: string;
  readonly routes?: readonly ConsoleRouteDiagnostic[];
}

export interface ConsoleSurfaceCatalog {
  readonly surfaces: readonly ConsoleSurfaceRef[];
  readonly routes?: readonly ConsoleRouteDiagnostic[];
}

export interface ConsoleStoreDiagnostic {
  readonly id: string;
  readonly label: string;
  readonly status: string;
  readonly backend: string;
  readonly source?: string;
  readonly path?: string;
  readonly detail?: string;
}

export interface ConsoleDiagnostics {
  readonly generated_at: string;
  readonly runtime: Record<string, unknown>;
  readonly access: Record<string, unknown>;
  readonly stores: readonly ConsoleStoreDiagnostic[];
  readonly routes: readonly ConsoleRouteDiagnostic[];
}

export interface LaunchpadApp {
  readonly id: string;
  readonly app_id?: string;
  readonly name: string;
  readonly version?: string;
  readonly oci_ref?: string;
  readonly immutable_digest?: string;
  readonly oss_supported?: boolean;
  readonly availability?: string;
  readonly redistribution?: string;
  readonly install_strategy?: string;
  readonly required_secrets?: readonly string[];
  readonly model_gateway_env?: readonly string[];
  readonly declared_capabilities?: readonly string[];
  readonly mcp_servers?: readonly Record<string, unknown>[];
  readonly filesystem_needs?: readonly string[];
  readonly network_needs?: readonly string[];
  readonly healthcheck?: readonly Record<string, unknown>[];
  readonly teardown_recipe?: Record<string, unknown>;
  readonly evidence_profile?: readonly string[];
  readonly risk_class?: string;
  readonly policy_ref?: string;
  readonly status?: Record<string, unknown>;
  readonly blocked_reason?: string;
}

export interface LaunchpadSubstrate {
  readonly id: string;
  readonly name: string;
  readonly kind?: string;
  readonly availability?: string;
  readonly default_dry_run?: boolean;
  readonly blocked_reason?: string;
}

export interface LaunchpadMatrixCell {
  readonly app_id: string;
  readonly substrate_id: string;
  readonly launchable: boolean;
  readonly verdict: string;
  readonly reason: string;
  readonly availability: string;
}

export interface LaunchpadPlanResponse {
  readonly launch_id: string;
  readonly app_id: string;
  readonly substrate_id: string;
  readonly state: string;
  readonly kernel_verdict: string;
  readonly reason?: string;
  readonly reason_code?: string;
  readonly plan_hash?: string;
  readonly evidence_refs?: readonly string[];
  readonly receipts?: readonly Record<string, unknown>[];
  readonly matrix_cell?: LaunchpadMatrixCell;
}

export interface LaunchpadRun {
  readonly launch_id?: string;
  readonly id?: string;
  readonly run_id?: string;
  readonly app_id: string;
  readonly substrate_id: string;
  readonly state: string;
  readonly kernel_verdict: string;
  readonly reason_code?: string;
  readonly reason?: string;
  readonly plan_hash?: string;
  readonly receipt_refs?: readonly Record<string, unknown>[];
  readonly install_receipt_refs?: readonly string[];
  readonly launch_receipt_refs?: readonly string[];
  readonly start_receipt_refs?: readonly string[];
  readonly secret_grant_refs?: readonly string[];
  readonly sandbox_grant_refs?: readonly string[];
  readonly mcp_refs?: readonly string[];
  readonly healthcheck_receipt_refs?: readonly string[];
  readonly teardown_receipt_refs?: readonly string[];
  readonly evidence_pack_refs?: readonly string[];
  readonly teardown_receipt_ref?: string;
  readonly verification_command?: string;
  readonly teardown_command?: string;
  readonly runtime_handles?: Record<string, unknown>;
}

export interface LaunchpadRunDetail {
  readonly run: LaunchpadRun;
  readonly instance: Record<string, unknown>;
  readonly gates: readonly Record<string, unknown>[];
  readonly events: readonly Record<string, unknown>[];
}

const client = createClient<paths>({
  baseUrl: "",
  fetch: (request) => {
    return fetch(new Request(request, { credentials: "include" }));
  },
});

const CONSOLE_ADMIN_KEY_STORAGE = "helm.console.admin_api_key";
const CONSOLE_TENANT_ID_STORAGE = "helm.console.tenant_id";
const DEFAULT_CONSOLE_TENANT_ID = "default";

export class ConsoleApiError extends Error {
  readonly status: number;
  readonly detail: string;

  constructor(message: string, status: number, detail: string) {
    super(`${message}: ${status} ${detail}`);
    this.name = "ConsoleApiError";
    this.status = status;
    this.detail = detail;
  }
}

function sessionStore(): Storage | null {
  if (typeof window === "undefined") return null;
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

export function getConsoleAdminKey(): string {
  return sessionStore()?.getItem(CONSOLE_ADMIN_KEY_STORAGE)?.trim() ?? "";
}

export function setConsoleAdminKey(value: string): void {
  const store = sessionStore();
  if (!store) return;
  const token = value.trim();
  if (token) {
    store.setItem(CONSOLE_ADMIN_KEY_STORAGE, token);
  } else {
    store.removeItem(CONSOLE_ADMIN_KEY_STORAGE);
  }
}

export function hasConsoleAdminKey(): boolean {
  return getConsoleAdminKey() !== "";
}

export function getConsoleTenantID(): string {
  const tenantID = sessionStore()?.getItem(CONSOLE_TENANT_ID_STORAGE)?.trim() ?? "";
  return tenantID || DEFAULT_CONSOLE_TENANT_ID;
}

export function setConsoleTenantID(value: string): void {
  const store = sessionStore();
  if (!store) return;
  const tenantID = value.trim();
  if (tenantID) {
    store.setItem(CONSOLE_TENANT_ID_STORAGE, tenantID);
  } else {
    store.removeItem(CONSOLE_TENANT_ID_STORAGE);
  }
}

export function isUnauthorizedError(error: unknown): boolean {
  if (error instanceof ConsoleApiError) return error.status === 401 || error.status === 403;
  if (typeof error === "object" && error !== null && "status" in error) {
    const status = Number((error as { readonly status?: unknown }).status);
    return status === 401 || status === 403;
  }
  return false;
}

function authHeaders(): Record<string, string> {
  const token = getConsoleAdminKey();
  const headers: Record<string, string> = { "X-Helm-Tenant-ID": getConsoleTenantID() };
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

function errorDetail(error: unknown, fallbackMessage: string): string {
  if (typeof error === "string" && error.trim() !== "") return error;
  if (typeof error === "object" && error !== null) {
    const record = error as Record<string, unknown>;
    const detail = record.detail ?? record.title ?? record.error ?? record.message;
    if (typeof detail === "string" && detail.trim() !== "") return detail;
    return JSON.stringify(error);
  }
  return String(error ?? fallbackMessage);
}

async function unwrap<T>(promise: Promise<{ data?: T; error?: unknown; response: Response }>, fallbackMessage: string): Promise<T> {
  const { data, error, response } = await promise;
  if (!response.ok || error || data === undefined) {
    throw new ConsoleApiError(fallbackMessage, response.status, errorDetail(error, fallbackMessage));
  }
  return data;
}

export async function loadBootstrap(): Promise<ConsoleBootstrap> {
  return unwrap(client.GET("/api/v1/console/bootstrap", { headers: authHeaders() }), "Console bootstrap failed") as Promise<ConsoleBootstrap>;
}

export async function loadConsoleDiagnostics(): Promise<ConsoleDiagnostics> {
  return getAdminJson<ConsoleDiagnostics>("/api/v1/console/diagnostics", "Console diagnostics failed");
}

export async function loadConsoleSurfaceCatalog(): Promise<ConsoleSurfaceCatalog> {
  return getAdminJson<ConsoleSurfaceCatalog>("/api/v1/console/surfaces", "Console surface catalog failed");
}

async function jsonFetch<T>(path: string, body: unknown, fallbackMessage: string): Promise<T> {
  const response = await fetch(path, {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    throw await consoleApiErrorFromResponse(response, fallbackMessage);
  }
  return await response.json() as T;
}

export async function runPublicDemo(actionID: string): Promise<DemoRunResult> {
  return jsonFetch<DemoRunResult>("/api/demo/run", { action_id: actionID, policy_id: "agent_tool_call_boundary" }, "Demo run failed");
}

export async function verifyPublicDemoReceipt(receipt: Receipt, expectedReceiptHash: string): Promise<DemoVerifyResult> {
  return jsonFetch<DemoVerifyResult>(
    "/api/demo/verify",
    { receipt, expected_receipt_hash: expectedReceiptHash },
    "Demo receipt verification failed",
  );
}

export async function tamperPublicDemoReceipt(receipt: Receipt, expectedReceiptHash: string, mutation = "flip_verdict"): Promise<DemoVerifyResult> {
  return jsonFetch<DemoVerifyResult>(
    "/api/demo/tamper",
    { receipt, expected_receipt_hash: expectedReceiptHash, mutation },
    "Demo tamper check failed",
  );
}

export async function evaluateIntent(request: DecisionRequest): Promise<void> {
  await unwrap(
    client.POST("/api/v1/evaluate", {
      headers: authHeaders(),
      body: {
        principal: request.principal,
        action: request.action,
        resource: request.resource,
        context: request.context ?? {},
      },
    }),
    "Intent evaluation failed",
  );
}

export async function loadReceipts(limit = 100): Promise<readonly Receipt[]> {
  const data = await unwrap(
    client.GET("/api/v1/receipts", {
      headers: authHeaders(),
      params: {
        query: { limit },
      },
    }),
    "Receipt load failed",
  ) as { receipts?: Receipt[] };
  return data.receipts ?? [];
}

export type AdminRecord = Record<string, unknown>;
export type AdminResult = unknown;

async function requestAdminJson<T = AdminResult>(
  path: string,
  fallbackMessage: string,
  init: RequestInit = {},
): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Accept", headers.get("Accept") ?? "application/json");
  for (const [key, value] of Object.entries(authHeaders())) {
    headers.set(key, value);
  }
  if (init.body !== undefined && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const response = await fetch(path, {
    ...init,
    credentials: "include",
    headers,
  });
  if (!response.ok) {
    throw await consoleApiErrorFromResponse(response, fallbackMessage);
  }
  if (response.status === 204) {
    return {} as T;
  }
  const contentType = response.headers.get("Content-Type") ?? "";
  if (contentType.includes("application/json")) {
    return (await response.json()) as T;
  }
  return { value: await response.text() } as T;
}

async function getAdminJson<T = AdminResult>(
  path: string,
  fallbackMessage: string,
): Promise<T> {
  return requestAdminJson<T>(path, fallbackMessage);
}

async function postAdminJson<T = AdminResult>(
  path: string,
  body: AdminRecord = {},
  fallbackMessage = "Admin action failed",
): Promise<T> {
  return requestAdminJson<T>(path, fallbackMessage, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

async function putAdminJson<T = AdminResult>(
  path: string,
  body: AdminRecord = {},
  fallbackMessage = "Admin update failed",
): Promise<T> {
  return requestAdminJson<T>(path, fallbackMessage, {
    method: "PUT",
    body: JSON.stringify(body),
  });
}

const enc = (value: string) => encodeURIComponent(value.trim());

export async function loadReceiptDetail(receiptId: string): Promise<Receipt> {
  return getAdminJson<Receipt>(`/api/v1/receipts/${enc(receiptId)}`, "Receipt detail failed");
}

export async function listApprovals(): Promise<AdminResult> {
  return getAdminJson("/api/v1/approvals", "Approvals load failed");
}

export async function createApproval(body: AdminRecord): Promise<AdminResult> {
  return postAdminJson("/api/v1/approvals", body, "Approval creation failed");
}

export async function createApprovalWebAuthnChallenge(
  approvalId: string,
  body: AdminRecord,
): Promise<AdminResult> {
  return postAdminJson(
    `/api/v1/approvals/${enc(approvalId)}/webauthn/challenge`,
    body,
    "Approval WebAuthn challenge failed",
  );
}

export async function assertApprovalWebAuthn(
  approvalId: string,
  body: AdminRecord,
): Promise<AdminResult> {
  return postAdminJson(
    `/api/v1/approvals/${enc(approvalId)}/webauthn/assert`,
    body,
    "Approval WebAuthn assertion failed",
  );
}

export async function transitionApproval(
  approvalId: string,
  action: string,
  body: AdminRecord,
): Promise<AdminResult> {
  return postAdminJson(
    `/api/v1/approvals/${enc(approvalId)}/${enc(action)}`,
    body,
    "Approval transition failed",
  );
}

export async function listMcpRegistry(): Promise<AdminResult> {
  return getAdminJson("/api/v1/mcp/registry", "MCP registry load failed");
}

export async function loadMcpCapabilities(): Promise<AdminResult> {
  return getAdminJson("/mcp/v1/capabilities", "MCP capabilities load failed");
}

export async function scanMcpRegistry(body: AdminRecord): Promise<AdminResult> {
  return postAdminJson("/api/v1/mcp/scan", body, "MCP registry scan failed");
}

export async function approveMcpRegistry(body: AdminRecord): Promise<AdminResult> {
  return postAdminJson(
    "/api/v1/mcp/registry/approve",
    body,
    "MCP registry approval failed",
  );
}

export async function loadMcpServer(serverId: string): Promise<AdminResult> {
  return getAdminJson(`/api/v1/mcp/registry/${enc(serverId)}`, "MCP server load failed");
}

export async function approveMcpServer(
  serverId: string,
  body: AdminRecord,
): Promise<AdminResult> {
  return postAdminJson(
    `/api/v1/mcp/registry/${enc(serverId)}/approve`,
    body,
    "MCP server approval failed",
  );
}

export async function revokeMcpServer(
  serverId: string,
  body: AdminRecord,
): Promise<AdminResult> {
  return postAdminJson(
    `/api/v1/mcp/registry/${enc(serverId)}/revoke`,
    body,
    "MCP server revoke failed",
  );
}

export async function listMcpAuthProfiles(): Promise<AdminResult> {
  return getAdminJson("/api/v1/mcp/auth-profiles", "MCP auth profiles load failed");
}

export async function updateMcpAuthProfile(
  profileId: string,
  body: AdminRecord,
): Promise<AdminResult> {
  return putAdminJson(
    `/api/v1/mcp/auth-profiles/${enc(profileId)}`,
    body,
    "MCP auth profile update failed",
  );
}

export async function authorizeMcpCall(body: AdminRecord): Promise<AdminResult> {
  return postAdminJson("/api/v1/mcp/authorize-call", body, "MCP authorization failed");
}

export async function listSandboxProfiles(): Promise<AdminResult> {
  return getAdminJson("/api/v1/sandbox/profiles", "Sandbox profiles load failed");
}

export async function listSandboxGrants(): Promise<AdminResult> {
  return getAdminJson("/api/v1/sandbox/grants", "Sandbox grants load failed");
}

export async function loadSandboxGrant(grantId: string): Promise<AdminResult> {
  return getAdminJson(`/api/v1/sandbox/grants/${enc(grantId)}`, "Sandbox grant load failed");
}

export async function createSandboxGrant(body: AdminRecord): Promise<AdminResult> {
  return postAdminJson("/api/v1/sandbox/grants", body, "Sandbox grant creation failed");
}

export async function verifySandboxGrant(grantId: string): Promise<AdminResult> {
  return postAdminJson(
    `/api/v1/sandbox/grants/${enc(grantId)}/verify`,
    {},
    "Sandbox grant verification failed",
  );
}

export async function preflightSandboxGrant(body: AdminRecord): Promise<AdminResult> {
  return postAdminJson("/api/v1/sandbox/preflight", body, "Sandbox preflight failed");
}

export async function inspectSandboxRuntime(
  runtime?: string,
  grantId?: string,
): Promise<AdminResult> {
  const params = new URLSearchParams();
  if (runtime) params.set("runtime", runtime);
  if (grantId) params.set("grant_id", grantId);
  const suffix = params.toString();
  return getAdminJson(
    `/api/v1/sandbox/grants/inspect${suffix ? `?${suffix}` : ""}`,
    "Sandbox runtime inspect failed",
  );
}

export async function listAgentIdentities(): Promise<AdminResult> {
  return getAdminJson("/api/v1/identity/agents", "Agent identities load failed");
}

export async function loadAuthzHealth(): Promise<AdminResult> {
  return getAdminJson("/api/v1/authz/health", "Authz health load failed");
}

export async function checkAuthz(body: AdminRecord): Promise<AdminResult> {
  return postAdminJson("/api/v1/authz/check", body, "Authz check failed");
}

export async function listAuthzSnapshots(): Promise<AdminResult> {
  return getAdminJson("/api/v1/authz/snapshots", "Authz snapshots load failed");
}

export async function loadAuthzSnapshot(snapshotId: string): Promise<AdminResult> {
  return getAdminJson(
    `/api/v1/authz/snapshots/${enc(snapshotId)}`,
    "Authz snapshot load failed",
  );
}

export async function listBudgets(): Promise<AdminResult> {
  return getAdminJson("/api/v1/budgets", "Budgets load failed");
}

export async function updateBudget(
  budgetId: string,
  body: AdminRecord,
): Promise<AdminResult> {
  return putAdminJson(`/api/v1/budgets/${enc(budgetId)}`, body, "Budget update failed");
}

export async function listBoundaryRecords(): Promise<AdminResult> {
  return getAdminJson("/api/v1/boundary/records", "Boundary records load failed");
}

export async function loadBoundaryRecord(recordId: string): Promise<AdminResult> {
  return getAdminJson(
    `/api/v1/boundary/records/${enc(recordId)}`,
    "Boundary record load failed",
  );
}

export async function loadBoundaryStatus(): Promise<AdminResult> {
  return getAdminJson("/api/v1/boundary/status", "Boundary status load failed");
}

export async function loadBoundaryCapabilities(): Promise<AdminResult> {
  return getAdminJson("/api/v1/boundary/capabilities", "Boundary capabilities load failed");
}

export async function verifyBoundaryRecord(recordId: string): Promise<AdminResult> {
  return postAdminJson(
    `/api/v1/boundary/records/${enc(recordId)}/verify`,
    {},
    "Boundary record verification failed",
  );
}

export async function listBoundaryCheckpoints(): Promise<AdminResult> {
  return getAdminJson("/api/v1/boundary/checkpoints", "Boundary checkpoints load failed");
}

export async function createBoundaryCheckpoint(body: AdminRecord): Promise<AdminResult> {
  return postAdminJson(
    "/api/v1/boundary/checkpoints",
    body,
    "Boundary checkpoint creation failed",
  );
}

export async function verifyBoundaryCheckpoint(
  checkpointId: string,
): Promise<AdminResult> {
  return postAdminJson(
    `/api/v1/boundary/checkpoints/${enc(checkpointId)}/verify`,
    {},
    "Boundary checkpoint verification failed",
  );
}

export async function listEvidenceEnvelopes(): Promise<AdminResult> {
  return getAdminJson("/api/v1/evidence/envelopes", "Evidence envelopes load failed");
}

export async function createEvidenceEnvelope(body: AdminRecord): Promise<AdminResult> {
  return postAdminJson(
    "/api/v1/evidence/envelopes",
    body,
    "Evidence envelope creation failed",
  );
}

export async function loadEvidenceEnvelope(manifestId: string): Promise<AdminResult> {
  return getAdminJson(
    `/api/v1/evidence/envelopes/${enc(manifestId)}`,
    "Evidence envelope load failed",
  );
}

export async function loadEvidenceEnvelopePayload(manifestId: string): Promise<AdminResult> {
  return getAdminJson(
    `/api/v1/evidence/envelopes/${enc(manifestId)}/payload`,
    "Evidence envelope payload load failed",
  );
}

export async function verifyEvidenceEnvelope(
  manifestId: string,
  body: AdminRecord = {},
): Promise<AdminResult> {
  return postAdminJson(
    `/api/v1/evidence/envelopes/${enc(manifestId)}/verify`,
    body,
    "Evidence envelope verification failed",
  );
}

export async function exportEvidence(body: AdminRecord): Promise<AdminResult> {
  const response = await fetch("/api/v1/evidence/export", {
    method: "POST",
    headers: {
      Accept: "application/octet-stream",
      "Content-Type": "application/json",
      ...authHeaders(),
    },
    credentials: "include",
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    throw await consoleApiErrorFromResponse(response, "Evidence export failed");
  }
  const bytes = await response.arrayBuffer();
  return {
    bytes: bytes.byteLength,
    content_type: response.headers.get("Content-Type") ?? "application/octet-stream",
  };
}

export async function verifyEvidenceBundleBase64(
  bundleBase64: string,
): Promise<AdminResult> {
  const binary = atob(bundleBase64.trim());
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  const response = await fetch("/api/v1/evidence/verify", {
    method: "POST",
    headers: {
      Accept: "application/json",
      ...authHeaders(),
    },
    credentials: "include",
    body: bytes,
  });
  if (!response.ok) {
    throw await consoleApiErrorFromResponse(response, "Evidence verification failed");
  }
  return await response.json() as AdminResult;
}

export async function listProofgraphSessions(): Promise<AdminResult> {
  return getAdminJson("/api/v1/proofgraph/sessions", "ProofGraph sessions load failed");
}

export async function loadProofgraphSessionReceipts(sessionId: string): Promise<AdminResult> {
  return getAdminJson(
    `/api/v1/proofgraph/sessions/${enc(sessionId)}/receipts`,
    "ProofGraph session receipts load failed",
  );
}

export async function loadProofgraphReceipt(receiptHash: string): Promise<AdminResult> {
  return getAdminJson(
    `/api/v1/proofgraph/receipts/${enc(receiptHash)}`,
    "ProofGraph receipt load failed",
  );
}

export async function listVerificationScopes(): Promise<AdminResult> {
  return getAdminJson("/api/v1/evidence/verification-scopes", "Verification scopes load failed");
}

export async function createVerificationScope(body: AdminRecord): Promise<AdminResult> {
  return postAdminJson(
    "/api/v1/evidence/verification-scopes",
    body,
    "Verification scope creation failed",
  );
}

export async function loadVerificationScope(scopeId: string): Promise<AdminResult> {
  return getAdminJson(
    `/api/v1/evidence/verification-scopes/${enc(scopeId)}`,
    "Verification scope load failed",
  );
}

export async function verifyVerificationScope(scopeId: string): Promise<AdminResult> {
  return postAdminJson(
    `/api/v1/evidence/verification-scopes/${enc(scopeId)}/verify`,
    {},
    "Verification scope verification failed",
  );
}

export async function replayVerifyEvidence(body: AdminRecord): Promise<AdminResult> {
  return postAdminJson("/api/v1/replay/verify", body, "Replay verification failed");
}

export async function runConformance(body: AdminRecord): Promise<AdminResult> {
  return postAdminJson("/api/v1/conformance/run", body, "Conformance run failed");
}

export async function listConformanceReports(): Promise<AdminResult> {
  return getAdminJson("/api/v1/conformance/reports", "Conformance reports load failed");
}

export async function loadConformanceReport(reportId: string): Promise<AdminResult> {
  return getAdminJson(
    `/api/v1/conformance/reports/${enc(reportId)}`,
    "Conformance report load failed",
  );
}

export async function listConformanceVectors(): Promise<AdminResult> {
  return getAdminJson("/api/v1/conformance/vectors", "Conformance vectors load failed");
}

export async function loadConformanceNegative(): Promise<AdminResult> {
  return getAdminJson("/api/v1/conformance/negative", "Conformance negative gates load failed");
}

export async function listHarnessTraces(): Promise<AdminResult> {
  return getAdminJson("/api/v1/telemetry/harness-traces", "Harness traces load failed");
}

export async function createHarnessTrace(body: AdminRecord): Promise<AdminResult> {
  return postAdminJson("/api/v1/telemetry/harness-traces", body, "Harness trace creation failed");
}

export async function loadHarnessTrace(traceId: string): Promise<AdminResult> {
  return getAdminJson(
    `/api/v1/telemetry/harness-traces/${enc(traceId)}`,
    "Harness trace load failed",
  );
}

export async function verifyHarnessTrace(traceId: string): Promise<AdminResult> {
  return postAdminJson(
    `/api/v1/telemetry/harness-traces/${enc(traceId)}/verify`,
    {},
    "Harness trace verification failed",
  );
}

export async function listPlanTransactions(): Promise<AdminResult> {
  return getAdminJson("/api/v1/plans/transactions", "Plan transactions load failed");
}

export async function createPlanTransaction(body: AdminRecord): Promise<AdminResult> {
  return postAdminJson("/api/v1/plans/transactions", body, "Plan transaction creation failed");
}

export async function loadPlanTransaction(transactionId: string): Promise<AdminResult> {
  return getAdminJson(
    `/api/v1/plans/transactions/${enc(transactionId)}`,
    "Plan transaction load failed",
  );
}

export async function verifyPlanTransaction(transactionId: string): Promise<AdminResult> {
  return postAdminJson(
    `/api/v1/plans/transactions/${enc(transactionId)}/verify`,
    {},
    "Plan transaction verification failed",
  );
}

export async function listHarnessChangeContracts(): Promise<AdminResult> {
  return getAdminJson("/api/v1/harness/change-contracts", "Harness changes load failed");
}

export async function createHarnessChangeContract(body: AdminRecord): Promise<AdminResult> {
  return postAdminJson(
    "/api/v1/harness/change-contracts",
    body,
    "Harness change creation failed",
  );
}

export async function loadHarnessChangeContract(changeId: string): Promise<AdminResult> {
  return getAdminJson(
    `/api/v1/harness/change-contracts/${enc(changeId)}`,
    "Harness change load failed",
  );
}

export async function approveHarnessChangeContract(changeId: string, body: AdminRecord): Promise<AdminResult> {
  return postAdminJson(
    `/api/v1/harness/change-contracts/${enc(changeId)}/approve`,
    body,
    "Harness change approval failed",
  );
}

export async function verifyHarnessChangeContract(changeId: string): Promise<AdminResult> {
  return postAdminJson(
    `/api/v1/harness/change-contracts/${enc(changeId)}/verify`,
    {},
    "Harness change verification failed",
  );
}

export async function verifyGUIActionReceipt(body: AdminRecord): Promise<AdminResult> {
  return postAdminJson("/api/v1/gui/receipts/verify", body, "GUI receipt verification failed");
}

export async function loadCoexistenceCapabilities(): Promise<AdminResult> {
  return getAdminJson(
    "/api/v1/coexistence/capabilities",
    "Coexistence capabilities load failed",
  );
}

export async function loadTelemetryOtelConfig(): Promise<AdminResult> {
  return getAdminJson("/api/v1/telemetry/otel/config", "Telemetry config load failed");
}

export async function exportTelemetry(body: AdminRecord): Promise<AdminResult> {
  return postAdminJson("/api/v1/telemetry/export", body, "Telemetry export failed");
}

export async function addTrustKey(body: AdminRecord): Promise<AdminResult> {
  return postAdminJson("/api/v1/trust/keys/add", body, "Trust key add failed");
}

export async function revokeTrustKey(body: AdminRecord): Promise<AdminResult> {
  return postAdminJson("/api/v1/trust/keys/revoke", body, "Trust key revoke failed");
}

export async function loadAgentUIInfo(): Promise<AdminResult> {
  return getAdminJson("/api/v1/agent-ui/info", "Agent UI info load failed");
}

export async function runAgentUI(body: AdminRecord): Promise<AdminResult> {
  const response = await fetch("/api/v1/agent-ui/run", {
    method: "POST",
    headers: {
      Accept: "text/event-stream, application/json",
      "Content-Type": "application/json",
      ...authHeaders(),
    },
    credentials: "include",
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    throw await consoleApiErrorFromResponse(response, "Agent UI run failed");
  }
  return { value: await response.text() };
}

export async function listLaunchpadApps(): Promise<readonly LaunchpadApp[]> {
  const body = await getAdminJson<{ readonly apps?: readonly LaunchpadApp[] }>(
    "/api/v1/launchpad/apps",
    "Launchpad apps load failed",
  );
  return body.apps ?? [];
}

export async function listLaunchpadSubstrates(): Promise<readonly LaunchpadSubstrate[]> {
  const body = await getAdminJson<{ readonly substrates?: readonly LaunchpadSubstrate[] }>(
    "/api/v1/launchpad/substrates",
    "Launchpad substrates load failed",
  );
  return body.substrates ?? [];
}

export async function loadLaunchpadMatrix(): Promise<readonly LaunchpadMatrixCell[]> {
  const body = await getAdminJson<{ readonly matrix?: readonly LaunchpadMatrixCell[] }>(
    "/api/v1/launchpad/matrix",
    "Launchpad matrix load failed",
  );
  return body.matrix ?? [];
}

export async function listLaunchpadRuns(): Promise<AdminResult> {
  return getAdminJson("/api/v1/launchpad/runs", "Launchpad runs load failed");
}

export async function planLaunchpad(appId: string, substrateId: string): Promise<LaunchpadPlanResponse> {
  return postAdminJson<LaunchpadPlanResponse>(
    "/api/v1/launchpad/plan",
    { app_id: appId, substrate_id: substrateId, principal: "console" },
    "Launchpad plan failed",
  );
}

export async function launchLaunchpad(appId: string, substrateId: string): Promise<LaunchpadRun> {
  return postAdminJson<LaunchpadRun>(
    "/api/v1/launchpad/launch",
    { app_id: appId, substrate_id: substrateId, principal: "console" },
    "Launchpad launch failed",
  );
}

export async function createLaunchpadRuntimeRun(appId: string, substrateId: string): Promise<LaunchpadRunDetail> {
  return postAdminJson<LaunchpadRunDetail>(
    "/api/v1/launchpad/runs",
    { app_id: appId, substrate_id: substrateId, principal: "console" },
    "Launchpad run failed",
  );
}

export async function loadLaunchpadRunDetail(runId: string): Promise<LaunchpadRunDetail> {
  return getAdminJson<LaunchpadRunDetail>(
    `/api/v1/launchpad/runs/${enc(runId)}`,
    "Launchpad run detail failed",
  );
}

export async function loadLaunchpadRunEvents(runId: string): Promise<AdminResult> {
  return getAdminJson(
    `/api/v1/launchpad/runs/${enc(runId)}/events`,
    "Launchpad run events failed",
  );
}

export async function loadLaunchpadRunReceipts(runId: string): Promise<AdminResult> {
  return getAdminJson(
    `/api/v1/launchpad/runs/${enc(runId)}/receipts`,
    "Launchpad run receipts failed",
  );
}

export async function loadLaunchpadRunLogs(runId: string): Promise<AdminResult> {
  return getAdminJson(
    `/api/v1/launchpad/runs/${enc(runId)}/logs`,
    "Launchpad run logs failed",
  );
}

export async function exportLaunchpadRunEvidence(runId: string): Promise<AdminResult> {
  return postAdminJson(
    `/api/v1/launchpad/runs/${enc(runId)}/evidence/export`,
    {},
    "Launchpad EvidencePack export failed",
  );
}

export async function teardownLaunchpadRuntimeRun(runId: string): Promise<LaunchpadRunDetail> {
  return postAdminJson<LaunchpadRunDetail>(
    `/api/v1/launchpad/runs/${enc(runId)}/teardown`,
    { cascade: true },
    "Launchpad teardown failed",
  );
}

export async function loadLaunchpadRun(launchId: string): Promise<LaunchpadRun> {
  return getAdminJson<LaunchpadRun>(
    `/api/v1/launchpad/launches/${enc(launchId)}`,
    "Launchpad run load failed",
  );
}

export async function repairLaunchpadRun(launchId: string): Promise<AdminResult> {
  return postAdminJson(
    `/api/v1/launchpad/launches/${enc(launchId)}/repair`,
    {},
    "Launchpad repair failed",
  );
}

export async function deleteLaunchpadRun(launchId: string): Promise<LaunchpadRun> {
  return postAdminJson<LaunchpadRun>(
    `/api/v1/launchpad/launches/${enc(launchId)}/delete`,
    { cascade: true },
    "Launchpad teardown failed",
  );
}

export async function listLaunchpadSecretGrants(): Promise<AdminResult> {
  return getAdminJson("/api/v1/launchpad/secrets", "Launchpad secret grants load failed");
}

export async function bindLaunchpadSecretGrant(body: AdminRecord): Promise<AdminResult> {
  return postAdminJson("/api/v1/launchpad/secrets", body, "Launchpad secret grant binding failed");
}

export async function simulateLaunchpadPolicy(appId: string, substrateId: string): Promise<AdminResult> {
  return postAdminJson(
    "/api/v1/launchpad/policy/simulate",
    { app_id: appId, substrate_id: substrateId, principal: "console" },
    "Launchpad policy simulation failed",
  );
}

export async function inspectLaunchpadSandbox(runId: string): Promise<AdminResult> {
  return getAdminJson(
    `/api/v1/launchpad/sandbox/${enc(runId)}`,
    "Launchpad sandbox inspect failed",
  );
}

export async function loadLaunchpadMcpThreatReviews(): Promise<AdminResult> {
  return getAdminJson(
    "/api/v1/launchpad/mcp/threat-reviews",
    "Launchpad MCP threat reviews failed",
  );
}

export async function approveLaunchpadMcpTools(body: AdminRecord): Promise<AdminResult> {
  return postAdminJson(
    "/api/v1/launchpad/mcp/approvals",
    body,
    "Launchpad MCP approval failed",
  );
}

export async function loadConsoleSurface(surface: string): Promise<ConsoleSurfaceState> {
  return unwrap(
    client.GET("/api/v1/console/surfaces/{surface_id}", {
      headers: authHeaders(),
      params: {
        path: { surface_id: surface as "overview" },
      },
    }),
    `Console surface ${surface} failed`,
  ) as Promise<ConsoleSurfaceState>;
}

export async function loadEndpoint(path: string): Promise<{ readonly status: number; readonly ok: boolean; readonly data: unknown }> {
  const response = await fetch(path, { headers: { Accept: "application/json", ...authHeaders() }, credentials: "include" });
  const contentType = response.headers.get("Content-Type") ?? "";
  let data: unknown;
  if (contentType.includes("application/json")) {
    data = await response.json();
  } else {
    data = await response.text();
  }
  return { status: response.status, ok: response.ok, data };
}

export async function replayVerifyCurrentEvidence(sessionID: string): Promise<VerificationResult> {
  const exportResponse = await fetch("/api/v1/evidence/export", {
    method: "POST",
    headers: {
      Accept: "application/octet-stream",
      "Content-Type": "application/json",
      ...authHeaders(),
    },
    credentials: "include",
    body: JSON.stringify({ session_id: sessionID, format: "tar.gz" }),
  });
  if (!exportResponse.ok) {
    throw await consoleApiErrorFromResponse(exportResponse, "Evidence export failed");
  }
  const bundle = await exportResponse.arrayBuffer();
  const verifyResponse = await fetch("/api/v1/replay/verify", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/octet-stream",
      ...authHeaders(),
    },
    credentials: "include",
    body: bundle,
  });
  if (!verifyResponse.ok) {
    throw await consoleApiErrorFromResponse(verifyResponse, "Replay verification failed");
  }
  return await verifyResponse.json() as VerificationResult;
}

export function watchReceipts(onReceipt: (receipt: Receipt) => void, onError: (error: Error) => void): () => void {
  if (typeof fetch === "undefined" || typeof ReadableStream === "undefined") return () => undefined;
  const controller = new AbortController();
  void streamReceiptEvents(controller.signal, onReceipt).catch((error: unknown) => {
    if (isAbortError(error)) return;
    onError(error instanceof Error ? error : new Error("Receipt stream disconnected"));
  });
  return () => controller.abort();
}

async function streamReceiptEvents(signal: AbortSignal, onReceipt: (receipt: Receipt) => void): Promise<void> {
  const response = await fetch("/api/v1/receipts/tail?limit=100", {
    headers: { Accept: "text/event-stream", ...authHeaders() },
    credentials: "include",
    signal,
  });
  if (!response.ok) {
    throw await consoleApiErrorFromResponse(response, "Receipt stream disconnected");
  }
  if (!response.body) {
    throw new Error("Receipt stream is unavailable in this browser");
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const frameBuffer = createSseFrameBuffer();
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    appendSseChunk(frameBuffer, decoder.decode(value, { stream: true }), (event) => {
      parseReceiptEvent(event, onReceipt);
    });
  }
  appendSseChunk(frameBuffer, decoder.decode(), (event) => {
    parseReceiptEvent(event, onReceipt);
  });
  if (frameBuffer.buffer.trim() !== "") {
    parseReceiptEvent(frameBuffer.buffer, onReceipt);
  }
  throw new Error("Receipt stream closed");
}

function parseReceiptEvent(raw: string, onReceipt: (receipt: Receipt) => void): void {
  let eventName = "message";
  const data: string[] = [];
  for (const line of raw.split(/\r?\n/)) {
    if (line === "" || line.startsWith(":")) continue;
    const separator = line.indexOf(":");
    const field = separator === -1 ? line : line.slice(0, separator);
    const value = separator === -1 ? "" : line.slice(separator + 1).replace(/^ /, "");
    if (field === "event") eventName = value;
    if (field === "data") data.push(value);
  }
  if (eventName !== "receipt" || data.length === 0) return;
  onReceipt(JSON.parse(data.join("\n")) as Receipt);
}

async function consoleApiErrorFromResponse(response: Response, fallbackMessage: string): Promise<ConsoleApiError> {
  const contentType = response.headers.get("Content-Type") ?? "";
  let detail = fallbackMessage;
  try {
    if (contentType.includes("application/json")) {
      detail = errorDetail(await response.json(), fallbackMessage);
    } else {
      detail = (await response.text()) || fallbackMessage;
    }
  } catch {
    detail = fallbackMessage;
  }
  return new ConsoleApiError(fallbackMessage, response.status, detail);
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}
