import createClient from "openapi-fetch";
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
  readonly helm_oss_version: string;
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

const client = createClient<paths>({
  baseUrl: "",
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
  return token ? { Authorization: `Bearer ${token}`, "X-Helm-Tenant-ID": getConsoleTenantID() } : {};
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

async function jsonFetch<T>(path: string, body: unknown, fallbackMessage: string): Promise<T> {
  const response = await fetch(path, {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
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
  const response = await fetch(path, { headers: { Accept: "application/json", ...authHeaders() } });
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
  let buffer = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const events = buffer.split(/\r?\n\r?\n/);
    buffer = events.pop() ?? "";
    for (const event of events) {
      parseReceiptEvent(event, onReceipt);
    }
  }
  if (buffer.trim() !== "") {
    parseReceiptEvent(buffer, onReceipt);
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
