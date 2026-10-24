/** The native gateway's stateless JSON response profile; no Tasks or sessions. */
export const NATIVE_GATEWAY_PROTOCOL_VERSION = "2026-07-28";

export interface NativeGatewayConfig {
  /** Exact worker/executor MCP endpoint. HTTP is allowed only on loopback. */
  mcpUrl: string;
  /** Episode bearer, never an upstream provider key. Called afresh per request. */
  episodeToken: () => string | Promise<string>;
  timeoutMs?: number;
  maxResponseBytes?: number;
}

export interface NativeGatewayRequestOptions {
  /** Aborts waiting locally. It does not establish containment of an effect. */
  signal?: AbortSignal;
}

export interface NativeGatewayTool {
  name: string;
  description?: string;
  inputSchema: Record<string, unknown>;
  annotations?: Record<string, unknown>;
}

/** toolName must be the exact discovered MCP name, without name normalization. */
export interface NativeGatewayEffect {
  toolName: string;
  target: string;
  arguments: Record<string, unknown>;
}

export type NativeGatewayStatus =
  | "succeeded"
  | "escalated"
  | "reconciling"
  | "denied"
  | "rejected"
  | "expired"
  | "cancelled"
  | "failed"
  | "invalid"
  | "not_found"
  | "conflict"
  | "refused";

export interface NativeGatewayOutcome {
  status: NativeGatewayStatus;
  attempt_id?: string;
  effect_type?: string;
  target?: string;
  state?: string;
  outcome?: string;
  reason_code?: string;
  [key: string]: unknown;
}

export interface NativeGatewayToolResult {
  isError: boolean;
  structuredContent: NativeGatewayOutcome;
}

/** Transport/protocol failure is distinct from a native denied/escalated result. */
export class NativeGatewayError extends Error {
  constructor(
    public readonly kind: "transport" | "http" | "rpc" | "protocol",
    public readonly requestId: string,
    public readonly effectMayHaveOccurred: boolean,
    public readonly code?: number,
  ) {
    // Do not echo credentials, request arguments or untrusted response bodies.
    super(
      `Native gateway ${kind} failure${code === undefined ? "" : ` (${code})`}`,
    );
    this.name = "NativeGatewayError";
  }
}

const protocolMeta = {
  "io.modelcontextprotocol/protocolVersion": NATIVE_GATEWAY_PROTOCOL_VERSION,
  "io.modelcontextprotocol/clientCapabilities": {},
};
const toolNamePattern = /^[A-Za-z0-9_-]{1,64}$/;
const attemptPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const statuses: NativeGatewayStatus[] = [
  "succeeded",
  "escalated",
  "reconciling",
  "denied",
  "rejected",
  "expired",
  "cancelled",
  "failed",
  "invalid",
  "not_found",
  "conflict",
  "refused",
];
const nonErrors = new Set(["succeeded", "escalated", "reconciling"]);
const encoder = new TextEncoder();

/**
 * Additive client for core/pkg/gateway/mcpserver. The gateway owns authority,
 * work-effect identity, dispatch and observation; this client owns none of them.
 * Calls are made once: even an internal RPC error, timeout or local cancellation
 * can follow a dispatch. Retain the returned attempt and use getAttempt to read
 * it. If its ID was lost, reconcile through the owning work/CP path before any
 * explicit replay. A succeeded effect is not organizational acceptance.
 *
 * @example
 * const gateway = new NativeGatewayClient({ mcpUrl, episodeToken: getEpisodeToken });
 * const tools = await gateway.listTools();
 * // Pick an exact discovered name; a framework action's metadata is not authority.
 * const result = await gateway.callEffect({ ...frameworkAction, target });
 * if (result.structuredContent.status === "reconciling") {
 *   await gateway.getAttempt(result.structuredContent.attempt_id!);
 * }
 */
export class NativeGatewayClient {
  private readonly url: string;
  private readonly token: NativeGatewayConfig["episodeToken"];
  private readonly timeoutMs: number;
  private readonly maxResponseBytes: number;

  constructor(config: NativeGatewayConfig) {
    const url = new URL(config.mcpUrl);
    const loopback = ["127.0.0.1", "[::1]"].includes(url.hostname);
    if (
      (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) ||
      url.username ||
      url.password ||
      url.search ||
      url.hash
    ) {
      throw new TypeError(
        "mcpUrl must be HTTPS (HTTP only on literal loopback), without credentials, query or fragment",
      );
    }
    if (typeof config.episodeToken !== "function") {
      throw new TypeError("episodeToken must supply a gateway episode bearer");
    }
    this.url = url.href;
    this.token = config.episodeToken;
    this.timeoutMs = positiveBound(config.timeoutMs ?? 360_000, 3_600_000);
    this.maxResponseBytes = positiveBound(
      config.maxResponseBytes ?? 8 * 1024 * 1024,
      64 * 1024 * 1024,
    );
  }

  /** Fresh, permission-filtered definitions. Discovery grants no authority. */
  listTools(
    options: NativeGatewayRequestOptions = {},
  ): Promise<NativeGatewayTool[]> {
    return this.request("tools/list", {}, options, false, (result) => {
      if (
        !Array.isArray(result.tools) ||
        result.nextCursor !== undefined ||
        result.cacheScope !== "private" ||
        !Number.isSafeInteger(result.ttlMs) ||
        Number(result.ttlMs) < 0
      ) {
        throw new TypeError("unsupported tool list");
      }
      const names = new Set<string>();
      for (const tool of result.tools) {
        if (
          !isRecord(tool) ||
          typeof tool.name !== "string" ||
          !toolNamePattern.test(tool.name) ||
          names.has(tool.name) ||
          !isRecord(tool.inputSchema) ||
          (tool.description !== undefined &&
            typeof tool.description !== "string") ||
          (tool.annotations !== undefined && !isRecord(tool.annotations))
        ) {
          throw new TypeError("invalid tool definition");
        }
        names.add(tool.name);
      }
      return result.tools as NativeGatewayTool[];
    });
  }

  /** Accepts normalized framework toolName/arguments plus an explicit target. */
  callEffect(
    effect: NativeGatewayEffect,
    options: NativeGatewayRequestOptions = {},
  ): Promise<NativeGatewayToolResult> {
    if (
      typeof effect.toolName !== "string" ||
      !toolNamePattern.test(effect.toolName) ||
      effect.toolName === "helm_attempt_get" ||
      typeof effect.target !== "string" ||
      !effect.target ||
      encoder.encode(effect.target).length > 512 ||
      !isRecord(effect.arguments)
    ) {
      throw new TypeError(
        "an exact MCP effect name, target and JSON argument object are required",
      );
    }
    const name = effect.toolName;
    const target = effect.target;
    // Snapshot before awaiting a token; do not silently omit/convert material input.
    const args = snapshotJSON(effect.arguments);
    return this.request(
      "tools/call",
      { name, arguments: { target, arguments: args } },
      options,
      true,
      (result) => {
        const out = toolResult(result);
        const value = out.structuredContent;
        if (
          value.state !== undefined &&
          (value.target !== target ||
            value.effect_type?.replaceAll(".", "_") !== name)
        ) {
          throw new TypeError("effect response does not match its binding");
        }
        return out;
      },
    );
  }

  /** Read only. A new episode needs a native continuation/reassignment grant. */
  getAttempt(
    attemptId: string,
    options: NativeGatewayRequestOptions = {},
  ): Promise<NativeGatewayToolResult> {
    if (!attemptPattern.test(attemptId))
      throw new TypeError("a native attempt UUID is required");
    return this.request(
      "tools/call",
      { name: "helm_attempt_get", arguments: { attempt_id: attemptId } },
      options,
      false,
      (result) => {
        const out = toolResult(result);
        if (
          out.structuredContent.attempt_id &&
          out.structuredContent.attempt_id !== attemptId
        ) {
          throw new TypeError(
            "attempt response does not match the requested attempt",
          );
        }
        return out;
      },
    );
  }

  private async request<T>(
    method: string,
    params: Record<string, unknown>,
    options: NativeGatewayRequestOptions,
    effect: boolean,
    validate: (result: Record<string, unknown>) => T,
  ): Promise<T> {
    const requestId = globalThis.crypto.randomUUID();
    const body = JSON.stringify({
      jsonrpc: "2.0",
      id: requestId,
      method,
      params: { ...params, _meta: protocolMeta },
    });
    if (encoder.encode(body).length > 256 * 1024)
      throw new TypeError("native MCP request exceeds 256 KiB");
    const controller = new AbortController();
    const abort = () => controller.abort();
    options.signal?.addEventListener("abort", abort, { once: true });
    if (options.signal?.aborted) abort();
    const timer = setTimeout(abort, this.timeoutMs);
    let started = false;
    let kind: NativeGatewayError["kind"] = "transport";
    let code: number | undefined;
    try {
      controller.signal.throwIfAborted();
      const token = await abortableToken(this.token, controller.signal);
      controller.signal.throwIfAborted();
      if (typeof token !== "string" || !/^[A-Za-z0-9._~+/-]+=*$/.test(token)) {
        throw new TypeError("invalid gateway bearer");
      }
      const headers = new Headers({
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
        "MCP-Protocol-Version": NATIVE_GATEWAY_PROTOCOL_VERSION,
        "Mcp-Method": method,
      });
      if (method === "tools/call") headers.set("Mcp-Name", String(params.name));
      started = true;
      const response = await fetch(this.url, {
        method: "POST",
        headers,
        body,
        signal: controller.signal,
        redirect: "error",
        credentials: "omit",
        cache: "no-store",
      });
      if (!response.ok) {
        kind = "http";
        code = response.status;
        await response.body?.cancel();
        throw new Error("HTTP failure");
      }
      kind = "protocol";
      if (
        response.headers
          .get("content-type")
          ?.split(";")[0]
          .trim()
          .toLowerCase() !== "application/json"
      ) {
        await response.body?.cancel();
        throw new Error("this profile requires JSON responses");
      }
      const envelope: unknown = JSON.parse(
        await readBounded(response, this.maxResponseBytes),
      );
      if (
        !isRecord(envelope) ||
        envelope.jsonrpc !== "2.0" ||
        envelope.id !== requestId ||
        "result" in envelope === "error" in envelope
      ) {
        throw new Error("invalid JSON-RPC response");
      }
      if ("error" in envelope) {
        if (
          !isRecord(envelope.error) ||
          !Number.isSafeInteger(envelope.error.code) ||
          typeof envelope.error.message !== "string"
        ) {
          throw new Error("invalid RPC error");
        }
        kind = "rpc";
        code = Number(envelope.error.code);
        throw new Error("RPC failure");
      }
      const result = envelope.result;
      if (
        !isRecord(result) ||
        result.resultType !== "complete" ||
        !isRecord(result._meta) ||
        !isRecord(result._meta["io.modelcontextprotocol/serverInfo"]) ||
        result._meta["io.modelcontextprotocol/serverInfo"].name !==
          "helm-gateway"
      ) {
        throw new Error("unsupported native gateway result");
      }
      return validate(result);
    } catch {
      throw new NativeGatewayError(
        controller.signal.aborted ? "transport" : kind,
        requestId,
        effect && started,
        code,
      );
    } finally {
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", abort);
    }
  }
}

function toolResult(result: Record<string, unknown>): NativeGatewayToolResult {
  const value = result.structuredContent;
  if (
    !isRecord(value) ||
    !statuses.includes(value.status as NativeGatewayStatus) ||
    typeof result.isError !== "boolean" ||
    result.isError === nonErrors.has(String(value.status))
  ) {
    throw new TypeError("invalid native tool outcome");
  }
  const hasAttempt = value.attempt_id !== undefined;
  if (
    hasAttempt &&
    (typeof value.attempt_id !== "string" ||
      !attemptPattern.test(value.attempt_id))
  ) {
    throw new TypeError("invalid native attempt identity");
  }
  const snapshot =
    value.state !== undefined ||
    value.effect_type !== undefined ||
    value.target !== undefined;
  if (snapshot) {
    if (
      !hasAttempt ||
      typeof value.state !== "string" ||
      !value.state ||
      typeof value.effect_type !== "string" ||
      !value.effect_type ||
      typeof value.target !== "string" ||
      !value.target
    ) {
      throw new TypeError("incomplete native attempt snapshot");
    }
    const terminal = [
      "OBSERVED",
      "RECONCILED",
      "SETTLED",
      "COMPENSATED",
    ].includes(String(value.state));
    const direct: Record<string, string> = {
      ESCALATED: "escalated",
      DENIED: "denied",
      REJECTED: "rejected",
      EXPIRED: "expired",
      CANCELLED: "cancelled",
    };
    const expected = terminal
      ? value.outcome === "SUCCEEDED"
        ? "succeeded"
        : "failed"
      : (direct[String(value.state)] ?? "reconciling");
    if (value.status !== expected)
      throw new TypeError("status does not match the native attempt");
  } else if (
    !["invalid", "denied", "not_found", "conflict", "refused"].includes(
      String(value.status),
    )
  ) {
    // gateway.go refusal(err, attemptID) deliberately emits no snapshot. Keep
    // its known ID for read-back after Dispatch/Observe failure, without ever
    // interpreting this minimal error shape as an in-flight/success result.
    throw new TypeError("native outcome requires an attempt snapshot");
  }
  return {
    isError: result.isError,
    structuredContent: value as NativeGatewayOutcome,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function positiveBound(value: number, ceiling: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > ceiling)
    throw new TypeError("invalid native client bound");
  return value;
}

function snapshotJSON(value: unknown, depth = 0): unknown {
  if (depth > 60)
    throw new TypeError("arguments exceed native JSON nesting bound");
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  )
    return value;
  if (Array.isArray(value)) {
    if (
      Object.getPrototypeOf(value) !== Array.prototype ||
      Reflect.ownKeys(value).length !== value.length + 1
    ) {
      throw new TypeError("arguments require dense JSON arrays");
    }
    return Array.from({ length: value.length }, (_, index) => {
      const property = Object.getOwnPropertyDescriptor(value, String(index));
      if (!property?.enumerable || !("value" in property))
        throw new TypeError("arguments require plain JSON array values");
      return snapshotJSON(property.value, depth + 1);
    });
  }
  if (
    isRecord(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value))
  ) {
    const entries = Object.entries(Object.getOwnPropertyDescriptors(value));
    if (Reflect.ownKeys(value).length !== entries.length)
      throw new TypeError("arguments cannot contain symbol keys");
    return Object.fromEntries(
      entries.map(([key, property]) => {
        if (!property.enumerable || !("value" in property))
          throw new TypeError("arguments require plain JSON properties");
        return [key, snapshotJSON(property.value, depth + 1)];
      }),
    );
  }
  throw new TypeError("arguments must contain only JSON values");
}

async function abortableToken(
  supply: NativeGatewayConfig["episodeToken"],
  signal: AbortSignal,
): Promise<string> {
  let abort = () => {};
  const cancelled = new Promise<never>((_resolve, reject) => {
    abort = () => reject(new Error("local request cancelled"));
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) abort();
  });
  try {
    return await Promise.race([Promise.resolve().then(supply), cancelled]);
  } finally {
    signal.removeEventListener("abort", abort);
  }
}

async function readBounded(response: Response, limit: number): Promise<string> {
  const reader = response.body?.getReader();
  if (!reader) throw new Error("missing response body");
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > limit) throw new Error("response exceeds its bound");
      chunks.push(value);
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}
