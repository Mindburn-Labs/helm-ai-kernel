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

async function unwrap<T>(promise: Promise<{ data?: T; error?: unknown; response: Response }>, fallbackMessage: string): Promise<T> {
  const { data, error, response } = await promise;
  if (!response.ok || error || data === undefined) {
    const detail = typeof error === "object" && error !== null ? JSON.stringify(error) : String(error ?? fallbackMessage);
    throw new Error(`${fallbackMessage}: ${response.status} ${detail}`);
  }
  return data;
}

export async function loadBootstrap(): Promise<ConsoleBootstrap> {
  return unwrap(client.GET("/api/v1/console/bootstrap"), "Console bootstrap failed") as Promise<ConsoleBootstrap>;
}

export async function evaluateIntent(request: DecisionRequest): Promise<void> {
  await unwrap(
    client.POST("/api/v1/evaluate", {
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
      params: {
        path: { surface_id: surface as "overview" },
      },
    }),
    `Console surface ${surface} failed`,
  ) as Promise<ConsoleSurfaceState>;
}

export async function loadEndpoint(path: string): Promise<{ readonly status: number; readonly ok: boolean; readonly data: unknown }> {
  const response = await fetch(path, { headers: { Accept: "application/json" } });
  const contentType = response.headers.get("Content-Type") ?? "";
  let data: unknown;
  if (contentType.includes("application/json")) {
    data = await response.json();
  } else {
    data = await response.text();
  }
  return { status: response.status, ok: response.ok, data };
}

export function watchReceipts(onReceipt: (receipt: Receipt) => void, onError: (error: Error) => void): () => void {
  if (typeof EventSource === "undefined") return () => undefined;
  const stream = new EventSource("/api/v1/receipts/tail?limit=100");
  stream.addEventListener("receipt", (event) => {
    try {
      onReceipt(JSON.parse((event as MessageEvent<string>).data) as Receipt);
    } catch (error) {
      onError(error instanceof Error ? error : new Error("Malformed receipt event"));
    }
  });
  stream.addEventListener("error", () => {
    onError(new Error("Receipt stream disconnected"));
  });
  return () => stream.close();
}
