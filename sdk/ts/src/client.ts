// HELM SDK — TypeScript Client
// Ergonomic wrapper over generated types. Uses native fetch. Zero deps.

import type {
  ChatCompletionRequest,
  ChatCompletionResponse,
  ApprovalRequest,
  Receipt,
  Session,
  VerificationResult,
  ConformanceRequest,
  ConformanceResult,
  VersionInfo,
  HelmError,
  ReasonCode,
} from './types.gen.js';

export type { ReasonCode, HelmError };

/** Governance metadata extracted from X-Helm-* response headers. */
export interface GovernanceMetadata {
  receiptId: string;
  status: string;
  outputHash: string;
  lamportClock: number;
  reasonCode: string;
  decisionId: string;
  proofGraphNode: string;
  signature: string;
  toolCalls: number;
}

/** Chat completion response with kernel-issued governance metadata. */
export interface ChatCompletionWithReceipt {
  response: ChatCompletionResponse;
  governance: GovernanceMetadata;
}

/** Thrown when the HELM API returns a non-2xx response. */
export class HelmApiError extends Error {
  readonly status: number;
  readonly reasonCode: ReasonCode;
  readonly details?: Record<string, unknown>;

  constructor(status: number, body: HelmError) {
    super(body.error.message);
    this.name = 'HelmApiError';
    this.status = status;
    this.reasonCode = body.error.reason_code;
    this.details = body.error.details;
  }
}

export interface HelmClientConfig {
  baseUrl: string;
  apiKey?: string;
  timeout?: number; // ms, default 30000
}

export class HelmClient {
  private readonly baseUrl: string;
  private readonly headers: Record<string, string>;
  private readonly timeout: number;

  constructor(config: HelmClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, '');
    this.timeout = config.timeout ?? 30_000;
    this.headers = { 'Content-Type': 'application/json' };
    if (config.apiKey) {
      this.headers['Authorization'] = `Bearer ${config.apiKey}`;
    }
  }

  // ── Internal ─────────────────────────────────────
  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);
    try {
      const res = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers: this.headers,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });
      if (!res.ok) {
        const err = (await res.json()) as HelmError;
        throw new HelmApiError(res.status, err);
      }
      return (await res.json()) as T;
    } finally {
      clearTimeout(timer);
    }
  }

  // ── OpenAI Proxy ─────────────────────────────────
  async chatCompletions(req: ChatCompletionRequest): Promise<ChatCompletionResponse> {
    return this.request<ChatCompletionResponse>('POST', '/v1/chat/completions', req);
  }

  /**
   * Send a chat completion request and extract kernel-issued governance metadata
   * from X-Helm-* response headers. Use this instead of chatCompletions() when
   * you need the kernel receipt.
   */
  async chatCompletionsWithReceipt(req: ChatCompletionRequest): Promise<ChatCompletionWithReceipt> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);
    try {
      const res = await fetch(`${this.baseUrl}/v1/chat/completions`, {
        method: 'POST',
        headers: this.headers,
        body: JSON.stringify(req),
        signal: controller.signal,
      });
      if (!res.ok) {
        const err = (await res.json()) as HelmError;
        throw new HelmApiError(res.status, err);
      }
      const response = (await res.json()) as ChatCompletionResponse;
      const governance: GovernanceMetadata = {
        receiptId: res.headers.get('X-Helm-Receipt-ID') ?? '',
        status: res.headers.get('X-Helm-Status') ?? '',
        outputHash: res.headers.get('X-Helm-Output-Hash') ?? '',
        lamportClock: parseInt(res.headers.get('X-Helm-Lamport-Clock') ?? '0', 10),
        reasonCode: res.headers.get('X-Helm-Reason-Code') ?? '',
        decisionId: res.headers.get('X-Helm-Decision-ID') ?? '',
        proofGraphNode: res.headers.get('X-Helm-ProofGraph-Node') ?? '',
        signature: res.headers.get('X-Helm-Signature') ?? '',
        toolCalls: parseInt(res.headers.get('X-Helm-Tool-Calls') ?? '0', 10),
      };
      return { response, governance };
    } finally {
      clearTimeout(timer);
    }
  }

  // ── Approval Ceremony ────────────────────────────
  async approveIntent(req: ApprovalRequest): Promise<Receipt> {
    return this.request<Receipt>('POST', '/api/v1/kernel/approve', req);
  }

  // ── ProofGraph ───────────────────────────────────
  async listSessions(limit = 50, offset = 0): Promise<Session[]> {
    return this.request<Session[]>('GET', `/api/v1/proofgraph/sessions?limit=${limit}&offset=${offset}`);
  }

  async getReceipts(sessionId: string): Promise<Receipt[]> {
    return this.request<Receipt[]>('GET', `/api/v1/proofgraph/sessions/${sessionId}/receipts`);
  }

  async getReceipt(receiptHash: string): Promise<Receipt> {
    return this.request<Receipt>('GET', `/api/v1/proofgraph/receipts/${receiptHash}`);
  }

  // ── Evidence ─────────────────────────────────────
  async exportEvidence(sessionId?: string): Promise<Blob> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);
    try {
      const res = await fetch(`${this.baseUrl}/api/v1/evidence/export`, {
        method: 'POST',
        headers: this.headers,
        body: JSON.stringify({ session_id: sessionId, format: 'tar.gz' }),
        signal: controller.signal,
      });
      if (!res.ok) throw new HelmApiError(res.status, (await res.json()) as HelmError);
      return res.blob();
    } finally {
      clearTimeout(timer);
    }
  }

  async verifyEvidence(bundle: Blob): Promise<VerificationResult> {
    const form = new FormData();
    form.append('bundle', bundle);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);
    try {
      const res = await fetch(`${this.baseUrl}/api/v1/evidence/verify`, {
        method: 'POST',
        body: form,
        signal: controller.signal,
      });
      if (!res.ok) throw new HelmApiError(res.status, (await res.json()) as HelmError);
      return (await res.json()) as VerificationResult;
    } finally {
      clearTimeout(timer);
    }
  }

  async replayVerify(bundle: Blob): Promise<VerificationResult> {
    const form = new FormData();
    form.append('bundle', bundle);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);
    try {
      const res = await fetch(`${this.baseUrl}/api/v1/replay/verify`, {
        method: 'POST',
        body: form,
        signal: controller.signal,
      });
      if (!res.ok) throw new HelmApiError(res.status, (await res.json()) as HelmError);
      return (await res.json()) as VerificationResult;
    } finally {
      clearTimeout(timer);
    }
  }

  // ── Conformance ──────────────────────────────────
  async conformanceRun(req: ConformanceRequest): Promise<ConformanceResult> {
    return this.request<ConformanceResult>('POST', '/api/v1/conformance/run', req);
  }

  async getConformanceReport(reportId: string): Promise<ConformanceResult> {
    return this.request<ConformanceResult>('GET', `/api/v1/conformance/reports/${reportId}`);
  }

  // ── System ───────────────────────────────────────
  async health(): Promise<{ status: string; version: string }> {
    return this.request('GET', '/healthz');
  }

  async version(): Promise<VersionInfo> {
    return this.request<VersionInfo>('GET', '/version');
  }
}

export default HelmClient;
