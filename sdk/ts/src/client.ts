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

export interface EvidenceEnvelopeExportRequest {
  manifest_id: string;
  envelope: 'dsse' | 'jws' | 'in-toto' | 'slsa' | 'sigstore' | 'scitt' | 'cose';
  native_evidence_hash: string;
  subject?: string;
  experimental?: boolean;
}

export interface EvidenceEnvelopeManifest {
  manifest_id: string;
  envelope: string;
  native_evidence_hash: string;
  native_authority: true;
  subject?: string;
  statement_hash?: string;
  experimental?: boolean;
  created_at: string;
  manifest_hash?: string;
}

export interface NegativeBoundaryVector {
  id: string;
  category: string;
  trigger: string;
  expected_verdict: 'ALLOW' | 'DENY' | 'ESCALATE';
  expected_reason_code: string;
  must_emit_receipt: boolean;
  must_not_dispatch: boolean;
  must_bind_evidence?: string[];
}

export interface McpRegistryDiscoverRequest {
  server_id: string;
  name?: string;
  transport?: string;
  endpoint?: string;
  tool_names?: string[];
  risk?: 'unknown' | 'low' | 'medium' | 'high' | 'critical';
  reason?: string;
}

export interface McpRegistryApprovalRequest {
  server_id: string;
  approver_id: string;
  approval_receipt_id: string;
  reason?: string;
}

export interface McpQuarantineRecord {
  server_id: string;
  name?: string;
  transport?: string;
  endpoint?: string;
  tool_names?: string[];
  risk: 'unknown' | 'low' | 'medium' | 'high' | 'critical';
  state: 'discovered' | 'quarantined' | 'approved' | 'revoked' | 'expired';
  discovered_at: string;
  approved_at?: string;
  approved_by?: string;
  approval_receipt_id?: string;
  revoked_at?: string;
  expires_at?: string;
  reason?: string;
}

export interface SandboxBackendProfile {
  name: string;
  kind: 'wasi-wazero' | 'wasi-wasmtime' | 'native-nsjail' | 'native-gvisor' | 'native-firecracker' | 'hosted-adapter';
  runtime: string;
  hosted: boolean;
  deny_network_by_default: boolean;
  native_isolation: boolean;
  experimental?: boolean;
}

export interface SandboxGrant {
  grant_id: string;
  runtime: string;
  runtime_version?: string;
  profile: string;
  image_digest?: string;
  template_digest?: string;
  filesystem_preopens?: Array<{ path: string; mode: 'ro' | 'rw'; content_hash?: string }>;
  env: { mode: 'deny-all' | 'allowlist' | 'redacted'; names?: string[]; names_hash?: string; redacted?: boolean };
  network: { mode: 'deny-all' | 'allowlist'; destinations?: string[]; cidrs?: string[] };
  limits?: { memory_bytes?: number; cpu_time?: number; output_bytes?: number; open_files?: number };
  declared_at: string;
  policy_epoch?: string;
  grant_hash?: string;
}

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

  async createEvidenceEnvelopeManifest(req: EvidenceEnvelopeExportRequest): Promise<EvidenceEnvelopeManifest> {
    return this.request<EvidenceEnvelopeManifest>('POST', '/api/v1/evidence/envelopes', req);
  }

  // ── Conformance ──────────────────────────────────
  async conformanceRun(req: ConformanceRequest): Promise<ConformanceResult> {
    return this.request<ConformanceResult>('POST', '/api/v1/conformance/run', req);
  }

  async getConformanceReport(reportId: string): Promise<ConformanceResult> {
    return this.request<ConformanceResult>('GET', `/api/v1/conformance/reports/${reportId}`);
  }

  async listNegativeConformanceVectors(): Promise<NegativeBoundaryVector[]> {
    return this.request<NegativeBoundaryVector[]>('GET', '/api/v1/conformance/negative');
  }

  // ── MCP Registry ─────────────────────────────────
  async listMcpRegistry(): Promise<McpQuarantineRecord[]> {
    return this.request<McpQuarantineRecord[]>('GET', '/api/v1/mcp/registry');
  }

  async discoverMcpServer(req: McpRegistryDiscoverRequest): Promise<McpQuarantineRecord> {
    return this.request<McpQuarantineRecord>('POST', '/api/v1/mcp/registry', req);
  }

  async approveMcpServer(req: McpRegistryApprovalRequest): Promise<McpQuarantineRecord> {
    return this.request<McpQuarantineRecord>('POST', '/api/v1/mcp/registry/approve', req);
  }

  // ── Sandbox ──────────────────────────────────────
  async inspectSandboxGrants(): Promise<SandboxBackendProfile[]>;
  async inspectSandboxGrants(runtime: string, profile?: string, policyEpoch?: string): Promise<SandboxGrant>;
  async inspectSandboxGrants(runtime?: string, profile?: string, policyEpoch?: string): Promise<SandboxBackendProfile[] | SandboxGrant> {
    const params = new URLSearchParams();
    if (runtime) params.set('runtime', runtime);
    if (profile) params.set('profile', profile);
    if (policyEpoch) params.set('policy_epoch', policyEpoch);
    const query = params.toString();
    return this.request<SandboxBackendProfile[] | SandboxGrant>(
      'GET',
      `/api/v1/sandbox/grants/inspect${query ? `?${query}` : ''}`,
    );
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
