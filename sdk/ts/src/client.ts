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
  payload_type?: string;
  payload_hash?: string;
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

export type SurfaceRecord = Record<string, unknown>;
export type BoundaryStatus = SurfaceRecord;
export type BoundaryCapabilitySummary = SurfaceRecord;
export type ExecutionBoundaryRecord = SurfaceRecord;
export type BoundaryRecordVerification = SurfaceRecord;
export type BoundaryCheckpoint = SurfaceRecord;
export type MCPAuthorizationProfile = SurfaceRecord;
export type MCPScanRequest = SurfaceRecord;
export type MCPScanResult = SurfaceRecord;
export type MCPAuthorizeCallRequest = SurfaceRecord;
export type SandboxPreflightRequest = SurfaceRecord;
export type SandboxPreflightResult = SurfaceRecord;
export type AuthzSnapshot = SurfaceRecord;
export type ApprovalCeremony = SurfaceRecord;
export type ApprovalWebAuthnChallenge = SurfaceRecord;
export type ApprovalWebAuthnAssertion = SurfaceRecord;
export type BudgetCeiling = SurfaceRecord;
export type AgentIdentityProfile = SurfaceRecord;
export type AuthzHealth = SurfaceRecord;
export type EvidenceEnvelopeVerification = SurfaceRecord;
export type EvidenceEnvelopePayload = SurfaceRecord;
export type TelemetryOTelConfig = SurfaceRecord;
export type TelemetryExportRequest = SurfaceRecord;
export type TelemetryExportResult = SurfaceRecord;
export type CoexistenceCapabilityManifest = SurfaceRecord;

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

  async listEvidenceEnvelopeManifests(): Promise<EvidenceEnvelopeManifest[]> {
    return this.request<EvidenceEnvelopeManifest[]>('GET', '/api/v1/evidence/envelopes');
  }

  async getEvidenceEnvelopeManifest(manifestId: string): Promise<EvidenceEnvelopeManifest> {
    return this.request<EvidenceEnvelopeManifest>('GET', `/api/v1/evidence/envelopes/${encodeURIComponent(manifestId)}`);
  }

  async verifyEvidenceEnvelopeManifest(manifestId: string): Promise<EvidenceEnvelopeVerification> {
    return this.request<EvidenceEnvelopeVerification>('POST', `/api/v1/evidence/envelopes/${encodeURIComponent(manifestId)}/verify`);
  }

  async getEvidenceEnvelopePayload(manifestId: string): Promise<EvidenceEnvelopePayload> {
    return this.request<EvidenceEnvelopePayload>('GET', `/api/v1/evidence/envelopes/${encodeURIComponent(manifestId)}/payload`);
  }

  // ── Execution Boundary ───────────────────────────
  async getBoundaryStatus(): Promise<BoundaryStatus> {
    return this.request<BoundaryStatus>('GET', '/api/v1/boundary/status');
  }

  async listBoundaryCapabilities(): Promise<BoundaryCapabilitySummary[]> {
    return this.request<BoundaryCapabilitySummary[]>('GET', '/api/v1/boundary/capabilities');
  }

  async listBoundaryRecords(query?: Record<string, string | number | undefined>): Promise<ExecutionBoundaryRecord[]> {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(query ?? {})) {
      if (value !== undefined && value !== '') params.set(key, String(value));
    }
    const qs = params.toString();
    return this.request<ExecutionBoundaryRecord[]>('GET', `/api/v1/boundary/records${qs ? `?${qs}` : ''}`);
  }

  async getBoundaryRecord(recordId: string): Promise<ExecutionBoundaryRecord> {
    return this.request<ExecutionBoundaryRecord>('GET', `/api/v1/boundary/records/${encodeURIComponent(recordId)}`);
  }

  async verifyBoundaryRecord(recordId: string): Promise<BoundaryRecordVerification> {
    return this.request<BoundaryRecordVerification>('POST', `/api/v1/boundary/records/${encodeURIComponent(recordId)}/verify`);
  }

  async listBoundaryCheckpoints(): Promise<BoundaryCheckpoint[]> {
    return this.request<BoundaryCheckpoint[]>('GET', '/api/v1/boundary/checkpoints');
  }

  async createBoundaryCheckpoint(): Promise<BoundaryCheckpoint> {
    return this.request<BoundaryCheckpoint>('POST', '/api/v1/boundary/checkpoints');
  }

  async verifyBoundaryCheckpoint(checkpointId: string): Promise<SurfaceRecord> {
    return this.request<SurfaceRecord>('POST', `/api/v1/boundary/checkpoints/${encodeURIComponent(checkpointId)}/verify`);
  }

  // ── Conformance ──────────────────────────────────
  async conformanceRun(req: ConformanceRequest): Promise<ConformanceResult> {
    return this.request<ConformanceResult>('POST', '/api/v1/conformance/run', req);
  }

  async getConformanceReport(reportId: string): Promise<ConformanceResult> {
    return this.request<ConformanceResult>('GET', `/api/v1/conformance/reports/${reportId}`);
  }

  async listConformanceReports(): Promise<ConformanceResult[]> {
    return this.request<ConformanceResult[]>('GET', '/api/v1/conformance/reports');
  }

  async listConformanceVectors(): Promise<NegativeBoundaryVector[]> {
    return this.request<NegativeBoundaryVector[]>('GET', '/api/v1/conformance/vectors');
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

  async getMcpRegistryRecord(serverId: string): Promise<McpQuarantineRecord> {
    return this.request<McpQuarantineRecord>('GET', `/api/v1/mcp/registry/${encodeURIComponent(serverId)}`);
  }

  async approveMcpRegistryRecord(serverId: string, req: Partial<McpRegistryApprovalRequest>): Promise<McpQuarantineRecord> {
    return this.request<McpQuarantineRecord>('POST', `/api/v1/mcp/registry/${encodeURIComponent(serverId)}/approve`, req);
  }

  async revokeMcpRegistryRecord(serverId: string, reason?: string): Promise<McpQuarantineRecord> {
    return this.request<McpQuarantineRecord>('POST', `/api/v1/mcp/registry/${encodeURIComponent(serverId)}/revoke`, { reason });
  }

  async scanMcpServer(req: MCPScanRequest): Promise<MCPScanResult> {
    return this.request<MCPScanResult>('POST', '/api/v1/mcp/scan', req);
  }

  async listMcpAuthProfiles(): Promise<MCPAuthorizationProfile[]> {
    return this.request<MCPAuthorizationProfile[]>('GET', '/api/v1/mcp/auth-profiles');
  }

  async putMcpAuthProfile(profileId: string, profile: MCPAuthorizationProfile): Promise<MCPAuthorizationProfile> {
    return this.request<MCPAuthorizationProfile>('PUT', `/api/v1/mcp/auth-profiles/${encodeURIComponent(profileId)}`, profile);
  }

  async authorizeMcpCall(req: MCPAuthorizeCallRequest): Promise<ExecutionBoundaryRecord> {
    return this.request<ExecutionBoundaryRecord>('POST', '/api/v1/mcp/authorize-call', req);
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

  async listSandboxProfiles(): Promise<SandboxBackendProfile[]> {
    return this.request<SandboxBackendProfile[]>('GET', '/api/v1/sandbox/profiles');
  }

  async listSandboxGrants(): Promise<SandboxGrant[]> {
    return this.request<SandboxGrant[]>('GET', '/api/v1/sandbox/grants');
  }

  async createSandboxGrant(req: SurfaceRecord): Promise<SandboxGrant> {
    return this.request<SandboxGrant>('POST', '/api/v1/sandbox/grants', req);
  }

  async getSandboxGrant(grantId: string): Promise<SandboxGrant> {
    return this.request<SandboxGrant>('GET', `/api/v1/sandbox/grants/${encodeURIComponent(grantId)}`);
  }

  async verifySandboxGrant(grantId: string): Promise<SandboxPreflightResult> {
    return this.request<SandboxPreflightResult>('POST', `/api/v1/sandbox/grants/${encodeURIComponent(grantId)}/verify`);
  }

  async preflightSandboxGrant(req: SandboxPreflightRequest): Promise<SandboxPreflightResult> {
    return this.request<SandboxPreflightResult>('POST', '/api/v1/sandbox/preflight', req);
  }

  // ── Identity, Authz, Approvals, Budgets ──────────
  async listAgentIdentities(): Promise<AgentIdentityProfile[]> {
    return this.request<AgentIdentityProfile[]>('GET', '/api/v1/identity/agents');
  }

  async getAuthzHealth(): Promise<AuthzHealth> {
    return this.request<AuthzHealth>('GET', '/api/v1/authz/health');
  }

  async checkAuthz(req: SurfaceRecord): Promise<AuthzSnapshot> {
    return this.request<AuthzSnapshot>('POST', '/api/v1/authz/check', req);
  }

  async listAuthzSnapshots(): Promise<AuthzSnapshot[]> {
    return this.request<AuthzSnapshot[]>('GET', '/api/v1/authz/snapshots');
  }

  async getAuthzSnapshot(snapshotId: string): Promise<AuthzSnapshot> {
    return this.request<AuthzSnapshot>('GET', `/api/v1/authz/snapshots/${encodeURIComponent(snapshotId)}`);
  }

  async listApprovalCeremonies(): Promise<ApprovalCeremony[]> {
    return this.request<ApprovalCeremony[]>('GET', '/api/v1/approvals');
  }

  async createApprovalCeremony(req: ApprovalCeremony): Promise<ApprovalCeremony> {
    return this.request<ApprovalCeremony>('POST', '/api/v1/approvals', req);
  }

  async transitionApprovalCeremony(approvalId: string, action: 'approve' | 'deny' | 'revoke', req: SurfaceRecord = {}): Promise<ApprovalCeremony> {
    return this.request<ApprovalCeremony>('POST', `/api/v1/approvals/${encodeURIComponent(approvalId)}/${action}`, req);
  }

  async createApprovalWebAuthnChallenge(approvalId: string, req: SurfaceRecord = {}): Promise<ApprovalWebAuthnChallenge> {
    return this.request<ApprovalWebAuthnChallenge>('POST', `/api/v1/approvals/${encodeURIComponent(approvalId)}/webauthn/challenge`, req);
  }

  async assertApprovalWebAuthnChallenge(approvalId: string, req: ApprovalWebAuthnAssertion): Promise<ApprovalCeremony> {
    return this.request<ApprovalCeremony>('POST', `/api/v1/approvals/${encodeURIComponent(approvalId)}/webauthn/assert`, req);
  }

  async listBudgetCeilings(): Promise<BudgetCeiling[]> {
    return this.request<BudgetCeiling[]>('GET', '/api/v1/budgets');
  }

  async putBudgetCeiling(budgetId: string, req: BudgetCeiling): Promise<BudgetCeiling> {
    return this.request<BudgetCeiling>('PUT', `/api/v1/budgets/${encodeURIComponent(budgetId)}`, req);
  }

  // ── Telemetry and Coexistence ────────────────────
  async getCoexistenceCapabilities(): Promise<CoexistenceCapabilityManifest> {
    return this.request<CoexistenceCapabilityManifest>('GET', '/api/v1/coexistence/capabilities');
  }

  async getTelemetryOTelConfig(): Promise<TelemetryOTelConfig> {
    return this.request<TelemetryOTelConfig>('GET', '/api/v1/telemetry/otel/config');
  }

  async exportTelemetry(req: TelemetryExportRequest): Promise<TelemetryExportResult> {
    return this.request<TelemetryExportResult>('POST', '/api/v1/telemetry/export', req);
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
