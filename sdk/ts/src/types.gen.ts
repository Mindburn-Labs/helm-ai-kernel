// AUTO-GENERATED from api/openapi/helm.openapi.yaml — DO NOT EDIT
// Regenerate: bash scripts/sdk/gen.sh

/** HELM error envelope — same shape for every error. */
export interface HelmError {
  error: {
    message: string;
    type: 'invalid_request' | 'authentication_error' | 'permission_denied' | 'not_found' | 'internal_error';
    code: string;
    reason_code: ReasonCode;
    details?: Record<string, unknown>;
  };
}

/** Deterministic reason codes returned by the kernel. */
export type ReasonCode =
  | 'ALLOW'
  | 'DENY_TOOL_NOT_FOUND'
  | 'DENY_SCHEMA_MISMATCH'
  | 'DENY_OUTPUT_DRIFT'
  | 'DENY_BUDGET_EXCEEDED'
  | 'DENY_APPROVAL_REQUIRED'
  | 'DENY_APPROVAL_TIMEOUT'
  | 'DENY_SANDBOX_TRAP'
  | 'DENY_GAS_EXHAUSTION'
  | 'DENY_TIME_LIMIT'
  | 'DENY_MEMORY_LIMIT'
  | 'DENY_POLICY_VIOLATION'
  | 'DENY_TRUST_KEY_REVOKED'
  | 'DENY_IDEMPOTENCY_DUPLICATE'
  | 'ERROR_INTERNAL';

export interface ChatCompletionRequest {
  model: string;
  messages: Array<{
    role: 'system' | 'user' | 'assistant' | 'tool';
    content: string;
    tool_call_id?: string;
  }>;
  tools?: Array<{
    type: 'function';
    function: {
      name: string;
      description?: string;
      parameters?: Record<string, unknown>;
    };
  }>;
  temperature?: number;
  max_tokens?: number;
  stream?: boolean;
}

export interface ChatCompletionResponse {
  id: string;
  object: string;
  created: number;
  model: string;
  choices: Array<{
    index: number;
    message: {
      role: string;
      content: string | null;
      tool_calls?: Array<{
        id: string;
        type: string;
        function: { name: string; arguments: string };
      }>;
    };
    finish_reason: string;
  }>;
  usage?: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
}

export interface ApprovalRequest {
  intent_hash: string;
  signature_b64: string;
  public_key_b64: string;
  challenge_response?: string;
}

export interface Receipt {
  receipt_id: string;
  decision_id: string;
  effect_id: string;
  status: 'APPROVED' | 'DENIED' | 'PENDING';
  reason_code: string;
  output_hash: string;
  blob_hash: string;
  prev_hash: string;
  lamport_clock: number;
  signature: string;
  timestamp: string;
  principal: string;
}

export interface Session {
  session_id: string;
  created_at: string;
  receipt_count: number;
  last_lamport_clock: number;
}

export interface ExportRequest {
  session_id?: string;
  format?: 'tar.gz';
}

export interface VerificationResult {
  verdict: 'PASS' | 'FAIL';
  checks: {
    signatures: 'PASS' | 'FAIL';
    causal_chain: 'PASS' | 'FAIL';
    policy_compliance: 'PASS' | 'FAIL';
  };
  errors: string[];
}

export interface ConformanceRequest {
  level: 'L1' | 'L2';
  profile?: string;
}

export interface ConformanceResult {
  report_id: string;
  level: string;
  verdict: 'PASS' | 'FAIL';
  gates: number;
  failed: number;
  details: Record<string, string>;
}

export interface VersionInfo {
  version: string;
  commit: string;
  build_time: string;
  go_version: string;
}
