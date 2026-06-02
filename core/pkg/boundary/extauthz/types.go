package extauthz

import "time"

const (
	SchemaVersionV1   = "extauthz.v1"
	ContractVersionV1 = "2026-06-01"

	VerdictAllow    = "ALLOW"
	VerdictDeny     = "DENY"
	VerdictEscalate = "ESCALATE"

	CachePolicyNoStore     = "no_store"
	ReplayHintSingleUse    = "single_use_permit"
	ProofStateAuthorized   = "AUTHORIZED"
	ProofStatePending      = "PROOF_PENDING"
	ProofStateFailed       = "PROOF_FINALIZATION_FAILED"
	ProofStateFinalized    = "PROOF_FINALIZED"
	ProofStateEffectFailed = "EFFECT_FAILED"

	EffectOutcomeSucceeded = "EFFECT_SUCCEEDED"
	EffectOutcomeFailed    = "EFFECT_FAILED"

	ReasonAllowVerified              = "ALLOW_VERIFIED"
	ReasonDenyNoDispatch             = "DENY_NO_DISPATCH"
	ReasonEscalateNoDispatch         = "ESCALATE_NO_DISPATCH"
	ReasonPermitConsumerRequired     = "DENY_PERMIT_CONSUMER_REQUIRED"
	ReasonDurablePermitStoreRequired = "DENY_DURABLE_PERMIT_STORE_REQUIRED"
)

type AuthorizationRequest struct {
	SchemaVersion           string         `json:"schema_version"`
	ContractVersion         string         `json:"contract_version"`
	RequestID               string         `json:"request_id"`
	TenantID                string         `json:"tenant_id"`
	WorkspaceID             string         `json:"workspace_id"`
	PrincipalID             string         `json:"principal_id"`
	PrincipalSeq            uint64         `json:"principal_seq"`
	AgentIdentityProfileRef string         `json:"agent_identity_profile_ref"`
	Protocol                string         `json:"protocol"`
	ActionURN               string         `json:"action_urn"`
	ToolURN                 string         `json:"tool_urn"`
	ConnectorID             string         `json:"connector_id"`
	ConnectorContractHash   string         `json:"connector_contract_hash"`
	ExecutorKind            string         `json:"executor_kind"`
	EffectClass             string         `json:"effect_class"`
	RiskClass               string         `json:"risk_class"`
	ArgsC14NHash            string         `json:"args_c14n_hash"`
	RequestBodyHash         string         `json:"request_body_hash"`
	PlanHash                string         `json:"plan_hash"`
	PolicyHash              string         `json:"policy_hash"`
	P0Hash                  string         `json:"p0_hash"`
	PolicyEpoch             string         `json:"policy_epoch"`
	IdempotencyKeyCandidate string         `json:"idempotency_key_candidate"`
	PayloadClass            string         `json:"payload_class"`
	RedactionProfile        string         `json:"redaction_profile"`
	UpstreamTraceID         string         `json:"upstream_trace_id"`
	UpstreamRunID           string         `json:"upstream_run_id"`
	DeadlineMS              uint64         `json:"deadline_ms"`
	RiskContext             map[string]any `json:"risk_context,omitempty"`
	RiskContextHash         string         `json:"risk_context_hash"`
}

// AuthorizationResponse is a pre-dispatch Kernel verdict. It deliberately has
// no final receipt or EvidencePack field because the external effect has not run.
type AuthorizationResponse struct {
	SchemaVersion           string `json:"schema_version"`
	ContractVersion         string `json:"contract_version"`
	RequestID               string `json:"request_id"`
	TenantID                string `json:"tenant_id"`
	WorkspaceID             string `json:"workspace_id"`
	PrincipalID             string `json:"principal_id"`
	PrincipalSeq            uint64 `json:"principal_seq"`
	AgentIdentityProfileRef string `json:"agent_identity_profile_ref"`
	Protocol                string `json:"protocol"`
	ActionURN               string `json:"action_urn"`
	ToolURN                 string `json:"tool_urn"`
	ConnectorID             string `json:"connector_id"`
	ConnectorContractHash   string `json:"connector_contract_hash"`
	ExecutorKind            string `json:"executor_kind"`
	EffectClass             string `json:"effect_class"`
	RiskClass               string `json:"risk_class"`
	ArgsC14NHash            string `json:"args_c14n_hash"`
	RequestBodyHash         string `json:"request_body_hash"`
	PlanHash                string `json:"plan_hash"`
	PolicyHash              string `json:"policy_hash"`
	P0Hash                  string `json:"p0_hash"`
	PolicyEpoch             string `json:"policy_epoch"`
	IdempotencyKeyCandidate string `json:"idempotency_key_candidate"`
	PayloadClass            string `json:"payload_class"`
	RedactionProfile        string `json:"redaction_profile"`
	UpstreamTraceID         string `json:"upstream_trace_id"`
	UpstreamRunID           string `json:"upstream_run_id"`
	DeadlineMS              uint64 `json:"deadline_ms"`
	RiskContextHash         string `json:"risk_context_hash"`

	Verdict    string `json:"verdict"`
	ReasonCode string `json:"reason_code"`

	KernelTrustRootID       string `json:"kernel_trust_root_id"`
	SigningKeyRef           string `json:"signing_key_ref"`
	KernelVerdictRef        string `json:"kernel_verdict_ref"`
	KernelVerdictHash       string `json:"kernel_verdict_hash"`
	KernelVerdictSignature  string `json:"kernel_verdict_signature"`
	KernelVerdictIssuedAt   string `json:"kernel_verdict_issued_at"`
	KernelVerdictExpiresAt  string `json:"kernel_verdict_expires_at"`
	EffectPermitRef         string `json:"effect_permit_ref,omitempty"`
	PermitNonce             string `json:"permit_nonce,omitempty"`
	PermitExpiry            string `json:"permit_expiry,omitempty"`
	ProofSessionRef         string `json:"proof_session_ref,omitempty"`
	EvidenceReservationRef  string `json:"evidence_reservation_ref,omitempty"`
	BudgetReservationRef    string `json:"budget_reservation_ref,omitempty"`
	CachePolicy             string `json:"cache_policy"`
	ReplayHint              string `json:"replay_hint"`
	DenialReceiptRef        string `json:"denial_receipt_ref,omitempty"`
	EscalationRef           string `json:"escalation_ref,omitempty"`
	EscalationReceiptRef    string `json:"escalation_receipt_ref,omitempty"`
	ProofObligation         string `json:"proof_obligation,omitempty"`
	ConnectorReceiptPolicy  string `json:"connector_receipt_policy,omitempty"`
	ProofFinalizationPolicy string `json:"proof_finalization_policy,omitempty"`
}

type TrustedKey struct {
	TrustRootID string
	PublicKey   []byte
	Enabled     bool
}

type TrustStore struct {
	Keys map[string]TrustedKey
}

type VerifyOptions struct {
	ExpectedKernelTrustRootID string
	ExpectedPolicyEpoch       string
	MaxVerdictTTL             time.Duration
	MaxPermitTTL              time.Duration
	PermitConsumer            PermitConsumer
}

type Evaluation struct {
	Verdict            string
	ReasonCode         string
	DispatchAuthorized bool
	KernelVerdictRef   string
	EffectPermitRef    string
}
