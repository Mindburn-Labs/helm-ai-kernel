package contracts

import "time"

// EvidencePack represents a complete audit trail for an effect execution.
// Per Section 6 - EvidencePack Normative Contract.
type EvidencePack struct {
	// Core Identity
	PackID        string    `json:"pack_id"`
	FormatVersion string    `json:"format_version"`
	CreatedAt     time.Time `json:"created_at"`

	// Identity
	Identity EvidencePackIdentity `json:"identity"`

	// Policy
	Policy EvidencePackPolicy `json:"policy"`

	// Effect
	Effect EvidencePackEffect `json:"effect"`

	// Context
	Context EvidencePackContext `json:"context"`

	// Execution
	Execution EvidencePackExecution `json:"execution"`

	// Receipts
	Receipts EvidencePackReceipts `json:"receipts"`

	// Reconciliation
	Reconciliation EvidencePackReconciliation `json:"reconciliation"`

	// Receipt-as-First-Class Enhancements
	ReplayScript     *ReplayScriptRef   `json:"replay_script,omitempty"`
	Provenance       *ReceiptProvenance `json:"provenance,omitempty"`
	BundledArtifacts []ParsedArtifact   `json:"bundled_artifacts,omitempty"`

	// Threat Scan Evidence
	ThreatScan *ThreatScanRef `json:"threat_scan,omitempty"`

	// Attestation
	Attestation EvidencePackAttestation `json:"attestation"`

	// V2: Execution Plane — enriched evidence
	NetworkLogs    []NetworkLogRef    `json:"network_logs,omitempty"`
	SecretEvents   []SecretEventRef   `json:"secret_events,omitempty"`
	PortExposures  []PortExposureRef  `json:"port_exposures,omitempty"`
	GitDiffs       []GitDiffRef       `json:"git_diffs,omitempty"`
	ReplayManifest *ReplayManifestRef `json:"replay_manifest,omitempty"`
}

// NetworkLogRef references a network activity log captured during execution.
type NetworkLogRef struct {
	LogID       string    `json:"log_id"`
	Hash        string    `json:"hash"`
	Source      string    `json:"source,omitempty"` // "sandbox", "firewall", "proxy"
	CapturedAt  time.Time `json:"captured_at"`
	BytesCaptured int64   `json:"bytes_captured,omitempty"`
}

// SecretEventRef references a secret access audit log.
type SecretEventRef struct {
	EventID    string    `json:"event_id"`
	Hash       string    `json:"hash"`
	SecretRef  string    `json:"secret_ref"`    // Identifier (never the secret value)
	Action     string    `json:"action"`        // "issue", "access", "revoke"
	OccurredAt time.Time `json:"occurred_at"`
}

// PortExposureRef references a port exposure event.
type PortExposureRef struct {
	EventID string    `json:"event_id"`
	Hash    string    `json:"hash"`
	Port    int       `json:"port"`
	Source  string    `json:"source,omitempty"`
	StartedAt time.Time `json:"started_at"`
}

// GitDiffRef references a git diff captured during execution.
type GitDiffRef struct {
	DiffID     string    `json:"diff_id"`
	Hash       string    `json:"hash"`
	Repository string    `json:"repository,omitempty"`
	FromRef    string    `json:"from_ref,omitempty"` // Base commit
	ToRef      string    `json:"to_ref,omitempty"`   // Head commit
	CapturedAt time.Time `json:"captured_at"`
}

// ReplayManifestRef references the replay manifest for reconstructing this run.
type ReplayManifestRef struct {
	ManifestID string `json:"manifest_id"`
	Hash       string `json:"hash"`
	Mode       string `json:"mode"` // "dry", "bounded", "full"
}

// EvidencePackIdentity tracks the actor submitting the effect.
type EvidencePackIdentity struct {
	ActorID            string   `json:"actor_id"`
	ActorType          string   `json:"actor_type"` // human, module, control_loop, external_system
	SessionID          string   `json:"session_id,omitempty"`
	DelegationChain    []string `json:"delegation_chain,omitempty"`
	DelegationSessionRef string `json:"delegation_session_ref,omitempty"` // binds to active DelegationSession.SessionID
}

// EvidencePackPolicy captures the policy decision.
type EvidencePackPolicy struct {
	DecisionID          string   `json:"decision_id"`
	PolicyVersion       string   `json:"policy_version"`
	RulesFired          []string `json:"rules_fired"`
	EvaluationGraphHash string   `json:"evaluation_graph_hash"`
}

// EvidencePackEffect describes the effect.
type EvidencePackEffect struct {
	EffectID          string `json:"effect_id"`
	EffectType        string `json:"effect_type"`
	EffectPayloadHash string `json:"effect_payload_hash"`
	IdempotencyKey    string `json:"idempotency_key,omitempty"`
	Classification    string `json:"classification,omitempty"` // reversible, compensatable, irreversible
}

// EvidencePackContext provides execution context.
type EvidencePackContext struct {
	ModeID             string `json:"mode_id,omitempty"`
	LoopID             string `json:"loop_id,omitempty"`
	Jurisdiction       string `json:"jurisdiction,omitempty"`
	PhenotypeHash      string `json:"phenotype_hash,omitempty"`
	OrchestrationRunID string `json:"orchestration_run_id,omitempty"`
	PhaseID            string `json:"phase_id,omitempty"`
	CheckpointRef      string `json:"checkpoint_ref,omitempty"`
	CritiqueRef        string `json:"critique_ref,omitempty"`
	HeuristicTraceID   string `json:"heuristic_trace_id,omitempty"`
}

// EvidencePackExecution captures execution details.
type EvidencePackExecution struct {
	ExecutionID   string    `json:"execution_id"`
	Status        string    `json:"status"` // success, failure, timeout, compensated
	ResultHash    string    `json:"result_hash,omitempty"`
	RetryCount    int       `json:"retry_count"`
	StartedAt     time.Time `json:"started_at"`
	CompletedAt   time.Time `json:"completed_at,omitempty"`
	DurationMs    int64     `json:"duration_ms,omitempty"`
	FailureReason string    `json:"failure_reason,omitempty"`
}

// EvidencePackReceipts contains receipts from PAL and external systems.
type EvidencePackReceipts struct {
	PALReceipts      []PALReceiptRef      `json:"pal_receipts,omitempty"`
	ExternalReceipts []ExternalReceiptRef `json:"external_receipts,omitempty"`
}

// PALReceiptRef references a PAL receipt.
type PALReceiptRef struct {
	ReceiptID   string    `json:"receipt_id"`
	ProviderID  string    `json:"provider_id"`
	ModelID     string    `json:"model_id,omitempty"`
	InputHash   string    `json:"input_hash"`
	OutputHash  string    `json:"output_hash"`
	TokensIn    int       `json:"tokens_in,omitempty"`
	TokensOut   int       `json:"tokens_out,omitempty"`
	CompletedAt time.Time `json:"completed_at"`
}

// ExternalReceiptRef references an external system receipt.
type ExternalReceiptRef struct {
	ReceiptID    string    `json:"receipt_id"`
	ExternalID   string    `json:"external_id,omitempty"`
	SystemName   string    `json:"system_name"`
	RequestHash  string    `json:"request_hash"`
	ResponseHash string    `json:"response_hash"`
	HTTPStatus   int       `json:"http_status,omitempty"`
	CompletedAt  time.Time `json:"completed_at"`
}

// EvidencePackReconciliation tracks reconciliation events.
type EvidencePackReconciliation struct {
	ReconciliationID string                `json:"reconciliation_id,omitempty"`
	OutboxID         string                `json:"outbox_id,omitempty"`
	CompensationRef  string                `json:"compensation_ref,omitempty"`
	DeniedAttempts   []DeniedAttemptRecord `json:"denied_attempts,omitempty"`
	FailedAttempts   []FailedAttemptRecord `json:"failed_attempts,omitempty"`
}

// DeniedAttemptRecord records a denied attempt.
type DeniedAttemptRecord struct {
	AttemptID  string    `json:"attempt_id"`
	DecisionID string    `json:"decision_id"`
	Reason     string    `json:"reason"`
	OccurredAt time.Time `json:"occurred_at"`
}

// FailedAttemptRecord records a failed execution attempt.
type FailedAttemptRecord struct {
	AttemptID   string    `json:"attempt_id"`
	Reason      string    `json:"reason"`
	RetryNumber int       `json:"retry_number"`
	OccurredAt  time.Time `json:"occurred_at"`
}

// EvidencePackAttestation provides cryptographic attestation.
type EvidencePackAttestation struct {
	PackHash      string `json:"pack_hash"`
	Signature     string `json:"signature,omitempty"`
	SignerID      string `json:"signer_id,omitempty"`
	KernelVersion string `json:"kernel_version,omitempty"`
}
