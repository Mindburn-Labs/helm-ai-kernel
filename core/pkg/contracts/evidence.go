package contracts

import "time"

// EvidencePack represents a complete audit trail for an effect execution.
// Per Section 6 - EvidencePack Normative Contract.
type EvidencePack struct {
	// Core Identity
	PackID        string    `json:"pack_id"`
	FormatVersion string    `json:"format_version"`
	CreatedAt     time.Time `json:"created_at"`
	// CorrelationID is the product request identity (X-Helm-Correlation-ID)
	// joining this pack to its decision, receipts, and lifecycle events
	// (pilot business-telemetry contract §2). Unsigned until HELM-303.
	CorrelationID string `json:"correlation_id,omitempty"`

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

	// SecurityFindings bind vulnerability lifecycle evidence to this pack.
	SecurityFindings []SecurityFindingRef `json:"security_findings,omitempty"`

	// Verification scope records what the verification did and did not cover.
	VerificationScopes []VerificationScope `json:"verification_scopes,omitempty"`

	// HarnessTraceRefs link telemetry that influenced execution or replay.
	HarnessTraceRefs []HarnessTraceRef `json:"harness_trace_refs,omitempty"`

	// EUAIActProfile binds high-risk AI system obligations to concrete evidence.
	EUAIActProfile *EUAIActEvidenceProfile `json:"eu_ai_act_profile,omitempty"`

	// Attestation
	Attestation EvidencePackAttestation `json:"attestation"`

	// V2: Execution Plane — enriched evidence
	NetworkLogs    []NetworkLogRef    `json:"network_logs,omitempty"`
	SecretEvents   []SecretEventRef   `json:"secret_events,omitempty"`
	PortExposures  []PortExposureRef  `json:"port_exposures,omitempty"`
	GitDiffs       []GitDiffRef       `json:"git_diffs,omitempty"`
	ReplayManifest *ReplayManifestRef `json:"replay_manifest,omitempty"`
}

// SecurityFindingRef links a HELM-owned vulnerability lifecycle record to an
// EvidencePack without making scanner output the source of truth.
type SecurityFindingRef struct {
	FindingID          string   `json:"finding_id"`
	State              string   `json:"state"`
	EventHash          string   `json:"event_hash"`
	ThreatModelRef     string   `json:"threat_model_ref,omitempty"`
	SandboxReceiptRef  string   `json:"sandbox_receipt_ref,omitempty"`
	VerifierRef        string   `json:"verifier_ref,omitempty"`
	PatchRef           string   `json:"patch_ref,omitempty"`
	RegressionTestRef  string   `json:"regression_test_ref,omitempty"`
	VariantScanRef     string   `json:"variant_scan_ref,omitempty"`
	LifecycleEventRefs []string `json:"lifecycle_event_refs,omitempty"`
}

// VerificationScope records verification coverage and residual risk.
type VerificationScope struct {
	VerificationScopeID string    `json:"verification_scope_id"`
	SubjectHash         string    `json:"subject_hash"`
	RiskClass           string    `json:"risk_class,omitempty"`
	ChecksPerformed     []string  `json:"checks_performed"`
	Assumptions         []string  `json:"assumptions,omitempty"`
	UntestedRegions     []string  `json:"untested_regions,omitempty"`
	KnownLimits         []string  `json:"known_limits,omitempty"`
	RemainingRisks      []string  `json:"remaining_risks,omitempty"`
	RequiredFollowup    []string  `json:"required_followup,omitempty"`
	VerifierHash        string    `json:"verifier_hash"`
	PolicyHash          string    `json:"policy_hash"`
	CreatedAt           time.Time `json:"created_at,omitempty"`
	ScopeHash           string    `json:"scope_hash,omitempty"`
}

// HarnessTraceRef points to a canonical harness trace artifact.
type HarnessTraceRef struct {
	TraceID string    `json:"trace_id"`
	Hash    string    `json:"hash"`
	URI     string    `json:"uri,omitempty"`
	Kind    string    `json:"kind,omitempty"`
	At      time.Time `json:"at,omitempty"`
}

// EUAIActEvidenceProfile captures the evidence refs needed to verify EU AI Act
// posture without making legal conclusions inside the pack.
type EUAIActEvidenceProfile struct {
	ProfileID                           string            `json:"profile_id,omitempty"`
	RoleMap                             EUAIActRoleMap    `json:"role_map,omitempty"`
	RiskCategory                        string            `json:"risk_category,omitempty"`
	RelevantArticles                    []string          `json:"relevant_articles,omitempty"`
	HighRiskReasons                     []string          `json:"high_risk_reasons,omitempty"`
	ProviderOrDeployerRole              string            `json:"provider_or_deployer_role,omitempty"`
	TechnicalDocumentationRefs          []string          `json:"technical_documentation_refs,omitempty"`
	RiskManagementRefs                  []string          `json:"risk_management_refs,omitempty"`
	DataGovernanceRefs                  []string          `json:"data_governance_refs,omitempty"`
	LogRecordRefs                       []string          `json:"log_record_refs,omitempty"`
	TransparencyNoticeRefs              []string          `json:"transparency_notice_refs,omitempty"`
	HumanOversightRefs                  []string          `json:"human_oversight_refs,omitempty"`
	AccuracyRobustnessCybersecurityRefs []string          `json:"accuracy_robustness_cybersecurity_refs,omitempty"`
	FRIARefs                            []string          `json:"fria_refs,omitempty"`
	AffectedPersonNoticeRefs            []string          `json:"affected_person_notice_refs,omitempty"`
	RegistrationRefs                    []string          `json:"registration_refs,omitempty"`
	IncidentRefs                        []string          `json:"incident_refs,omitempty"`
	CorrectiveActionRefs                []string          `json:"corrective_action_refs,omitempty"`
	RedactionProfile                    string            `json:"redaction_profile,omitempty"`
	RetentionProfile                    string            `json:"retention_profile,omitempty"`
	TimelineStatus                      string            `json:"timeline_status,omitempty"`
	RedactionMetadata                   map[string]string `json:"redaction_metadata,omitempty"`
}

// EUAIActRoleMap records who acts in each regulatory role for this pack.
type EUAIActRoleMap struct {
	Provider            string `json:"provider,omitempty"`
	Deployer            string `json:"deployer,omitempty"`
	Importer            string `json:"importer,omitempty"`
	Distributor         string `json:"distributor,omitempty"`
	ProductManufacturer string `json:"product_manufacturer,omitempty"`
	Operator            string `json:"operator,omitempty"`
}

// NetworkLogRef references a network activity log captured during execution.
type NetworkLogRef struct {
	LogID         string    `json:"log_id"`
	Hash          string    `json:"hash"`
	Source        string    `json:"source,omitempty"` // "sandbox", "firewall", "proxy"
	CapturedAt    time.Time `json:"captured_at"`
	BytesCaptured int64     `json:"bytes_captured,omitempty"`
}

// SecretEventRef references a secret access audit log.
type SecretEventRef struct {
	EventID    string    `json:"event_id"`
	Hash       string    `json:"hash"`
	SecretRef  string    `json:"secret_ref"` // Identifier (never the secret value)
	Action     string    `json:"action"`     // "issue", "access", "revoke"
	OccurredAt time.Time `json:"occurred_at"`
}

// PortExposureRef references a port exposure event.
type PortExposureRef struct {
	EventID   string    `json:"event_id"`
	Hash      string    `json:"hash"`
	Port      int       `json:"port"`
	Source    string    `json:"source,omitempty"`
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
	ActorID              string   `json:"actor_id"`
	ActorType            string   `json:"actor_type"` // human, module, control_loop, external_system
	SessionID            string   `json:"session_id,omitempty"`
	DelegationChain      []string `json:"delegation_chain,omitempty"`
	DelegationSessionRef string   `json:"delegation_session_ref,omitempty"` // binds to active DelegationSession.SessionID
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
