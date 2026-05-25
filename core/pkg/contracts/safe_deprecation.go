package contracts

import "time"

// SafeDepState is the kernel-visible emergency posture after hazard appraisal.
type SafeDepState string

const (
	SafeDepTerminalFreeze     SafeDepState = "terminal_freeze"
	SafeDepDegradedNarrowing  SafeDepState = "degraded_narrowing"
	SafeDepDeprecatedReadonly SafeDepState = "deprecated_readonly"
)

// SafeDepHazardCode identifies the condition that forced emergency appraisal.
type SafeDepHazardCode string

const (
	HazardDeadManExpired        SafeDepHazardCode = "DEAD_MAN_EXPIRED"
	HazardContinuityMissing     SafeDepHazardCode = "CONTINUITY_MISSING"
	HazardEnginePinMismatch     SafeDepHazardCode = "ENGINE_PIN_MISMATCH"
	HazardAttestationFailure    SafeDepHazardCode = "ATTESTATION_FAILURE"
	HazardVerifierProfileDrift  SafeDepHazardCode = "VERIFIER_PROFILE_DRIFT"
	HazardCredentialExpired     SafeDepHazardCode = "CREDENTIAL_EXPIRED"
	HazardAPIRot                SafeDepHazardCode = "API_ROT"
	HazardNetworkPartition      SafeDepHazardCode = "NETWORK_PARTITION"
	HazardTransparencyLogOutage SafeDepHazardCode = "TRANSPARENCY_LOG_OUTAGE"
	HazardStalePolicyFeed       SafeDepHazardCode = "STALE_POLICY_FEED"
)

type HazardClassification struct {
	HazardCode        SafeDepHazardCode `json:"hazard_code"`
	State             SafeDepState      `json:"state"`
	ReasonCode        ReasonCode        `json:"reason_code"`
	LaneID            string            `json:"lane_id,omitempty"`
	ConnectorID       string            `json:"connector_id,omitempty"`
	ActiveClock       bool              `json:"active_clock"`
	HighRiskLane      bool              `json:"high_risk_lane"`
	ActivationAllowed bool              `json:"activation_allowed"`
}

type ContinuityCheckpoint struct {
	CheckpointID                 string    `json:"checkpoint_id"`
	OrgGenomeHash                string    `json:"org_genome_hash"`
	PolicyHash                   string    `json:"policy_hash"`
	PolicyEpoch                  uint64    `json:"policy_epoch"`
	HazardSequence               uint64    `json:"hazard_sequence"`
	LamportClock                 uint64    `json:"lamport_clock"`
	DeadManWindowID              string    `json:"dead_man_window_id"`
	DeadManActive                bool      `json:"dead_man_active"`
	LatestAcceptedCheckpointHash string    `json:"latest_accepted_checkpoint_hash"`
	PreviousCheckpointHash       string    `json:"previous_checkpoint_hash,omitempty"`
	Nonce                        string    `json:"nonce"`
	AttestedTime                 time.Time `json:"attested_time"`
	ExpiresAt                    time.Time `json:"expires_at"`
	Signature                    string    `json:"signature,omitempty"`
}

type VerifierProfile struct {
	ProfileID           string            `json:"profile_id"`
	Platform            string            `json:"platform"`
	RootSetHash         string            `json:"root_set_hash"`
	VerifierKeyID       string            `json:"verifier_key_id"`
	AppraisalPolicyHash string            `json:"appraisal_policy_hash"`
	RequiredPCRs        map[string]string `json:"required_pcrs,omitempty"`
	MeasurementHash     string            `json:"measurement_hash,omitempty"`
	AllowSynthetic      bool              `json:"allow_synthetic"`
	ExpiresAt           time.Time         `json:"expires_at"`
}

type AttestationResultEnvelope struct {
	EnvelopeID      string    `json:"envelope_id"`
	ProfileID       string    `json:"profile_id"`
	Subject         string    `json:"subject"`
	Platform        string    `json:"platform"`
	MeasurementHash string    `json:"measurement_hash"`
	Nonce           string    `json:"nonce"`
	TrustTier       string    `json:"trust_tier"`
	PolicyHash      string    `json:"policy_hash"`
	Synthetic       bool      `json:"synthetic"`
	IssuedAt        time.Time `json:"issued_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	Signature       string    `json:"signature"`
}

type EmergencyCapsule struct {
	CapsuleID              string                     `json:"capsule_id"`
	Version                uint64                     `json:"version"`
	ApertureID             string                     `json:"aperture_id"`
	HazardCode             SafeDepHazardCode          `json:"hazard_code"`
	State                  SafeDepState               `json:"state"`
	OrgGenomeHash          string                     `json:"org_genome_hash"`
	PolicyEpoch            uint64                     `json:"policy_epoch"`
	PolicyHash             string                     `json:"policy_hash"`
	P0CeilingsHash         string                     `json:"p0_ceilings_hash"`
	P1BundleHash           string                     `json:"p1_bundle_hash"`
	CPIHash                string                     `json:"cpi_hash"`
	ProviderRegistryHash   string                     `json:"provider_registry_hash"`
	CredentialRegistryHash string                     `json:"credential_registry_hash"`
	VerifierProfileHash    string                     `json:"verifier_profile_hash"`
	PredecessorHash        string                     `json:"predecessor_hash"`
	SubsetProofHash        string                     `json:"subset_proof_hash"`
	SubsetProofKind        string                     `json:"subset_proof_kind"`
	AllowedActions         []string                   `json:"allowed_actions,omitempty"`
	AllowedConnectors      []string                   `json:"allowed_connectors,omitempty"`
	TTLSeconds             int64                      `json:"ttl_seconds"`
	NotBefore              time.Time                  `json:"not_before"`
	ExpiresAt              time.Time                  `json:"expires_at"`
	Signatures             []ThresholdSignature       `json:"signatures,omitempty"`
	Ceremony               HardwareCeremonyTranscript `json:"ceremony"`
	Delegation             EmergencyDelegationChain   `json:"delegation"`
	Attestation            AttestationResultEnvelope  `json:"attestation"`
	Transparency           TransparencyAnchor         `json:"transparency,omitempty"`
}

type ThresholdSignature struct {
	SignerID       string `json:"signer_id"`
	Role           string `json:"role"`
	DeviceID       string `json:"device_id"`
	KeyID          string `json:"key_id"`
	PublicKey      string `json:"public_key,omitempty"`
	Scheme         string `json:"scheme,omitempty"`
	Signature      string `json:"signature"`
	RevokedAtEpoch uint64 `json:"revoked_at_epoch,omitempty"`
}

type HardwareCeremonyTranscript struct {
	CeremonyID          string             `json:"ceremony_id"`
	RequiredQuorum      int                `json:"required_quorum"`
	EnrolledSignerCount int                `json:"enrolled_signer_count"`
	Approvals           []HardwareApproval `json:"approvals"`
	StartedAt           time.Time          `json:"started_at"`
	ExpiresAt           time.Time          `json:"expires_at"`
	VetoUntil           time.Time          `json:"veto_until,omitempty"`
	TranscriptHash      string             `json:"transcript_hash"`
}

type HardwareApproval struct {
	SignerID            string    `json:"signer_id"`
	Role                string    `json:"role"`
	DeviceID            string    `json:"device_id"`
	AuthenticatorAAGUID string    `json:"authenticator_aaguid,omitempty"`
	AssertionHash       string    `json:"assertion_hash"`
	AssertionSignature  string    `json:"assertion_signature,omitempty"`
	SignedAt            time.Time `json:"signed_at"`
	RevokedAtEpoch      uint64    `json:"revoked_at_epoch,omitempty"`
}

type EmergencyDelegationChain struct {
	SessionID            string                   `json:"session_id"`
	HumanSubjectID       string                   `json:"human_subject_id"`
	AuthorizedResources  []string                 `json:"authorized_resources,omitempty"`
	Scope                []string                 `json:"scope,omitempty"`
	MaxHops              int                      `json:"max_hops"`
	NotBefore            time.Time                `json:"not_before"`
	ExpiresAt            time.Time                `json:"expires_at"`
	Hops                 []EmergencyDelegationHop `json:"hops,omitempty"`
	CompletionReceiptRef string                   `json:"completion_receipt_ref,omitempty"`
}

type EmergencyDelegationHop struct {
	IssuerID  string    `json:"issuer_id"`
	SubjectID string    `json:"subject_id"`
	ScopeHash string    `json:"scope_hash"`
	SignedAt  time.Time `json:"signed_at"`
	Signature string    `json:"signature"`
}

type TransparencyAnchor struct {
	Backend            string    `json:"backend,omitempty"`
	LogID              string    `json:"log_id,omitempty"`
	InclusionProofHash string    `json:"inclusion_proof_hash,omitempty"`
	CheckpointHash     string    `json:"checkpoint_hash,omitempty"`
	Deferred           bool      `json:"deferred,omitempty"`
	DeferredUntil      time.Time `json:"deferred_until,omitempty"`
}

type ActivationReceipt struct {
	ActivationID        string                    `json:"activation_id"`
	CapsuleID           string                    `json:"capsule_id"`
	ApertureID          string                    `json:"aperture_id"`
	State               SafeDepState              `json:"state"`
	HazardCode          SafeDepHazardCode         `json:"hazard_code"`
	ContinuityHash      string                    `json:"continuity_hash"`
	CeremonyHash        string                    `json:"ceremony_hash"`
	DelegationSessionID string                    `json:"delegation_session_id"`
	PolicyEpoch         uint64                    `json:"policy_epoch"`
	ActivatedAt         time.Time                 `json:"activated_at"`
	ExpiresAt           time.Time                 `json:"expires_at"`
	ReasonCode          ReasonCode                `json:"reason_code"`
	ProofGraphRef       string                    `json:"proof_graph_ref,omitempty"`
	EvidencePackRef     string                    `json:"evidence_pack_ref,omitempty"`
	Transparency        TransparencyAnchor        `json:"transparency,omitempty"`
	Attestation         AttestationResultEnvelope `json:"attestation"`
	Signature           string                    `json:"signature,omitempty"`
}

type DevFallbackPosture struct {
	AuditMode              bool `json:"audit_mode"`
	MockAttester           bool `json:"mock_attester"`
	SyntheticNitro         bool `json:"synthetic_nitro"`
	SoftwareHSM            bool `json:"software_hsm"`
	DevBearerAuth          bool `json:"dev_bearer_auth"`
	EnvCredentialFallback  bool `json:"env_credential_fallback"`
	UnsignedMutableOverlay bool `json:"unsigned_mutable_overlay"`
}
