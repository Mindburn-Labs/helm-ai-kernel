package contracts

import "time"

// Receipt represents a proof of effect execution, linked to a decision.
type Receipt struct {
	ReceiptID           string         `json:"receipt_id"`
	DecisionID          string         `json:"decision_id"`
	EffectID            string         `json:"effect_id"`
	ExternalReferenceID string         `json:"external_reference_id"`
	Status              string         `json:"status"`
	BlobHash            string         `json:"blob_hash,omitempty"`   // Link to Input Snapshot CAS
	OutputHash          string         `json:"output_hash,omitempty"` // Link to Tool Output CAS
	Timestamp           time.Time      `json:"timestamp"`
	ExecutorID          string         `json:"executor_id,omitempty"`
	Metadata            map[string]any `json:"metadata,omitempty"`
	Signature           string         `json:"signature,omitempty"` // Cryptographic proof of execution
	// V2: Tamper-Evidence
	MerkleRoot        string             `json:"merkle_root,omitempty"`
	WitnessSignatures []WitnessSignature `json:"witness_signatures,omitempty"`

	// V3: Causal chain – ProofGraph DAG
	PrevHash     string `json:"prev_hash"`           // SHA-256 of the previous canonical signed receipt envelope
	LamportClock uint64 `json:"lamport_clock"`       // Monotonic logical clock per session
	ArgsHash     string `json:"args_hash,omitempty"` // SHA-256 of JCS-canonicalized tool args bound at the PEP boundary

	// Receipt-as-First-Class Artifact Extensions
	ReplayScript     *ReplayScriptRef   `json:"replay_script,omitempty"`     // Link to deterministic replay script
	Provenance       *ReceiptProvenance `json:"provenance,omitempty"`        // Chain of custody
	BundledArtifacts []ParsedArtifact   `json:"bundled_artifacts,omitempty"` // Hashable bundles of related artifacts

	// V4: Inference Telemetry (Local Inference Gateway)
	GatewayID      string `json:"gateway_id,omitempty"`      // Node identity of the serving LIG
	RuntimeType    string `json:"runtime_type,omitempty"`    // e.g. "ollama", "vllm"
	RuntimeVersion string `json:"runtime_version,omitempty"` // Exact semver of the inference engine
	ModelHash      string `json:"model_hash,omitempty"`      // SHA-256 snapshot of the loaded weights

	// V5: Execution Plane — sandbox and evidence enrichment
	NetworkLogRef     string              `json:"network_log_ref,omitempty"`      // Reference to network activity log
	SecretEventsRef   string              `json:"secret_events_ref,omitempty"`    // Reference to secret access audit log
	PortExposures     []PortExposureEvent `json:"port_exposures,omitempty"`       // Port exposure events during execution
	SandboxLeaseID    string              `json:"sandbox_lease_id,omitempty"`     // Execution lease that governed this receipt
	EffectGraphNodeID string              `json:"effect_graph_node_id,omitempty"` // Which DAG node produced this receipt

	// Unified Sub-package Compatibility Fields
	Type             string            `json:"type,omitempty"`
	LaunchID         string            `json:"launch_id,omitempty"`
	DecisionHash     string            `json:"decision_hash,omitempty"`
	Verdict          string            `json:"verdict,omitempty"`
	Subject          any               `json:"subject,omitempty"`
	CreatedAt        time.Time         `json:"created_at,omitempty"`
	Hash             string            `json:"hash,omitempty"`
	PackID           string            `json:"pack_id,omitempty"`
	PackName         string            `json:"pack_name,omitempty"`
	PackVersion      string            `json:"pack_version,omitempty"`
	PackHash         string            `json:"pack_hash,omitempty"`
	Action           string            `json:"action,omitempty"`
	InstalledBy      string            `json:"installed_by,omitempty"`
	InstalledAt      time.Time         `json:"installed_at,omitempty"`
	PrevReceiptID    string            `json:"prev_receipt_id,omitempty"`
	ContentHash      string            `json:"content_hash,omitempty"`
	ID               string            `json:"id,omitempty"`
	RiskTier         RiskTier          `json:"risk_tier,omitempty"`
	EffectType       string            `json:"effect_type,omitempty"`
	ToolFingerprint  string            `json:"tool_fingerprint,omitempty"`
	Evidence         map[string]string `json:"evidence,omitempty"`
	RetryCount       int               `json:"retry_count,omitempty"`
	IdempotencyKey   string            `json:"idempotency_key,omitempty"`
	ToolName         string            `json:"tool_name,omitempty"`
	ReasonCode       string            `json:"reason_code,omitempty"`
	SkillID          string            `json:"skill_id,omitempty"`
	SkillContentHash string            `json:"skill_content_hash,omitempty"`
	PolicyHash       string            `json:"policy_hash,omitempty"`
	ProjectionPaths  []Projection      `json:"projection_paths,omitempty"`
	Direction        string            `json:"direction,omitempty"`
	Counterparty     string            `json:"counterparty,omitempty"`
	SessionID        string            `json:"session_id,omitempty"`
	ScopeHash        string            `json:"scope_hash,omitempty"`
	IssuedAt         time.Time         `json:"issued_at,omitempty"`

	// Safe Deprecation Mode emergency authority bindings.
	EmergencyActivationID        string `json:"emergency_activation_id,omitempty"`
	EmergencyDelegationSessionID string `json:"emergency_delegation_session_id,omitempty"`
	EmergencyScopeHash           string `json:"emergency_scope_hash,omitempty"`
	SafeDepState                 string `json:"safe_dep_state,omitempty"`
	SafeDepReasonCode            string `json:"safe_dep_reason_code,omitempty"`
}

type Projection struct {
	Agent string `json:"agent"`
	Path  string `json:"path"`
}

// PortExposureEvent records a port being exposed or accessed during sandbox execution.
type PortExposureEvent struct {
	Port         int       `json:"port"`
	Protocol     string    `json:"protocol"`                // "tcp", "udp"
	Direction    string    `json:"direction"`               // "inbound", "outbound"
	AllowedPeers []string  `json:"allowed_peers,omitempty"` // Permitted peer addresses
	StartedAt    time.Time `json:"started_at"`
	ClosedAt     time.Time `json:"closed_at,omitempty"`
}

// ReplayScriptRef points to the script that can reproduce this receipt's effect.
type ReplayScriptRef struct {
	ScriptID   string `json:"script_id"`
	ScriptHash string `json:"script_hash"`
	Engine     string `json:"engine"` // e.g., "governance-v1", "frontier-adapter-v1"
	Entrypoint string `json:"entrypoint"`
}

// ReceiptProvenance tracks the origin and chain of custody for the receipt.
type ReceiptProvenance struct {
	GeneratedBy string    `json:"generated_by"` // Agent/Component ID
	GeneratedAt time.Time `json:"generated_at"`
	Context     string    `json:"context"`           // e.g., "production", "simulation"
	Parents     []string  `json:"parents,omitempty"` // Parent Receipt IDs used as input
}

// ParsedArtifact represents a hashable bundle of data produced or used.
type ParsedArtifact struct {
	ArtifactID   string `json:"artifact_id"`
	Type         string `json:"type"` // e.g., "file", "db_record", "api_response"
	Hash         string `json:"hash"`
	URIRef       string `json:"uri_ref,omitempty"`       // Where to find it
	Inlinedigest string `json:"inline_digest,omitempty"` // Small data can be inlined
}

type WitnessSignature struct {
	WitnessID string `json:"witness_id"`
	Signature string `json:"signature"`
}
