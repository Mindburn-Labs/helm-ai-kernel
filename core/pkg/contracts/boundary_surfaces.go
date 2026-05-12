package contracts

import (
	"fmt"
	"strings"
	"time"
)

// BoundaryStatus is the public health summary for the proof-bearing execution
// boundary. It is intentionally mechanism-focused and vendor-neutral.
type BoundaryStatus struct {
	Status              string            `json:"status"`
	Mode                string            `json:"mode"`
	Version             string            `json:"version,omitempty"`
	ReceiptSigner       string            `json:"receipt_signer"`
	ReceiptStore        string            `json:"receipt_store"`
	PDP                 string            `json:"pdp"`
	MCPFirewall         string            `json:"mcp_firewall"`
	Sandbox             string            `json:"sandbox"`
	Authz               string            `json:"authz"`
	EvidenceVerifier    string            `json:"evidence_verifier"`
	CheckpointLog       string            `json:"checkpoint_log"`
	LastCheckpointHash  string            `json:"last_checkpoint_hash,omitempty"`
	OpenApprovalCount   int               `json:"open_approval_count"`
	QuarantinedMCPCount int               `json:"quarantined_mcp_count"`
	UpdatedAt           time.Time         `json:"updated_at"`
	Components          map[string]string `json:"components,omitempty"`
}

// BoundaryCapabilitySummary describes what the OSS boundary can enforce and
// what remains a non-authoritative export or integration surface.
type BoundaryCapabilitySummary struct {
	CapabilityID     string   `json:"capability_id"`
	Category         string   `json:"category"`
	Status           string   `json:"status"`
	Authority        string   `json:"authority"`
	PublicRoutes     []string `json:"public_routes,omitempty"`
	CLICommands      []string `json:"cli_commands,omitempty"`
	ReceiptBindings  []string `json:"receipt_bindings,omitempty"`
	ConformanceLevel string   `json:"conformance_level,omitempty"`
	Notes            string   `json:"notes,omitempty"`
}

type BoundarySearchRequest struct {
	Verdict       string `json:"verdict,omitempty"`
	ReasonCode    string `json:"reason_code,omitempty"`
	ToolName      string `json:"tool_name,omitempty"`
	MCPServerID   string `json:"mcp_server_id,omitempty"`
	PolicyEpoch   string `json:"policy_epoch,omitempty"`
	ReceiptID     string `json:"receipt_id,omitempty"`
	Limit         int    `json:"limit,omitempty"`
	IncludeDenied bool   `json:"include_denied,omitempty"`
}

type BoundaryRecordVerification struct {
	RecordID       string            `json:"record_id"`
	Verdict        string            `json:"verdict"`
	RecordHash     string            `json:"record_hash,omitempty"`
	ReceiptID      string            `json:"receipt_id,omitempty"`
	Verified       bool              `json:"verified"`
	Offline        bool              `json:"offline"`
	Checks         map[string]string `json:"checks"`
	Errors         []string          `json:"errors,omitempty"`
	VerifiedAt     time.Time         `json:"verified_at"`
	CheckpointHash string            `json:"checkpoint_hash,omitempty"`
	InclusionProof []string          `json:"inclusion_proof,omitempty"`
}

// BoundaryCheckpoint is a tamper-evident checkpoint over record and receipt
// roots. It lets offline verifiers detect omission, reordering, or tampering.
type BoundaryCheckpoint struct {
	CheckpointID      string    `json:"checkpoint_id"`
	Sequence          int64     `json:"sequence"`
	RecordCount       int       `json:"record_count"`
	ReceiptCount      int       `json:"receipt_count"`
	RecordRootHash    string    `json:"record_root_hash"`
	ReceiptRootHash   string    `json:"receipt_root_hash"`
	PreviousHash      string    `json:"previous_hash,omitempty"`
	RecordHashes      []string  `json:"record_hashes,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	CheckpointHash    string    `json:"checkpoint_hash,omitempty"`
	InclusionProofURI string    `json:"inclusion_proof_uri,omitempty"`
}

func (c BoundaryCheckpoint) Validate() error {
	if c.CheckpointID == "" {
		return fmt.Errorf("checkpoint id is required")
	}
	if c.Sequence < 0 {
		return fmt.Errorf("checkpoint sequence cannot be negative")
	}
	if c.RecordRootHash == "" || c.ReceiptRootHash == "" {
		return fmt.Errorf("record and receipt roots are required")
	}
	if c.CreatedAt.IsZero() {
		return fmt.Errorf("created_at is required")
	}
	return nil
}

func (c BoundaryCheckpoint) Seal() (BoundaryCheckpoint, error) {
	if err := c.Validate(); err != nil {
		return BoundaryCheckpoint{}, err
	}
	c.CheckpointHash = ""
	hash, err := hashJCS(c)
	if err != nil {
		return BoundaryCheckpoint{}, err
	}
	c.CheckpointHash = hash
	return c, nil
}

type ApprovalCeremonyState string

const (
	ApprovalCeremonyPending ApprovalCeremonyState = "pending"
	ApprovalCeremonyAllowed ApprovalCeremonyState = "approved"
	ApprovalCeremonyDenied  ApprovalCeremonyState = "denied"
	ApprovalCeremonyRevoked ApprovalCeremonyState = "revoked"
	ApprovalCeremonyExpired ApprovalCeremonyState = "expired"
)

type ApprovalCeremony struct {
	ApprovalID       string                `json:"approval_id"`
	Subject          string                `json:"subject"`
	Action           string                `json:"action"`
	State            ApprovalCeremonyState `json:"state"`
	RequestedBy      string                `json:"requested_by"`
	Approvers        []string              `json:"approvers,omitempty"`
	Quorum           int                   `json:"quorum,omitempty"`
	TimelockUntil    time.Time             `json:"timelock_until,omitempty"`
	ExpiresAt        time.Time             `json:"expires_at,omitempty"`
	BreakGlass       bool                  `json:"break_glass,omitempty"`
	AuthMethod       string                `json:"auth_method,omitempty"`
	ChallengeID      string                `json:"challenge_id,omitempty"`
	ChallengeHash    string                `json:"challenge_hash,omitempty"`
	AssertionHash    string                `json:"assertion_hash,omitempty"`
	Reason           string                `json:"reason,omitempty"`
	ReceiptID        string                `json:"receipt_id,omitempty"`
	BoundaryRecordID string                `json:"boundary_record_id,omitempty"`
	CreatedAt        time.Time             `json:"created_at"`
	UpdatedAt        time.Time             `json:"updated_at"`
	CeremonyHash     string                `json:"ceremony_hash,omitempty"`
}

func (a ApprovalCeremony) Validate() error {
	if a.ApprovalID == "" {
		return fmt.Errorf("approval id is required")
	}
	if a.Subject == "" || a.Action == "" {
		return fmt.Errorf("approval subject and action are required")
	}
	if a.State == "" {
		return fmt.Errorf("approval state is required")
	}
	if a.RequestedBy == "" {
		return fmt.Errorf("requested_by is required")
	}
	if a.CreatedAt.IsZero() || a.UpdatedAt.IsZero() {
		return fmt.Errorf("approval timestamps are required")
	}
	return nil
}

func (a ApprovalCeremony) Seal() (ApprovalCeremony, error) {
	if err := a.Validate(); err != nil {
		return ApprovalCeremony{}, err
	}
	a.CeremonyHash = ""
	hash, err := hashJCS(a)
	if err != nil {
		return ApprovalCeremony{}, err
	}
	a.CeremonyHash = hash
	return a, nil
}

type ApprovalWebAuthnChallenge struct {
	ChallengeID   string    `json:"challenge_id"`
	ApprovalID    string    `json:"approval_id"`
	Method        string    `json:"method"`
	Challenge     string    `json:"challenge,omitempty"`
	ChallengeHash string    `json:"challenge_hash"`
	ExpiresAt     time.Time `json:"expires_at"`
	CreatedAt     time.Time `json:"created_at"`
	Verified      bool      `json:"verified"`
	AssertionHash string    `json:"assertion_hash,omitempty"`
}

type ApprovalWebAuthnAssertion struct {
	ChallengeID string `json:"challenge_id"`
	Actor       string `json:"actor"`
	Assertion   string `json:"assertion"`
	ReceiptID   string `json:"receipt_id,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

type AgentIdentityProfile struct {
	AgentID      string    `json:"agent_id"`
	DisplayName  string    `json:"display_name,omitempty"`
	IdentityType string    `json:"identity_type"`
	Issuer       string    `json:"issuer,omitempty"`
	Subject      string    `json:"subject,omitempty"`
	Audience     []string  `json:"audience,omitempty"`
	SPIFFEID     string    `json:"spiffe_id,omitempty"`
	KeyID        string    `json:"key_id,omitempty"`
	AnonymousDev bool      `json:"anonymous_dev,omitempty"`
	LastVerified time.Time `json:"last_verified,omitempty"`
	IdentityHash string    `json:"identity_hash,omitempty"`
}

type BudgetCeiling struct {
	BudgetID              string    `json:"budget_id"`
	Subject               string    `json:"subject"`
	ToolCallLimit         int       `json:"tool_call_limit,omitempty"`
	SpendLimitCents       int64     `json:"spend_limit_cents,omitempty"`
	EgressLimitBytes      int64     `json:"egress_limit_bytes,omitempty"`
	WriteOperationLimit   int       `json:"write_operation_limit,omitempty"`
	ApprovalRequiredAbove int64     `json:"approval_required_above_cents,omitempty"`
	Window                string    `json:"window"`
	PolicyEpoch           string    `json:"policy_epoch,omitempty"`
	UpdatedAt             time.Time `json:"updated_at"`
}

type AuthzHealth struct {
	Status           string    `json:"status"`
	Resolver         string    `json:"resolver"`
	ModelID          string    `json:"model_id,omitempty"`
	RelationshipHash string    `json:"relationship_hash,omitempty"`
	Stale            bool      `json:"stale,omitempty"`
	ModelMismatch    bool      `json:"model_mismatch,omitempty"`
	CheckedAt        time.Time `json:"checked_at"`
}

type MCPScanRequest struct {
	ServerID  string   `json:"server_id"`
	Name      string   `json:"name,omitempty"`
	Transport string   `json:"transport,omitempty"`
	Endpoint  string   `json:"endpoint,omitempty"`
	ToolNames []string `json:"tool_names,omitempty"`
}

type MCPScanResult struct {
	ServerID            string    `json:"server_id"`
	Risk                string    `json:"risk"`
	State               string    `json:"state"`
	ToolCount           int       `json:"tool_count"`
	Findings            []string  `json:"findings,omitempty"`
	RecommendedAction   string    `json:"recommended_action"`
	QuarantineRecordID  string    `json:"quarantine_record_id,omitempty"`
	RequiresApproval    bool      `json:"requires_approval"`
	SchemaPinRequired   bool      `json:"schema_pin_required"`
	AuthorizationNeeded bool      `json:"authorization_needed"`
	ScannedAt           time.Time `json:"scanned_at"`
}

type MCPAuthorizeCallRequest struct {
	ServerID         string   `json:"server_id"`
	ToolName         string   `json:"tool_name"`
	ArgsHash         string   `json:"args_hash,omitempty"`
	GrantedScopes    []string `json:"granted_scopes,omitempty"`
	PinnedSchemaHash string   `json:"pinned_schema_hash,omitempty"`
	ToolSchema       any      `json:"tool_schema,omitempty"`
	OutputSchema     any      `json:"output_schema,omitempty"`
	OAuthResource    string   `json:"oauth_resource,omitempty"`
	ReceiptID        string   `json:"receipt_id,omitempty"`
}

type SandboxPreflightRequest struct {
	Runtime           string       `json:"runtime"`
	Profile           string       `json:"profile"`
	ImageDigest       string       `json:"image_digest,omitempty"`
	RequestedGrant    SandboxGrant `json:"requested_grant,omitempty"`
	PolicyEpoch       string       `json:"policy_epoch,omitempty"`
	ExpectedGrantHash string       `json:"expected_grant_hash,omitempty"`
}

type SandboxPreflightResult struct {
	Verdict       Verdict    `json:"verdict"`
	ReasonCode    ReasonCode `json:"reason_code,omitempty"`
	GrantID       string     `json:"grant_id,omitempty"`
	GrantHash     string     `json:"grant_hash,omitempty"`
	DispatchReady bool       `json:"dispatch_ready"`
	Findings      []string   `json:"findings,omitempty"`
	CheckedAt     time.Time  `json:"checked_at"`
}

type EvidenceEnvelopeVerification struct {
	ManifestID   string            `json:"manifest_id"`
	ManifestHash string            `json:"manifest_hash,omitempty"`
	Envelope     string            `json:"envelope"`
	PayloadHash  string            `json:"payload_hash,omitempty"`
	Verified     bool              `json:"verified"`
	NativeRoot   string            `json:"native_root"`
	Checks       map[string]string `json:"checks"`
	Errors       []string          `json:"errors,omitempty"`
	VerifiedAt   time.Time         `json:"verified_at"`
}

type EvidenceEnvelopePayload struct {
	ManifestID    string         `json:"manifest_id"`
	Envelope      string         `json:"envelope"`
	PayloadType   string         `json:"payload_type"`
	Payload       map[string]any `json:"payload"`
	PayloadHash   string         `json:"payload_hash"`
	GeneratedAt   time.Time      `json:"generated_at"`
	Authoritative bool           `json:"authoritative"`
}

type TelemetryOTelConfig struct {
	ServiceName     string            `json:"service_name"`
	SignalType      string            `json:"signal_type"`
	Authoritative   bool              `json:"authoritative"`
	SpanAttributes  map[string]string `json:"span_attributes"`
	ExportedSignals []string          `json:"exported_signals"`
}

type TelemetryExportRequest struct {
	Format     string            `json:"format"`
	ReceiptID  string            `json:"receipt_id,omitempty"`
	RecordHash string            `json:"record_hash,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type TelemetryExportResult struct {
	ExportID      string            `json:"export_id"`
	Format        string            `json:"format"`
	Authoritative bool              `json:"authoritative"`
	Attributes    map[string]string `json:"attributes"`
	ExportedAt    time.Time         `json:"exported_at"`
}

type CoexistenceCapabilityManifest struct {
	ManifestID      string    `json:"manifest_id"`
	Authority       string    `json:"authority"`
	BoundaryRole    string    `json:"boundary_role"`
	SupportedInputs []string  `json:"supported_inputs"`
	ExportSurfaces  []string  `json:"export_surfaces"`
	ReceiptBindings []string  `json:"receipt_bindings"`
	GeneratedAt     time.Time `json:"generated_at"`
}

type FrameworkScaffold struct {
	Framework      string   `json:"framework"`
	Language       string   `json:"language"`
	Files          []string `json:"files"`
	RequiredRoutes []string `json:"required_routes"`
	Mode           string   `json:"mode"`
	Notes          string   `json:"notes,omitempty"`
}

func NormalizeSurfaceLimit(limit int) int {
	if limit <= 0 {
		return 50
	}
	if limit > 1000 {
		return 1000
	}
	return limit
}

func SurfaceID(prefix, value string) string {
	normalized := strings.NewReplacer(":", "-", "/", "-", " ", "-").Replace(strings.ToLower(strings.TrimSpace(value)))
	if normalized == "" {
		normalized = "default"
	}
	return prefix + "-" + normalized
}
