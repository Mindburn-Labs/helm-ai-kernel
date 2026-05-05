package contracts

import (
	"fmt"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
)

// SandboxGrant binds the authority HELM gave a sandbox before execution.
// Hosted sandboxes are executors only; this record remains the HELM-native
// policy authority that offline verifiers can inspect.
type SandboxGrant struct {
	GrantID            string              `json:"grant_id"`
	Runtime            string              `json:"runtime"`
	RuntimeVersion     string              `json:"runtime_version,omitempty"`
	Profile            string              `json:"profile"`
	ImageDigest        string              `json:"image_digest,omitempty"`
	TemplateDigest     string              `json:"template_digest,omitempty"`
	FilesystemPreopens []FilesystemPreopen `json:"filesystem_preopens,omitempty"`
	Env                EnvExposurePolicy   `json:"env"`
	Network            NetworkGrant        `json:"network"`
	Limits             SandboxGrantLimits  `json:"limits,omitempty"`
	DeclaredAt         time.Time           `json:"declared_at"`
	PolicyEpoch        string              `json:"policy_epoch,omitempty"`
	GrantHash          string              `json:"grant_hash,omitempty"`
}

type FilesystemPreopen struct {
	Path        string `json:"path"`
	Mode        string `json:"mode"` // ro or rw
	ContentHash string `json:"content_hash,omitempty"`
}

type EnvExposurePolicy struct {
	Mode      string   `json:"mode"` // deny-all, allowlist, redacted
	Names     []string `json:"names,omitempty"`
	NamesHash string   `json:"names_hash,omitempty"`
	Redacted  bool     `json:"redacted,omitempty"`
}

type NetworkGrant struct {
	Mode         string   `json:"mode"` // deny-all, allowlist
	Destinations []string `json:"destinations,omitempty"`
	CIDRs        []string `json:"cidrs,omitempty"`
}

type SandboxGrantLimits struct {
	MemoryBytes int64         `json:"memory_bytes,omitempty"`
	CPUTime     time.Duration `json:"cpu_time,omitempty"`
	OutputBytes int64         `json:"output_bytes,omitempty"`
	OpenFiles   int           `json:"open_files,omitempty"`
}

// AuthzSnapshot binds a relationship-graph authorization decision to the
// relationship model and tuple snapshot observed by the PDP.
type AuthzSnapshot struct {
	SnapshotID       string    `json:"snapshot_id"`
	Resolver         string    `json:"resolver"`
	ModelID          string    `json:"model_id"`
	RelationshipHash string    `json:"relationship_hash"`
	SnapshotToken    string    `json:"snapshot_token,omitempty"`
	Subject          string    `json:"subject"`
	Object           string    `json:"object"`
	Relation         string    `json:"relation"`
	Decision         bool      `json:"decision"`
	Stale            bool      `json:"stale,omitempty"`
	ModelMismatch    bool      `json:"model_mismatch,omitempty"`
	CheckedAt        time.Time `json:"checked_at"`
	SnapshotHash     string    `json:"snapshot_hash,omitempty"`
}

// MCPAuthorizationProfile records the protected-resource and scope contract
// enforced for an MCP server or wrapped upstream.
type MCPAuthorizationProfile struct {
	ProfileID            string   `json:"profile_id"`
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers,omitempty"`
	ScopesSupported      []string `json:"scopes_supported,omitempty"`
	RequiredScopes       []string `json:"required_scopes,omitempty"`
	ProtocolVersions     []string `json:"protocol_versions,omitempty"`
	ToolScopeHash        string   `json:"tool_scope_hash,omitempty"`
	ProfileHash          string   `json:"profile_hash,omitempty"`
}

// ExecutionBoundaryRecord is the compact receipt-boundary preimage that links
// policy, MCP auth, sandbox grants, relationship snapshots, and allow/deny
// decisions before an actuator can dispatch.
type ExecutionBoundaryRecord struct {
	RecordID           string     `json:"record_id"`
	Verdict            Verdict    `json:"verdict"`
	ReasonCode         ReasonCode `json:"reason_code,omitempty"`
	ToolName           string     `json:"tool_name,omitempty"`
	ArgsHash           string     `json:"args_hash,omitempty"`
	PolicyEpoch        string     `json:"policy_epoch"`
	MCPServerID        string     `json:"mcp_server_id,omitempty"`
	OAuthResource      string     `json:"oauth_resource,omitempty"`
	OAuthScopes        []string   `json:"oauth_scopes,omitempty"`
	SandboxGrantHash   string     `json:"sandbox_grant_hash,omitempty"`
	AuthzSnapshotHash  string     `json:"authz_snapshot_hash,omitempty"`
	ReceiptID          string     `json:"receipt_id,omitempty"`
	ApprovalReceiptID  string     `json:"approval_receipt_id,omitempty"`
	DirectDispatchSeen bool       `json:"direct_dispatch_seen,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	RecordHash         string     `json:"record_hash,omitempty"`
}

// EvidenceEnvelopeManifest records a non-authoritative export wrapper over a
// HELM-native EvidencePack root.
type EvidenceEnvelopeManifest struct {
	ManifestID         string    `json:"manifest_id"`
	Envelope           string    `json:"envelope"`
	NativeEvidenceHash string    `json:"native_evidence_hash"`
	NativeAuthority    bool      `json:"native_authority"`
	Subject            string    `json:"subject,omitempty"`
	StatementHash      string    `json:"statement_hash,omitempty"`
	PayloadType        string    `json:"payload_type,omitempty"`
	PayloadHash        string    `json:"payload_hash,omitempty"`
	Experimental       bool      `json:"experimental,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
	ManifestHash       string    `json:"manifest_hash,omitempty"`
}

func (g SandboxGrant) Validate() error {
	if g.GrantID == "" {
		return fmt.Errorf("sandbox grant id is required")
	}
	if g.Runtime == "" {
		return fmt.Errorf("sandbox runtime is required")
	}
	if g.Profile == "" {
		return fmt.Errorf("sandbox profile is required")
	}
	if g.DeclaredAt.IsZero() {
		return fmt.Errorf("sandbox declared_at is required")
	}
	for _, preopen := range g.FilesystemPreopens {
		if preopen.Path == "" {
			return fmt.Errorf("filesystem preopen path is required")
		}
		if preopen.Mode != "ro" && preopen.Mode != "rw" {
			return fmt.Errorf("filesystem preopen %q has invalid mode %q", preopen.Path, preopen.Mode)
		}
	}
	switch g.Env.Mode {
	case "deny-all":
	case "allowlist":
		if len(g.Env.Names) == 0 && g.Env.NamesHash == "" {
			return fmt.Errorf("env allowlist requires names or names_hash")
		}
	case "redacted":
		if !g.Env.Redacted {
			return fmt.Errorf("redacted env mode requires redacted=true")
		}
	default:
		return fmt.Errorf("invalid env mode %q", g.Env.Mode)
	}
	switch g.Network.Mode {
	case "deny-all":
	case "allowlist":
		if len(g.Network.Destinations) == 0 && len(g.Network.CIDRs) == 0 {
			return fmt.Errorf("network allowlist requires destinations or cidrs")
		}
	default:
		return fmt.Errorf("invalid network mode %q", g.Network.Mode)
	}
	return nil
}

func (g SandboxGrant) Seal() (SandboxGrant, error) {
	if err := g.Validate(); err != nil {
		return SandboxGrant{}, err
	}
	g.GrantHash = ""
	hash, err := hashJCS(g)
	if err != nil {
		return SandboxGrant{}, err
	}
	g.GrantHash = hash
	return g, nil
}

func (s AuthzSnapshot) Validate() error {
	if s.SnapshotID == "" {
		return fmt.Errorf("authz snapshot id is required")
	}
	if s.Resolver == "" {
		return fmt.Errorf("authz resolver is required")
	}
	if s.ModelID == "" {
		return fmt.Errorf("authz model id is required")
	}
	if s.RelationshipHash == "" {
		return fmt.Errorf("relationship hash is required")
	}
	if s.Subject == "" || s.Object == "" || s.Relation == "" {
		return fmt.Errorf("subject, object, and relation are required")
	}
	if s.CheckedAt.IsZero() {
		return fmt.Errorf("authz checked_at is required")
	}
	return nil
}

func (s AuthzSnapshot) Seal() (AuthzSnapshot, error) {
	if err := s.Validate(); err != nil {
		return AuthzSnapshot{}, err
	}
	s.SnapshotHash = ""
	hash, err := hashJCS(s)
	if err != nil {
		return AuthzSnapshot{}, err
	}
	s.SnapshotHash = hash
	return s, nil
}

func (p MCPAuthorizationProfile) Validate() error {
	if p.ProfileID == "" {
		return fmt.Errorf("mcp authorization profile id is required")
	}
	if p.Resource == "" {
		return fmt.Errorf("mcp protected resource is required")
	}
	if len(p.RequiredScopes) > 0 && len(p.ScopesSupported) == 0 {
		return fmt.Errorf("required scopes cannot be advertised without supported scopes")
	}
	return nil
}

func (p MCPAuthorizationProfile) Seal() (MCPAuthorizationProfile, error) {
	if err := p.Validate(); err != nil {
		return MCPAuthorizationProfile{}, err
	}
	p.ProfileHash = ""
	hash, err := hashJCS(p)
	if err != nil {
		return MCPAuthorizationProfile{}, err
	}
	p.ProfileHash = hash
	return p, nil
}

func (r ExecutionBoundaryRecord) Validate() error {
	if r.RecordID == "" {
		return fmt.Errorf("execution boundary record id is required")
	}
	if !IsCanonicalVerdict(string(r.Verdict)) {
		return fmt.Errorf("invalid verdict %q", r.Verdict)
	}
	if r.PolicyEpoch == "" {
		return fmt.Errorf("policy epoch is required")
	}
	if r.CreatedAt.IsZero() {
		return fmt.Errorf("created_at is required")
	}
	if r.Verdict != VerdictAllow && r.ReasonCode == "" {
		return fmt.Errorf("deny or escalate boundary records require a reason code")
	}
	if r.ReasonCode != "" && !IsCanonicalReasonCode(string(r.ReasonCode)) {
		return fmt.Errorf("invalid reason code %q", r.ReasonCode)
	}
	return nil
}

func (r ExecutionBoundaryRecord) Seal() (ExecutionBoundaryRecord, error) {
	if err := r.Validate(); err != nil {
		return ExecutionBoundaryRecord{}, err
	}
	r.RecordHash = ""
	hash, err := hashJCS(r)
	if err != nil {
		return ExecutionBoundaryRecord{}, err
	}
	r.RecordHash = hash
	return r, nil
}

func (m EvidenceEnvelopeManifest) Validate() error {
	if m.ManifestID == "" {
		return fmt.Errorf("envelope manifest id is required")
	}
	if m.Envelope == "" {
		return fmt.Errorf("envelope type is required")
	}
	if m.NativeEvidenceHash == "" {
		return fmt.Errorf("native evidence hash is required")
	}
	if !m.NativeAuthority {
		return fmt.Errorf("native EvidencePack authority must remain true")
	}
	if m.CreatedAt.IsZero() {
		return fmt.Errorf("created_at is required")
	}
	switch strings.ToLower(m.Envelope) {
	case "dsse", "jws", "in-toto", "slsa", "sigstore", "scitt", "cose":
	default:
		return fmt.Errorf("unsupported envelope type %q", m.Envelope)
	}
	return nil
}

func (m EvidenceEnvelopeManifest) Seal() (EvidenceEnvelopeManifest, error) {
	if err := m.Validate(); err != nil {
		return EvidenceEnvelopeManifest{}, err
	}
	m.ManifestHash = ""
	hash, err := hashJCS(m)
	if err != nil {
		return EvidenceEnvelopeManifest{}, err
	}
	m.ManifestHash = hash
	return m, nil
}

func hashJCS(v any) (string, error) {
	hash, err := canonicalize.CanonicalHash(v)
	if err != nil {
		return "", err
	}
	return "sha256:" + hash, nil
}
