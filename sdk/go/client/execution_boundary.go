package client

import (
	"fmt"
	"net/url"
	"time"
)

type EvidenceEnvelopeExportRequest struct {
	ManifestID         string `json:"manifest_id"`
	Envelope           string `json:"envelope"`
	NativeEvidenceHash string `json:"native_evidence_hash"`
	Subject            string `json:"subject,omitempty"`
	Experimental       bool   `json:"experimental,omitempty"`
}

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

type NegativeBoundaryVector struct {
	ID                 string   `json:"id"`
	Category           string   `json:"category"`
	Trigger            string   `json:"trigger"`
	ExpectedVerdict    string   `json:"expected_verdict"`
	ExpectedReasonCode string   `json:"expected_reason_code"`
	MustEmitReceipt    bool     `json:"must_emit_receipt"`
	MustNotDispatch    bool     `json:"must_not_dispatch"`
	MustBindEvidence   []string `json:"must_bind_evidence,omitempty"`
}

type MCPRegistryDiscoverRequest struct {
	ServerID  string   `json:"server_id"`
	Name      string   `json:"name,omitempty"`
	Transport string   `json:"transport,omitempty"`
	Endpoint  string   `json:"endpoint,omitempty"`
	ToolNames []string `json:"tool_names,omitempty"`
	Risk      string   `json:"risk,omitempty"`
	Reason    string   `json:"reason,omitempty"`
}

type MCPRegistryApprovalRequest struct {
	ServerID          string `json:"server_id"`
	ApproverID        string `json:"approver_id"`
	ApprovalReceiptID string `json:"approval_receipt_id"`
	Reason            string `json:"reason,omitempty"`
}

type MCPQuarantineRecord struct {
	ServerID          string    `json:"server_id"`
	Name              string    `json:"name,omitempty"`
	Transport         string    `json:"transport,omitempty"`
	Endpoint          string    `json:"endpoint,omitempty"`
	ToolNames         []string  `json:"tool_names,omitempty"`
	Risk              string    `json:"risk"`
	State             string    `json:"state"`
	DiscoveredAt      time.Time `json:"discovered_at"`
	ApprovedAt        time.Time `json:"approved_at,omitempty"`
	ApprovedBy        string    `json:"approved_by,omitempty"`
	ApprovalReceiptID string    `json:"approval_receipt_id,omitempty"`
	RevokedAt         time.Time `json:"revoked_at,omitempty"`
	ExpiresAt         time.Time `json:"expires_at,omitempty"`
	Reason            string    `json:"reason,omitempty"`
}

type SandboxBackendProfile struct {
	Name                 string `json:"name"`
	Kind                 string `json:"kind"`
	Runtime              string `json:"runtime"`
	Hosted               bool   `json:"hosted"`
	DenyNetworkByDefault bool   `json:"deny_network_by_default"`
	NativeIsolation      bool   `json:"native_isolation"`
	Experimental         bool   `json:"experimental,omitempty"`
}

type SandboxGrant struct {
	GrantID            string                 `json:"grant_id"`
	Runtime            string                 `json:"runtime"`
	RuntimeVersion     string                 `json:"runtime_version,omitempty"`
	Profile            string                 `json:"profile"`
	ImageDigest        string                 `json:"image_digest,omitempty"`
	TemplateDigest     string                 `json:"template_digest,omitempty"`
	FilesystemPreopens []map[string]any       `json:"filesystem_preopens,omitempty"`
	Env                map[string]any         `json:"env"`
	Network            map[string]any         `json:"network"`
	Limits             map[string]any         `json:"limits,omitempty"`
	DeclaredAt         time.Time              `json:"declared_at"`
	PolicyEpoch        string                 `json:"policy_epoch,omitempty"`
	GrantHash          string                 `json:"grant_hash,omitempty"`
	Metadata           map[string]interface{} `json:"metadata,omitempty"`
}

type SurfaceRecord map[string]any
type BoundaryStatus map[string]any
type BoundaryCapabilitySummary map[string]any
type ExecutionBoundaryRecord map[string]any
type BoundaryRecordVerification map[string]any
type BoundaryCheckpoint map[string]any
type EvidenceEnvelopeVerification map[string]any
type EvidenceEnvelopePayload map[string]any
type MCPAuthorizationProfile map[string]any
type MCPScanRequest map[string]any
type MCPScanResult map[string]any
type MCPAuthorizeCallRequest map[string]any
type SandboxPreflightRequest map[string]any
type SandboxPreflightResult map[string]any
type AuthzSnapshot map[string]any
type ApprovalCeremony map[string]any
type ApprovalWebAuthnChallenge map[string]any
type ApprovalWebAuthnAssertion map[string]any
type BudgetCeiling map[string]any
type AgentIdentityProfile map[string]any
type AuthzHealth map[string]any
type TelemetryOTelConfig map[string]any
type TelemetryExportRequest map[string]any
type TelemetryExportResult map[string]any
type CoexistenceCapabilityManifest map[string]any

func (c *HelmClient) CreateEvidenceEnvelopeManifest(req EvidenceEnvelopeExportRequest) (*EvidenceEnvelopeManifest, error) {
	var out EvidenceEnvelopeManifest
	err := c.do("POST", "/api/v1/evidence/envelopes", req, &out)
	return &out, err
}

func (c *HelmClient) ListEvidenceEnvelopeManifests() ([]EvidenceEnvelopeManifest, error) {
	var out []EvidenceEnvelopeManifest
	err := c.do("GET", "/api/v1/evidence/envelopes", nil, &out)
	return out, err
}

func (c *HelmClient) GetEvidenceEnvelopeManifest(manifestID string) (*EvidenceEnvelopeManifest, error) {
	var out EvidenceEnvelopeManifest
	err := c.do("GET", "/api/v1/evidence/envelopes/"+url.PathEscape(manifestID), nil, &out)
	return &out, err
}

func (c *HelmClient) VerifyEvidenceEnvelopeManifest(manifestID string) (*EvidenceEnvelopeVerification, error) {
	var out EvidenceEnvelopeVerification
	err := c.do("POST", "/api/v1/evidence/envelopes/"+url.PathEscape(manifestID)+"/verify", nil, &out)
	return &out, err
}

func (c *HelmClient) GetEvidenceEnvelopePayload(manifestID string) (*EvidenceEnvelopePayload, error) {
	var out EvidenceEnvelopePayload
	err := c.do("GET", "/api/v1/evidence/envelopes/"+url.PathEscape(manifestID)+"/payload", nil, &out)
	return &out, err
}

func (c *HelmClient) GetBoundaryStatus() (*BoundaryStatus, error) {
	var out BoundaryStatus
	err := c.do("GET", "/api/v1/boundary/status", nil, &out)
	return &out, err
}

func (c *HelmClient) ListBoundaryCapabilities() ([]BoundaryCapabilitySummary, error) {
	var out []BoundaryCapabilitySummary
	err := c.do("GET", "/api/v1/boundary/capabilities", nil, &out)
	return out, err
}

func (c *HelmClient) ListBoundaryRecords(query url.Values) ([]ExecutionBoundaryRecord, error) {
	path := "/api/v1/boundary/records"
	if query != nil && query.Encode() != "" {
		path += "?" + query.Encode()
	}
	var out []ExecutionBoundaryRecord
	err := c.do("GET", path, nil, &out)
	return out, err
}

func (c *HelmClient) GetBoundaryRecord(recordID string) (*ExecutionBoundaryRecord, error) {
	var out ExecutionBoundaryRecord
	err := c.do("GET", "/api/v1/boundary/records/"+url.PathEscape(recordID), nil, &out)
	return &out, err
}

func (c *HelmClient) VerifyBoundaryRecord(recordID string) (*BoundaryRecordVerification, error) {
	var out BoundaryRecordVerification
	err := c.do("POST", "/api/v1/boundary/records/"+url.PathEscape(recordID)+"/verify", nil, &out)
	return &out, err
}

func (c *HelmClient) ListBoundaryCheckpoints() ([]BoundaryCheckpoint, error) {
	var out []BoundaryCheckpoint
	err := c.do("GET", "/api/v1/boundary/checkpoints", nil, &out)
	return out, err
}

func (c *HelmClient) CreateBoundaryCheckpoint() (*BoundaryCheckpoint, error) {
	var out BoundaryCheckpoint
	err := c.do("POST", "/api/v1/boundary/checkpoints", nil, &out)
	return &out, err
}

func (c *HelmClient) VerifyBoundaryCheckpoint(checkpointID string) (*SurfaceRecord, error) {
	var out SurfaceRecord
	err := c.do("POST", "/api/v1/boundary/checkpoints/"+url.PathEscape(checkpointID)+"/verify", nil, &out)
	return &out, err
}

func (c *HelmClient) ListNegativeConformanceVectors() ([]NegativeBoundaryVector, error) {
	var out []NegativeBoundaryVector
	err := c.do("GET", "/api/v1/conformance/negative", nil, &out)
	return out, err
}

func (c *HelmClient) ListConformanceReports() ([]ConformanceResult, error) {
	var out []ConformanceResult
	err := c.do("GET", "/api/v1/conformance/reports", nil, &out)
	return out, err
}

func (c *HelmClient) ListConformanceVectors() ([]NegativeBoundaryVector, error) {
	var out []NegativeBoundaryVector
	err := c.do("GET", "/api/v1/conformance/vectors", nil, &out)
	return out, err
}

func (c *HelmClient) ListMCPRegistry() ([]MCPQuarantineRecord, error) {
	var out []MCPQuarantineRecord
	err := c.do("GET", "/api/v1/mcp/registry", nil, &out)
	return out, err
}

func (c *HelmClient) DiscoverMCPServer(req MCPRegistryDiscoverRequest) (*MCPQuarantineRecord, error) {
	var out MCPQuarantineRecord
	err := c.do("POST", "/api/v1/mcp/registry", req, &out)
	return &out, err
}

func (c *HelmClient) ApproveMCPServer(req MCPRegistryApprovalRequest) (*MCPQuarantineRecord, error) {
	var out MCPQuarantineRecord
	err := c.do("POST", "/api/v1/mcp/registry/approve", req, &out)
	return &out, err
}

func (c *HelmClient) GetMCPRegistryRecord(serverID string) (*MCPQuarantineRecord, error) {
	var out MCPQuarantineRecord
	err := c.do("GET", "/api/v1/mcp/registry/"+url.PathEscape(serverID), nil, &out)
	return &out, err
}

func (c *HelmClient) ApproveMCPRegistryRecord(serverID string, req MCPRegistryApprovalRequest) (*MCPQuarantineRecord, error) {
	var out MCPQuarantineRecord
	err := c.do("POST", "/api/v1/mcp/registry/"+url.PathEscape(serverID)+"/approve", req, &out)
	return &out, err
}

func (c *HelmClient) RevokeMCPRegistryRecord(serverID, reason string) (*MCPQuarantineRecord, error) {
	var out MCPQuarantineRecord
	err := c.do("POST", "/api/v1/mcp/registry/"+url.PathEscape(serverID)+"/revoke", map[string]string{"reason": reason}, &out)
	return &out, err
}

func (c *HelmClient) ScanMCPServer(req MCPScanRequest) (*MCPScanResult, error) {
	var out MCPScanResult
	err := c.do("POST", "/api/v1/mcp/scan", req, &out)
	return &out, err
}

func (c *HelmClient) ListMCPAuthProfiles() ([]MCPAuthorizationProfile, error) {
	var out []MCPAuthorizationProfile
	err := c.do("GET", "/api/v1/mcp/auth-profiles", nil, &out)
	return out, err
}

func (c *HelmClient) PutMCPAuthProfile(profileID string, profile MCPAuthorizationProfile) (*MCPAuthorizationProfile, error) {
	var out MCPAuthorizationProfile
	err := c.do("PUT", "/api/v1/mcp/auth-profiles/"+url.PathEscape(profileID), profile, &out)
	return &out, err
}

func (c *HelmClient) AuthorizeMCPCall(req MCPAuthorizeCallRequest) (*ExecutionBoundaryRecord, error) {
	var out ExecutionBoundaryRecord
	err := c.do("POST", "/api/v1/mcp/authorize-call", req, &out)
	return &out, err
}

func (c *HelmClient) ListSandboxBackendProfiles() ([]SandboxBackendProfile, error) {
	var out []SandboxBackendProfile
	err := c.do("GET", "/api/v1/sandbox/grants/inspect", nil, &out)
	return out, err
}

func (c *HelmClient) ListSandboxProfiles() ([]SandboxBackendProfile, error) {
	var out []SandboxBackendProfile
	err := c.do("GET", "/api/v1/sandbox/profiles", nil, &out)
	return out, err
}

func (c *HelmClient) ListSandboxGrants() ([]SandboxGrant, error) {
	var out []SandboxGrant
	err := c.do("GET", "/api/v1/sandbox/grants", nil, &out)
	return out, err
}

func (c *HelmClient) CreateSandboxGrant(req SurfaceRecord) (*SandboxGrant, error) {
	var out SandboxGrant
	err := c.do("POST", "/api/v1/sandbox/grants", req, &out)
	return &out, err
}

func (c *HelmClient) GetSandboxGrant(grantID string) (*SandboxGrant, error) {
	var out SandboxGrant
	err := c.do("GET", "/api/v1/sandbox/grants/"+url.PathEscape(grantID), nil, &out)
	return &out, err
}

func (c *HelmClient) VerifySandboxGrant(grantID string) (*SandboxPreflightResult, error) {
	var out SandboxPreflightResult
	err := c.do("POST", "/api/v1/sandbox/grants/"+url.PathEscape(grantID)+"/verify", nil, &out)
	return &out, err
}

func (c *HelmClient) PreflightSandboxGrant(req SandboxPreflightRequest) (*SandboxPreflightResult, error) {
	var out SandboxPreflightResult
	err := c.do("POST", "/api/v1/sandbox/preflight", req, &out)
	return &out, err
}

func (c *HelmClient) InspectSandboxGrant(runtimeName, profile, policyEpoch string) (*SandboxGrant, error) {
	q := url.Values{}
	q.Set("runtime", runtimeName)
	if profile != "" {
		q.Set("profile", profile)
	}
	if policyEpoch != "" {
		q.Set("policy_epoch", policyEpoch)
	}
	var out SandboxGrant
	err := c.do("GET", fmt.Sprintf("/api/v1/sandbox/grants/inspect?%s", q.Encode()), nil, &out)
	return &out, err
}

func (c *HelmClient) ListAgentIdentities() ([]AgentIdentityProfile, error) {
	var out []AgentIdentityProfile
	err := c.do("GET", "/api/v1/identity/agents", nil, &out)
	return out, err
}

func (c *HelmClient) GetAuthzHealth() (*AuthzHealth, error) {
	var out AuthzHealth
	err := c.do("GET", "/api/v1/authz/health", nil, &out)
	return &out, err
}

func (c *HelmClient) CheckAuthz(req SurfaceRecord) (*AuthzSnapshot, error) {
	var out AuthzSnapshot
	err := c.do("POST", "/api/v1/authz/check", req, &out)
	return &out, err
}

func (c *HelmClient) ListAuthzSnapshots() ([]AuthzSnapshot, error) {
	var out []AuthzSnapshot
	err := c.do("GET", "/api/v1/authz/snapshots", nil, &out)
	return out, err
}

func (c *HelmClient) GetAuthzSnapshot(snapshotID string) (*AuthzSnapshot, error) {
	var out AuthzSnapshot
	err := c.do("GET", "/api/v1/authz/snapshots/"+url.PathEscape(snapshotID), nil, &out)
	return &out, err
}

func (c *HelmClient) ListApprovalCeremonies() ([]ApprovalCeremony, error) {
	var out []ApprovalCeremony
	err := c.do("GET", "/api/v1/approvals", nil, &out)
	return out, err
}

func (c *HelmClient) CreateApprovalCeremony(req ApprovalCeremony) (*ApprovalCeremony, error) {
	var out ApprovalCeremony
	err := c.do("POST", "/api/v1/approvals", req, &out)
	return &out, err
}

func (c *HelmClient) TransitionApprovalCeremony(approvalID, action string, req SurfaceRecord) (*ApprovalCeremony, error) {
	var out ApprovalCeremony
	err := c.do("POST", "/api/v1/approvals/"+url.PathEscape(approvalID)+"/"+url.PathEscape(action), req, &out)
	return &out, err
}

func (c *HelmClient) CreateApprovalWebAuthnChallenge(approvalID string, req SurfaceRecord) (*ApprovalWebAuthnChallenge, error) {
	var out ApprovalWebAuthnChallenge
	err := c.do("POST", "/api/v1/approvals/"+url.PathEscape(approvalID)+"/webauthn/challenge", req, &out)
	return &out, err
}

func (c *HelmClient) AssertApprovalWebAuthnChallenge(approvalID string, req ApprovalWebAuthnAssertion) (*ApprovalCeremony, error) {
	var out ApprovalCeremony
	err := c.do("POST", "/api/v1/approvals/"+url.PathEscape(approvalID)+"/webauthn/assert", req, &out)
	return &out, err
}

func (c *HelmClient) ListBudgetCeilings() ([]BudgetCeiling, error) {
	var out []BudgetCeiling
	err := c.do("GET", "/api/v1/budgets", nil, &out)
	return out, err
}

func (c *HelmClient) PutBudgetCeiling(budgetID string, req BudgetCeiling) (*BudgetCeiling, error) {
	var out BudgetCeiling
	err := c.do("PUT", "/api/v1/budgets/"+url.PathEscape(budgetID), req, &out)
	return &out, err
}

func (c *HelmClient) GetCoexistenceCapabilities() (*CoexistenceCapabilityManifest, error) {
	var out CoexistenceCapabilityManifest
	err := c.do("GET", "/api/v1/coexistence/capabilities", nil, &out)
	return &out, err
}

func (c *HelmClient) GetTelemetryOTelConfig() (*TelemetryOTelConfig, error) {
	var out TelemetryOTelConfig
	err := c.do("GET", "/api/v1/telemetry/otel/config", nil, &out)
	return &out, err
}

func (c *HelmClient) ExportTelemetry(req TelemetryExportRequest) (*TelemetryExportResult, error) {
	var out TelemetryExportResult
	err := c.do("POST", "/api/v1/telemetry/export", req, &out)
	return &out, err
}
