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

func (c *HelmClient) CreateEvidenceEnvelopeManifest(req EvidenceEnvelopeExportRequest) (*EvidenceEnvelopeManifest, error) {
	var out EvidenceEnvelopeManifest
	err := c.do("POST", "/api/v1/evidence/envelopes", req, &out)
	return &out, err
}

func (c *HelmClient) ListNegativeConformanceVectors() ([]NegativeBoundaryVector, error) {
	var out []NegativeBoundaryVector
	err := c.do("GET", "/api/v1/conformance/negative", nil, &out)
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

func (c *HelmClient) ListSandboxBackendProfiles() ([]SandboxBackendProfile, error) {
	var out []SandboxBackendProfile
	err := c.do("GET", "/api/v1/sandbox/grants/inspect", nil, &out)
	return out, err
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
