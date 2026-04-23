// Package receipts defines the IntegrationReceipt envelope — the standard
// proof-of-execution for every operation routed through the Integration Gateway.
// It extends contracts.Receipt with integration-specific sections: policy decisions,
// capability references, auth context, zero-trust provenance, cost impact, and evidence.
package receipts

import (
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/integrations/capgraph"
)

// IntegrationReceipt is the unified receipt envelope for all integration executions.
// Every runtime (MCP, HTTP, webhook, scrape, etc.) must emit this envelope.
type IntegrationReceipt struct {
	contracts.Receipt

	// PolicyDecision records the gateway's allow/deny decision.
	PolicyDecision PolicyDecision `json:"policy_decision"`

	// CapabilityRef identifies the capability and connector version that was invoked.
	CapabilityRef CapabilityRef `json:"capability_ref"`

	// AuthContext records who invoked the capability (no secrets).
	AuthContext AuthContext `json:"auth_context"`

	// Provenance records zero-trust provenance for the response.
	Provenance ZTProvenance `json:"zt_provenance"`

	// Cost records the cost impact of this execution.
	Cost CostImpact `json:"cost"`

	// EvidenceRefs links to evidence artifacts produced by this execution.
	EvidenceRefs []EvidenceRef `json:"evidence_refs,omitempty"`
}

// PolicyDecision records the gateway's policy evaluation result.
type PolicyDecision struct {
	Allowed    bool     `json:"allowed"`
	Reasons    []string `json:"reasons,omitempty"`     // Why allowed or denied.
	PolicyHash string   `json:"policy_hash,omitempty"` // Hash of the policy set evaluated.
}

// CapabilityRef identifies the specific capability and connector that was invoked.
type CapabilityRef struct {
	URN              capgraph.CapabilityURN `json:"urn"`
	ConnectorVersion string                 `json:"connector_version"`
	ConnectionID     string                 `json:"connection_id,omitempty"`
}

// AuthContext records the principal context for the execution (no secrets).
type AuthContext struct {
	PrincipalID string   `json:"principal_id"`
	OrgID       string   `json:"org_id,omitempty"`
	Roles       []string `json:"roles,omitempty"`
}

// ZTProvenance records zero-trust provenance metadata for the response.
// Absorbs the provenance fields from connectors/zerotrust.go.
type ZTProvenance struct {
	TrustLevel   string    `json:"trust_level"`             // FULL, VERIFIED, RESTRICTED, UNTRUSTED
	TTL          int       `json:"ttl_seconds,omitempty"`   // Response validity window.
	Residency    string    `json:"residency,omitempty"`     // Data residency region.
	ResponseHash string    `json:"response_hash,omitempty"` // SHA-256 of the response body.
	AnomalyFlags []string  `json:"anomaly_flags,omitempty"` // Detected anomalies.
	VerifiedAt   time.Time `json:"verified_at"`
}

// CostImpact records the resource cost of the execution.
type CostImpact struct {
	DurationMs      int64 `json:"duration_ms,omitempty"`       // Execution duration in ms.
	RateLimitUnits  int   `json:"rate_limit_units,omitempty"`  // Rate limit units consumed.
	SpendDeltaCents int64 `json:"spend_delta_cents,omitempty"` // Cost in cents.
}

// EvidenceRef links to stored evidence artifacts.
type EvidenceRef struct {
	ArtifactID string `json:"artifact_id"`
	Hash       string `json:"hash"`
	StorageURI string `json:"storage_uri,omitempty"`
}

// NewDenied creates a receipt for a denied execution.
func NewDenied(capRef CapabilityRef, auth AuthContext, reasons []string) *IntegrationReceipt {
	return &IntegrationReceipt{
		Receipt: contracts.Receipt{
			Status:    "denied",
			Timestamp: time.Now().UTC(),
		},
		PolicyDecision: PolicyDecision{
			Allowed: false,
			Reasons: reasons,
		},
		CapabilityRef: capRef,
		AuthContext:   auth,
	}
}

// NewAllowed creates a receipt template for an allowed execution.
// The caller must fill in runtime-specific fields (provenance, cost, evidence).
func NewAllowed(capRef CapabilityRef, auth AuthContext, policyHash string) *IntegrationReceipt {
	return &IntegrationReceipt{
		Receipt: contracts.Receipt{
			Status:    "executed",
			Timestamp: time.Now().UTC(),
		},
		PolicyDecision: PolicyDecision{
			Allowed:    true,
			PolicyHash: policyHash,
		},
		CapabilityRef: capRef,
		AuthContext:   auth,
	}
}
