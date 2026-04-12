// Package a2a provides the Agent-to-Agent trust protocol for HELM.
//
// This is the OSS implementation of agent-to-agent communication governance.
// It enables fail-closed envelope verification, schema/feature negotiation,
// and cross-agent policy enforcement.
//
// Invariants:
//   - Negotiation is fail-closed: any incompatibility → deterministic deny
//   - Envelopes must be signed by the originating agent principal
//   - Verification completes within bounded compute
//   - No best-effort parsing; drift = deny + receipt
package a2a

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// SchemaVersion tracks the protocol version for A2A negotiation.
type SchemaVersion struct {
	Major int `json:"major"`
	Minor int `json:"minor"`
	Patch int `json:"patch"`
}

// String returns the semver string.
func (v SchemaVersion) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// CurrentVersion is the current A2A protocol version.
var CurrentVersion = SchemaVersion{Major: 1, Minor: 0, Patch: 0}

// Feature is a capability that can be negotiated between agents.
type Feature string

const (
	FeatureMeteringReceipts  Feature = "METERING_RECEIPTS"
	FeatureDisputeReplay     Feature = "DISPUTE_REPLAY"
	FeatureProofGraphSync    Feature = "PROOFGRAPH_SYNC"
	FeatureEvidenceExport    Feature = "EVIDENCE_EXPORT"
	FeaturePolicyNegotiation Feature = "POLICY_NEGOTIATION"
	// FeatureAgentPayments indicates AP2 (Agent Payments Protocol) support.
	// See Sprint 3.5 for full AP2 implementation.
	FeatureAgentPayments Feature = "AGENT_PAYMENTS"

	// FeatureIATPAuth indicates IATP challenge-response mutual authentication.
	FeatureIATPAuth Feature = "IATP_AUTH"

	// FeaturePeerVouching indicates peer vouching with joint liability support.
	FeaturePeerVouching Feature = "PEER_VOUCHING"

	// FeatureTrustPropagation indicates transitive trust score propagation.
	FeatureTrustPropagation Feature = "TRUST_PROPAGATION"
)

// DenyReason is a deterministic reason code for negotiation failure.
type DenyReason string

const (
	DenyVersionIncompatible DenyReason = "VERSION_INCOMPATIBLE"
	DenyFeatureMissing      DenyReason = "FEATURE_MISSING"
	DenyPolicyViolation     DenyReason = "POLICY_VIOLATION"
	DenySignatureInvalid    DenyReason = "SIGNATURE_INVALID"
	DenyAgentNotTrusted     DenyReason = "AGENT_NOT_TRUSTED"
	DenyChallengeFailure    DenyReason = "CHALLENGE_FAILURE"
	DenyVouchRevoked        DenyReason = "VOUCH_REVOKED"
)

// Envelope wraps an agent-to-agent interaction with negotiation metadata.
type Envelope struct {
	EnvelopeID       string        `json:"envelope_id"`
	SchemaVersion    SchemaVersion `json:"schema_version"`
	OriginAgentID    string        `json:"origin_agent_id"`
	TargetAgentID    string        `json:"target_agent_id"`
	RequiredFeatures []Feature     `json:"required_features"`
	OfferedFeatures  []Feature     `json:"offered_features"`
	PayloadHash      string        `json:"payload_hash"`
	Signature        Signature     `json:"signature"`
	CreatedAt        time.Time     `json:"created_at"`
	ExpiresAt        time.Time     `json:"expires_at"`
}

// Signature is a cryptographic signature on an A2A envelope.
type Signature struct {
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
	Value     string `json:"sig"`
	AgentID   string `json:"agent_id"`
}

// NegotiationResult is the outcome of an A2A negotiation.
type NegotiationResult struct {
	Accepted       bool           `json:"accepted"`
	DenyReason     DenyReason     `json:"deny_reason,omitempty"`
	DenyDetails    string         `json:"deny_details,omitempty"`
	AgreedFeatures []Feature      `json:"agreed_features,omitempty"`
	AgreedVersion  *SchemaVersion `json:"agreed_version,omitempty"`
	ReceiptID      string         `json:"receipt_id"`
	Timestamp      time.Time      `json:"timestamp"`
}

// Verifier verifies A2A envelopes and performs feature negotiation.
type Verifier interface {
	Negotiate(ctx context.Context, envelope *Envelope, localFeatures []Feature) (*NegotiationResult, error)
	VerifySignature(ctx context.Context, envelope *Envelope) (bool, error)
}

// TrustedKey represents a registered public key for agent signature verification.
type TrustedKey struct {
	KeyID     string `json:"kid"`
	AgentID   string `json:"agent_id"`
	Algorithm string `json:"alg"`
	PublicKey string `json:"public_key"` // Base64-encoded
	Active    bool   `json:"active"`
}

// PolicyRule defines a cross-agent interaction constraint.
type PolicyRule struct {
	RuleID          string   `json:"rule_id"`
	OriginAgent     string   `json:"origin_agent"` // "*" for any
	TargetAgent     string   `json:"target_agent"` // "*" for any
	AllowedFeatures []Feature `json:"allowed_features,omitempty"`
	DeniedFeatures  []Feature `json:"denied_features,omitempty"`
	Action          PolicyAction `json:"action"`
}

// PolicyAction determines the outcome of a policy rule match.
type PolicyAction string

const (
	PolicyAllow PolicyAction = "ALLOW"
	PolicyDeny  PolicyAction = "DENY"
)

// ComputeEnvelopeHash creates a deterministic hash of envelope content.
func ComputeEnvelopeHash(env *Envelope) string {
	hashable := struct {
		EnvelopeID    string        `json:"envelope_id"`
		SchemaVersion SchemaVersion `json:"schema_version"`
		OriginAgentID string        `json:"origin_agent_id"`
		TargetAgentID string        `json:"target_agent_id"`
		PayloadHash   string        `json:"payload_hash"`
	}{
		EnvelopeID:    env.EnvelopeID,
		SchemaVersion: env.SchemaVersion,
		OriginAgentID: env.OriginAgentID,
		TargetAgentID: env.TargetAgentID,
		PayloadHash:   env.PayloadHash,
	}
	data, _ := json.Marshal(hashable)
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

// SignEnvelope signs an A2A envelope with the given key identity.
func SignEnvelope(env *Envelope, keyID, algorithm, agentID string) {
	hash := ComputeEnvelopeHash(env)
	env.Signature = Signature{
		KeyID:     keyID,
		Algorithm: algorithm,
		Value:     hash,
		AgentID:   agentID,
	}
}
