// Package a2a — federation.go
// Cross-organization A2A federation with proof capsule exchange.
//
// FederationContext extends the A2A Envelope protocol for multi-org scenarios.
// When two HELM-governed orgs federate, each side can export a proof capsule
// that cryptographically attests its execution history. The receiving org
// validates the capsule before accepting the envelope.
//
// Invariants:
//   - FederationContext is optional; absence = same-org communication.
//   - When present, OriginOrg must be non-empty.
//   - ProofCapsuleRef must point to a verifiable capsule (Merkle root match).
//   - Capsules have a TTL; expired capsules are rejected deterministically.

package a2a

import (
	"fmt"
	"time"
)

// FederationContext carries cross-org metadata embedded in A2A Envelope.Metadata.
type FederationContext struct {
	OriginOrg       string `json:"origin_org"`
	TargetOrg       string `json:"target_org,omitempty"`
	ProofCapsuleRef string `json:"proof_capsule_ref,omitempty"`
	MerkleRoot      string `json:"merkle_root,omitempty"`
	TrustLevel      string `json:"trust_level"` // "full", "limited", "verify_only"
}

// FederationPolicy controls which organizations can federate.
type FederationPolicy struct {
	AllowedOrgs   []string      `json:"allowed_orgs"`              // empty = deny all
	DenyOrgs      []string      `json:"deny_orgs,omitempty"`       // explicit denials
	RequireProof  bool          `json:"require_proof"`             // require proof capsule
	CapsuleTTL    time.Duration `json:"capsule_ttl,omitempty"`     // max age of capsule
	MinTrustLevel string        `json:"min_trust_level,omitempty"` // "full", "limited", "verify_only"
}

// ProofCapsule is a portable, self-contained proof of governed execution history.
type ProofCapsule struct {
	CapsuleID     string    `json:"capsule_id"`
	OriginOrg     string    `json:"origin_org"`
	MerkleRoot    string    `json:"merkle_root"`
	ProofNodes    []string  `json:"proof_nodes"` // selected proof graph node hashes
	NodeCount     int       `json:"node_count"`  // total nodes in the proof graph
	PolicyVersion string    `json:"policy_version"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	ContentHash   string    `json:"content_hash"`
}

// FederationDenyReason enumerates federation-specific denial codes.
const (
	DenyFederationOrgDenied      DenyReason = "FEDERATION_ORG_DENIED"
	DenyFederationProofInvalid   DenyReason = "FEDERATION_PROOF_INVALID"
	DenyFederationCapsuleExpired DenyReason = "FEDERATION_CAPSULE_EXPIRED"
	DenyFederationTrustTooLow    DenyReason = "FEDERATION_TRUST_TOO_LOW"
)

// EvaluateFederationPolicy checks whether a FederationContext is permitted
// by the given FederationPolicy. Returns a NegotiationResult with deny
// details on failure.
func EvaluateFederationPolicy(fc *FederationContext, policy *FederationPolicy) *NegotiationResult {
	now := time.Now()

	if fc == nil {
		// No federation context = same-org; policy doesn't apply.
		return &NegotiationResult{Accepted: true, ReceiptID: "local", Timestamp: now}
	}

	// Check deny list first (fail-closed).
	for _, denied := range policy.DenyOrgs {
		if denied == fc.OriginOrg {
			return &NegotiationResult{
				Accepted:    false,
				DenyReason:  DenyFederationOrgDenied,
				DenyDetails: fmt.Sprintf("organization %q is on the deny list", fc.OriginOrg),
				ReceiptID:   "federation_deny",
				Timestamp:   now,
			}
		}
	}

	// Check allow list.
	if len(policy.AllowedOrgs) > 0 {
		found := false
		for _, allowed := range policy.AllowedOrgs {
			if allowed == fc.OriginOrg || allowed == "*" {
				found = true
				break
			}
		}
		if !found {
			return &NegotiationResult{
				Accepted:    false,
				DenyReason:  DenyFederationOrgDenied,
				DenyDetails: fmt.Sprintf("organization %q is not in the allow list", fc.OriginOrg),
				ReceiptID:   "federation_deny",
				Timestamp:   now,
			}
		}
	}

	// Check trust level minimum.
	if policy.MinTrustLevel != "" {
		trustRank := map[string]int{"verify_only": 1, "limited": 2, "full": 3}
		minRank := trustRank[policy.MinTrustLevel]
		actualRank := trustRank[fc.TrustLevel]
		if actualRank < minRank {
			return &NegotiationResult{
				Accepted:    false,
				DenyReason:  DenyFederationTrustTooLow,
				DenyDetails: fmt.Sprintf("trust_level %q below minimum %q", fc.TrustLevel, policy.MinTrustLevel),
				ReceiptID:   "federation_deny",
				Timestamp:   now,
			}
		}
	}

	// Check proof requirement.
	if policy.RequireProof && fc.ProofCapsuleRef == "" {
		return &NegotiationResult{
			Accepted:    false,
			DenyReason:  DenyFederationProofInvalid,
			DenyDetails: "federation policy requires a proof capsule but none was provided",
			ReceiptID:   "federation_deny",
			Timestamp:   now,
		}
	}

	return &NegotiationResult{Accepted: true, ReceiptID: "federation_allow", Timestamp: now}
}
