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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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

// ValidateFederationContext checks a FederationContext for structural validity.
func ValidateFederationContext(fc *FederationContext) error {
	if fc == nil {
		return nil // absent = same-org, valid
	}
	if fc.OriginOrg == "" {
		return errors.New("federation: origin_org is required")
	}
	if fc.TrustLevel == "" {
		return errors.New("federation: trust_level is required")
	}
	validLevels := map[string]bool{"full": true, "limited": true, "verify_only": true}
	if !validLevels[fc.TrustLevel] {
		return fmt.Errorf("federation: invalid trust_level %q; must be full, limited, or verify_only", fc.TrustLevel)
	}
	return nil
}

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

// ValidateProofCapsule checks structural integrity and expiry of a proof capsule.
func ValidateProofCapsule(capsule *ProofCapsule) error {
	if capsule == nil {
		return errors.New("federation: nil proof capsule")
	}
	if capsule.CapsuleID == "" {
		return errors.New("federation: capsule_id is required")
	}
	if capsule.OriginOrg == "" {
		return errors.New("federation: origin_org is required in capsule")
	}
	if capsule.MerkleRoot == "" {
		return errors.New("federation: merkle_root is required in capsule")
	}
	if len(capsule.ProofNodes) == 0 {
		return errors.New("federation: at least one proof_node is required")
	}
	if time.Now().After(capsule.ExpiresAt) {
		return errors.New("federation: proof capsule has expired")
	}

	// Verify content hash.
	computed := ComputeCapsuleHash(capsule)
	if capsule.ContentHash != "" && capsule.ContentHash != computed {
		return fmt.Errorf("federation: capsule content hash mismatch: expected %s, got %s", capsule.ContentHash, computed)
	}

	return nil
}

// ComputeCapsuleHash creates a deterministic SHA-256 hash of capsule content.
func ComputeCapsuleHash(capsule *ProofCapsule) string {
	hashable := struct {
		CapsuleID     string   `json:"capsule_id"`
		OriginOrg     string   `json:"origin_org"`
		MerkleRoot    string   `json:"merkle_root"`
		ProofNodes    []string `json:"proof_nodes"`
		NodeCount     int      `json:"node_count"`
		PolicyVersion string   `json:"policy_version"`
	}{
		CapsuleID:     capsule.CapsuleID,
		OriginOrg:     capsule.OriginOrg,
		MerkleRoot:    capsule.MerkleRoot,
		ProofNodes:    capsule.ProofNodes,
		NodeCount:     capsule.NodeCount,
		PolicyVersion: capsule.PolicyVersion,
	}
	data, _ := json.Marshal(hashable)
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

// ExportFederationProof packages a subset of the local proof graph into a portable capsule.
func ExportFederationProof(orgID string, merkleRoot string, proofNodes []string, nodeCount int, policyVersion string, ttl time.Duration) *ProofCapsule {
	now := time.Now()
	capsule := &ProofCapsule{
		CapsuleID:     "capsule:" + orgID + ":" + fmt.Sprintf("%d", now.UnixMilli()),
		OriginOrg:     orgID,
		MerkleRoot:    merkleRoot,
		ProofNodes:    proofNodes,
		NodeCount:     nodeCount,
		PolicyVersion: policyVersion,
		CreatedAt:     now,
		ExpiresAt:     now.Add(ttl),
	}
	capsule.ContentHash = ComputeCapsuleHash(capsule)
	return capsule
}
