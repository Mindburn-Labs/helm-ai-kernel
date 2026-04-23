// Package federation implements L3 multi-org trust establishment,
// federation protocol, and cross-org policy inheritance for HELM.
//
// Federation enables fail-closed mutual authentication between
// organizations. Each org publishes a trust root (signing key + DID),
// and bilateral agreements are formed via a propose/accept handshake
// where both parties sign the canonical agreement content.
//
// Policy inheritance follows a narrowing-only rule: a child org can
// only restrict capabilities granted by its parent, never expand them.
//
// All content hashes use JCS (RFC 8785) canonicalization + SHA-256.
package federation

import (
	"time"
)

// OrgTrustRoot represents an organization's trust anchor for federation.
type OrgTrustRoot struct {
	OrgID         string    `json:"org_id"`
	OrgDID        string    `json:"org_did"`
	OrgName       string    `json:"org_name"`
	PublicKey     string    `json:"public_key"` // hex-encoded org signing key
	Algorithm     string    `json:"algorithm"`  // "ed25519" or "ml-dsa-65"
	EstablishedAt time.Time `json:"established_at"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
	Revoked       bool      `json:"revoked"`
	ContentHash   string    `json:"content_hash"`
}

// FederationAgreement is a mutual trust binding between two organizations.
// Both parties must sign the canonical content for the agreement to be valid.
type FederationAgreement struct {
	AgreementID  string       `json:"agreement_id"`
	OrgA         OrgTrustRoot `json:"org_a"`
	OrgB         OrgTrustRoot `json:"org_b"`
	Capabilities []string     `json:"capabilities"` // shared capabilities
	PolicyHash   string       `json:"policy_hash"`  // agreed policy hash
	SignatureA   string       `json:"signature_a"`  // OrgA's signature
	SignatureB   string       `json:"signature_b"`  // OrgB's signature
	CreatedAt    time.Time    `json:"created_at"`
	ExpiresAt    time.Time    `json:"expires_at"`
	ContentHash  string       `json:"content_hash"`
}

// FederationPolicy defines cross-org policy inheritance rules.
// Narrowing-only: a child can only restrict capabilities, never expand.
type FederationPolicy struct {
	PolicyID      string   `json:"policy_id"`
	ParentOrgID   string   `json:"parent_org_id"`
	ChildOrgID    string   `json:"child_org_id"`
	InheritedCaps []string `json:"inherited_capabilities"` // caps child receives from parent
	DeniedCaps    []string `json:"denied_capabilities"`    // caps explicitly blocked
	NarrowingOnly bool     `json:"narrowing_only"`         // child can only narrow, never expand
}
