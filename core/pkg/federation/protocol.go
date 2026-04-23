package federation

import (
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
)

// FederationProtocol handles org-to-org mutual authentication and agreement establishment.
type FederationProtocol struct {
	localOrg   OrgTrustRoot
	signer     crypto.Signer
	trustStore *TrustRootStore
	clock      func() time.Time
}

// NewFederationProtocol creates a new protocol instance for the local organization.
func NewFederationProtocol(localOrg OrgTrustRoot, signer crypto.Signer, store *TrustRootStore) *FederationProtocol {
	return &FederationProtocol{
		localOrg:   localOrg,
		signer:     signer,
		trustStore: store,
		clock:      time.Now,
	}
}

// WithClock overrides the clock for testing.
func (p *FederationProtocol) WithClock(clock func() time.Time) *FederationProtocol {
	p.clock = clock
	return p
}

// ProposeAgreement creates a federation agreement proposal signed by the local org.
// The proposal contains SignatureA (local org) and an empty SignatureB (awaiting remote).
func (p *FederationProtocol) ProposeAgreement(remoteOrg OrgTrustRoot, capabilities []string, ttl time.Duration) (*FederationAgreement, error) {
	if remoteOrg.OrgID == "" {
		return nil, fmt.Errorf("federation: remote org_id must not be empty")
	}
	if remoteOrg.OrgID == p.localOrg.OrgID {
		return nil, fmt.Errorf("federation: cannot federate with self")
	}
	if len(capabilities) == 0 {
		return nil, fmt.Errorf("federation: capabilities must not be empty")
	}

	now := p.clock()

	// Sort capabilities for deterministic hashing.
	sortedCaps := make([]string, len(capabilities))
	copy(sortedCaps, capabilities)
	sort.Strings(sortedCaps)

	agreement := &FederationAgreement{
		AgreementID:  fmt.Sprintf("fed-agr:%s:%s:%d", p.localOrg.OrgID, remoteOrg.OrgID, now.UnixMilli()),
		OrgA:         p.localOrg,
		OrgB:         remoteOrg,
		Capabilities: sortedCaps,
		CreatedAt:    now,
		ExpiresAt:    now.Add(ttl),
	}

	// Compute the policy hash over capabilities.
	policyHash, err := canonicalize.CanonicalHash(sortedCaps)
	if err != nil {
		return nil, fmt.Errorf("federation: policy hash failed: %w", err)
	}
	agreement.PolicyHash = policyHash

	// Compute content hash over the agreement body (excluding signatures and content hash).
	contentHash, err := computeAgreementContentHash(agreement)
	if err != nil {
		return nil, fmt.Errorf("federation: content hash failed: %w", err)
	}
	agreement.ContentHash = contentHash

	// Sign the content hash with local org's key.
	contentHashBytes, err := hex.DecodeString(agreement.ContentHash)
	if err != nil {
		return nil, fmt.Errorf("federation: decode content hash failed: %w", err)
	}
	sig, err := p.signer.Sign(contentHashBytes)
	if err != nil {
		return nil, fmt.Errorf("federation: signing proposal failed: %w", err)
	}
	agreement.SignatureA = sig

	return agreement, nil
}

// AcceptAgreement validates and counter-signs a federation proposal.
// The local org must be OrgB in the proposal. Returns the fully signed agreement.
func (p *FederationProtocol) AcceptAgreement(proposal *FederationAgreement) (*FederationAgreement, error) {
	if proposal == nil {
		return nil, fmt.Errorf("federation: nil proposal")
	}

	// Validate that local org is OrgB.
	if proposal.OrgB.OrgID != p.localOrg.OrgID {
		return nil, fmt.Errorf("federation: local org %s is not OrgB (%s) in proposal",
			p.localOrg.OrgID, proposal.OrgB.OrgID)
	}

	// Verify OrgA is trusted.
	if !p.trustStore.IsTrusted(proposal.OrgA.OrgID) {
		return nil, fmt.Errorf("federation: OrgA %s is not trusted", proposal.OrgA.OrgID)
	}

	// Verify the proposal is not expired.
	now := p.clock()
	if now.After(proposal.ExpiresAt) {
		return nil, fmt.Errorf("federation: proposal expired at %s", proposal.ExpiresAt.Format(time.RFC3339))
	}

	// Verify content hash integrity.
	expectedHash, err := computeAgreementContentHash(proposal)
	if err != nil {
		return nil, fmt.Errorf("federation: content hash verification failed: %w", err)
	}
	if proposal.ContentHash != expectedHash {
		return nil, fmt.Errorf("federation: content hash mismatch: got %s, want %s",
			proposal.ContentHash, expectedHash)
	}

	// Verify OrgA's signature on the content hash.
	contentHashBytes, err := hex.DecodeString(proposal.ContentHash)
	if err != nil {
		return nil, fmt.Errorf("federation: decode content hash failed: %w", err)
	}
	valid, err := crypto.Verify(proposal.OrgA.PublicKey, proposal.SignatureA, contentHashBytes)
	if err != nil {
		return nil, fmt.Errorf("federation: signature verification error: %w", err)
	}
	if !valid {
		return nil, fmt.Errorf("federation: OrgA signature invalid")
	}

	// Counter-sign: OrgB signs the same content hash.
	sig, err := p.signer.Sign(contentHashBytes)
	if err != nil {
		return nil, fmt.Errorf("federation: counter-signing failed: %w", err)
	}

	accepted := *proposal
	accepted.SignatureB = sig
	return &accepted, nil
}

// VerifyAgreement checks both signatures and trust roots on a fully signed agreement.
func (p *FederationProtocol) VerifyAgreement(agreement *FederationAgreement) error {
	if agreement == nil {
		return fmt.Errorf("federation: nil agreement")
	}

	// Both signatures must be present.
	if agreement.SignatureA == "" {
		return fmt.Errorf("federation: missing OrgA signature")
	}
	if agreement.SignatureB == "" {
		return fmt.Errorf("federation: missing OrgB signature")
	}

	// Verify not expired.
	now := p.clock()
	if now.After(agreement.ExpiresAt) {
		return fmt.Errorf("federation: agreement expired at %s", agreement.ExpiresAt.Format(time.RFC3339))
	}

	// Verify content hash.
	expectedHash, err := computeAgreementContentHash(agreement)
	if err != nil {
		return fmt.Errorf("federation: content hash computation failed: %w", err)
	}
	if agreement.ContentHash != expectedHash {
		return fmt.Errorf("federation: content hash mismatch")
	}

	contentHashBytes, err := hex.DecodeString(agreement.ContentHash)
	if err != nil {
		return fmt.Errorf("federation: decode content hash failed: %w", err)
	}

	// Verify OrgA is trusted and signature is valid.
	if !p.trustStore.IsTrusted(agreement.OrgA.OrgID) {
		return fmt.Errorf("federation: OrgA %s is not trusted", agreement.OrgA.OrgID)
	}
	validA, err := crypto.Verify(agreement.OrgA.PublicKey, agreement.SignatureA, contentHashBytes)
	if err != nil {
		return fmt.Errorf("federation: OrgA signature verification error: %w", err)
	}
	if !validA {
		return fmt.Errorf("federation: OrgA signature invalid")
	}

	// Verify OrgB is trusted and signature is valid.
	if !p.trustStore.IsTrusted(agreement.OrgB.OrgID) {
		return fmt.Errorf("federation: OrgB %s is not trusted", agreement.OrgB.OrgID)
	}
	validB, err := crypto.Verify(agreement.OrgB.PublicKey, agreement.SignatureB, contentHashBytes)
	if err != nil {
		return fmt.Errorf("federation: OrgB signature verification error: %w", err)
	}
	if !validB {
		return fmt.Errorf("federation: OrgB signature invalid")
	}

	return nil
}

// computeAgreementContentHash computes a JCS + SHA-256 content hash for the agreement body.
// Excludes signatures and the content hash itself for a stable identity.
func computeAgreementContentHash(a *FederationAgreement) (string, error) {
	hashable := struct {
		AgreementID  string   `json:"agreement_id"`
		OrgAID       string   `json:"org_a_id"`
		OrgBID       string   `json:"org_b_id"`
		Capabilities []string `json:"capabilities"`
		PolicyHash   string   `json:"policy_hash"`
		CreatedAt    string   `json:"created_at"`
		ExpiresAt    string   `json:"expires_at"`
	}{
		AgreementID:  a.AgreementID,
		OrgAID:       a.OrgA.OrgID,
		OrgBID:       a.OrgB.OrgID,
		Capabilities: a.Capabilities,
		PolicyHash:   a.PolicyHash,
		CreatedAt:    a.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		ExpiresAt:    a.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
	return canonicalize.CanonicalHash(hashable)
}
