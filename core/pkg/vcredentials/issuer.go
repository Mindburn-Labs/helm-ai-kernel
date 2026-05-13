package vcredentials

import (
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

// Issuer creates signed W3C Verifiable Credentials for agent capabilities.
//
// Each issued credential binds an agent's verified capabilities to the issuing
// HELM instance's DID, signs the canonical (JCS) representation, and produces
// a self-contained, offline-verifiable proof artifact.
type Issuer struct {
	issuerDID  string
	issuerName string
	signer     crypto.Signer
	clock      func() time.Time
}

// NewIssuer creates a credential issuer bound to a HELM instance DID and signer.
func NewIssuer(issuerDID, issuerName string, signer crypto.Signer) *Issuer {
	return &Issuer{
		issuerDID:  issuerDID,
		issuerName: issuerName,
		signer:     signer,
		clock:      time.Now,
	}
}

// NewIssuerWithClock creates a credential issuer with a custom clock function.
// This is primarily useful for deterministic testing.
func NewIssuerWithClock(issuerDID, issuerName string, signer crypto.Signer, clock func() time.Time) *Issuer {
	return &Issuer{
		issuerDID:  issuerDID,
		issuerName: issuerName,
		signer:     signer,
		clock:      clock,
	}
}

// Issue creates a signed Verifiable Credential for an agent's capabilities.
//
// The credential includes the W3C base context and the HELM agent capability
// extension context. The proof is computed over the JCS-canonicalized credential
// (with the proof field omitted), ensuring deterministic cross-platform verification.
func (i *Issuer) Issue(id string, subject AgentCapabilitySubject, validDuration time.Duration) (*VerifiableCredential, error) {
	if id == "" {
		return nil, fmt.Errorf("credential ID is required")
	}
	if subject.ID == "" {
		return nil, fmt.Errorf("subject ID (agent DID) is required")
	}
	if len(subject.Capabilities) == 0 {
		return nil, fmt.Errorf("at least one capability is required")
	}

	now := i.clock()
	vc := &VerifiableCredential{
		Context: []string{
			ContextW3CCredentials,
			ContextHELMAgent,
		},
		ID:   id,
		Type: []string{TypeVerifiableCredential, TypeAgentCapabilityCredential},
		Issuer: CredentialIssuer{
			ID:   i.issuerDID,
			Name: i.issuerName,
		},
		ValidFrom:         now,
		CredentialSubject: subject,
	}

	if validDuration > 0 {
		validUntil := now.Add(validDuration)
		vc.ValidUntil = validUntil
	}

	if err := i.sign(vc, now); err != nil {
		return nil, fmt.Errorf("signing credential: %w", err)
	}

	return vc, nil
}

// sign computes the JCS canonical form of the credential (without proof) and signs it.
func (i *Issuer) sign(vc *VerifiableCredential, now time.Time) error {
	// Canonicalize the credential without the proof field for signing.
	signable := &VerifiableCredential{
		Context:           vc.Context,
		ID:                vc.ID,
		Type:              vc.Type,
		Issuer:            vc.Issuer,
		ValidFrom:         vc.ValidFrom,
		ValidUntil:        vc.ValidUntil,
		CredentialSubject: vc.CredentialSubject,
		// Proof is intentionally nil — excluded from the signed payload.
	}

	canonical, err := canonicalize.JCS(signable)
	if err != nil {
		return fmt.Errorf("JCS canonicalization failed: %w", err)
	}

	sigHex, err := i.signer.Sign(canonical)
	if err != nil {
		return fmt.Errorf("signing failed: %w", err)
	}

	vc.Proof = &CredentialProof{
		Type:               proofTypeForSigner(i.signer),
		Created:            now,
		VerificationMethod: i.issuerDID + "#key-1",
		ProofPurpose:       ProofPurposeAssertion,
		ProofValue:         sigHex,
	}

	return nil
}

// proofTypeForSigner determines the proof type based on the signer's public key size.
// Ed25519 keys are 32 bytes; anything else is assumed post-quantum (ML-DSA-65).
func proofTypeForSigner(s crypto.Signer) string {
	if len(s.PublicKeyBytes()) == 32 {
		return ProofTypeEd25519
	}
	return ProofTypeMLDSA
}
