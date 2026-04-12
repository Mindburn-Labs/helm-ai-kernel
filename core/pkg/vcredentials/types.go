// Package vcredentials implements W3C Verifiable Credential Data Model v2.0
// for agent capability certificates.
//
// Reference: https://www.w3.org/TR/vc-data-model-2.0/
//
// HELM is the first AI execution firewall to issue W3C Verifiable Credentials
// for agent capabilities. Each credential cryptographically attests to the
// specific actions an agent is authorized to perform, the constraints under
// which those actions are valid, and the governance instance that verified them.
//
// Credentials are signed using JCS (RFC 8785) canonicalization for deterministic,
// cross-platform verification — consistent with all other HELM proof artifacts.
package vcredentials

import "time"

// W3C VC JSON-LD contexts.
const (
	// ContextW3CCredentials is the base W3C Verifiable Credentials v2 context.
	ContextW3CCredentials = "https://www.w3.org/ns/credentials/v2"

	// ContextHELMAgent is the HELM agent capability extension context.
	ContextHELMAgent = "https://helm.mindburn.org/ns/agent-capability/v1"
)

// Credential type constants.
const (
	// TypeVerifiableCredential is the base W3C VC type.
	TypeVerifiableCredential = "VerifiableCredential"

	// TypeAgentCapabilityCredential is the HELM-specific credential type.
	TypeAgentCapabilityCredential = "AgentCapabilityCredential"
)

// Proof type constants matching HELM signer algorithms.
const (
	// ProofTypeEd25519 is the proof type for Ed25519 signatures.
	ProofTypeEd25519 = "Ed25519Signature2020"

	// ProofTypeMLDSA is the proof type for ML-DSA-65 (post-quantum) signatures.
	ProofTypeMLDSA = "MLDSASignature2024"
)

// ProofPurposeAssertion is the standard proof purpose for credential issuance.
const ProofPurposeAssertion = "assertionMethod"

// VerifiableCredential implements a simplified W3C Verifiable Credential Data Model v2.0.
// It binds an agent's verified capabilities to a cryptographic proof chain.
type VerifiableCredential struct {
	Context           []string               `json:"@context"`
	ID                string                 `json:"id"`
	Type              []string               `json:"type"`
	Issuer            CredentialIssuer       `json:"issuer"`
	ValidFrom         time.Time              `json:"validFrom"`
	ValidUntil        time.Time              `json:"validUntil,omitempty"`
	CredentialSubject AgentCapabilitySubject `json:"credentialSubject"`
	Proof             *CredentialProof       `json:"proof,omitempty"`
}

// CredentialIssuer identifies who issued the credential.
type CredentialIssuer struct {
	ID   string `json:"id"`             // DID of the HELM instance
	Name string `json:"name,omitempty"` // Human-readable name
}

// AgentCapabilitySubject describes the agent and its verified capabilities.
type AgentCapabilitySubject struct {
	ID           string                `json:"id"`                      // Agent DID
	AgentName    string                `json:"agentName,omitempty"`     // Human-readable agent name
	Capabilities []CapabilityClaim     `json:"capabilities"`           // Verified capability claims
	Constraints  CapabilityConstraints `json:"constraints,omitempty"` // Envelope constraints
}

// CapabilityClaim is a single verified capability granted to an agent.
type CapabilityClaim struct {
	Action     string    `json:"action"`              // e.g., "EXECUTE_TOOL", "SEND_EMAIL"
	Resource   string    `json:"resource,omitempty"`  // Specific resource scope
	Verified   bool      `json:"verified"`            // Whether the capability was verified
	VerifiedAt time.Time `json:"verifiedAt"`          // When verification occurred
}

// CapabilityConstraints limit when, where, and how capabilities may be exercised.
type CapabilityConstraints struct {
	RiskCeiling    string   `json:"riskCeiling,omitempty"`    // Max risk level: LOW, MEDIUM, HIGH
	Geofence       []string `json:"geofence,omitempty"`       // Allowed regions: e.g. ["US", "EU"]
	MaxBudgetCents int64    `json:"maxBudgetCents,omitempty"` // Spending ceiling in cents
	PrivilegeTier  string   `json:"privilegeTier,omitempty"`  // RESTRICTED, STANDARD, ELEVATED, SYSTEM
	TrustFloor     int      `json:"trustFloor,omitempty"`     // Minimum behavioral trust score (0-1000)
}

// CredentialProof is the cryptographic proof binding the credential to its issuer.
type CredentialProof struct {
	Type               string    `json:"type"`               // "Ed25519Signature2020" or "MLDSASignature2024"
	Created            time.Time `json:"created"`            // When the proof was created
	VerificationMethod string    `json:"verificationMethod"` // DID + key fragment reference
	ProofPurpose       string    `json:"proofPurpose"`       // "assertionMethod"
	ProofValue         string    `json:"proofValue"`         // Hex-encoded signature
}
