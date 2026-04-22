package certification

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ModuleAttestation represents a certified module attestation per Section 10.
//
//nolint:govet // fieldalignment: struct layout is human-readable
type ModuleAttestation struct {
	AttestationID string                 `json:"attestation_id"`
	Version       string                 `json:"version"`
	Module        ModuleIdentity         `json:"module"`
	Provenance    BuildProvenance        `json:"provenance"`
	Certification CertificationResults   `json:"certification"`
	Signatures    []AttestationSignature `json:"signatures"`
	Validity      AttestationValidity    `json:"validity,omitempty"`
	CreatedAt     time.Time              `json:"created_at"`
}

// ModuleIdentity contains content-addressed module identification.
type ModuleIdentity struct {
	ModuleID     string `json:"module_id"`
	Name         string `json:"name,omitempty"`
	Version      string `json:"version,omitempty"`
	ArtifactHash string `json:"artifact_hash"`
	ManifestHash string `json:"manifest_hash"`
	SourceRepo   string `json:"source_repo,omitempty"`
	CommitHash   string `json:"commit_hash,omitempty"`
}

// BuildProvenance captures build reproducibility information.
//
//nolint:govet // fieldalignment: struct layout is human-readable
type BuildProvenance struct {
	BuilderID            string            `json:"builder_id"`
	BuildTimestamp       time.Time         `json:"build_timestamp"`
	BuildConfigHash      string            `json:"build_config_hash"`
	DependencyHashes     map[string]string `json:"dependency_hashes,omitempty"`
	Reproducible         bool              `json:"reproducible"`
	ReproducibilityProof string            `json:"reproducibility_proof,omitempty"`
}

// CertificationResults contains test and audit results.
type CertificationResults struct {
	SchemaConformance   ConformanceResult     `json:"schema_conformance"`
	DeterminismTests    DeterminismTestResult `json:"determinism_tests"`
	PermissionsDeclared PermissionsDecl       `json:"permissions_declared"`
	SecurityAudit       *SecurityAuditResult  `json:"security_audit,omitempty"`
}

// ConformanceResult for schema validation.
//
//nolint:govet // fieldalignment: struct layout is human-readable
type ConformanceResult struct {
	Passed           bool      `json:"passed"`
	TestedAt         time.Time `json:"tested_at"`
	SchemasValidated []string  `json:"schemas_validated,omitempty"`
}

// DeterminismTestResult for determinism verification.
//
//nolint:govet // fieldalignment: struct layout is human-readable
type DeterminismTestResult struct {
	Passed    bool      `json:"passed"`
	TestedAt  time.Time `json:"tested_at"`
	TestCount int       `json:"test_count"`
	SeedUsed  string    `json:"seed_used,omitempty"`
}

// PermissionsDecl declares module permissions.
//
//nolint:govet // fieldalignment: struct layout is human-readable
type PermissionsDecl struct {
	EffectTypes          []string           `json:"effect_types"`
	RequiredCapabilities []string           `json:"required_capabilities,omitempty"`
	ResourceLimits       map[string]float64 `json:"resource_limits,omitempty"`
}

// SecurityAuditResult for optional security audit.
//
//nolint:govet // fieldalignment: struct layout is human-readable
type SecurityAuditResult struct {
	Audited         bool      `json:"audited"`
	AuditorID       string    `json:"auditor_id,omitempty"`
	AuditReportHash string    `json:"audit_report_hash,omitempty"`
	AuditDate       time.Time `json:"audit_date,omitempty"`
}

// AttestationSignature is a cryptographic signature on the attestation.
type AttestationSignature struct {
	SignerID    string    `json:"signer_id"`
	SignerRole  string    `json:"signer_role"`
	Signature   string    `json:"signature"`
	Algorithm   string    `json:"algorithm"`
	SignedAt    time.Time `json:"signed_at"`
	PublicKeyID string    `json:"public_key_id,omitempty"`
}

// AttestationValidity specifies validity period.
type AttestationValidity struct {
	NotBefore          time.Time `json:"not_before,omitempty"`
	NotAfter           time.Time `json:"not_after,omitempty"`
	RevocationEndpoint string    `json:"revocation_endpoint,omitempty"`
}

// Certifier creates and signs module attestations.
type Certifier struct {
	signerID   string
	signerRole string
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

// NewCertifier creates a new certifier with Ed25519 keys.
func NewCertifier(signerID, signerRole string, privateKey ed25519.PrivateKey) *Certifier {
	return &Certifier{
		signerID:   signerID,
		signerRole: signerRole,
		privateKey: privateKey,
		publicKey:  privateKey.Public().(ed25519.PublicKey),
	}
}

// CreateAttestation creates a new module attestation.
func (c *Certifier) CreateAttestation(
	module ModuleIdentity,
	provenance BuildProvenance,
	certification CertificationResults,
) (*ModuleAttestation, error) {
	att := &ModuleAttestation{
		AttestationID: uuid.New().String(),
		Version:       "1.0.0",
		Module:        module,
		Provenance:    provenance,
		Certification: certification,
		Signatures:    []AttestationSignature{},
		CreatedAt:     time.Now(),
	}

	return att, nil
}

// Sign adds a signature to the attestation.
func (c *Certifier) Sign(att *ModuleAttestation) error {
	// Compute attestation hash (excluding signatures)
	attHash, err := att.computeHash()
	if err != nil {
		return fmt.Errorf("failed to compute attestation hash: %w", err)
	}

	// Sign with Ed25519
	sig := ed25519.Sign(c.privateKey, attHash)

	att.Signatures = append(att.Signatures, AttestationSignature{
		SignerID:    c.signerID,
		SignerRole:  c.signerRole,
		Signature:   base64.StdEncoding.EncodeToString(sig),
		Algorithm:   "ed25519",
		SignedAt:    time.Now(),
		PublicKeyID: hex.EncodeToString(c.publicKey[:8]), // First 8 bytes as key ID
	})

	return nil
}

// Verify verifies all signatures on the attestation.
func (att *ModuleAttestation) Verify(publicKeys map[string]ed25519.PublicKey) error {
	attHash, err := att.computeHash()
	if err != nil {
		return fmt.Errorf("failed to compute attestation hash: %w", err)
	}

	for i, sig := range att.Signatures {
		pubKey, ok := publicKeys[sig.SignerID]
		if !ok {
			return fmt.Errorf("unknown signer: %s", sig.SignerID)
		}

		sigBytes, err := base64.StdEncoding.DecodeString(sig.Signature)
		if err != nil {
			return fmt.Errorf("invalid signature encoding for signature %d: %w", i, err)
		}

		if !ed25519.Verify(pubKey, attHash, sigBytes) {
			return fmt.Errorf("signature verification failed for signer %s", sig.SignerID)
		}
	}

	return nil
}

// computeHash computes the canonical hash of the attestation (excluding signatures).
func (att *ModuleAttestation) computeHash() ([]byte, error) {
	// Create a copy without signatures for hashing
	//nolint:govet // fieldalignment: anonymous struct layout is intentional
	hashable := struct {
		AttestationID string               `json:"attestation_id"`
		Version       string               `json:"version"`
		Module        ModuleIdentity       `json:"module"`
		Provenance    BuildProvenance      `json:"provenance"`
		Certification CertificationResults `json:"certification"`
		CreatedAt     time.Time            `json:"created_at"`
	}{
		AttestationID: att.AttestationID,
		Version:       att.Version,
		Module:        att.Module,
		Provenance:    att.Provenance,
		Certification: att.Certification,
		CreatedAt:     att.CreatedAt,
	}

	//nolint:wrapcheck // internal method, error context is clear
	data, err := json.Marshal(hashable)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(data)
	return hash[:], nil
}

// ComputeArtifactHash and VerifyArtifactHash removed - were dead code
