// quantum_posture: provider certification uses classical Ed25519 signatures;
// this preview contract makes no hybrid or post-quantum certification claim.
package contracts

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

const (
	LaunchProviderCertificationSchemaVersion = "launch_provider_certification.v1"

	LaunchProviderCertificationActive  = "ACTIVE"
	LaunchProviderCertificationRevoked = "REVOKED"
)

// LaunchProviderCertificationRecord is source-owned certification evidence.
// A capability profile can reference this record, but cannot authorize itself:
// dispatch requires signature verification through a configured trust root and
// a current-record check against the owning certification registry.
type LaunchProviderCertificationRecord struct {
	SchemaVersion             string `json:"schema_version"`
	CertificationID           string `json:"certification_id"`
	ProfileRef                string `json:"profile_ref"`
	ProfileHash               string `json:"profile_hash"`
	ProviderID                string `json:"provider_id"`
	ConnectorID               string `json:"connector_id"`
	ConnectorContractHash     string `json:"connector_contract_hash"`
	CertificationTier         string `json:"certification_tier"`
	CertificationSuiteHash    string `json:"certification_suite_hash"`
	CertificationEvidenceHash string `json:"certification_evidence_hash"`
	AdmissionStatus           string `json:"admission_status"`
	IssuedAt                  string `json:"issued_at"`
	ExpiresAt                 string `json:"expires_at"`
	SignerKeyID               string `json:"signer_key_id"`
	RecordHash                string `json:"record_hash"`
	Signature                 string `json:"signature"`
}

// LaunchProviderCertificationSigningBytes is the RFC 8785 payload signed by
// the certification authority. RecordHash and Signature are excluded from the
// payload to avoid self-reference.
func LaunchProviderCertificationSigningBytes(record LaunchProviderCertificationRecord) ([]byte, error) {
	record.RecordHash = ""
	record.Signature = ""
	if err := validateLaunchProviderCertificationShape(record, false); err != nil {
		return nil, err
	}
	return canonicalize.JCS(record)
}

// SignLaunchProviderCertificationRecord exists for source-owned fixtures and
// certification tooling. Production signing remains certification-service
// owned and does not live in a provider connector.
func SignLaunchProviderCertificationRecord(record LaunchProviderCertificationRecord, privateKey ed25519.PrivateKey) (LaunchProviderCertificationRecord, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return record, errors.New("launch provider certification private key has invalid size")
	}
	payload, err := LaunchProviderCertificationSigningBytes(record)
	if err != nil {
		return record, err
	}
	record.RecordHash = canonicalize.ComputeArtifactHash(payload)
	record.Signature = "ed25519:" + hex.EncodeToString(ed25519.Sign(privateKey, payload))
	return record, nil
}

// VerifyLaunchProviderCertificationRecord proves content integrity, trust-root
// signature, active status, and the certification validity window. Callers
// must additionally prove this is the current non-revoked registry record.
func VerifyLaunchProviderCertificationRecord(record LaunchProviderCertificationRecord, publicKey ed25519.PublicKey, now time.Time) error {
	if err := validateLaunchProviderCertificationShape(record, true); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("launch provider certification public key has invalid size")
	}
	if record.AdmissionStatus != LaunchProviderCertificationActive {
		return errors.New("launch provider certification is not active")
	}
	issuedAt, _ := time.Parse(time.RFC3339Nano, record.IssuedAt)
	expiresAt, _ := time.Parse(time.RFC3339Nano, record.ExpiresAt)
	if now.IsZero() || now.Before(issuedAt) || !now.Before(expiresAt) {
		return errors.New("launch provider certification is not active at verification time")
	}
	payload, err := LaunchProviderCertificationSigningBytes(record)
	if err != nil {
		return err
	}
	expectedHash := canonicalize.ComputeArtifactHash(payload)
	if !launchConstantEqual(record.RecordHash, expectedHash) {
		return errors.New("launch provider certification record hash mismatch")
	}
	signature, err := parseLaunchProviderCertificationSignature(record.Signature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return errors.New("launch provider certification signature verification failed")
	}
	return nil
}

func validateLaunchProviderCertificationShape(record LaunchProviderCertificationRecord, sealed bool) error {
	if record.SchemaVersion != LaunchProviderCertificationSchemaVersion || record.CertificationID == "" || record.ProfileRef == "" || record.ProviderID == "" || record.ConnectorID == "" || record.CertificationTier == "" || record.SignerKeyID == "" {
		return errors.New("launch provider certification identity is incomplete")
	}
	for field, value := range map[string]string{
		"profile_hash":                record.ProfileHash,
		"connector_contract_hash":     record.ConnectorContractHash,
		"certification_suite_hash":    record.CertificationSuiteHash,
		"certification_evidence_hash": record.CertificationEvidenceHash,
	} {
		if !validLaunchSHA256(value) {
			return fmt.Errorf("launch provider certification %s is invalid", field)
		}
	}
	switch record.AdmissionStatus {
	case LaunchProviderCertificationActive, LaunchProviderCertificationRevoked:
	default:
		return errors.New("launch provider certification admission status is invalid")
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, record.IssuedAt)
	if err != nil {
		return errors.New("launch provider certification issue time is invalid")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, record.ExpiresAt)
	if err != nil || !issuedAt.Before(expiresAt) {
		return errors.New("launch provider certification expiry is invalid")
	}
	if sealed {
		if !validLaunchSHA256(record.RecordHash) {
			return errors.New("launch provider certification record hash is invalid")
		}
		if _, err := parseLaunchProviderCertificationSignature(record.Signature); err != nil {
			return err
		}
	} else if record.RecordHash != "" || record.Signature != "" {
		return errors.New("unsealed launch provider certification cannot carry hash or signature")
	}
	return nil
}

func parseLaunchProviderCertificationSignature(value string) ([]byte, error) {
	const prefix = "ed25519:"
	if !strings.HasPrefix(value, prefix) {
		return nil, errors.New("launch provider certification signature must use ed25519 prefix")
	}
	raw := strings.TrimPrefix(value, prefix)
	if len(raw) != ed25519.SignatureSize*2 || strings.ToLower(raw) != raw {
		return nil, errors.New("launch provider certification signature must be lowercase hex")
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != ed25519.SignatureSize {
		return nil, errors.New("launch provider certification signature is invalid")
	}
	return decoded, nil
}
