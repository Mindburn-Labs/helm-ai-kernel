package approvalceremony

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

// CeremonyCommitment binds the immutable challenge specification, issued
// challenge, and verified signer set without assigning durable storage
// ownership to the Kernel package.
func CeremonyCommitment(record Record) (string, error) {
	payload, err := ceremonyCommitmentPayload(record)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(hash[:]), nil
}

func ceremonyCommitmentPayload(record Record) ([]byte, error) {
	if record.Challenge == nil || record.VerifiedRef == nil {
		return nil, invalidRecord("ceremony commitment requires challenge and verified_ref")
	}
	if !validToken(record.ApprovalID) || !validToken(record.TenantID) || !validToken(record.WorkspaceID) {
		return nil, invalidRecord("ceremony commitment record scope is invalid")
	}
	if err := record.Spec.Validate(); err != nil {
		return nil, err
	}
	if record.Spec.TenantID != record.TenantID || record.Spec.WorkspaceID != record.WorkspaceID {
		return nil, invalidRecord("ceremony commitment challenge_spec scope mismatch")
	}
	if err := validateChallenge(record, *record.Challenge); err != nil {
		return nil, err
	}
	if err := validateVerifiedRef(*record.Challenge, *record.VerifiedRef); err != nil {
		return nil, err
	}
	specHash, err := canonicalize.CanonicalHash(record.Spec)
	if err != nil {
		return nil, fmt.Errorf("commit approval challenge spec: %w", err)
	}
	payload, err := canonicalize.JCS(struct {
		Domain            string    `json:"domain"`
		ApprovalID        string    `json:"approval_id"`
		TenantID          string    `json:"tenant_id"`
		WorkspaceID       string    `json:"workspace_id"`
		ChallengeSpecHash string    `json:"challenge_spec_hash"`
		ChallengeHash     string    `json:"challenge_hash"`
		SignerSetHash     string    `json:"signer_set_hash"`
		VerifiedAt        time.Time `json:"verified_at"`
	}{
		Domain: "HELM/ApprovalCeremonyCommitment/v1", ApprovalID: record.ApprovalID,
		TenantID: record.TenantID, WorkspaceID: record.WorkspaceID,
		ChallengeSpecHash: "sha256:" + specHash, ChallengeHash: record.Challenge.ChallengeHash,
		SignerSetHash: record.VerifiedRef.SignerSetHash,
		VerifiedAt:    record.VerifiedRef.VerifiedAt,
	})
	if err != nil {
		return nil, fmt.Errorf("commit approval ceremony: %w", err)
	}
	return payload, nil
}
