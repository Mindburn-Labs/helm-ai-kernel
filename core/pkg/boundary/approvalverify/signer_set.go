package approvalverify

import (
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// ComputeSignerSetHash validates a canonical verifier-derived signer set and
// returns the exact hash committed by VerifiedApprovalRef. Signers must already
// use the portable canonical order; callers may not repair persisted evidence
// by silently sorting it at read time.
func ComputeSignerSetHash(
	challengeHash string,
	authoritySnapshotHash string,
	requiredRole string,
	signers []VerifiedSigner,
) (string, error) {
	if !canonicalSHA256Ref(challengeHash) || !canonicalSHA256Ref(authoritySnapshotHash) {
		return "", verificationFailed("signer set binding hashes are invalid")
	}
	if requiredRole == "" || strings.IndexFunc(requiredRole, unicode.IsSpace) >= 0 {
		return "", verificationFailed("signer set required role is invalid")
	}
	if len(signers) == 0 {
		return "", verificationFailed("signer set is empty")
	}

	seenPrincipals := make(map[string]struct{}, len(signers))
	seenCredentials := make(map[string]struct{}, len(signers))
	seenDevices := make(map[string]struct{}, len(signers))
	seenKeys := make(map[string]struct{}, len(signers))
	for index, signer := range signers {
		if !contracts.IsApprovalSignerIdentifier(signer.PrincipalID) ||
			!contracts.IsApprovalSignerIdentifier(signer.CredentialID) ||
			!contracts.IsApprovalSignerIdentifier(signer.DeviceID) ||
			!contracts.IsApprovalSignerIdentifier(signer.KeyID) {
			return "", verificationFailed("signer set identity is invalid")
		}
		if signer.Role != requiredRole || !canonicalSHA256Ref(signer.AssertionHash) {
			return "", verificationFailed("signer set role or assertion hash is invalid")
		}
		if _, exists := seenPrincipals[signer.PrincipalID]; exists {
			return "", duplicateSigner("principal_id", signer.PrincipalID)
		}
		if _, exists := seenCredentials[signer.CredentialID]; exists {
			return "", duplicateSigner("credential_id", signer.CredentialID)
		}
		if _, exists := seenDevices[signer.DeviceID]; exists {
			return "", duplicateSigner("device_id", signer.DeviceID)
		}
		if _, exists := seenKeys[signer.KeyID]; exists {
			return "", duplicateSigner("key_id", signer.KeyID)
		}
		if index > 0 && !verifiedSignerLess(signers[index-1], signer) {
			return "", verificationFailed("signer set is not in canonical order")
		}
		seenPrincipals[signer.PrincipalID] = struct{}{}
		seenCredentials[signer.CredentialID] = struct{}{}
		seenDevices[signer.DeviceID] = struct{}{}
		seenKeys[signer.KeyID] = struct{}{}
	}

	hash, err := canonicalize.CanonicalHash(struct {
		Domain                string           `json:"domain"`
		ChallengeHash         string           `json:"challenge_hash"`
		AuthoritySnapshotHash string           `json:"authority_snapshot_hash"`
		Signers               []VerifiedSigner `json:"signers"`
	}{
		Domain:                "HELM/ApprovalSignerSet/v1",
		ChallengeHash:         challengeHash,
		AuthoritySnapshotHash: authoritySnapshotHash,
		Signers:               signers,
	})
	if err != nil {
		return "", fmt.Errorf("%w: signer set canonicalization failed", ErrVerificationFailed)
	}
	return "sha256:" + hash, nil
}

func verifiedSignerLess(left, right VerifiedSigner) bool {
	if left.PrincipalID != right.PrincipalID {
		return left.PrincipalID < right.PrincipalID
	}
	if left.CredentialID != right.CredentialID {
		return left.CredentialID < right.CredentialID
	}
	if left.DeviceID != right.DeviceID {
		return left.DeviceID < right.DeviceID
	}
	return left.KeyID < right.KeyID
}

func canonicalSHA256Ref(value string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	raw := strings.TrimPrefix(value, prefix)
	if len(raw) != 64 || strings.ToLower(raw) != raw {
		return false
	}
	decoded, err := hex.DecodeString(raw)
	return err == nil && len(decoded) == 32
}
