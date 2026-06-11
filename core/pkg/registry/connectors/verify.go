package connectors

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// VerifyRelease checks that the release's BinaryHash matches the SHA-256
// digest of binaryData, then fails closed unless the caller uses
// VerifyReleaseWithSignature with a trusted signature proof.
func VerifyRelease(release ConnectorRelease, binaryData []byte) error {
	if _, err := verifyReleaseHash(release, binaryData); err != nil {
		return err
	}
	return fmt.Errorf("connector %q: trusted signature proof is required (fail-closed)", release.ConnectorID)
}

// TrustedSignatureProof is produced by a trust resolver after cryptographic
// verification of SignatureRef against trusted publisher material.
type TrustedSignatureProof struct {
	SignatureRef string `json:"signature_ref"`
	SignerID     string `json:"signer_id"`
	SubjectHash  string `json:"subject_hash"`
	Verified     bool   `json:"verified"`
}

// VerifyReleaseWithSignature checks binary integrity and requires an external
// signature proof bound to the computed binary hash and release SignatureRef.
func VerifyReleaseWithSignature(release ConnectorRelease, binaryData []byte, proof TrustedSignatureProof) error {
	computed, err := verifyReleaseHash(release, binaryData)
	if err != nil {
		return err
	}
	if !proof.Verified {
		return fmt.Errorf("connector %q: signature proof is not verified (fail-closed)", release.ConnectorID)
	}
	if proof.SignerID == "" {
		return fmt.Errorf("connector %q: signature proof signer_id is empty (fail-closed)", release.ConnectorID)
	}
	if proof.SignatureRef != release.SignatureRef {
		return fmt.Errorf("connector %q: signature proof ref mismatch (fail-closed)", release.ConnectorID)
	}
	if proof.SubjectHash != computed {
		return fmt.Errorf("connector %q: signature proof subject hash mismatch (fail-closed)", release.ConnectorID)
	}
	return nil
}

func verifyReleaseHash(release ConnectorRelease, binaryData []byte) (string, error) {
	if release.ConnectorID == "" {
		return "", fmt.Errorf("connector release: connector_id is empty (fail-closed)")
	}
	if release.BinaryHash == "" {
		return "", fmt.Errorf("connector %q: binary_hash is empty (fail-closed)", release.ConnectorID)
	}
	if release.SignatureRef == "" {
		return "", fmt.Errorf("connector %q: signature_ref is empty (fail-closed)", release.ConnectorID)
	}
	if len(binaryData) == 0 {
		return "", fmt.Errorf("connector %q: binary data is empty (fail-closed)", release.ConnectorID)
	}

	hash := sha256.Sum256(binaryData)
	computed := hex.EncodeToString(hash[:])

	if computed != release.BinaryHash {
		return "", fmt.Errorf("connector %q: binary hash mismatch: expected %s, got %s", release.ConnectorID, release.BinaryHash, computed)
	}

	return computed, nil
}
