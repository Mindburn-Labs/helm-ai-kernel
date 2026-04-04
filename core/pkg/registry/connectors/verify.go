package connectors

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// VerifyRelease checks that the release's BinaryHash matches the SHA-256
// digest of binaryData, and that the SignatureRef is non-empty.
// Fail-closed: any mismatch or missing field returns an error.
func VerifyRelease(release ConnectorRelease, binaryData []byte) error {
	if release.ConnectorID == "" {
		return fmt.Errorf("connector release: connector_id is empty (fail-closed)")
	}
	if release.BinaryHash == "" {
		return fmt.Errorf("connector %q: binary_hash is empty (fail-closed)", release.ConnectorID)
	}
	if release.SignatureRef == "" {
		return fmt.Errorf("connector %q: signature_ref is empty (fail-closed)", release.ConnectorID)
	}
	if len(binaryData) == 0 {
		return fmt.Errorf("connector %q: binary data is empty (fail-closed)", release.ConnectorID)
	}

	hash := sha256.Sum256(binaryData)
	computed := hex.EncodeToString(hash[:])

	if computed != release.BinaryHash {
		return fmt.Errorf("connector %q: binary hash mismatch: expected %s, got %s", release.ConnectorID, release.BinaryHash, computed)
	}

	return nil
}
