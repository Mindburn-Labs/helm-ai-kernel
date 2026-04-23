package skills

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Install adds a skill bundle to the store after verifying its integrity.
// Fail-closed: the bundle hash must match the SHA-256 of bundleData,
// the signature_ref must be non-empty, and the manifest ID must be set.
// On success the manifest is stored with state forced to candidate.
func Install(ctx context.Context, store SkillStore, manifest SkillManifest, bundleData []byte) error {
	if store == nil {
		return fmt.Errorf("skill store is nil (fail-closed)")
	}
	if manifest.ID == "" {
		return fmt.Errorf("skill manifest ID is required (fail-closed)")
	}
	if manifest.BundleHash == "" {
		return fmt.Errorf("skill %q: bundle_hash is required (fail-closed)", manifest.ID)
	}
	if len(bundleData) == 0 {
		return fmt.Errorf("skill %q: bundle data is empty (fail-closed)", manifest.ID)
	}

	// Verify bundle hash (accepts both sha256: prefixed and bare hex).
	hash := sha256.Sum256(bundleData)
	prefixed := "sha256:" + hex.EncodeToString(hash[:])
	bare := hex.EncodeToString(hash[:])
	if prefixed != manifest.BundleHash && bare != manifest.BundleHash {
		return fmt.Errorf("skill %q: bundle hash mismatch: expected %s, got %s (fail-closed)", manifest.ID, manifest.BundleHash, prefixed)
	}

	// Verify signature_ref is present (actual signature validation is handled by VerifyBundle / external verifier).
	if manifest.SignatureRef == "" {
		return fmt.Errorf("skill %q: signature_ref is required (fail-closed)", manifest.ID)
	}

	// Force state to candidate on install.
	manifest.State = SkillBundleStateCandidate

	if err := store.Put(ctx, manifest); err != nil {
		return fmt.Errorf("skill %q: failed to store manifest: %w", manifest.ID, err)
	}

	return nil
}
