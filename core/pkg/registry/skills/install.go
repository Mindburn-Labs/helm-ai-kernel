package skills

import (
	"context"
	"fmt"
)

// Install is retained for compatibility, but fails closed because a caller
// must provide trusted signature proof. Use InstallVerified after resolving
// and cryptographically verifying manifest.SignatureRef.
func Install(ctx context.Context, store SkillStore, manifest SkillManifest, bundleData []byte) error {
	if err := validateInstallInputs(store, manifest, bundleData); err != nil {
		return err
	}
	if _, err := verifyBundleHash(manifest, bundleData); err != nil {
		return err
	}
	return fmt.Errorf("skill %q: trusted signature proof is required (fail-closed)", manifest.ID)
}

// InstallVerified adds a skill bundle to the store after verifying integrity
// and trusted signature proof. On success the manifest is stored as candidate.
func InstallVerified(ctx context.Context, store SkillStore, manifest SkillManifest, bundleData []byte, proof TrustedSignatureProof) error {
	if err := validateInstallInputs(store, manifest, bundleData); err != nil {
		return err
	}
	if err := VerifyBundleWithSignature(manifest, bundleData, proof); err != nil {
		return err
	}

	manifest.State = SkillBundleStateCandidate
	if err := store.Put(ctx, manifest); err != nil {
		return fmt.Errorf("skill %q: failed to store manifest: %w", manifest.ID, err)
	}

	return nil
}

func validateInstallInputs(store SkillStore, manifest SkillManifest, bundleData []byte) error {
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
	if manifest.SignatureRef == "" {
		return fmt.Errorf("skill %q: signature_ref is required (fail-closed)", manifest.ID)
	}
	return nil
}
