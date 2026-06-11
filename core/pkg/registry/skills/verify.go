package skills

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	semver "github.com/Masterminds/semver/v3"
)

// VerifyBundle checks bundle integrity, then fails closed unless the caller
// uses VerifyBundleWithSignature with a trusted signature proof.
func VerifyBundle(manifest SkillManifest, bundleData []byte) error {
	if _, err := verifyBundleHash(manifest, bundleData); err != nil {
		return err
	}
	return fmt.Errorf("skill %q: trusted signature proof is required (fail-closed)", manifest.ID)
}

// TrustedSignatureProof is produced by a trust resolver after cryptographic
// verification of SignatureRef against trusted publisher material.
type TrustedSignatureProof struct {
	SignatureRef string `json:"signature_ref"`
	SignerID     string `json:"signer_id"`
	SubjectHash  string `json:"subject_hash"`
	Verified     bool   `json:"verified"`
}

// VerifyBundleWithSignature checks bundle integrity and requires an external
// signature proof bound to the computed bundle hash and manifest SignatureRef.
func VerifyBundleWithSignature(manifest SkillManifest, bundleData []byte, proof TrustedSignatureProof) error {
	computed, err := verifyBundleHash(manifest, bundleData)
	if err != nil {
		return err
	}
	if manifest.SignatureRef == "" {
		return fmt.Errorf("skill %q: signature_ref is empty (fail-closed)", manifest.ID)
	}
	if !proof.Verified {
		return fmt.Errorf("skill %q: signature proof is not verified (fail-closed)", manifest.ID)
	}
	if proof.SignerID == "" {
		return fmt.Errorf("skill %q: signature proof signer_id is empty (fail-closed)", manifest.ID)
	}
	if proof.SignatureRef != manifest.SignatureRef {
		return fmt.Errorf("skill %q: signature proof ref mismatch (fail-closed)", manifest.ID)
	}
	if proof.SubjectHash != computed {
		return fmt.Errorf("skill %q: signature proof subject hash mismatch (fail-closed)", manifest.ID)
	}
	return nil
}

func verifyBundleHash(manifest SkillManifest, bundleData []byte) (string, error) {
	if manifest.BundleHash == "" {
		return "", fmt.Errorf("skill %q: bundle_hash is empty (fail-closed)", manifest.ID)
	}
	if len(bundleData) == 0 {
		return "", fmt.Errorf("skill %q: bundle data is empty (fail-closed)", manifest.ID)
	}

	hash := sha256.Sum256(bundleData)
	computed := "sha256:" + hex.EncodeToString(hash[:])

	// Also accept bare hex for backwards compatibility.
	bare := hex.EncodeToString(hash[:])
	if computed != manifest.BundleHash && bare != manifest.BundleHash {
		return "", fmt.Errorf("skill %q: bundle hash mismatch: expected %s, got %s", manifest.ID, manifest.BundleHash, computed)
	}

	return computed, nil
}

// VerifyCompatibility checks that the manifest's kernel version constraints
// are satisfied by the given runtime and kernel versions. Both runtimeVersion
// and kernelVersion must be valid semver strings. Fail-closed: any parse
// failure or constraint violation returns an error.
func VerifyCompatibility(manifest SkillManifest, runtimeVersion, kernelVersion string) error {
	if manifest.Compatibility.RuntimeSpecVersion == "" {
		return fmt.Errorf("skill %q: runtime_spec_version is empty (fail-closed)", manifest.ID)
	}

	// Validate runtime spec version matches.
	reqRuntime, err := semver.NewVersion(manifest.Compatibility.RuntimeSpecVersion)
	if err != nil {
		return fmt.Errorf("skill %q: invalid runtime_spec_version %q: %w", manifest.ID, manifest.Compatibility.RuntimeSpecVersion, err)
	}

	actualRuntime, err := semver.NewVersion(runtimeVersion)
	if err != nil {
		return fmt.Errorf("skill %q: invalid runtime version %q: %w", manifest.ID, runtimeVersion, err)
	}

	if !actualRuntime.Equal(reqRuntime) {
		return fmt.Errorf("skill %q: runtime version %s does not match required %s", manifest.ID, runtimeVersion, manifest.Compatibility.RuntimeSpecVersion)
	}

	// Validate kernel version is within min/max range.
	if manifest.Compatibility.MinKernelVersion == "" {
		return fmt.Errorf("skill %q: min_kernel_version is empty (fail-closed)", manifest.ID)
	}

	minKernel, err := semver.NewVersion(manifest.Compatibility.MinKernelVersion)
	if err != nil {
		return fmt.Errorf("skill %q: invalid min_kernel_version %q: %w", manifest.ID, manifest.Compatibility.MinKernelVersion, err)
	}

	actualKernel, err := semver.NewVersion(kernelVersion)
	if err != nil {
		return fmt.Errorf("skill %q: invalid kernel version %q: %w", manifest.ID, kernelVersion, err)
	}

	if actualKernel.LessThan(minKernel) {
		return fmt.Errorf("skill %q: kernel version %s is below minimum %s", manifest.ID, kernelVersion, manifest.Compatibility.MinKernelVersion)
	}

	if manifest.Compatibility.MaxKernelVersion != "" {
		maxKernel, err := semver.NewVersion(manifest.Compatibility.MaxKernelVersion)
		if err != nil {
			return fmt.Errorf("skill %q: invalid max_kernel_version %q: %w", manifest.ID, manifest.Compatibility.MaxKernelVersion, err)
		}

		if actualKernel.GreaterThan(maxKernel) {
			return fmt.Errorf("skill %q: kernel version %s exceeds maximum %s", manifest.ID, kernelVersion, manifest.Compatibility.MaxKernelVersion)
		}
	}

	return nil
}
