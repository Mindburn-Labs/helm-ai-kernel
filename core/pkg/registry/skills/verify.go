package skills

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	semver "github.com/Masterminds/semver/v3"
)

// VerifyBundle checks that the manifest's BundleHash matches the SHA-256
// digest of bundleData. Fail-closed: any mismatch returns an error.
func VerifyBundle(manifest SkillManifest, bundleData []byte) error {
	if manifest.BundleHash == "" {
		return fmt.Errorf("skill %q: bundle_hash is empty (fail-closed)", manifest.ID)
	}
	if len(bundleData) == 0 {
		return fmt.Errorf("skill %q: bundle data is empty (fail-closed)", manifest.ID)
	}

	hash := sha256.Sum256(bundleData)
	computed := "sha256:" + hex.EncodeToString(hash[:])

	// Also accept bare hex for backwards compatibility.
	bare := hex.EncodeToString(hash[:])
	if computed != manifest.BundleHash && bare != manifest.BundleHash {
		return fmt.Errorf("skill %q: bundle hash mismatch: expected %s, got %s", manifest.ID, manifest.BundleHash, computed)
	}

	return nil
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
