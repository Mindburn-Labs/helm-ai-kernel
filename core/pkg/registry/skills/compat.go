package skills

import (
	"fmt"

	semver "github.com/Masterminds/semver/v3"
)

// CheckCompatibility performs a full compatibility check for a skill manifest
// against the running environment. It verifies:
//   - All required_packs are present in availablePacks
//   - All required_connectors are present in availableConnectors
//   - The kernel version falls within [min_kernel_version, max_kernel_version]
//
// Fail-closed: any missing dependency or version constraint violation returns an error.
func CheckCompatibility(
	manifest SkillManifest,
	runtimeVersion, kernelVersion string,
	availablePacks, availableConnectors []string,
) error {
	// Build lookup sets.
	packSet := make(map[string]bool, len(availablePacks))
	for _, p := range availablePacks {
		packSet[p] = true
	}

	connSet := make(map[string]bool, len(availableConnectors))
	for _, c := range availableConnectors {
		connSet[c] = true
	}

	// Check required packs.
	for _, req := range manifest.Compatibility.RequiredPacks {
		if !packSet[req] {
			return fmt.Errorf("skill %q: required pack %q is not available (fail-closed)", manifest.ID, req)
		}
	}

	// Check required connectors.
	for _, req := range manifest.Compatibility.RequiredConnectors {
		if !connSet[req] {
			return fmt.Errorf("skill %q: required connector %q is not available (fail-closed)", manifest.ID, req)
		}
	}

	// Validate kernel version range.
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
		return fmt.Errorf("skill %q: kernel version %s is below minimum %s (fail-closed)", manifest.ID, kernelVersion, manifest.Compatibility.MinKernelVersion)
	}

	if manifest.Compatibility.MaxKernelVersion != "" {
		maxKernel, err := semver.NewVersion(manifest.Compatibility.MaxKernelVersion)
		if err != nil {
			return fmt.Errorf("skill %q: invalid max_kernel_version %q: %w", manifest.ID, manifest.Compatibility.MaxKernelVersion, err)
		}

		if actualKernel.GreaterThan(maxKernel) {
			return fmt.Errorf("skill %q: kernel version %s exceeds maximum %s (fail-closed)", manifest.ID, kernelVersion, manifest.Compatibility.MaxKernelVersion)
		}
	}

	return nil
}
