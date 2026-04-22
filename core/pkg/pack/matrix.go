package pack

import (
	"fmt"

	"github.com/Masterminds/semver/v3"
)

// CheckCompatibility verifies if a pack is compatible with the given kernel version.
// Users build on standards (compatibility matrix) instead of just the repo.
func CheckCompatibility(manifest PackManifest, kernelVersion string) error {
	if manifest.ApplicabilityConstraints == nil || manifest.ApplicabilityConstraints.KernelVersion == "" {
		// No constraint specified, assume compatible (or default to stricter policy if needed)
		return nil
	}

	constraint, err := semver.NewConstraint(manifest.ApplicabilityConstraints.KernelVersion)
	if err != nil {
		return fmt.Errorf("invalid kernel version constraint in pack %s: %w", manifest.PackID, err)
	}

	kernelV, err := semver.NewVersion(kernelVersion)
	if err != nil {
		return fmt.Errorf("invalid kernel version %s: %w", kernelVersion, err)
	}

	if !constraint.Check(kernelV) {
		return fmt.Errorf("pack %s requires kernel %s, but running %s", manifest.PackID, manifest.ApplicabilityConstraints.KernelVersion, kernelVersion)
	}

	return nil
}

// CheckDependency verifies if a required dependency is present and satisfies the version constraint.
func CheckDependency(dep PackDependency, installedPacks []PackVersion) error {
	found := false
	for _, installed := range installedPacks {
		if installed.PackName == dep.PackName {
			found = true
			constraint, err := semver.NewConstraint(dep.VersionSpec)
			if err != nil {
				return fmt.Errorf("invalid dependency constraint for %s: %w", dep.PackName, err)
			}

			installedV, err := semver.NewVersion(installed.Version)
			if err != nil {
				return fmt.Errorf("invalid installed version of %s: %w", dep.PackName, err)
			}

			if !constraint.Check(installedV) {
				return fmt.Errorf("dependency %s requires version %s, but found %s", dep.PackName, dep.VersionSpec, installed.Version)
			}
			break
		}
	}

	if !found && !dep.Optional {
		return fmt.Errorf("missing required dependency: %s", dep.PackName)
	}

	return nil
}
