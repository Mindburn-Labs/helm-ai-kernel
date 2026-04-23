// Package pack — Formal compatibility matrix specification.
//
// Per HELM 2030 Spec §5.1:
//
//	HELM MUST include compatibility versioning with a formal matrix.
//
// Resolves: GAP-A1. Extends existing CheckCompatibility/CheckDependency
// with a typed, queryable CompatibilityMatrix.
package pack

import (
	"time"

	"github.com/Masterminds/semver/v3"
)

// CompatibilityMatrix is a versioned record of what components are
// compatible with each other across the HELM ecosystem.
type CompatibilityMatrix struct {
	MatrixID    string               `json:"matrix_id"`
	Version     string               `json:"version"`
	Entries     []CompatibilityEntry `json:"entries"`
	PublishedAt time.Time            `json:"published_at"`
	PublishedBy string               `json:"published_by"`
}

// CompatibilityEntry records compatibility between two components.
type CompatibilityEntry struct {
	ComponentA string       `json:"component_a"` // e.g. "kernel"
	VersionA   string       `json:"version_a"`   // semver range, e.g. ">=1.2.0"
	ComponentB string       `json:"component_b"` // e.g. "sdk-ts"
	VersionB   string       `json:"version_b"`   // semver range
	Status     CompatStatus `json:"status"`
	Notes      string       `json:"notes,omitempty"`
	TestedAt   time.Time    `json:"tested_at"`
}

// CompatStatus records whether two versions are compatible.
type CompatStatus string

const (
	CompatFull       CompatStatus = "FULL"       // fully compatible
	CompatPartial    CompatStatus = "PARTIAL"    // works with known limitations
	CompatBroken     CompatStatus = "BROKEN"     // known incompatibility
	CompatUntested   CompatStatus = "UNTESTED"   // no data
	CompatDeprecated CompatStatus = "DEPRECATED" // works but version is deprecated
)

// IsCompatible checks if two component versions are compatible in the matrix.
func (m *CompatibilityMatrix) IsCompatible(compA, verA, compB, verB string) CompatStatus {
	for _, e := range m.Entries {
		if e.ComponentA == compA && e.ComponentB == compB {
			if matchesConstraint(e.VersionA, verA) && matchesConstraint(e.VersionB, verB) {
				return e.Status
			}
		}
		// Check reverse direction
		if e.ComponentA == compB && e.ComponentB == compA {
			if matchesConstraint(e.VersionA, verB) && matchesConstraint(e.VersionB, verA) {
				return e.Status
			}
		}
	}
	return CompatUntested
}

func matchesConstraint(constraint, version string) bool {
	c, err := semver.NewConstraint(constraint)
	if err != nil {
		return false
	}
	v, err := semver.NewVersion(version)
	if err != nil {
		return false
	}
	return c.Check(v)
}
