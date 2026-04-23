// Package versioning provides semantic versioning for HELM public APIs.
// This package implements SemVer 2.0.0 (https://semver.org) for API versioning.
package versioning

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Version represents a semantic version following SemVer 2.0.0.
type Version struct {
	Major      int    `json:"major"`
	Minor      int    `json:"minor"`
	Patch      int    `json:"patch"`
	Prerelease string `json:"prerelease,omitempty"`
	Build      string `json:"build,omitempty"`
}

// String returns the string representation of the version.
func (v Version) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Prerelease != "" {
		s += "-" + v.Prerelease
	}
	if v.Build != "" {
		s += "+" + v.Build
	}
	return s
}

// Parse parses a version string into a Version struct.
func Parse(version string) (*Version, error) {
	// Regex for semantic versioning
	re := regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z\-\.]+))?(?:\+([0-9A-Za-z\-\.]+))?$`)
	matches := re.FindStringSubmatch(version)
	if matches == nil {
		return nil, fmt.Errorf("invalid version string: %s", version)
	}

	major, _ := strconv.Atoi(matches[1])
	minor, _ := strconv.Atoi(matches[2])
	patch, _ := strconv.Atoi(matches[3])

	return &Version{
		Major:      major,
		Minor:      minor,
		Patch:      patch,
		Prerelease: matches[4],
		Build:      matches[5],
	}, nil
}

// Compare compares two versions.
// Returns -1 if v < other, 0 if v == other, 1 if v > other.
func (v Version) Compare(other Version) int {
	if v.Major != other.Major {
		return compareInt(v.Major, other.Major)
	}
	if v.Minor != other.Minor {
		return compareInt(v.Minor, other.Minor)
	}
	if v.Patch != other.Patch {
		return compareInt(v.Patch, other.Patch)
	}
	// Pre-release versions have lower precedence
	if v.Prerelease != "" && other.Prerelease == "" {
		return -1
	}
	if v.Prerelease == "" && other.Prerelease != "" {
		return 1
	}
	return strings.Compare(v.Prerelease, other.Prerelease)
}

func compareInt(a, b int) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// IsCompatible checks if other version is compatible with v (same major version).
func (v Version) IsCompatible(other Version) bool {
	return v.Major == other.Major
}

// IncrementMajor returns a new version with major incremented.
func (v Version) IncrementMajor() Version {
	return Version{Major: v.Major + 1, Minor: 0, Patch: 0}
}

// IncrementMinor returns a new version with minor incremented.
func (v Version) IncrementMinor() Version {
	return Version{Major: v.Major, Minor: v.Minor + 1, Patch: 0}
}

// IncrementPatch returns a new version with patch incremented.
func (v Version) IncrementPatch() Version {
	return Version{Major: v.Major, Minor: v.Minor, Patch: v.Patch + 1}
}

// ===== API Version Registry =====

// APIRegistry tracks versioned APIs and their lifecycle.
type APIRegistry struct {
	APIs map[string]*APIDefinition `json:"apis"`
}

// APIDefinition describes a versioned API endpoint or package.
type APIDefinition struct {
	Name           string          `json:"name"`
	Description    string          `json:"description"`
	CurrentVersion Version         `json:"current_version"`
	Versions       []APIVersion    `json:"versions"`
	DeprecatedAPIs []DeprecatedAPI `json:"deprecated_apis,omitempty"`
	Stability      StabilityLevel  `json:"stability"`
	LastUpdated    time.Time       `json:"last_updated"`
}

// APIVersion tracks a specific version of an API.
type APIVersion struct {
	Version    Version   `json:"version"`
	ReleasedAt time.Time `json:"released_at"`
	Changelog  string    `json:"changelog"`
	Breaking   bool      `json:"breaking"`
	Deprecates []string  `json:"deprecates,omitempty"`
}

// StabilityLevel indicates API stability.
type StabilityLevel string

const (
	StabilityExperimental StabilityLevel = "EXPERIMENTAL"
	StabilityBeta         StabilityLevel = "BETA"
	StabilityStable       StabilityLevel = "STABLE"
	StabilityDeprecated   StabilityLevel = "DEPRECATED"
)

// DeprecatedAPI describes deprecated functionality.
type DeprecatedAPI struct {
	Name           string    `json:"name"`
	DeprecatedIn   Version   `json:"deprecated_in"`
	RemovalTarget  *Version  `json:"removal_target,omitempty"`
	Replacement    string    `json:"replacement,omitempty"`
	Reason         string    `json:"reason"`
	DeprecatedAt   time.Time `json:"deprecated_at"`
	MigrationGuide string    `json:"migration_guide,omitempty"`
}

// NewAPIRegistry creates a new API registry.
func NewAPIRegistry() *APIRegistry {
	return &APIRegistry{
		APIs: make(map[string]*APIDefinition),
	}
}

// RegisterAPI registers a new API.
func (r *APIRegistry) RegisterAPI(api *APIDefinition) {
	r.APIs[api.Name] = api
}

// GetAPI retrieves an API definition.
func (r *APIRegistry) GetAPI(name string) (*APIDefinition, bool) {
	api, ok := r.APIs[name]
	return api, ok
}

// ListDeprecated returns all deprecated APIs.
func (r *APIRegistry) ListDeprecated() []DeprecatedAPI {
	var deprecated []DeprecatedAPI
	for _, api := range r.APIs {
		deprecated = append(deprecated, api.DeprecatedAPIs...)
	}
	return deprecated
}

// AddVersion adds a new version to an API.
func (api *APIDefinition) AddVersion(version APIVersion) {
	api.Versions = append(api.Versions, version)
	if version.Version.Compare(api.CurrentVersion) > 0 {
		api.CurrentVersion = version.Version
	}
	api.LastUpdated = time.Now()
}

// MarkDeprecated marks an API element as deprecated.
func (api *APIDefinition) MarkDeprecated(deprecated DeprecatedAPI) {
	deprecated.DeprecatedAt = time.Now()
	api.DeprecatedAPIs = append(api.DeprecatedAPIs, deprecated)
}

// ===== HELM API Versions =====

// HELMAPIs returns the current HELM public API definitions.
func HELMAPIs() *APIRegistry {
	registry := NewAPIRegistry()

	// Core Governance API
	registry.RegisterAPI(&APIDefinition{
		Name:           "governance",
		Description:    "HELM Governance API",
		CurrentVersion: Version{Major: 1, Minor: 5, Patch: 0},
		Stability:      StabilityStable,
		Versions: []APIVersion{
			{
				Version:    Version{Major: 1, Minor: 0, Patch: 0},
				ReleasedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				Changelog:  "Initial release",
			},
			{
				Version:    Version{Major: 1, Minor: 5, Patch: 0},
				ReleasedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				Changelog:  "v1.5 compliance release with pack merge ambiguity detection",
			},
		},
		LastUpdated: time.Now(),
	})

	// Kernel API
	registry.RegisterAPI(&APIDefinition{
		Name:           "kernel",
		Description:    "HELM Kernel API (CSNF, ConsistencyToken)",
		CurrentVersion: Version{Major: 1, Minor: 5, Patch: 0},
		Stability:      StabilityStable,
		Versions: []APIVersion{
			{
				Version:    Version{Major: 1, Minor: 5, Patch: 0},
				ReleasedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				Changelog:  "Native CSNF with ConsistencyToken integration",
			},
		},
		LastUpdated: time.Now(),
	})

	// Policy PDP API
	registry.RegisterAPI(&APIDefinition{
		Name:           "policy/pdp",
		Description:    "Policy Decision Point API",
		CurrentVersion: Version{Major: 2, Minor: 0, Patch: 0},
		Stability:      StabilityStable,
		Versions: []APIVersion{
			{
				Version:    Version{Major: 1, Minor: 0, Patch: 0},
				ReleasedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				Changelog:  "Initial CEL-based PDP",
			},
			{
				Version:    Version{Major: 2, Minor: 0, Patch: 0},
				ReleasedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				Changelog:  "Breaking: Unified PDP with delegation",
				Breaking:   true,
			},
		},
		DeprecatedAPIs: []DeprecatedAPI{
			{
				Name:           "EvaluateSingle",
				DeprecatedIn:   Version{Major: 2, Minor: 0, Patch: 0},
				RemovalTarget:  &Version{Major: 3, Minor: 0, Patch: 0},
				Replacement:    "EvaluateBatch",
				Reason:         "Performance optimization, batching preferred",
				MigrationGuide: "Replace EvaluateSingle(ctx, req) with EvaluateBatch(ctx, []req)[0]",
			},
		},
		LastUpdated: time.Now(),
	})

	// Crypto API
	registry.RegisterAPI(&APIDefinition{
		Name:           "crypto",
		Description:    "Cryptographic primitives API",
		CurrentVersion: Version{Major: 2, Minor: 0, Patch: 0},
		Stability:      StabilityStable,
		Versions: []APIVersion{
			{
				Version:    Version{Major: 1, Minor: 0, Patch: 0},
				ReleasedAt: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
				Changelog:  "Initial crypto primitives",
			},
			{
				Version:    Version{Major: 2, Minor: 0, Patch: 0},
				ReleasedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				Changelog:  "Ed25519 native signing",
				Breaking:   true,
			},
		},
		DeprecatedAPIs: []DeprecatedAPI{
			{
				Name:           "LegacySigner",
				DeprecatedIn:   Version{Major: 2, Minor: 0, Patch: 0},
				RemovalTarget:  &Version{Major: 2, Minor: 1, Patch: 0},
				Replacement:    "crypto.NewEd25519Signer()",
				Reason:         "Replaced by canonical Ed25519 signing",
				MigrationGuide: "Use the canonical Ed25519 signer",
			},
		},
		LastUpdated: time.Now(),
	})

	// Compliance API
	registry.RegisterAPI(&APIDefinition{
		Name:           "compliance",
		Description:    "Regulatory compliance API (DORA, MiCA)",
		CurrentVersion: Version{Major: 1, Minor: 0, Patch: 0},
		Stability:      StabilityStable,
		Versions: []APIVersion{
			{
				Version:    Version{Major: 1, Minor: 0, Patch: 0},
				ReleasedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				Changelog:  "Initial release with DORA and MiCA support",
			},
		},
		LastUpdated: time.Now(),
	})

	return registry
}

// ToJSON exports the registry as JSON.
func (r *APIRegistry) ToJSON() ([]byte, error) {
	//nolint:wrapcheck // error context is clear from method name
	return json.MarshalIndent(r, "", "  ")
}
