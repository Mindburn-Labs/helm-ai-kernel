// Package kernel provides interoperability constraints for HELM.
// Per HELM Normative Addendum v1.5 Sections K and L.
package kernel

import (
	"fmt"
)

// ============================================================================
// Section K: Inline Blob Size Constraints
// ============================================================================

// MaxInlineBytes is the maximum size for inline blob content.
// Per Section K.1: MAX_INLINE_BYTES constant.
const MaxInlineBytes = 4096 // 4 KiB

// InlineBlobPolicy defines the policy for oversized blobs.
type InlineBlobPolicy string

const (
	InlineBlobPolicyReject    InlineBlobPolicy = "REJECT"
	InlineBlobPolicyReference InlineBlobPolicy = "REFERENCE"
	InlineBlobPolicyTruncate  InlineBlobPolicy = "TRUNCATE"
)

// InlineBlobValidator validates blob sizes.
type InlineBlobValidator struct {
	MaxBytes int
	Policy   InlineBlobPolicy
}

// NewInlineBlobValidator creates a validator with default settings.
func NewInlineBlobValidator() *InlineBlobValidator {
	return &InlineBlobValidator{
		MaxBytes: MaxInlineBytes,
		Policy:   InlineBlobPolicyReject,
	}
}

// WithMaxBytes sets a custom max size.
func (v *InlineBlobValidator) WithMaxBytes(max int) *InlineBlobValidator {
	v.MaxBytes = max
	return v
}

// WithPolicy sets the oversized blob policy.
func (v *InlineBlobValidator) WithPolicy(policy InlineBlobPolicy) *InlineBlobValidator {
	v.Policy = policy
	return v
}

// InlineBlobResult represents the result of blob validation.
type InlineBlobResult struct {
	Valid         bool             `json:"valid"`
	OriginalSize  int              `json:"original_size"`
	PolicyApplied InlineBlobPolicy `json:"policy_applied,omitempty"`
	ReferenceID   string           `json:"reference_id,omitempty"` // For REFERENCE policy
	TruncatedTo   int              `json:"truncated_to,omitempty"` // For TRUNCATE policy
	Error         string           `json:"error,omitempty"`
}

// Validate checks if blob data is within limits.
func (v *InlineBlobValidator) Validate(data []byte) InlineBlobResult {
	size := len(data)

	if size <= v.MaxBytes {
		return InlineBlobResult{
			Valid:        true,
			OriginalSize: size,
		}
	}

	// Apply policy for oversized blobs
	switch v.Policy {
	case InlineBlobPolicyReject:
		return InlineBlobResult{
			Valid:         false,
			OriginalSize:  size,
			PolicyApplied: InlineBlobPolicyReject,
			Error:         fmt.Sprintf("blob size %d exceeds MAX_INLINE_BYTES (%d)", size, v.MaxBytes),
		}
	case InlineBlobPolicyReference:
		return InlineBlobResult{
			Valid:         false,
			OriginalSize:  size,
			PolicyApplied: InlineBlobPolicyReference,
			ReferenceID:   "", // Caller must generate reference
		}
	case InlineBlobPolicyTruncate:
		return InlineBlobResult{
			Valid:         true, // Truncation is valid
			OriginalSize:  size,
			PolicyApplied: InlineBlobPolicyTruncate,
			TruncatedTo:   v.MaxBytes,
		}
	default:
		return InlineBlobResult{
			Valid:        false,
			OriginalSize: size,
			Error:        "unknown policy",
		}
	}
}

// ValidateSize checks size only without policy application.
func ValidateInlineSize(size int) error {
	if size > MaxInlineBytes {
		return fmt.Errorf("blob size %d exceeds MAX_INLINE_BYTES (%d)", size, MaxInlineBytes)
	}
	return nil
}

// ============================================================================
// Section L: Schema Versioning and Compatibility
// ============================================================================

// SchemaVersionFormat is the version format pattern (SemVer).
const SchemaVersionFormat = "MAJOR.MINOR.PATCH"

// CompatibilityPolicy defines backward/forward compatibility.
type CompatibilityPolicy string

const (
	CompatibilityPolicyStrict   CompatibilityPolicy = "STRICT"   // Exact version match
	CompatibilityPolicyBackward CompatibilityPolicy = "BACKWARD" // Newer can read older
	CompatibilityPolicyForward  CompatibilityPolicy = "FORWARD"  // Older can read newer
	CompatibilityPolicyFull     CompatibilityPolicy = "FULL"     // Backward + Forward
)

// SchemaVersion represents a semantic version.
type SchemaVersion struct {
	Major int    `json:"major"`
	Minor int    `json:"minor"`
	Patch int    `json:"patch"`
	Label string `json:"label,omitempty"` // e.g., "-beta.1"
}

// ParseSchemaVersion parses a version string.
func ParseSchemaVersion(s string) (*SchemaVersion, error) {
	var major, minor, patch int
	var label string

	// Try parsing with label
	n, _ := fmt.Sscanf(s, "%d.%d.%d-%s", &major, &minor, &patch, &label)
	if n < 3 {
		// Try without label
		n, err := fmt.Sscanf(s, "%d.%d.%d", &major, &minor, &patch)
		if n < 3 || err != nil {
			return nil, fmt.Errorf("invalid schema version: %s (expected %s)", s, SchemaVersionFormat)
		}
	}

	return &SchemaVersion{
		Major: major,
		Minor: minor,
		Patch: patch,
		Label: label,
	}, nil
}

// String returns the version string.
func (v SchemaVersion) String() string {
	if v.Label != "" {
		return fmt.Sprintf("%d.%d.%d-%s", v.Major, v.Minor, v.Patch, v.Label)
	}
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// Compare compares two versions.
// Returns: -1 if v < other, 0 if v == other, 1 if v > other
func (v SchemaVersion) Compare(other SchemaVersion) int {
	if v.Major != other.Major {
		if v.Major < other.Major {
			return -1
		}
		return 1
	}
	if v.Minor != other.Minor {
		if v.Minor < other.Minor {
			return -1
		}
		return 1
	}
	if v.Patch != other.Patch {
		if v.Patch < other.Patch {
			return -1
		}
		return 1
	}
	return 0
}

// IsCompatible checks version compatibility based on policy.
func (v SchemaVersion) IsCompatible(other SchemaVersion, policy CompatibilityPolicy) bool {
	switch policy {
	case CompatibilityPolicyStrict:
		return v.Compare(other) == 0

	case CompatibilityPolicyBackward:
		// Current can read older: current >= other, same major
		return v.Major == other.Major && v.Compare(other) >= 0

	case CompatibilityPolicyForward:
		// Current can be read by newer: current <= other, same major
		return v.Major == other.Major && v.Compare(other) <= 0

	case CompatibilityPolicyFull:
		// Same major version
		return v.Major == other.Major

	default:
		return false
	}
}

// SchemaMetadata contains version and compatibility info.
// Per Section L.2: Schema metadata requirements.
type SchemaMetadata struct {
	SchemaID      string              `json:"$id"`
	SchemaVersion string              `json:"schema_version"`
	Compatibility CompatibilityPolicy `json:"x-helm-compatibility,omitempty"`
	Deprecated    bool                `json:"x-helm-deprecated,omitempty"`
	DeprecatedBy  string              `json:"x-helm-deprecated-by,omitempty"`
	MinVersion    string              `json:"x-helm-min-version,omitempty"`
}

// ValidateSchemaMetadata validates schema metadata.
func ValidateSchemaMetadata(meta SchemaMetadata) []string {
	issues := []string{}

	if meta.SchemaVersion == "" {
		issues = append(issues, "schema_version is required")
	} else if _, err := ParseSchemaVersion(meta.SchemaVersion); err != nil {
		issues = append(issues, err.Error())
	}

	if meta.SchemaID == "" {
		issues = append(issues, "$id is required")
	}

	if meta.Deprecated && meta.DeprecatedBy == "" {
		issues = append(issues, "deprecated schemas must specify x-helm-deprecated-by")
	}

	return issues
}

// SchemaRegistry manages schema versions.
type SchemaRegistry struct {
	schemas map[string]map[string]SchemaMetadata // schemaID -> version -> metadata
}

// NewSchemaRegistry creates a new registry.
func NewSchemaRegistry() *SchemaRegistry {
	return &SchemaRegistry{
		schemas: make(map[string]map[string]SchemaMetadata),
	}
}

// Register adds a schema to the registry.
func (r *SchemaRegistry) Register(meta SchemaMetadata) error {
	issues := ValidateSchemaMetadata(meta)
	if len(issues) > 0 {
		return fmt.Errorf("invalid schema metadata: %v", issues)
	}

	if _, exists := r.schemas[meta.SchemaID]; !exists {
		r.schemas[meta.SchemaID] = make(map[string]SchemaMetadata)
	}

	r.schemas[meta.SchemaID][meta.SchemaVersion] = meta
	return nil
}

// GetLatest returns the latest version of a schema.
func (r *SchemaRegistry) GetLatest(schemaID string) (*SchemaMetadata, error) {
	versions, exists := r.schemas[schemaID]
	if !exists {
		return nil, fmt.Errorf("schema %s not found", schemaID)
	}

	var latest *SchemaMetadata
	var latestVer *SchemaVersion

	for _, meta := range versions {
		ver, _ := ParseSchemaVersion(meta.SchemaVersion)
		if latestVer == nil || ver.Compare(*latestVer) > 0 {
			m := meta
			latest = &m
			latestVer = ver
		}
	}

	return latest, nil
}

// IsVersionSupported checks if a version is supported.
func (r *SchemaRegistry) IsVersionSupported(schemaID, version string, policy CompatibilityPolicy) (bool, error) {
	latest, err := r.GetLatest(schemaID)
	if err != nil {
		return false, err
	}

	latestVer, _ := ParseSchemaVersion(latest.SchemaVersion)
	checkVer, err := ParseSchemaVersion(version)
	if err != nil {
		return false, err
	}

	return latestVer.IsCompatible(*checkVer, policy), nil
}
