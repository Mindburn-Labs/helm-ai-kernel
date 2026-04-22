package kernel

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// ============================================================================
// Section K: Inline Blob Size Tests
// ============================================================================

func TestInlineBlobValidator(t *testing.T) {
	t.Run("within limits", func(t *testing.T) {
		v := NewInlineBlobValidator()
		result := v.Validate(make([]byte, 1000))
		require.True(t, result.Valid)
		require.Equal(t, 1000, result.OriginalSize)
	})

	t.Run("exactly at limit", func(t *testing.T) {
		v := NewInlineBlobValidator()
		result := v.Validate(make([]byte, MaxInlineBytes))
		require.True(t, result.Valid)
	})

	t.Run("exceeds limit with reject policy", func(t *testing.T) {
		v := NewInlineBlobValidator()
		result := v.Validate(make([]byte, MaxInlineBytes+1))
		require.False(t, result.Valid)
		require.Equal(t, InlineBlobPolicyReject, result.PolicyApplied)
		require.NotEmpty(t, result.Error)
	})

	t.Run("exceeds limit with reference policy", func(t *testing.T) {
		v := NewInlineBlobValidator().WithPolicy(InlineBlobPolicyReference)
		result := v.Validate(make([]byte, MaxInlineBytes+1))
		require.False(t, result.Valid)
		require.Equal(t, InlineBlobPolicyReference, result.PolicyApplied)
	})

	t.Run("exceeds limit with truncate policy", func(t *testing.T) {
		v := NewInlineBlobValidator().WithPolicy(InlineBlobPolicyTruncate)
		result := v.Validate(make([]byte, MaxInlineBytes+100))
		require.True(t, result.Valid) // Truncation succeeds
		require.Equal(t, InlineBlobPolicyTruncate, result.PolicyApplied)
		require.Equal(t, MaxInlineBytes, result.TruncatedTo)
	})

	t.Run("custom max bytes", func(t *testing.T) {
		v := NewInlineBlobValidator().WithMaxBytes(100)

		result := v.Validate(make([]byte, 100))
		require.True(t, result.Valid)

		result = v.Validate(make([]byte, 101))
		require.False(t, result.Valid)
	})
}

func TestValidateInlineSize(t *testing.T) {
	t.Run("within limit", func(t *testing.T) {
		err := ValidateInlineSize(1000)
		require.NoError(t, err)
	})

	t.Run("exceeds limit", func(t *testing.T) {
		err := ValidateInlineSize(MaxInlineBytes + 1)
		require.Error(t, err)
		require.Contains(t, err.Error(), "MAX_INLINE_BYTES")
	})
}

// ============================================================================
// Section L: Schema Versioning Tests
// ============================================================================

func TestSchemaVersion(t *testing.T) {
	t.Run("parse valid version", func(t *testing.T) {
		v, err := ParseSchemaVersion("1.2.3")
		require.NoError(t, err)
		require.Equal(t, 1, v.Major)
		require.Equal(t, 2, v.Minor)
		require.Equal(t, 3, v.Patch)
	})

	t.Run("parse version with label", func(t *testing.T) {
		v, err := ParseSchemaVersion("1.0.0-beta.1")
		require.NoError(t, err)
		require.Equal(t, 1, v.Major)
		require.Equal(t, "beta.1", v.Label)
	})

	t.Run("invalid version", func(t *testing.T) {
		_, err := ParseSchemaVersion("invalid")
		require.Error(t, err)
	})

	t.Run("string format", func(t *testing.T) {
		v := SchemaVersion{Major: 1, Minor: 2, Patch: 3}
		require.Equal(t, "1.2.3", v.String())

		v.Label = "alpha"
		require.Equal(t, "1.2.3-alpha", v.String())
	})
}

func TestSchemaVersionCompare(t *testing.T) {
	tests := []struct {
		v1       string
		v2       string
		expected int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.1", "1.0.0", 1},
		{"1.0.0", "1.0.1", -1},
		{"1.1.0", "1.0.0", 1},
		{"2.0.0", "1.9.9", 1},
	}

	for _, tc := range tests {
		t.Run(tc.v1+"_vs_"+tc.v2, func(t *testing.T) {
			ver1, _ := ParseSchemaVersion(tc.v1)
			ver2, _ := ParseSchemaVersion(tc.v2)
			require.Equal(t, tc.expected, ver1.Compare(*ver2))
		})
	}
}

func TestSchemaVersionCompatibility(t *testing.T) {
	v1_0, _ := ParseSchemaVersion("1.0.0")
	v1_1, _ := ParseSchemaVersion("1.1.0")
	v1_2, _ := ParseSchemaVersion("1.2.0")
	v2_0, _ := ParseSchemaVersion("2.0.0")

	t.Run("strict requires exact match", func(t *testing.T) {
		require.True(t, v1_0.IsCompatible(*v1_0, CompatibilityPolicyStrict))
		require.False(t, v1_0.IsCompatible(*v1_1, CompatibilityPolicyStrict))
	})

	t.Run("backward compatibility", func(t *testing.T) {
		// v1.2 can read v1.0 and v1.1
		require.True(t, v1_2.IsCompatible(*v1_0, CompatibilityPolicyBackward))
		require.True(t, v1_2.IsCompatible(*v1_1, CompatibilityPolicyBackward))
		require.True(t, v1_2.IsCompatible(*v1_2, CompatibilityPolicyBackward))

		// v1.0 cannot read v1.2 or v1.1
		require.False(t, v1_0.IsCompatible(*v1_2, CompatibilityPolicyBackward))

		// Different major versions are not compatible
		require.False(t, v2_0.IsCompatible(*v1_0, CompatibilityPolicyBackward))
	})

	t.Run("forward compatibility", func(t *testing.T) {
		// v1.0 can be read by v1.2
		require.True(t, v1_0.IsCompatible(*v1_2, CompatibilityPolicyForward))
		require.True(t, v1_0.IsCompatible(*v1_0, CompatibilityPolicyForward))

		// v1.2 cannot be read by v1.0
		require.False(t, v1_2.IsCompatible(*v1_0, CompatibilityPolicyForward))
	})

	t.Run("full compatibility", func(t *testing.T) {
		// Same major version
		require.True(t, v1_0.IsCompatible(*v1_2, CompatibilityPolicyFull))
		require.True(t, v1_2.IsCompatible(*v1_0, CompatibilityPolicyFull))

		// Different major versions
		require.False(t, v1_0.IsCompatible(*v2_0, CompatibilityPolicyFull))
	})
}

func TestSchemaMetadataValidation(t *testing.T) {
	t.Run("valid metadata", func(t *testing.T) {
		meta := SchemaMetadata{
			SchemaID:      "https://helm.example/schemas/test",
			SchemaVersion: "1.0.0",
		}
		issues := ValidateSchemaMetadata(meta)
		require.Empty(t, issues)
	})

	t.Run("missing version", func(t *testing.T) {
		meta := SchemaMetadata{
			SchemaID: "https://helm.example/schemas/test",
		}
		issues := ValidateSchemaMetadata(meta)
		require.Len(t, issues, 1)
		require.Contains(t, issues[0], "schema_version")
	})

	t.Run("missing id", func(t *testing.T) {
		meta := SchemaMetadata{
			SchemaVersion: "1.0.0",
		}
		issues := ValidateSchemaMetadata(meta)
		require.Len(t, issues, 1)
		require.Contains(t, issues[0], "$id")
	})

	t.Run("deprecated without replacement", func(t *testing.T) {
		meta := SchemaMetadata{
			SchemaID:      "https://helm.example/schemas/test",
			SchemaVersion: "1.0.0",
			Deprecated:    true,
		}
		issues := ValidateSchemaMetadata(meta)
		require.Len(t, issues, 1)
		require.Contains(t, issues[0], "deprecated")
	})
}

func TestSchemaRegistry(t *testing.T) {
	t.Run("register and get latest", func(t *testing.T) {
		reg := NewSchemaRegistry()

		_ = reg.Register(SchemaMetadata{
			SchemaID:      "test",
			SchemaVersion: "1.0.0",
		})
		_ = reg.Register(SchemaMetadata{
			SchemaID:      "test",
			SchemaVersion: "1.1.0",
		})

		latest, err := reg.GetLatest("test")
		require.NoError(t, err)
		require.Equal(t, "1.1.0", latest.SchemaVersion)
	})

	t.Run("version supported check", func(t *testing.T) {
		reg := NewSchemaRegistry()
		_ = reg.Register(SchemaMetadata{
			SchemaID:      "test",
			SchemaVersion: "1.2.0",
		})

		supported, err := reg.IsVersionSupported("test", "1.0.0", CompatibilityPolicyBackward)
		require.NoError(t, err)
		require.True(t, supported)

		supported, err = reg.IsVersionSupported("test", "2.0.0", CompatibilityPolicyBackward)
		require.NoError(t, err)
		require.False(t, supported)
	})
}
