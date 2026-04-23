package versioning

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestVersionParse(t *testing.T) {
	tests := []struct {
		input   string
		want    *Version
		wantErr bool
	}{
		{"1.0.0", &Version{Major: 1, Minor: 0, Patch: 0}, false},
		{"v1.0.0", &Version{Major: 1, Minor: 0, Patch: 0}, false},
		{"2.3.4", &Version{Major: 2, Minor: 3, Patch: 4}, false},
		{"1.0.0-alpha", &Version{Major: 1, Minor: 0, Patch: 0, Prerelease: "alpha"}, false},
		{"1.0.0-beta.1", &Version{Major: 1, Minor: 0, Patch: 0, Prerelease: "beta.1"}, false},
		{"1.0.0+build.123", &Version{Major: 1, Minor: 0, Patch: 0, Build: "build.123"}, false},
		{"1.0.0-rc.1+build.123", &Version{Major: 1, Minor: 0, Patch: 0, Prerelease: "rc.1", Build: "build.123"}, false},
		{"invalid", nil, true},
		{"1.0", nil, true},
		{"", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := Parse(tt.input)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.want.Major, got.Major)
				require.Equal(t, tt.want.Minor, got.Minor)
				require.Equal(t, tt.want.Patch, got.Patch)
				require.Equal(t, tt.want.Prerelease, got.Prerelease)
				require.Equal(t, tt.want.Build, got.Build)
			}
		})
	}
}

func TestVersionString(t *testing.T) {
	tests := []struct {
		version Version
		want    string
	}{
		{Version{Major: 1, Minor: 0, Patch: 0}, "1.0.0"},
		{Version{Major: 2, Minor: 3, Patch: 4}, "2.3.4"},
		{Version{Major: 1, Minor: 0, Patch: 0, Prerelease: "alpha"}, "1.0.0-alpha"},
		{Version{Major: 1, Minor: 0, Patch: 0, Build: "build.1"}, "1.0.0+build.1"},
		{Version{Major: 1, Minor: 0, Patch: 0, Prerelease: "rc.1", Build: "sha.abc"}, "1.0.0-rc.1+sha.abc"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			require.Equal(t, tt.want, tt.version.String())
		})
	}
}

func TestVersionCompare(t *testing.T) {
	tests := []struct {
		v1   Version
		v2   Version
		want int
	}{
		{Version{Major: 1, Minor: 0, Patch: 0}, Version{Major: 1, Minor: 0, Patch: 0}, 0},
		{Version{Major: 1, Minor: 0, Patch: 0}, Version{Major: 2, Minor: 0, Patch: 0}, -1},
		{Version{Major: 2, Minor: 0, Patch: 0}, Version{Major: 1, Minor: 0, Patch: 0}, 1},
		{Version{Major: 1, Minor: 1, Patch: 0}, Version{Major: 1, Minor: 0, Patch: 0}, 1},
		{Version{Major: 1, Minor: 0, Patch: 1}, Version{Major: 1, Minor: 0, Patch: 0}, 1},
		{Version{Major: 1, Minor: 0, Patch: 0, Prerelease: "alpha"}, Version{Major: 1, Minor: 0, Patch: 0}, -1},
		{Version{Major: 1, Minor: 0, Patch: 0}, Version{Major: 1, Minor: 0, Patch: 0, Prerelease: "alpha"}, 1},
	}

	for _, tt := range tests {
		t.Run(tt.v1.String()+"_vs_"+tt.v2.String(), func(t *testing.T) {
			require.Equal(t, tt.want, tt.v1.Compare(tt.v2))
		})
	}
}

func TestVersionCompatibility(t *testing.T) {
	v1 := Version{Major: 1, Minor: 0, Patch: 0}
	v1_1 := Version{Major: 1, Minor: 1, Patch: 0}
	v2 := Version{Major: 2, Minor: 0, Patch: 0}

	require.True(t, v1.IsCompatible(v1_1))
	require.False(t, v1.IsCompatible(v2))
}

func TestVersionIncrement(t *testing.T) {
	v := Version{Major: 1, Minor: 2, Patch: 3}

	major := v.IncrementMajor()
	require.Equal(t, Version{Major: 2, Minor: 0, Patch: 0}, major)

	minor := v.IncrementMinor()
	require.Equal(t, Version{Major: 1, Minor: 3, Patch: 0}, minor)

	patch := v.IncrementPatch()
	require.Equal(t, Version{Major: 1, Minor: 2, Patch: 4}, patch)
}

func TestAPIRegistry(t *testing.T) {
	registry := NewAPIRegistry()

	api := &APIDefinition{
		Name:           "test-api",
		Description:    "Test API",
		CurrentVersion: Version{Major: 1, Minor: 0, Patch: 0},
		Stability:      StabilityStable,
		LastUpdated:    time.Now(),
	}

	registry.RegisterAPI(api)

	// Retrieve
	got, ok := registry.GetAPI("test-api")
	require.True(t, ok)
	require.Equal(t, "test-api", got.Name)

	// Not found
	_, ok = registry.GetAPI("nonexistent")
	require.False(t, ok)
}

func TestAPIAddVersion(t *testing.T) {
	api := &APIDefinition{
		Name:           "test-api",
		CurrentVersion: Version{Major: 1, Minor: 0, Patch: 0},
	}

	api.AddVersion(APIVersion{
		Version:    Version{Major: 1, Minor: 1, Patch: 0},
		ReleasedAt: time.Now(),
		Changelog:  "Minor update",
	})

	require.Len(t, api.Versions, 1)
	require.Equal(t, 1, api.CurrentVersion.Minor)
}

func TestAPIMarkDeprecated(t *testing.T) {
	api := &APIDefinition{
		Name:           "test-api",
		CurrentVersion: Version{Major: 2, Minor: 0, Patch: 0},
	}

	removal := Version{Major: 3, Minor: 0, Patch: 0}
	api.MarkDeprecated(DeprecatedAPI{
		Name:          "OldFunction",
		DeprecatedIn:  Version{Major: 2, Minor: 0, Patch: 0},
		RemovalTarget: &removal,
		Replacement:   "NewFunction",
		Reason:        "Performance improvement",
	})

	require.Len(t, api.DeprecatedAPIs, 1)
	require.Equal(t, "OldFunction", api.DeprecatedAPIs[0].Name)
	require.NotZero(t, api.DeprecatedAPIs[0].DeprecatedAt)
}

func TestHELMAPIs(t *testing.T) {
	registry := HELMAPIs()

	// Check core APIs exist
	governance, ok := registry.GetAPI("governance")
	require.True(t, ok)
	require.Equal(t, StabilityStable, governance.Stability)

	kernel, ok := registry.GetAPI("kernel")
	require.True(t, ok)
	require.Equal(t, StabilityStable, kernel.Stability)

	pdp, ok := registry.GetAPI("policy/pdp")
	require.True(t, ok)
	require.True(t, len(pdp.DeprecatedAPIs) > 0)

	crypto, ok := registry.GetAPI("crypto")
	require.True(t, ok)
	require.True(t, len(crypto.DeprecatedAPIs) > 0)

	// Check deprecated APIs list
	deprecated := registry.ListDeprecated()
	require.Greater(t, len(deprecated), 0)
}

func TestRegistryToJSON(t *testing.T) {
	registry := HELMAPIs()
	jsonBytes, err := registry.ToJSON()
	require.NoError(t, err)
	require.NotEmpty(t, jsonBytes)
	require.Contains(t, string(jsonBytes), "governance")
}
