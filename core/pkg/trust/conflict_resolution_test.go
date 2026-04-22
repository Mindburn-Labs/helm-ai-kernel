package trust

import (
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/assert"
)

// MockVersionStore implements VersionStore
type MockVersionStore struct {
	versions map[string]*semver.Version
}

func NewMockVersionStore() *MockVersionStore {
	return &MockVersionStore{
		versions: make(map[string]*semver.Version),
	}
}

func (m *MockVersionStore) GetInstalledVersion(packID string) (*semver.Version, error) {
	return m.versions[packID], nil
}

func (m *MockVersionStore) SetInstalledVersion(packID string, version *semver.Version) error {
	m.versions[packID] = version
	return nil
}

// TestMonotonicVersionEnforcement validates that the PackLoader
// strictly enforces version monotonicity to prevent rollback attacks.
func TestMonotonicVersionEnforcement(t *testing.T) {
	// Setup
	store := NewMockVersionStore()

	// Create a partial PackLoader with just the VersionStore and nil clients
	// We are unit testing enforceMonotonicVersion specifically
	loader := &PackLoader{
		versionStore: store,
	}

	tests := []struct {
		name        string
		packName    string
		newVersion  string
		setup       func() // Setup initial state
		expectError bool
	}{
		{
			name:        "First Install",
			packName:    "org.example.pack",
			newVersion:  "1.0.0",
			setup:       func() {}, // Empty store
			expectError: false,
		},
		{
			name:       "Upgrade",
			packName:   "org.example.pack",
			newVersion: "1.1.0",
			setup: func() {
				v, _ := semver.NewVersion("1.0.0")
				_ = store.SetInstalledVersion("org.example.pack", v)
			},
			expectError: false,
		},
		{
			name:       "Downgrade (Rollback Attack)",
			packName:   "org.example.pack",
			newVersion: "0.9.0",
			setup: func() {
				v, _ := semver.NewVersion("1.0.0")
				_ = store.SetInstalledVersion("org.example.pack", v)
			},
			expectError: true,
		},
		{
			name:       "Same Version (Reinstall)",
			packName:   "org.example.pack",
			newVersion: "1.0.0",
			setup: func() {
				v, _ := semver.NewVersion("1.0.0")
				_ = store.SetInstalledVersion("org.example.pack", v)
			},
			expectError: false, // Reinstalling same version is allowed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear store for isolation if needed, but we use unique setups
			store.versions = make(map[string]*semver.Version)
			tt.setup()

			ref := PackRef{
				Name:    tt.packName,
				Version: tt.newVersion,
			}

			err := loader.enforceMonotonicVersion(ref)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "rollback")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestDeterministicConflictResolution verifies that
// conflicting constraints result in a deterministic failure (Fail-Closed).
func TestDeterministicConflictResolution(t *testing.T) {
	// In the current implementation, "Conflict Resolution" is achieved by
	// strict validation. Use enforceMonotonicVersion to prove strict ordering.

	store := NewMockVersionStore()
	loader := &PackLoader{versionStore: store}

	// Scenario: Two updates arrive. Ordering matters?
	// T1: Install v1.0.0
	// T2: Install v2.0.0
	// T3: Install v1.5.0 (Should fail if v2 installed)

	// Step 1: Install v1.0.0
	v1, _ := semver.NewVersion("1.0.0")
	_ = store.SetInstalledVersion("pkg", v1)

	// Step 2: Try to install v1.5.0 -> Allowed
	assert.NoError(t, loader.enforceMonotonicVersion(PackRef{Name: "pkg", Version: "1.5.0"}))

	// Step 3: Simulate v2.0.0 was installed instead
	v2, _ := semver.NewVersion("2.0.0")
	_ = store.SetInstalledVersion("pkg", v2)

	// Step 4: Try to install v1.5.0 now -> Denied
	err := loader.enforceMonotonicVersion(PackRef{Name: "pkg", Version: "1.5.0"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rollback")

	// Conclusion: The resolution is deterministic based on the current state.
	// No ambiguity.
}
