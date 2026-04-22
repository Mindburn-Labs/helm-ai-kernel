package pack

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestRegistry() *InMemoryRegistry {
	registry := NewInMemoryRegistry()

	registry.Register(&Pack{
		PackID: "pack-auth-v1",
		Manifest: PackManifest{
			Name:    "auth-pack",
			Version: "1.0.0",
			Capabilities: []string{
				"auth",
				"oauth",
			},
		},
		ContentHash: "sha256:abc123",
		CreatedAt:   time.Now(),
	})

	registry.Register(&Pack{
		PackID: "pack-auth-v2",
		Manifest: PackManifest{
			Name:    "auth-pack",
			Version: "2.0.0",
			Capabilities: []string{
				"auth",
				"oauth",
				"sso",
			},
		},
		ContentHash: "sha256:def456",
		CreatedAt:   time.Now(),
	})

	registry.Register(&Pack{
		PackID: "pack-payment-v1",
		Manifest: PackManifest{
			Name:    "payment-pack",
			Version: "1.0.0",
			Capabilities: []string{
				"payment_processing",
				"pci_dss",
			},
		},
		ContentHash: "sha256:ghi789",
		CreatedAt:   time.Now(),
	})

	registry.Register(&Pack{
		PackID: "pack-logging-v1",
		Manifest: PackManifest{
			Name:    "logging-pack",
			Version: "1.0.0",
			Capabilities: []string{
				"logging",
				"audit_trail",
			},
		},
		ContentHash: "sha256:jkl012",
		CreatedAt:   time.Now(),
	})

	return registry
}

func TestResolver_Resolve(t *testing.T) {
	registry := setupTestRegistry()
	resolver := NewResolver(registry)

	req := &ResolutionRequest{
		RequestID:    "test-request",
		Capabilities: []string{"auth", "payment_processing"},
		Constraints:  DefaultConstraints(),
	}

	result, err := resolver.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, result)

	t.Run("Result has correct metadata", func(t *testing.T) {
		assert.NotEmpty(t, result.ResultID)
		assert.Equal(t, "test-request", result.RequestID)
		assert.NotEmpty(t, result.TotalHash)
	})

	t.Run("Resolves requested capabilities", func(t *testing.T) {
		assert.Len(t, result.Packs, 2)

		// Should have auth and payment packs
		names := make(map[string]bool)
		for _, pack := range result.Packs {
			names[pack.Manifest.Name] = true
		}
		assert.True(t, names["auth-pack"])
		assert.True(t, names["payment-pack"])
	})

	t.Run("Prefers latest version", func(t *testing.T) {
		for _, pack := range result.Packs {
			if pack.Manifest.Name == "auth-pack" {
				assert.Equal(t, "2.0.0", pack.Manifest.Version) // Should pick v2
			}
		}
	})

	t.Run("Install order is populated", func(t *testing.T) {
		assert.Len(t, result.InstallOrder, 2)
	})
}

func TestResolver_NilRequest(t *testing.T) {
	registry := setupTestRegistry()
	resolver := NewResolver(registry)

	_, err := resolver.Resolve(context.Background(), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "request is nil")
}

func TestResolver_EmptyCapabilities(t *testing.T) {
	registry := setupTestRegistry()
	resolver := NewResolver(registry)

	req := &ResolutionRequest{
		Capabilities: []string{},
	}

	_, err := resolver.Resolve(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no capabilities")
}

func TestResolver_MissingCapability(t *testing.T) {
	registry := setupTestRegistry()
	resolver := NewResolver(registry)

	req := &ResolutionRequest{
		Capabilities: []string{"nonexistent"},
		Constraints:  DefaultConstraints(),
	}

	_, err := resolver.Resolve(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no pack provides")
}

func TestResolver_PinnedVersion(t *testing.T) {
	registry := setupTestRegistry()
	resolver := NewResolver(registry)

	req := &ResolutionRequest{
		Capabilities: []string{"auth"},
		Constraints: ResolutionConstraints{
			PinnedVersions: map[string]string{
				"auth": "pack-auth-v1", // Pin to v1
			},
		},
	}

	result, err := resolver.Resolve(context.Background(), req)
	require.NoError(t, err)

	assert.Len(t, result.Packs, 1)
	assert.Equal(t, "1.0.0", result.Packs[0].Manifest.Version)
	assert.Equal(t, "pinned version", result.Packs[0].Reason)
}

func TestResolver_ExcludedPacks(t *testing.T) {
	registry := setupTestRegistry()
	resolver := NewResolver(registry)

	req := &ResolutionRequest{
		Capabilities: []string{"auth"},
		Constraints: ResolutionConstraints{
			ExcludedPacks: []string{"auth-pack"},
		},
	}

	_, err := resolver.Resolve(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "excluded")
}

func TestResolver_Caching(t *testing.T) {
	registry := setupTestRegistry()
	resolver := NewResolver(registry)

	req := &ResolutionRequest{
		RequestID:    "cached-request",
		Capabilities: []string{"logging"},
		Constraints:  DefaultConstraints(),
	}

	result1, _ := resolver.Resolve(context.Background(), req)
	result2, _ := resolver.Resolve(context.Background(), req)

	// Should return same result from cache
	assert.Equal(t, result1.ResultID, result2.ResultID)
	assert.Equal(t, result1.TotalHash, result2.TotalHash)
}

func TestResolver_DeterministicHash(t *testing.T) {
	registry := setupTestRegistry()

	resolver1 := NewResolver(registry)
	resolver2 := NewResolver(registry)

	req := &ResolutionRequest{
		Capabilities: []string{"auth", "payment_processing", "logging"},
		Constraints:  DefaultConstraints(),
	}

	// Clear any cached results by using fresh resolvers
	result1, _ := resolver1.Resolve(context.Background(), req)

	// Clear cache for resolver2
	resolver2.cache = NewResolutionCache()
	result2, _ := resolver2.Resolve(context.Background(), req)

	// Hashes should be identical for same input
	assert.Equal(t, result1.TotalHash, result2.TotalHash)
}

func TestInMemoryRegistry(t *testing.T) {
	registry := NewInMemoryRegistry()

	pack := &Pack{
		PackID: "test-pack",
		Manifest: PackManifest{
			Name:    "test",
			Version: "1.0.0",
			Capabilities: []string{
				"test_cap",
			},
		},
		ContentHash: "sha256:test",
		CreatedAt:   time.Now(),
	}

	registry.Register(pack)

	t.Run("GetPack", func(t *testing.T) {
		found, err := registry.GetPack(context.Background(), "test-pack")
		require.NoError(t, err)
		assert.Equal(t, pack.Manifest.Name, found.Manifest.Name)
	})

	t.Run("GetPack not found", func(t *testing.T) {
		_, err := registry.GetPack(context.Background(), "nonexistent")
		assert.Error(t, err)
	})

	t.Run("FindByCapability", func(t *testing.T) {
		found, err := registry.FindByCapability(context.Background(), "test_cap")
		require.NoError(t, err)
		assert.Len(t, found, 1)
	})

	t.Run("ListVersions", func(t *testing.T) {
		versions, err := registry.ListVersions(context.Background(), "test")
		require.NoError(t, err)
		assert.Len(t, versions, 1)
	})
}
