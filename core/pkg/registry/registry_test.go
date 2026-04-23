package registry

import (
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/manifest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInMemoryRegistry(t *testing.T) {
	r := NewInMemoryRegistry()

	bundleV1 := &manifest.Bundle{
		Manifest: manifest.Module{Name: "app-a", Version: "1.0.0"},
	}
	bundleV2 := &manifest.Bundle{
		Manifest: manifest.Module{Name: "app-a", Version: "2.0.0"},
	}

	t.Run("Register and Get", func(t *testing.T) {
		err := r.Register(bundleV1)
		require.NoError(t, err)

		got, err := r.Get("app-a")
		require.NoError(t, err)
		assert.Equal(t, "1.0.0", got.Manifest.Version)

		// Overwrite
		err = r.Register(bundleV2)
		require.NoError(t, err)
		got, err = r.Get("app-a")
		require.NoError(t, err)
		assert.Equal(t, "2.0.0", got.Manifest.Version)
	})

	t.Run("Get Not Found", func(t *testing.T) {
		_, err := r.Get("missing-app")
		assert.ErrorIs(t, err, ErrModuleNotFound)
	})

	t.Run("Canary Rollout", func(t *testing.T) {
		// Reset to V1
		_ = r.Register(bundleV1)

		// Rollout V2 at 50%
		err := r.SetRollout("app-a", bundleV2, 50)
		require.NoError(t, err)

		// Test deterministic hashing
		// User A -> Hash ?
		// User B -> Hash ?
		// We expect roughly 50/50, but for unit test we assume specific behavior or just consistency.

		v1Count := 0
		v2Count := 0
		users := []string{"user-1", "user-2", "user-3", "user-4", "user-5", "user-6", "user-7", "user-8", "user-9", "user-10"}

		for _, u := range users {
			b, err := r.GetForUser("app-a", u)
			require.NoError(t, err)
			if b.Manifest.Version == "1.0.0" {
				v1Count++
			} else {
				v2Count++
			}
		}

		// Ensure we saw both versions (probabilistic but high chance with 10 random-ish users?)
		// To be safe, let's verify specific hardcoded users if we knew the hash algo result used in crc32.
		// For now, loose assertion:
		assert.True(t, v1Count > 0, "Should have some v1 users")
		assert.True(t, v2Count > 0, "Should have some v2 users")
	})

	t.Run("Rollout 0% (All Stable)", func(t *testing.T) {
		_ = r.Register(bundleV1)
		_ = r.SetRollout("app-a", bundleV2, 0)

		b, _ := r.GetForUser("app-a", "any-user")
		assert.Equal(t, "1.0.0", b.Manifest.Version)
	})

	t.Run("Rollout 100% (All Canary)", func(t *testing.T) {
		_ = r.Register(bundleV1)
		_ = r.SetRollout("app-a", bundleV2, 100)

		b, _ := r.GetForUser("app-a", "any-user")
		assert.Equal(t, "2.0.0", b.Manifest.Version)
	})
}
