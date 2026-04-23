package pack

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDrillVerification(t *testing.T) {
	ctx := context.Background()
	registry := NewInMemoryRegistry()
	verifier := NewVerifier(registry)

	// Create a dummy pack
	packID := "test-pack-drill"
	manifest := PackManifest{
		PackID:       packID,
		Name:         "Test Pack for Drills",
		Version:      "1.0.0",
		Capabilities: []string{"something"},
		Metadata:     make(map[string]interface{}),
		Signatures:   []Signature{{SignerID: "test"}}, // conform to signature check
	}

	// Register pack in registry so resolver can find it if needed,
	// though verifier works on ResolvedPack directly usually.
	// But let's construct ResolvedPack for the test.
	resolvedPack := ResolvedPack{
		PackID:      packID,
		Manifest:    manifest,
		ContentHash: "hash123",
	}

	t.Run("Fails when required drill is missing", func(t *testing.T) {
		req := &VerificationRequest{
			RequestID: "req-1",
			Packs:     []ResolvedPack{resolvedPack},
			Options: VerificationOptions{
				RequiredDrills: []string{"drill-network-partition"},
				RequiredChecks: []string{"signature"}, // basic checks
			},
		}

		result, err := verifier.Verify(ctx, req)
		require.NoError(t, err)
		assert.Equal(t, VerificationFailed, result.Status)
		require.Len(t, result.PackResults, 1)

		res := result.PackResults[0]
		assert.Equal(t, VerificationFailed, res.OverallStatus)

		// Find the drill check
		found := false
		for _, check := range res.Checks {
			if check.CheckType == "drill_drill-network-partition" {
				found = true
				assert.False(t, check.Passed)
				assert.Contains(t, check.Message, "Missing passing evidence")
			}
		}
		assert.True(t, found, "Drill check should exist")
	})

	t.Run("Passes when drill evidence is present and passing", func(t *testing.T) {
		// Update pack with PASS evidence
		packWithPass := resolvedPack
		packWithPass.Manifest = manifest // Copy manifest
		// Re-initialize map to avoid mutation issues across tests if shallow copy
		packWithPass.Manifest.Metadata = map[string]interface{}{
			"drill:drill-network-partition": "PASS",
		}

		req := &VerificationRequest{
			RequestID: "req-2",
			Packs:     []ResolvedPack{packWithPass},
			Options: VerificationOptions{
				RequiredDrills: []string{"drill-network-partition"},
				RequiredChecks: []string{"signature"},
			},
		}

		result, err := verifier.Verify(ctx, req)
		require.NoError(t, err)
		assert.Equal(t, VerificationPassed, result.Status)

		res := result.PackResults[0]
		assert.Equal(t, VerificationPassed, res.OverallStatus)

		found := false
		for _, check := range res.Checks {
			if check.CheckType == "drill_drill-network-partition" {
				found = true
				assert.True(t, check.Passed)
			}
		}
		assert.True(t, found)
	})

	t.Run("Fails when drill evidence is present but FAILING", func(t *testing.T) {
		// Update pack with FAIL evidence
		packWithFail := resolvedPack
		packWithFail.Manifest = manifest
		packWithFail.Manifest.Metadata = map[string]interface{}{
			"drill:drill-network-partition": "FAIL",
		}

		req := &VerificationRequest{
			RequestID: "req-3",
			Packs:     []ResolvedPack{packWithFail},
			Options: VerificationOptions{
				RequiredDrills: []string{"drill-network-partition"},
				RequiredChecks: []string{"signature"},
			},
		}

		result, err := verifier.Verify(ctx, req)
		require.NoError(t, err)
		assert.Equal(t, VerificationFailed, result.Status)

		res := result.PackResults[0]
		assert.Equal(t, VerificationFailed, res.OverallStatus)

		found := false
		for _, check := range res.Checks {
			if check.CheckType == "drill_drill-network-partition" {
				found = true
				assert.False(t, check.Passed)
			}
		}
		assert.True(t, found)
	})
}
