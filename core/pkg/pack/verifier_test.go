package pack

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeTestPacks() []ResolvedPack {
	return []ResolvedPack{
		{
			PackID: "pack-1",
			Manifest: PackManifest{
				Name:    "auth-pack",
				Version: "1.0.0",
				Capabilities: []string{
					"auth",
				},
			},
			ContentHash: "sha256:abc123",
		},
		{
			PackID: "pack-2",
			Manifest: PackManifest{
				Name:    "payment-pack",
				Version: "1.0.0",
				Capabilities: []string{
					"payment",
				},
			},
			ContentHash: "sha256:def456",
		},
	}
}

func TestVerifier_Verify(t *testing.T) {
	registry := NewInMemoryRegistry()
	verifier := NewVerifier(registry)

	req := &VerificationRequest{
		RequestID: "test-verify",
		Packs:     makeTestPacks(),
		Options:   DefaultVerificationOptions(),
	}

	result, err := verifier.Verify(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, result)

	t.Run("Result has correct metadata", func(t *testing.T) {
		assert.NotEmpty(t, result.ResultID)
		assert.Equal(t, "test-verify", result.RequestID)
		assert.Equal(t, VerificationPassed, result.Status)
	})

	t.Run("All packs verified", func(t *testing.T) {
		assert.Len(t, result.PackResults, 2)
	})

	t.Run("Summary calculated", func(t *testing.T) {
		assert.Equal(t, 2, result.Summary.TotalPacks)
		assert.Equal(t, 2, result.Summary.PassedPacks)
		assert.Equal(t, 0, result.Summary.FailedPacks)
		assert.Greater(t, result.Summary.AvgTrustScore, 0.0)
	})
}

func TestVerifier_NilRequest(t *testing.T) {
	verifier := NewVerifier(nil)

	_, err := verifier.Verify(context.Background(), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "request is nil")
}

func TestVerifier_MissingContentHash(t *testing.T) {
	verifier := NewVerifier(nil)

	packs := []ResolvedPack{
		{
			PackID: "bad-pack",
			Manifest: PackManifest{
				Name:    "test",
				Version: "1.0.0",
				Capabilities: []string{
					"test",
				},
			},
			ContentHash: "", // Missing!
		},
	}

	req := &VerificationRequest{
		RequestID: "test-missing-hash",
		Packs:     packs,
		Options:   DefaultVerificationOptions(),
	}

	result, err := verifier.Verify(context.Background(), req)
	require.NoError(t, err) // Verification runs, just marks as failed

	assert.Equal(t, 1, result.Summary.FailedPacks)
	assert.Equal(t, VerificationFailed, result.Status)
}

func TestVerifier_MissingFields(t *testing.T) {
	verifier := NewVerifier(nil)

	packs := []ResolvedPack{
		{
			PackID: "", // Missing!
			Manifest: PackManifest{
				Name: "test",
			},
		},
	}

	req := &VerificationRequest{
		Packs:   packs,
		Options: DefaultVerificationOptions(),
	}

	result, _ := verifier.Verify(context.Background(), req)

	// Integrity check should fail
	found := false
	for _, check := range result.PackResults[0].Checks {
		if check.CheckType == CheckContentHash && !check.Passed {
			found = true
		}
	}
	assert.True(t, found)
}

func TestVerifier_WithTrustAnchors(t *testing.T) {
	verifier := NewVerifier(nil)

	verifier.AddTrustAnchor(TrustAnchor{
		AnchorID:   "anchor-1",
		Name:       "HELM Signing Key",
		PublicKey:  "-----BEGIN PUBLIC KEY-----",
		ValidFrom:  time.Now().Add(-24 * time.Hour),
		ValidUntil: time.Now().Add(365 * 24 * time.Hour),
		TrustLevel: 5,
	})

	req := &VerificationRequest{
		Packs:   makeTestPacks(),
		Options: DefaultVerificationOptions(),
	}

	result, _ := verifier.Verify(context.Background(), req)

	// With trust anchors, signature check runs
	assert.Equal(t, VerificationPassed, result.Status)
}

func TestVerifier_TrustScore(t *testing.T) {
	verifier := NewVerifier(nil)

	req := &VerificationRequest{
		Packs:   makeTestPacks(),
		Options: DefaultVerificationOptions(),
	}

	result, _ := verifier.Verify(context.Background(), req)

	for _, packResult := range result.PackResults {
		// All checks passed = trust score 1.0
		assert.Equal(t, 1.0, packResult.TrustScore)
	}

	assert.Equal(t, 1.0, result.Summary.AvgTrustScore)
}

func TestComputePackHash(t *testing.T) {
	pack := &Pack{
		Manifest: PackManifest{
			Name:    "test-pack",
			Version: "1.0.0",
			Capabilities: []string{
				"cap1",
				"cap2",
			},
		},
	}

	hash1 := ComputePackHash(pack)
	hash2 := ComputePackHash(pack)

	assert.Equal(t, hash1, hash2) // Deterministic
	assert.Len(t, hash1, 64)      // SHA256 hex
}
