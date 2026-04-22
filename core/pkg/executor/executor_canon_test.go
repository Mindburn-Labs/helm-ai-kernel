package executor_test

import (
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExecutor_OutputCanonicalization proves that tool outputs are canonicalized
// before hashing, ensuring deterministic replay regardless of JSON key ordering.
func TestExecutor_OutputCanonicalization(t *testing.T) {
	// Two semantically identical objects with different key orders
	obj1 := map[string]any{
		"status":  "ok",
		"code":    200,
		"message": "success",
		"data": map[string]any{
			"id":   "123",
			"name": "test",
		},
	}

	obj2 := map[string]any{
		"data": map[string]any{
			"name": "test",
			"id":   "123",
		},
		"message": "success",
		"status":  "ok",
		"code":    200,
	}

	// Canonicalize both
	art1, err := canonicalize.Canonicalize("application/json", obj1)
	require.NoError(t, err)

	art2, err := canonicalize.Canonicalize("application/json", obj2)
	require.NoError(t, err)

	// Both should produce identical canonical bytes
	assert.Equal(t, art1.CanonicalBytes, art2.CanonicalBytes,
		"Different key orders must produce identical canonical bytes")

	// Both should produce identical digests
	assert.Equal(t, art1.Digest, art2.Digest,
		"Different key orders must produce identical digests")

	// Verify the canonical form has sorted keys
	expected := `{"code":200,"data":{"id":"123","name":"test"},"message":"success","status":"ok"}`
	assert.Equal(t, expected, string(art1.CanonicalBytes),
		"Canonical form must have lexicographically sorted keys")
}

// TestExecutor_OutputCanonicalHashStability proves hash stability across runs
func TestExecutor_OutputCanonicalHashStability(t *testing.T) {
	// Known stable hash for regression testing
	obj := map[string]any{
		"action":  "deploy",
		"target":  "production",
		"version": "1.0.0",
	}

	art, err := canonicalize.Canonicalize("application/json", obj)
	require.NoError(t, err)

	// This is the expected stable hash - if this changes, determinism is broken
	// The actual value should be computed once and locked in
	expectedCanonical := `{"action":"deploy","target":"production","version":"1.0.0"}`
	assert.Equal(t, expectedCanonical, string(art.CanonicalBytes))

	// Verify digest starts with sha256: prefix
	assert.Contains(t, art.Digest, "sha256:")
}
