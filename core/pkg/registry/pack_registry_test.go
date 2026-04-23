package registry

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockVerifier is a test verifier that always succeeds.
type mockVerifier struct{}

func (m *mockVerifier) VerifyPackSignature(contentHash string, signature *PackSignature) (bool, error) {
	return true, nil
}

// failingVerifier always fails verification.
type failingVerifier struct{}

func (f *failingVerifier) VerifyPackSignature(contentHash string, signature *PackSignature) (bool, error) {
	return false, nil
}

func TestPackRegistry_Publish(t *testing.T) {
	registry := NewPackRegistry(&mockVerifier{})

	entry := &PackEntry{
		Name:         "test-pack",
		Version:      "1.0.0",
		ContentHash:  "sha256:abc123",
		Capabilities: []string{"payment", "auth"},
		Signatures: []PackSignature{
			{SignerID: "signer-1", Algorithm: "ed25519", Signature: "sig123"},
		},
	}

	err := registry.Publish(entry)
	require.NoError(t, err)

	assert.NotEmpty(t, entry.PackID)
	assert.Equal(t, PackStatePublished, entry.State)
	assert.Equal(t, 1, registry.Count())
}

func TestPackRegistry_PublishWithoutSignature_Fails(t *testing.T) {
	registry := NewPackRegistry(&mockVerifier{})

	entry := &PackEntry{
		Name:        "test-pack",
		Version:     "1.0.0",
		ContentHash: "sha256:abc123",
		Signatures:  []PackSignature{}, // No signatures
	}

	err := registry.Publish(entry)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one signature is required")
}

func TestPackRegistry_PublishWithInvalidSignature_Fails(t *testing.T) {
	registry := NewPackRegistry(&failingVerifier{})

	entry := &PackEntry{
		Name:        "test-pack",
		Version:     "1.0.0",
		ContentHash: "sha256:abc123",
		Signatures: []PackSignature{
			{SignerID: "signer-1", Algorithm: "ed25519", Signature: "badsig"},
		},
	}

	err := registry.Publish(entry)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no valid signature found")
}

func TestPackRegistry_PublishWithoutVerifier_FailsClosed(t *testing.T) {
	registry := NewPackRegistry(nil)

	entry := &PackEntry{
		Name:        "test-pack",
		Version:     "1.0.0",
		ContentHash: "sha256:abc123",
		Signatures: []PackSignature{
			{SignerID: "signer-1", Algorithm: "ed25519", Signature: "sig"},
		},
	}

	err := registry.Publish(entry)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "verifier not configured")
}

func TestPackRegistry_Search_DeterministicOrder(t *testing.T) {
	registry := NewPackRegistry(&mockVerifier{})

	// Publish packs in random order
	packs := []struct {
		name    string
		version string
	}{
		{"zebra-pack", "1.0.0"},
		{"alpha-pack", "2.0.0"},
		{"alpha-pack", "1.0.0"},
		{"beta-pack", "1.0.0"},
	}

	for _, p := range packs {
		err := registry.Publish(&PackEntry{
			Name:        p.name,
			Version:     p.version,
			ContentHash: "sha256:" + p.name + p.version,
			Signatures:  []PackSignature{{SignerID: "s1", Signature: "sig"}},
		})
		require.NoError(t, err)
	}

	// Search twice, expect same order
	result1 := registry.Search(PackSearchQuery{})
	result2 := registry.Search(PackSearchQuery{})

	require.Equal(t, 4, result1.TotalCount)

	for i := range result1.Entries {
		assert.Equal(t, result1.Entries[i].PackID, result2.Entries[i].PackID)
	}

	// Verify alphabetical ordering
	assert.Equal(t, "alpha-pack", result1.Entries[0].Name)
	assert.Equal(t, "1.0.0", result1.Entries[0].Version)
	assert.Equal(t, "alpha-pack", result1.Entries[1].Name)
	assert.Equal(t, "2.0.0", result1.Entries[1].Version)
	assert.Equal(t, "beta-pack", result1.Entries[2].Name)
	assert.Equal(t, "zebra-pack", result1.Entries[3].Name)
}

func TestPackRegistry_StagedActivation(t *testing.T) {
	registry := NewPackRegistry(&mockVerifier{})

	entry := &PackEntry{
		Name:        "staged-pack",
		Version:     "1.0.0",
		ContentHash: "sha256:staged123",
		Signatures:  []PackSignature{{SignerID: "s1", Signature: "sig"}},
	}

	err := registry.Publish(entry)
	require.NoError(t, err)
	assert.Equal(t, PackStatePublished, entry.State)

	// Cannot activate directly from published
	err = registry.Activate(entry.PackID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be verified or signed")

	// Mark verified
	err = registry.MarkVerified(entry.PackID)
	require.NoError(t, err)
	updated, _ := registry.Get(entry.PackID)
	assert.Equal(t, PackStateVerified, updated.State)

	// Mark signed
	err = registry.MarkSigned(entry.PackID)
	require.NoError(t, err)
	updated, _ = registry.Get(entry.PackID)
	assert.Equal(t, PackStateSigned, updated.State)

	// Now can activate
	err = registry.Activate(entry.PackID)
	require.NoError(t, err)
	updated, _ = registry.Get(entry.PackID)
	assert.Equal(t, PackStateActive, updated.State)
}

func TestPackRegistry_Verify(t *testing.T) {
	registry := NewPackRegistry(&mockVerifier{})

	entry := &PackEntry{
		Name:        "verify-pack",
		Version:     "1.0.0",
		ContentHash: "sha256:verify123",
		Signatures:  []PackSignature{{SignerID: "s1", Signature: "sig"}},
	}

	err := registry.Publish(entry)
	require.NoError(t, err)

	valid, err := registry.VerifyPack(entry.PackID)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestPackRegistry_VerifyWithoutVerifier_FailsClosed(t *testing.T) {
	registry := NewPackRegistry(nil)
	registry.mu.Lock()
	registry.entries["pack-1"] = &PackEntry{
		PackID:      "pack-1",
		Name:        "verify-pack",
		Version:     "1.0.0",
		ContentHash: "sha256:verify123",
		Signatures:  []PackSignature{{SignerID: "s1", Signature: "sig"}},
		State:       PackStatePublished,
	}
	registry.mu.Unlock()

	valid, err := registry.VerifyPack("pack-1")
	assert.Error(t, err)
	assert.False(t, valid)
	assert.Contains(t, err.Error(), "verifier not configured")
}

func TestPackRegistry_GetByNameVersion(t *testing.T) {
	registry := NewPackRegistry(&mockVerifier{})

	// Publish multiple versions
	for _, v := range []string{"1.0.0", "1.1.0", "2.0.0"} {
		err := registry.Publish(&PackEntry{
			Name:        "multi-version",
			Version:     v,
			ContentHash: "sha256:" + v,
			Signatures:  []PackSignature{{SignerID: "s1", Signature: "sig"}},
		})
		require.NoError(t, err)
	}

	// Get specific version
	entry, ok := registry.GetByNameVersion("multi-version", "1.1.0")
	require.True(t, ok)
	assert.Equal(t, "1.1.0", entry.Version)

	// Get non-existent version
	_, ok = registry.GetByNameVersion("multi-version", "3.0.0")
	assert.False(t, ok)
}

func TestPackRegistry_ListVersions(t *testing.T) {
	registry := NewPackRegistry(&mockVerifier{})

	// Publish in non-sorted order
	for _, v := range []string{"2.0.0", "1.0.0", "1.1.0"} {
		err := registry.Publish(&PackEntry{
			Name:        "list-pack",
			Version:     v,
			ContentHash: "sha256:" + v,
			Signatures:  []PackSignature{{SignerID: "s1", Signature: "sig"}},
		})
		require.NoError(t, err)
	}

	versions := registry.ListVersions("list-pack")
	assert.Equal(t, []string{"1.0.0", "1.1.0", "2.0.0"}, versions)
}

func TestPackRegistry_Hash_Deterministic(t *testing.T) {
	// Create two registries with same content
	r1 := NewPackRegistry(&mockVerifier{})
	r2 := NewPackRegistry(&mockVerifier{})

	entry := &PackEntry{
		PackID:      "fixed-id-123",
		Name:        "hash-test",
		Version:     "1.0.0",
		ContentHash: "sha256:hash123",
		Signatures:  []PackSignature{{SignerID: "s1", Signature: "sig"}},
		PublishedAt: time.Now(),
	}

	// Manually set to bypass ID generation
	r1.mu.Lock()
	r1.entries[entry.PackID] = entry
	r1.mu.Unlock()

	r2.mu.Lock()
	r2.entries[entry.PackID] = entry
	r2.mu.Unlock()

	hash1 := r1.Hash()
	hash2 := r2.Hash()

	assert.Equal(t, hash1, hash2)
	assert.NotEmpty(t, hash1)
}
