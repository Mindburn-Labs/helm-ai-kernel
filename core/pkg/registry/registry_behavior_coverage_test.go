package registry

import (
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/manifest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisterNilBundle(t *testing.T) {
	r := NewInMemoryRegistry()
	err := r.Register(nil)
	assert.Error(t, err)
}

func TestUnregisterMissing(t *testing.T) {
	r := NewInMemoryRegistry()
	err := r.Unregister("nonexistent")
	assert.ErrorIs(t, err, ErrModuleNotFound)
}

func TestUnregisterExisting(t *testing.T) {
	r := NewInMemoryRegistry()
	_ = r.Register(&manifest.Bundle{Manifest: manifest.Module{Name: "mod-a"}})
	require.NoError(t, r.Unregister("mod-a"))
	_, err := r.Get("mod-a")
	assert.ErrorIs(t, err, ErrModuleNotFound)
}

func TestListEmpty(t *testing.T) {
	r := NewInMemoryRegistry()
	assert.Empty(t, r.List())
}

func TestListMultiple(t *testing.T) {
	r := NewInMemoryRegistry()
	_ = r.Register(&manifest.Bundle{Manifest: manifest.Module{Name: "a"}})
	_ = r.Register(&manifest.Bundle{Manifest: manifest.Module{Name: "b"}})
	assert.Len(t, r.List(), 2)
}

func TestSetRolloutInvalidPercentage(t *testing.T) {
	r := NewInMemoryRegistry()
	_ = r.Register(&manifest.Bundle{Manifest: manifest.Module{Name: "app"}})
	assert.Error(t, r.SetRollout("app", nil, 101))
	assert.Error(t, r.SetRollout("app", nil, -1))
}

func TestSetRolloutMissing(t *testing.T) {
	r := NewInMemoryRegistry()
	err := r.SetRollout("absent", nil, 50)
	assert.ErrorIs(t, err, ErrModuleNotFound)
}

func TestGetForUserMissing(t *testing.T) {
	r := NewInMemoryRegistry()
	_, err := r.GetForUser("absent", "user-1")
	assert.ErrorIs(t, err, ErrModuleNotFound)
}

func TestGetForUserNoCanary(t *testing.T) {
	r := NewInMemoryRegistry()
	_ = r.Register(&manifest.Bundle{Manifest: manifest.Module{Name: "m", Version: "1.0.0"}})
	b, err := r.GetForUser("m", "user-x")
	require.NoError(t, err)
	assert.Equal(t, "1.0.0", b.Manifest.Version)
}

func TestInstallExistingPack(t *testing.T) {
	r := NewInMemoryRegistry()
	_ = r.Register(&manifest.Bundle{Manifest: manifest.Module{Name: "p1"}})
	assert.NoError(t, r.Install("tenant-1", "p1"))
}

func TestInstallMissingPack(t *testing.T) {
	r := NewInMemoryRegistry()
	assert.ErrorIs(t, r.Install("tenant-1", "missing"), ErrModuleNotFound)
}

func TestPackRegistryPublishNil(t *testing.T) {
	pr := NewPackRegistry(&mockVerifier{})
	assert.Error(t, pr.Publish(nil))
}

func TestPackRegistryPublishMissingName(t *testing.T) {
	pr := NewPackRegistry(&mockVerifier{})
	err := pr.Publish(&PackEntry{Version: "1.0.0", ContentHash: "h", Signatures: []PackSignature{{SignerID: "s"}}})
	assert.Error(t, err)
}

func TestPackRegistryDeprecate(t *testing.T) {
	pr := NewPackRegistry(&mockVerifier{})
	e := &PackEntry{Name: "dp", Version: "1.0.0", ContentHash: "h", Signatures: []PackSignature{{SignerID: "s", Signature: "sig"}}}
	require.NoError(t, pr.Publish(e))
	require.NoError(t, pr.Deprecate(e.PackID))
	got, ok := pr.Get(e.PackID)
	require.True(t, ok)
	assert.Equal(t, PackStateDeprecated, got.State)
}

func TestPackRegistrySearchByCapability(t *testing.T) {
	pr := NewPackRegistry(&mockVerifier{})
	_ = pr.Publish(&PackEntry{Name: "p1", Version: "1.0.0", ContentHash: "h1", Capabilities: []string{"auth"}, Signatures: []PackSignature{{SignerID: "s", Signature: "sig"}}})
	_ = pr.Publish(&PackEntry{Name: "p2", Version: "1.0.0", ContentHash: "h2", Capabilities: []string{"billing"}, Signatures: []PackSignature{{SignerID: "s", Signature: "sig"}}})
	result := pr.Search(PackSearchQuery{Capability: "auth"})
	assert.Equal(t, 1, result.TotalCount)
	assert.Equal(t, "p1", result.Entries[0].Name)
}
