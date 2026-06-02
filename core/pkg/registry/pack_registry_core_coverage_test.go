package registry

import (
	"errors"
	"strings"
	"testing"
)

type registryErrorVerifier struct{}

func (registryErrorVerifier) VerifyPackSignature(string, *PackSignature) (bool, error) {
	return false, errors.New("verify failed")
}

func TestPackRegistryAdditionalEdgeBranches(t *testing.T) {
	registry := NewPackRegistry(&mockVerifier{})
	requireRegistryErrorContains(t, registry.Publish(&PackEntry{Name: "missing-version", ContentHash: "hash", Signatures: []PackSignature{{SignerID: "s"}}}), "pack version is required")
	requireRegistryErrorContains(t, registry.Publish(&PackEntry{Name: "missing-hash", Version: "1.0.0", Signatures: []PackSignature{{SignerID: "s"}}}), "content hash is required")
	requireRegistryErrorContains(t, NewPackRegistry(registryErrorVerifier{}).Publish(&PackEntry{Name: "bad", Version: "1.0.0", ContentHash: "hash", Signatures: []PackSignature{{SignerID: "s"}}}), "no valid signature found")

	alphaAuth := publishRegistryCoveragePack(t, registry, "p-alpha-auth", "alpha", "1.0.0", []string{"auth"})
	alphaBilling := publishRegistryCoveragePack(t, registry, "p-alpha-billing", "alpha", "2.0.0", []string{"billing"})
	betaAuth := publishRegistryCoveragePack(t, registry, "p-beta-auth", "beta", "1.0.0", []string{"auth"})
	alphaAuth.State = PackStateActive
	alphaBilling.State = PackStateDeprecated
	betaAuth.State = PackStatePublished

	if _, ok := registry.GetByNameVersion("missing", "1.0.0"); ok {
		t.Fatal("GetByNameVersion missing name ok = true")
	}
	filtered := registry.Search(PackSearchQuery{Name: "alpha", Capability: "auth"})
	if filtered.TotalCount != 1 || filtered.Entries[0].PackID != "p-alpha-auth" {
		t.Fatalf("Search by capability with name filter = %#v, want only alpha auth", filtered.Entries)
	}
	deprecated := registry.Search(PackSearchQuery{States: []PackState{PackStateDeprecated}})
	if deprecated.TotalCount != 1 || deprecated.Entries[0].PackID != "p-alpha-billing" {
		t.Fatalf("Search deprecated = %#v, want alpha billing", deprecated.Entries)
	}
	limited := registry.Search(PackSearchQuery{Limit: 1})
	if limited.TotalCount != 3 || len(limited.Entries) != 1 {
		t.Fatalf("Search limit total=%d len=%d, want total 3 len 1", limited.TotalCount, len(limited.Entries))
	}

	ok, err := registry.VerifyPack("missing")
	if ok {
		t.Fatal("VerifyPack missing ok = true")
	}
	requireRegistryErrorContains(t, err, "pack not found")
	registry.verifier = &failingVerifier{}
	ok, err = registry.VerifyPack("p-alpha-auth")
	if ok || err == nil {
		t.Fatalf("VerifyPack failing verifier = (%v, %v), want false error", ok, err)
	}
	registry.verifier = &mockVerifier{}

	requireRegistryErrorContains(t, registry.Activate("missing"), "pack not found")
	requireRegistryErrorContains(t, registry.MarkVerified("missing"), "pack not found")
	requireRegistryErrorContains(t, registry.MarkSigned("missing"), "pack not found")
	requireRegistryErrorContains(t, registry.Deprecate("missing"), "pack not found")
	requireRegistryErrorContains(t, registry.MarkVerified("p-alpha-auth"), "must be published before verification")
	requireRegistryErrorContains(t, registry.MarkSigned("p-beta-auth"), "must be verified before signing")
}

func publishRegistryCoveragePack(t *testing.T, registry *PackRegistry, id, name, version string, capabilities []string) *PackEntry {
	t.Helper()
	entry := &PackEntry{
		PackID:       id,
		Name:         name,
		Version:      version,
		ContentHash:  "sha256:" + id,
		Capabilities: capabilities,
		Signatures:   []PackSignature{{SignerID: "signer", Signature: "sig"}},
	}
	if err := registry.Publish(entry); err != nil {
		t.Fatalf("Publish %s: %v", id, err)
	}
	return entry
}

func requireRegistryErrorContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want substring %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want substring %q", err, want)
	}
}
