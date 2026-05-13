package registry

import (
	"encoding/json"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/manifest"
)

func TestFinal_ErrModuleNotFound(t *testing.T) {
	if ErrModuleNotFound.Error() == "" {
		t.Fatal("error should have message")
	}
}

func TestFinal_NewInMemoryRegistry(t *testing.T) {
	r := NewInMemoryRegistry()
	if r == nil {
		t.Fatal("nil registry")
	}
}

func TestFinal_RegisterBundle(t *testing.T) {
	r := NewInMemoryRegistry()
	err := r.Register(&manifest.Bundle{Manifest: manifest.Module{Name: "mod1", Version: "1.0"}})
	if err != nil {
		t.Fatal(err)
	}
}

func TestFinal_RegisterNilBundle(t *testing.T) {
	r := NewInMemoryRegistry()
	err := r.Register(nil)
	if err == nil {
		t.Fatal("should error on nil")
	}
}

func TestFinal_GetBundle(t *testing.T) {
	r := NewInMemoryRegistry()
	r.Register(&manifest.Bundle{Manifest: manifest.Module{Name: "mod1", Version: "1.0"}})
	b, err := r.Get("mod1")
	if err != nil || b.Manifest.Version != "1.0" {
		t.Fatal("get failed")
	}
}

func TestFinal_GetBundleNotFound(t *testing.T) {
	r := NewInMemoryRegistry()
	_, err := r.Get("nope")
	if err == nil {
		t.Fatal("should error")
	}
}

func TestFinal_UnregisterBundle(t *testing.T) {
	r := NewInMemoryRegistry()
	r.Register(&manifest.Bundle{Manifest: manifest.Module{Name: "mod1"}})
	err := r.Unregister("mod1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Get("mod1")
	if err == nil {
		t.Fatal("should be gone")
	}
}

func TestFinal_UnregisterNotFound(t *testing.T) {
	r := NewInMemoryRegistry()
	err := r.Unregister("nope")
	if err == nil {
		t.Fatal("should error")
	}
}

func TestFinal_ListBundles(t *testing.T) {
	r := NewInMemoryRegistry()
	r.Register(&manifest.Bundle{Manifest: manifest.Module{Name: "a"}})
	r.Register(&manifest.Bundle{Manifest: manifest.Module{Name: "b"}})
	list := r.List()
	if len(list) != 2 {
		t.Fatal("expected 2")
	}
}

func TestFinal_ListBundlesEmpty(t *testing.T) {
	r := NewInMemoryRegistry()
	list := r.List()
	if len(list) != 0 {
		t.Fatal("should be empty")
	}
}

func TestFinal_SetRollout(t *testing.T) {
	r := NewInMemoryRegistry()
	r.Register(&manifest.Bundle{Manifest: manifest.Module{Name: "mod1"}})
	err := r.SetRollout("mod1", &manifest.Bundle{Manifest: manifest.Module{Name: "mod1", Version: "2.0"}}, 50)
	if err != nil {
		t.Fatal(err)
	}
}

func TestFinal_SetRolloutNotFound(t *testing.T) {
	r := NewInMemoryRegistry()
	err := r.SetRollout("nope", nil, 50)
	if err == nil {
		t.Fatal("should error")
	}
}

func TestFinal_SetRolloutInvalidPercentage(t *testing.T) {
	r := NewInMemoryRegistry()
	r.Register(&manifest.Bundle{Manifest: manifest.Module{Name: "mod1"}})
	err := r.SetRollout("mod1", nil, 150)
	if err == nil {
		t.Fatal("should error on >100")
	}
}

func TestFinal_GetForUserStable(t *testing.T) {
	r := NewInMemoryRegistry()
	r.Register(&manifest.Bundle{Manifest: manifest.Module{Name: "mod1", Version: "1.0"}})
	b, err := r.GetForUser("mod1", "user-1")
	if err != nil || b.Manifest.Version != "1.0" {
		t.Fatal("should get stable")
	}
}

func TestFinal_GetForUserNotFound(t *testing.T) {
	r := NewInMemoryRegistry()
	_, err := r.GetForUser("nope", "user-1")
	if err == nil {
		t.Fatal("should error")
	}
}

func TestFinal_InstallSuccess(t *testing.T) {
	r := NewInMemoryRegistry()
	r.Register(&manifest.Bundle{Manifest: manifest.Module{Name: "mod1"}})
	err := r.Install("tenant-1", "mod1")
	if err != nil {
		t.Fatal(err)
	}
}

func TestFinal_InstallNotFound(t *testing.T) {
	r := NewInMemoryRegistry()
	err := r.Install("tenant-1", "nope")
	if err == nil {
		t.Fatal("should error")
	}
}

func TestFinal_PackStateConstants(t *testing.T) {
	states := []PackState{PackStatePublished, PackStateVerified, PackStateSigned, PackStateActive, PackStateDeprecated}
	if len(states) != 5 {
		t.Fatal("expected 5 pack states")
	}
}

func TestFinal_PackEntryJSONRoundTrip(t *testing.T) {
	pe := PackEntry{PackID: "p1", Name: "pack1", Version: "1.0", State: PackStatePublished}
	data, _ := json.Marshal(pe)
	var got PackEntry
	json.Unmarshal(data, &got)
	if got.PackID != "p1" || got.State != PackStatePublished {
		t.Fatal("round-trip")
	}
}

func TestFinal_PackSignatureJSONRoundTrip(t *testing.T) {
	ps := PackSignature{SignerID: "s1", Algorithm: "ed25519", Signature: "sig"}
	data, _ := json.Marshal(ps)
	var got PackSignature
	json.Unmarshal(data, &got)
	if got.SignerID != "s1" {
		t.Fatal("sig round-trip")
	}
}

func TestFinal_PackSearchQueryJSONRoundTrip(t *testing.T) {
	q := PackSearchQuery{Name: "test", Limit: 10}
	data, _ := json.Marshal(q)
	var got PackSearchQuery
	json.Unmarshal(data, &got)
	if got.Name != "test" || got.Limit != 10 {
		t.Fatal("query round-trip")
	}
}

func TestFinal_PackSearchResultJSONRoundTrip(t *testing.T) {
	r := PackSearchResult{TotalCount: 5, Entries: []*PackEntry{}}
	data, _ := json.Marshal(r)
	var got PackSearchResult
	json.Unmarshal(data, &got)
	if got.TotalCount != 5 {
		t.Fatal("result round-trip")
	}
}

func TestFinal_NewPackRegistryNilVerifier(t *testing.T) {
	r := NewPackRegistry(nil)
	if r == nil {
		t.Fatal("nil registry")
	}
}

func TestFinal_PublishNilEntry(t *testing.T) {
	r := NewPackRegistry(nil)
	err := r.Publish(nil)
	if err == nil {
		t.Fatal("should error on nil")
	}
}

func TestFinal_PublishMissingName(t *testing.T) {
	r := NewPackRegistry(nil)
	err := r.Publish(&PackEntry{Version: "1.0", ContentHash: "h", Signatures: []PackSignature{{}}})
	if err == nil {
		t.Fatal("should error on missing name")
	}
}

func TestFinal_CountEmpty(t *testing.T) {
	r := NewPackRegistry(nil)
	if r.Count() != 0 {
		t.Fatal("should be 0")
	}
}

func TestFinal_ListVersionsEmpty(t *testing.T) {
	r := NewPackRegistry(nil)
	v := r.ListVersions("nope")
	if len(v) != 0 {
		t.Fatal("should be empty")
	}
}

func TestFinal_SearchEmpty(t *testing.T) {
	r := NewPackRegistry(nil)
	result := r.Search(PackSearchQuery{})
	if result.TotalCount != 0 {
		t.Fatal("should be 0")
	}
}

func TestFinal_RegisterOverwrites(t *testing.T) {
	r := NewInMemoryRegistry()
	r.Register(&manifest.Bundle{Manifest: manifest.Module{Name: "mod1", Version: "1.0"}})
	r.Register(&manifest.Bundle{Manifest: manifest.Module{Name: "mod1", Version: "2.0"}})
	b, _ := r.Get("mod1")
	if b.Manifest.Version != "2.0" {
		t.Fatal("should overwrite")
	}
}
