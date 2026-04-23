package evidencepack

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFinal_ManifestVersionConstant(t *testing.T) {
	if ManifestVersion == "" {
		t.Fatal("ManifestVersion should not be empty")
	}
}

func TestFinal_ManifestJSON(t *testing.T) {
	m := Manifest{Version: ManifestVersion, PackID: "p1", PolicyHash: "h1"}
	data, _ := json.Marshal(m)
	var m2 Manifest
	json.Unmarshal(data, &m2)
	if m2.PackID != "p1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_ManifestEntryJSON(t *testing.T) {
	me := ManifestEntry{Path: "receipts/r1.json", ContentHash: "sha256:abc", Size: 1024, ContentType: "application/json"}
	data, _ := json.Marshal(me)
	var me2 ManifestEntry
	json.Unmarshal(data, &me2)
	if me2.Path != "receipts/r1.json" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_HashContent(t *testing.T) {
	h := HashContent([]byte("hello"))
	if !strings.HasPrefix(h, "sha256:") {
		t.Fatal("hash should start with sha256:")
	}
}

func TestFinal_HashContentDeterminism(t *testing.T) {
	h1 := HashContent([]byte("test"))
	h2 := HashContent([]byte("test"))
	if h1 != h2 {
		t.Fatal("hash should be deterministic")
	}
}

func TestFinal_HashContentDifferentInputs(t *testing.T) {
	h1 := HashContent([]byte("a"))
	h2 := HashContent([]byte("b"))
	if h1 == h2 {
		t.Fatal("different inputs should produce different hashes")
	}
}

func TestFinal_ComputeManifestHash(t *testing.T) {
	m := &Manifest{
		Version:    ManifestVersion,
		PackID:     "p1",
		CreatedAt:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		PolicyHash: "h1",
		Entries: []ManifestEntry{
			{Path: "a.json", ContentHash: "sha256:aaa", Size: 100},
		},
	}
	h, err := ComputeManifestHash(m)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "sha256:") {
		t.Fatal("manifest hash should start with sha256:")
	}
}

func TestFinal_ComputeManifestHashDeterminism(t *testing.T) {
	m := &Manifest{Version: "1.0.0", PackID: "p1", CreatedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)}
	h1, _ := ComputeManifestHash(m)
	h2, _ := ComputeManifestHash(m)
	if h1 != h2 {
		t.Fatal("manifest hash should be deterministic")
	}
}

func TestFinal_ComputeManifestHashSortedEntries(t *testing.T) {
	m1 := &Manifest{Version: "1.0.0", PackID: "p1", CreatedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		Entries: []ManifestEntry{{Path: "a.json", ContentHash: "h1", Size: 10}, {Path: "b.json", ContentHash: "h2", Size: 20}}}
	m2 := &Manifest{Version: "1.0.0", PackID: "p1", CreatedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		Entries: []ManifestEntry{{Path: "b.json", ContentHash: "h2", Size: 20}, {Path: "a.json", ContentHash: "h1", Size: 10}}}
	h1, _ := ComputeManifestHash(m1)
	h2, _ := ComputeManifestHash(m2)
	if h1 != h2 {
		t.Fatal("entry order should not affect manifest hash")
	}
}

func TestFinal_BuilderNew(t *testing.T) {
	b := NewBuilder("p1", "did:example:123", "intent-1", "policy-hash-1")
	if b == nil {
		t.Fatal("builder should not be nil")
	}
}

func TestFinal_BuilderAddAndBuild(t *testing.T) {
	b := NewBuilder("p1", "did:example:123", "intent-1", "policy-hash-1")
	b.AddRawEntry("receipts/r1.json", "application/json", []byte(`{"id":"r1"}`))
	m, data, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if m == nil || len(data) == 0 {
		t.Fatal("build should produce manifest and data")
	}
	if len(m.Entries) != 1 {
		t.Fatal("should have 1 entry")
	}
}

func TestFinal_BuilderManifestHash(t *testing.T) {
	b := NewBuilder("p1", "did:example:123", "intent-1", "ph1")
	b.AddRawEntry("a.json", "application/json", []byte("data"))
	m, _, _ := b.Build()
	if m.ManifestHash == "" {
		t.Fatal("manifest hash should be computed")
	}
}

func TestFinal_BuilderEmptyBuildErrors(t *testing.T) {
	b := NewBuilder("p1", "did:example:123", "intent-1", "ph1")
	_, _, err := b.Build()
	if err == nil {
		t.Fatal("empty builder should error on build")
	}
}

func TestFinal_StreamEntryJSON(t *testing.T) {
	se := StreamEntry{Path: "a.json", ContentType: "application/json", Data: []byte("test")}
	data, _ := json.Marshal(se)
	var se2 StreamEntry
	json.Unmarshal(data, &se2)
	if se2.Path != "a.json" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_ConcurrentHashContent(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 15; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			HashContent([]byte{byte(i)})
		}(i)
	}
	wg.Wait()
}

func TestFinal_ManifestEntryZeroSize(t *testing.T) {
	me := ManifestEntry{Path: "empty.json", ContentHash: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Size: 0}
	if me.Size != 0 {
		t.Fatal("zero-sized entry should have size 0")
	}
}

func TestFinal_ManifestVersionIs100(t *testing.T) {
	if ManifestVersion != "1.0.0" {
		t.Fatalf("want 1.0.0, got %s", ManifestVersion)
	}
}

func TestFinal_HashContentEmpty(t *testing.T) {
	h := HashContent([]byte{})
	if h == "" {
		t.Fatal("hash of empty bytes should not be empty string")
	}
}

func TestFinal_BuilderPackID(t *testing.T) {
	b := NewBuilder("my-pack", "did:x:1", "i1", "ph1")
	b.AddRawEntry("test.json", "application/json", []byte("{}"))
	m, _, _ := b.Build()
	if m.PackID != "my-pack" {
		t.Fatal("packID should match builder argument")
	}
}

func TestFinal_BuilderPolicyHash(t *testing.T) {
	b := NewBuilder("p1", "did:x:1", "i1", "policy-abc")
	b.AddRawEntry("test.json", "application/json", []byte("{}"))
	m, _, _ := b.Build()
	if m.PolicyHash != "policy-abc" {
		t.Fatal("policy hash should match builder argument")
	}
}

func TestFinal_ManifestEntrySizePositive(t *testing.T) {
	b := NewBuilder("p1", "did:x:1", "i1", "ph1")
	b.AddRawEntry("a.json", "application/json", []byte("hello"))
	m, _, _ := b.Build()
	if m.Entries[0].Size != 5 {
		t.Fatalf("want size 5, got %d", m.Entries[0].Size)
	}
}

func TestFinal_ManifestEntryContentHash(t *testing.T) {
	b := NewBuilder("p1", "did:x:1", "i1", "ph1")
	b.AddRawEntry("a.json", "application/json", []byte("hello"))
	m, _, _ := b.Build()
	if !strings.HasPrefix(m.Entries[0].ContentHash, "sha256:") {
		t.Fatal("entry content hash should have sha256 prefix")
	}
}

func TestFinal_MultipleEntriesBuilder(t *testing.T) {
	b := NewBuilder("p1", "did:x:1", "i1", "ph1")
	b.AddRawEntry("a.json", "application/json", []byte("a"))
	b.AddRawEntry("b.json", "application/json", []byte("b"))
	b.AddRawEntry("c.json", "application/json", []byte("c"))
	m, _, _ := b.Build()
	if len(m.Entries) != 3 {
		t.Fatal("should have 3 entries")
	}
}
