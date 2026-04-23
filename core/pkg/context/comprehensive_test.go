package context

import (
	"testing"
	"time"
)

func TestExportBundleSuccess(t *testing.T) {
	ns := map[string][]BundleEntry{"ops": {{Key: "k", Value: "v", TrustLevel: "CURATED"}}}
	b, err := ExportBundle("b1", "org1", "1.0", "admin", ns)
	if err != nil || b.BundleID != "b1" {
		t.Fatalf("err=%v bundle=%v", err, b)
	}
}

func TestExportBundleMissingFields(t *testing.T) {
	_, err := ExportBundle("", "org1", "1.0", "admin", nil)
	if err == nil {
		t.Fatal("expected error for empty bundle_id")
	}
}

func TestExportBundleMissingOrgID(t *testing.T) {
	_, err := ExportBundle("b1", "", "1.0", "admin", nil)
	if err == nil {
		t.Fatal("expected error for empty org_id")
	}
}

func TestExportBundleMissingVersion(t *testing.T) {
	_, err := ExportBundle("b1", "org1", "", "admin", nil)
	if err == nil {
		t.Fatal("expected error for empty version")
	}
}

func TestExportBundleContentHash(t *testing.T) {
	ns := map[string][]BundleEntry{"ns": {{Key: "k", Value: "v"}}}
	b, _ := ExportBundle("b1", "org1", "1.0", "admin", ns)
	if len(b.ContentHash) < 10 {
		t.Fatal("expected content hash")
	}
}

func TestValidateBundleValid(t *testing.T) {
	b := ContextBundle{BundleID: "b1", OrgID: "o1", Version: "1.0", Namespaces: map[string][]BundleEntry{"ns": {}}}
	if err := ValidateBundle(b); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateBundleMissingBundleID(t *testing.T) {
	b := ContextBundle{OrgID: "o1", Version: "1.0", Namespaces: map[string][]BundleEntry{"ns": {}}}
	if err := ValidateBundle(b); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateBundleEmptyNamespaces(t *testing.T) {
	b := ContextBundle{BundleID: "b1", OrgID: "o1", Version: "1.0"}
	if err := ValidateBundle(b); err == nil {
		t.Fatal("expected error for empty namespaces")
	}
}

func TestNewContextSlice(t *testing.T) {
	cs := NewContextSlice("s1", "policy-1", []Namespace{NSIdentity, NSPolicy})
	if cs.SliceID != "s1" || cs.CreatedFor != "policy-1" {
		t.Fatal("wrong slice fields")
	}
}

func TestContextSliceSetGet(t *testing.T) {
	cs := NewContextSlice("s1", "p1", []Namespace{NSIdentity})
	cs.Set(NSIdentity, "name", "Alice")
	v, ok := cs.Get(NSIdentity, "name")
	if !ok || v != "Alice" {
		t.Fatalf("expected Alice, got %v ok=%v", v, ok)
	}
}

func TestContextSliceGetMissing(t *testing.T) {
	cs := NewContextSlice("s1", "p1", nil)
	_, ok := cs.Get(NSPolicy, "key")
	if ok {
		t.Fatal("expected not found")
	}
}

func TestContextSliceHasNamespace(t *testing.T) {
	cs := NewContextSlice("s1", "p1", []Namespace{NSIdentity, NSExecution})
	if !cs.HasNamespace(NSIdentity) {
		t.Fatal("expected to have NSIdentity")
	}
	if cs.HasNamespace(NSVendor) {
		t.Fatal("should not have NSVendor")
	}
}

func TestCanonicalNamespacesCount(t *testing.T) {
	ns := CanonicalNamespaces()
	if len(ns) != 12 {
		t.Fatalf("expected 12 canonical namespaces, got %d", len(ns))
	}
}

func TestCanonicalNamespacesRequiredFields(t *testing.T) {
	for _, ns := range CanonicalNamespaces() {
		if ns.Namespace == NSIdentity && !ns.Required {
			t.Fatal("NSIdentity should be required")
		}
	}
}

func TestBundleStoreContextRoundTrip(t *testing.T) {
	s := NewBundleStore()
	b := &ContextBundle{BundleID: "b1", OrgID: "o1", Version: "1.0", Namespaces: map[string][]BundleEntry{"ns": {}}}
	s.PutContext(b)
	got, err := s.GetContext("b1")
	if err != nil || got.BundleID != "b1" {
		t.Fatalf("err=%v got=%v", err, got)
	}
}

func TestBundleStoreContextNotFound(t *testing.T) {
	s := NewBundleStore()
	_, err := s.GetContext("missing")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBundleStoreDocumentRoundTrip(t *testing.T) {
	s := NewBundleStore()
	d := &DocumentBundle{BundleID: "d1", Title: "Guide", Version: "1.0", CreatedAt: time.Now()}
	s.PutDocument(d)
	got, err := s.GetDocument("d1")
	if err != nil || got.Title != "Guide" {
		t.Fatalf("err=%v got=%v", err, got)
	}
}

func TestBundleStoreDocumentNotFound(t *testing.T) {
	s := NewBundleStore()
	_, err := s.GetDocument("missing")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBundleStoreDocumentMissingID(t *testing.T) {
	s := NewBundleStore()
	err := s.PutDocument(&DocumentBundle{})
	if err == nil {
		t.Fatal("expected error for empty bundle_id")
	}
}

func TestBundleStoreListContexts(t *testing.T) {
	s := NewBundleStore()
	s.PutContext(&ContextBundle{BundleID: "a", OrgID: "o", Version: "1", Namespaces: map[string][]BundleEntry{"n": {}}})
	s.PutContext(&ContextBundle{BundleID: "b", OrgID: "o", Version: "1", Namespaces: map[string][]BundleEntry{"n": {}}})
	if len(s.ListContexts()) != 2 {
		t.Fatalf("expected 2 bundles")
	}
}
