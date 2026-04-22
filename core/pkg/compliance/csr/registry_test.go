package csr

import (
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jkg"
)

func validSource(id string) *ComplianceSource {
	return &ComplianceSource{
		SourceID:     id,
		Name:         "Test Source " + id,
		Description:  "Test compliance source",
		Class:        ClassLaw,
		SourceType:   "gazette",
		Jurisdiction: jkg.JurisdictionEU,
		FetchMethod:  FetchREST,
		EndpointURL:  "https://example.com/api",
		AuthType:     AuthNone,
		Trust: TrustModel{
			HashChainPolicy: "sha256",
			TimestampPolicy: "internal",
		},
		Normalization: NormalizationMapping{
			ObligationSchema: "helm://schemas/compliance/Obligation.v1",
		},
		UpdateCadence:   "daily",
		TTL:             24 * time.Hour,
		ChangeDetection: "hash",
		EvidenceRules: EvidenceEmissionRules{
			EmitSourceVersion: true,
			EmitContentHash:   true,
			EmitRetrievalTime: true,
		},
		Provenance: "Official source",
	}
}

func TestRegistry_Register(t *testing.T) {
	reg := NewInMemoryCSR()
	src := validSource("test-1")

	if err := reg.Register(src); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	got, err := reg.Get("test-1")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.SourceID != "test-1" {
		t.Errorf("expected source_id test-1, got %s", got.SourceID)
	}
}

func TestRegistry_DuplicateDetection(t *testing.T) {
	reg := NewInMemoryCSR()
	src := validSource("dup-1")

	if err := reg.Register(src); err != nil {
		t.Fatalf("first Register failed: %v", err)
	}

	err := reg.Register(src)
	if err == nil {
		t.Fatal("expected error on duplicate registration")
	}
}

func TestRegistry_GetNotFound(t *testing.T) {
	reg := NewInMemoryCSR()
	_, err := reg.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent source")
	}
}

func TestRegistry_ListByClass(t *testing.T) {
	reg := NewInMemoryCSR()

	law := validSource("law-1")
	law.Class = ClassLaw

	privacy := validSource("priv-1")
	privacy.Class = ClassPrivacy

	sanctions := validSource("sanc-1")
	sanctions.Class = ClassSanctions

	for _, s := range []*ComplianceSource{law, privacy, sanctions} {
		if err := reg.Register(s); err != nil {
			t.Fatalf("Register failed: %v", err)
		}
	}

	lawSources := reg.ListByClass(ClassLaw)
	if len(lawSources) != 1 {
		t.Errorf("expected 1 LAW source, got %d", len(lawSources))
	}

	privSources := reg.ListByClass(ClassPrivacy)
	if len(privSources) != 1 {
		t.Errorf("expected 1 PRIVACY source, got %d", len(privSources))
	}

	aiSources := reg.ListByClass(ClassAIGovernance)
	if len(aiSources) != 0 {
		t.Errorf("expected 0 AI_GOVERNANCE sources, got %d", len(aiSources))
	}
}

func TestRegistry_ListByJurisdiction(t *testing.T) {
	reg := NewInMemoryCSR()

	eu := validSource("eu-1")
	eu.Jurisdiction = jkg.JurisdictionEU

	us := validSource("us-1")
	us.Jurisdiction = jkg.JurisdictionUS

	gb := validSource("gb-1")
	gb.Jurisdiction = jkg.JurisdictionGB

	for _, s := range []*ComplianceSource{eu, us, gb} {
		if err := reg.Register(s); err != nil {
			t.Fatalf("Register failed: %v", err)
		}
	}

	euSources := reg.ListByJurisdiction(jkg.JurisdictionEU)
	if len(euSources) != 1 {
		t.Errorf("expected 1 EU source, got %d", len(euSources))
	}
}

func TestRegistry_ListAll(t *testing.T) {
	reg := NewInMemoryCSR()
	for i := 0; i < 5; i++ {
		if err := reg.Register(validSource("all-" + string(rune('a'+i)))); err != nil {
			t.Fatalf("Register failed: %v", err)
		}
	}

	all := reg.ListAll()
	if len(all) != 5 {
		t.Errorf("expected 5 sources, got %d", len(all))
	}
}

func TestRegistry_Unregister(t *testing.T) {
	reg := NewInMemoryCSR()
	src := validSource("del-1")

	if err := reg.Register(src); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	if err := reg.Unregister("del-1"); err != nil {
		t.Fatalf("Unregister failed: %v", err)
	}

	_, err := reg.Get("del-1")
	if err == nil {
		t.Fatal("expected error after unregister")
	}
}

func TestRegistry_UnregisterNotFound(t *testing.T) {
	reg := NewInMemoryCSR()
	err := reg.Unregister("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent source")
	}
}

func TestRegistry_ValidationErrors(t *testing.T) {
	reg := NewInMemoryCSR()

	tests := []struct {
		name   string
		modify func(s *ComplianceSource)
	}{
		{"nil source", func(_ *ComplianceSource) {}},
		{"empty source_id", func(s *ComplianceSource) { s.SourceID = "" }},
		{"empty name", func(s *ComplianceSource) { s.Name = "" }},
		{"empty class", func(s *ComplianceSource) { s.Class = "" }},
		{"invalid class", func(s *ComplianceSource) { s.Class = "INVALID" }},
		{"empty fetch_method", func(s *ComplianceSource) { s.FetchMethod = "" }},
		{"empty endpoint_url", func(s *ComplianceSource) { s.EndpointURL = "" }},
		{"empty hash_chain_policy", func(s *ComplianceSource) { s.Trust.HashChainPolicy = "" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var src *ComplianceSource
			if tt.name == "nil source" {
				src = nil
			} else {
				src = validSource("val-test")
				tt.modify(src)
			}
			if err := reg.Register(src); err == nil {
				t.Error("expected validation error")
			}
		})
	}
}

func TestAllSourceClasses(t *testing.T) {
	classes := AllSourceClasses()
	if len(classes) != 10 {
		t.Errorf("expected 10 source classes, got %d", len(classes))
	}
}

func TestRegistry_SnapshotDeterminism(t *testing.T) {
	// Build registry twice in different insertion orders → same hash
	build := func(order []string) *InMemoryCSR {
		reg := NewInMemoryCSR()
		for _, id := range order {
			if err := reg.Register(validSource(id)); err != nil {
				t.Fatalf("Register failed: %v", err)
			}
		}
		return reg
	}

	reg1 := build([]string{"zz-source", "aa-source", "mm-source"})
	reg2 := build([]string{"mm-source", "aa-source", "zz-source"})

	snap1, err := reg1.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot 1 failed: %v", err)
	}
	snap2, err := reg2.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot 2 failed: %v", err)
	}

	if snap1.Hash != snap2.Hash {
		t.Errorf("snapshot hashes differ: %s vs %s", snap1.Hash, snap2.Hash)
	}
	if snap1.Count != 3 {
		t.Errorf("expected count 3, got %d", snap1.Count)
	}

	// Verify sorted order
	if snap1.Sources[0].SourceID != "aa-source" {
		t.Errorf("expected first source aa-source, got %s", snap1.Sources[0].SourceID)
	}
	if snap1.Sources[2].SourceID != "zz-source" {
		t.Errorf("expected last source zz-source, got %s", snap1.Sources[2].SourceID)
	}
}

func TestRegistry_SnapshotEmpty(t *testing.T) {
	reg := NewInMemoryCSR()
	snap, err := reg.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot failed: %v", err)
	}
	if snap.Count != 0 {
		t.Errorf("expected count 0, got %d", snap.Count)
	}
	if snap.Hash == "" {
		t.Error("expected non-empty hash even for empty registry")
	}
}

func TestSeedRegistry(t *testing.T) {
	reg := NewInMemoryCSR()
	if err := SeedRegistry(reg); err != nil {
		t.Fatalf("SeedRegistry failed: %v", err)
	}

	all := reg.ListAll()
	if len(all) < 25 {
		t.Errorf("expected at least 25 default sources, got %d", len(all))
	}

	// Verify all 10 classes have at least one source
	classCounts := make(map[SourceClass]int)
	for _, s := range all {
		classCounts[s.Class]++
	}
	for _, class := range AllSourceClasses() {
		if classCounts[class] == 0 {
			t.Errorf("class %s has no default sources", class)
		}
	}
}
