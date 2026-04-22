package aibom

import (
	"strings"
	"testing"
	"time"
)

func TestVerify_ValidBOM(t *testing.T) {
	bom, err := Generate(GenerateConfig{
		Component: "kernel",
		Models: []ModelProvenance{
			{ModelID: "m1", Provider: "openai", ModelName: "gpt-4o", ModelVersion: "2025-01"},
		},
	})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if err := Verify(bom); err != nil {
		t.Fatalf("Verify should succeed on untampered BOM: %v", err)
	}
}

func TestVerify_TamperedBOM(t *testing.T) {
	bom, err := Generate(GenerateConfig{
		Component: "kernel",
		Models: []ModelProvenance{
			{ModelID: "m1", Provider: "openai", ModelName: "gpt-4o", ModelVersion: "2025-01"},
		},
	})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Tamper with the BOM after hashing.
	bom.Component = "tampered-component"

	err = Verify(bom)
	if err == nil {
		t.Fatal("Verify should fail on tampered BOM")
	}
	if !strings.Contains(err.Error(), "content hash mismatch") {
		t.Errorf("expected content hash mismatch error, got: %v", err)
	}
}

func TestVerify_MissingHash(t *testing.T) {
	bom := &AIBOM{
		BomID:         "bom-nohash",
		FormatVersion: "1.0.0",
		Component:     "test",
		CreatedAt:     time.Now(),
		Models:        []ModelProvenance{},
		Dependencies:  []DependencyEntry{},
	}

	err := Verify(bom)
	if err == nil {
		t.Fatal("Verify should fail when content hash is missing")
	}
	if !strings.Contains(err.Error(), "no content hash") {
		t.Errorf("expected 'no content hash' error, got: %v", err)
	}
}

func TestDiff_ModelsAddedRemoved(t *testing.T) {
	modelA := ModelProvenance{ModelID: "ma", Provider: "openai", ModelName: "gpt-4", ModelVersion: "v1"}
	modelB := ModelProvenance{ModelID: "mb", Provider: "anthropic", ModelName: "claude", ModelVersion: "v1"}
	modelC := ModelProvenance{ModelID: "mc", Provider: "local", ModelName: "llama", ModelVersion: "v3"}

	old := &AIBOM{
		BomID:  "old-bom",
		Models: []ModelProvenance{modelA, modelB},
	}
	new := &AIBOM{
		BomID:  "new-bom",
		Models: []ModelProvenance{modelB, modelC},
	}

	diff := Diff(old, new)

	if diff.OldBomID != "old-bom" || diff.NewBomID != "new-bom" {
		t.Errorf("unexpected bom IDs: %s, %s", diff.OldBomID, diff.NewBomID)
	}

	// modelC should be added (not in old).
	if len(diff.ModelsAdded) != 1 {
		t.Fatalf("expected 1 model added, got %d", len(diff.ModelsAdded))
	}
	if diff.ModelsAdded[0].ModelID != "mc" {
		t.Errorf("expected added model mc, got %s", diff.ModelsAdded[0].ModelID)
	}

	// modelA should be removed (not in new).
	if len(diff.ModelsRemoved) != 1 {
		t.Fatalf("expected 1 model removed, got %d", len(diff.ModelsRemoved))
	}
	if diff.ModelsRemoved[0].ModelID != "ma" {
		t.Errorf("expected removed model ma, got %s", diff.ModelsRemoved[0].ModelID)
	}
}

func TestDiff_DepsChanged(t *testing.T) {
	old := &AIBOM{
		BomID: "old",
		Dependencies: []DependencyEntry{
			{Name: "github.com/foo/bar", Version: "v1.0.0", Type: "go-module"},
			{Name: "github.com/baz/qux", Version: "v2.0.0", Type: "go-module"},
			{Name: "github.com/old/removed", Version: "v1.0.0", Type: "go-module"},
		},
	}
	new := &AIBOM{
		BomID: "new",
		Dependencies: []DependencyEntry{
			{Name: "github.com/foo/bar", Version: "v1.0.0", Type: "go-module"}, // unchanged
			{Name: "github.com/baz/qux", Version: "v3.0.0", Type: "go-module"}, // version changed
			{Name: "github.com/new/added", Version: "v1.0.0", Type: "go-module"}, // added
		},
	}

	diff := Diff(old, new)

	// github.com/new/added should appear in added.
	if len(diff.DepsAdded) != 1 {
		t.Fatalf("expected 1 dep added, got %d", len(diff.DepsAdded))
	}
	if diff.DepsAdded[0].Name != "github.com/new/added" {
		t.Errorf("expected added dep github.com/new/added, got %s", diff.DepsAdded[0].Name)
	}

	// github.com/old/removed should appear in removed.
	if len(diff.DepsRemoved) != 1 {
		t.Fatalf("expected 1 dep removed, got %d", len(diff.DepsRemoved))
	}
	if diff.DepsRemoved[0].Name != "github.com/old/removed" {
		t.Errorf("expected removed dep github.com/old/removed, got %s", diff.DepsRemoved[0].Name)
	}

	// github.com/baz/qux should appear in changed.
	if len(diff.DepsChanged) != 1 {
		t.Fatalf("expected 1 dep changed, got %d", len(diff.DepsChanged))
	}
	if diff.DepsChanged[0].Name != "github.com/baz/qux" {
		t.Errorf("expected changed dep github.com/baz/qux, got %s", diff.DepsChanged[0].Name)
	}
	if diff.DepsChanged[0].OldVersion != "v2.0.0" || diff.DepsChanged[0].NewVersion != "v3.0.0" {
		t.Errorf("unexpected version change: %s -> %s", diff.DepsChanged[0].OldVersion, diff.DepsChanged[0].NewVersion)
	}
}

func TestDiff_NoDifference(t *testing.T) {
	models := []ModelProvenance{
		{ModelID: "m1", Provider: "openai", ModelName: "gpt-4", ModelVersion: "v1"},
	}
	deps := []DependencyEntry{
		{Name: "github.com/foo/bar", Version: "v1.0.0", Type: "go-module"},
	}

	a := &AIBOM{BomID: "a", Models: models, Dependencies: deps}
	b := &AIBOM{BomID: "b", Models: models, Dependencies: deps}

	diff := Diff(a, b)

	if len(diff.ModelsAdded) != 0 {
		t.Errorf("expected no models added, got %d", len(diff.ModelsAdded))
	}
	if len(diff.ModelsRemoved) != 0 {
		t.Errorf("expected no models removed, got %d", len(diff.ModelsRemoved))
	}
	if len(diff.DepsAdded) != 0 {
		t.Errorf("expected no deps added, got %d", len(diff.DepsAdded))
	}
	if len(diff.DepsRemoved) != 0 {
		t.Errorf("expected no deps removed, got %d", len(diff.DepsRemoved))
	}
	if len(diff.DepsChanged) != 0 {
		t.Errorf("expected no deps changed, got %d", len(diff.DepsChanged))
	}
}
