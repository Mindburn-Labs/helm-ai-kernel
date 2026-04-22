package aibom

import (
	"os"
	"path/filepath"
	"testing"
)

// ── Generator ──

func TestGenerate_MinimalConfig(t *testing.T) {
	bom, err := Generate(GenerateConfig{Component: "test-comp"})
	if err != nil {
		t.Fatal(err)
	}
	if bom.Component != "test-comp" {
		t.Fatalf("expected component 'test-comp', got %q", bom.Component)
	}
	if bom.FormatVersion != "1.0.0" {
		t.Fatalf("expected format version 1.0.0, got %s", bom.FormatVersion)
	}
	if bom.ContentHash == "" {
		t.Fatal("expected non-empty content hash")
	}
}

func TestGenerate_WithModels(t *testing.T) {
	bom, err := Generate(GenerateConfig{
		Component: "llm-gw",
		Models: []ModelProvenance{
			{ModelID: "m1", Provider: "openai", ModelName: "gpt-4o"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(bom.Models) != 1 || bom.Models[0].ModelID != "m1" {
		t.Fatal("expected model entry m1")
	}
}

func TestGenerate_WithDatasets(t *testing.T) {
	bom, err := Generate(GenerateConfig{
		Component: "rag",
		Datasets: []DatasetLineage{
			{DatasetID: "d1", Name: "corpus", Version: "1.0"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(bom.Datasets) != 1 {
		t.Fatal("expected 1 dataset entry")
	}
}

func TestGenerate_GoMod(t *testing.T) {
	dir := t.TempDir()
	modFile := filepath.Join(dir, "go.mod")
	content := "module example\n\ngo 1.22\n\nrequire (\n\tgithub.com/foo/bar v1.2.3\n\tgithub.com/baz/qux v0.1.0 // indirect\n)\n"
	if err := os.WriteFile(modFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	bom, err := Generate(GenerateConfig{Component: "test", GoModPath: modFile})
	if err != nil {
		t.Fatal(err)
	}
	if len(bom.Dependencies) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(bom.Dependencies))
	}
}

func TestGenerate_GoModIndirect(t *testing.T) {
	dir := t.TempDir()
	modFile := filepath.Join(dir, "go.mod")
	content := "module example\n\ngo 1.22\n\nrequire (\n\tgithub.com/x/y v1.0.0 // indirect\n)\n"
	os.WriteFile(modFile, []byte(content), 0644)
	bom, _ := Generate(GenerateConfig{Component: "test", GoModPath: modFile})
	if bom.Dependencies[0].SPDXID != "indirect" {
		t.Fatal("expected indirect marker on SPDXID")
	}
}

func TestGenerate_GoModMissing(t *testing.T) {
	_, err := Generate(GenerateConfig{Component: "test", GoModPath: "/nonexistent/go.mod"})
	if err == nil {
		t.Fatal("expected error for missing go.mod")
	}
}

func TestGenerate_BomIDPrefix(t *testing.T) {
	bom, _ := Generate(GenerateConfig{Component: "c"})
	if len(bom.BomID) < 5 || bom.BomID[:4] != "bom-" {
		t.Fatalf("expected bom- prefix, got %q", bom.BomID)
	}
}

// ── Verifier ──

func TestVerify_ValidBOMIntegrity(t *testing.T) {
	bom, _ := Generate(GenerateConfig{Component: "verified"})
	if err := Verify(bom); err != nil {
		t.Fatalf("valid BOM should verify: %v", err)
	}
}

func TestVerify_TamperedBOMFails(t *testing.T) {
	bom, _ := Generate(GenerateConfig{Component: "tampered"})
	bom.Component = "changed"
	if err := Verify(bom); err == nil {
		t.Fatal("tampered BOM should fail verification")
	}
}

func TestVerify_EmptyHash(t *testing.T) {
	bom := &AIBOM{BomID: "x", Component: "y", ContentHash: ""}
	if err := Verify(bom); err == nil {
		t.Fatal("expected error for empty content hash")
	}
}

// ── Diff ──

func TestDiff_ModelAdded(t *testing.T) {
	old := &AIBOM{BomID: "old", Models: []ModelProvenance{}}
	new := &AIBOM{BomID: "new", Models: []ModelProvenance{{ModelID: "m1"}}}
	d := Diff(old, new)
	if len(d.ModelsAdded) != 1 || d.ModelsAdded[0].ModelID != "m1" {
		t.Fatal("expected 1 model added")
	}
}

func TestDiff_ModelRemoved(t *testing.T) {
	old := &AIBOM{BomID: "old", Models: []ModelProvenance{{ModelID: "m1"}}}
	new := &AIBOM{BomID: "new", Models: []ModelProvenance{}}
	d := Diff(old, new)
	if len(d.ModelsRemoved) != 1 {
		t.Fatal("expected 1 model removed")
	}
}

func TestDiff_DepVersionChanged(t *testing.T) {
	old := &AIBOM{BomID: "old", Dependencies: []DependencyEntry{{Name: "foo", Version: "1.0"}}}
	new := &AIBOM{BomID: "new", Dependencies: []DependencyEntry{{Name: "foo", Version: "2.0"}}}
	d := Diff(old, new)
	if len(d.DepsChanged) != 1 || d.DepsChanged[0].OldVersion != "1.0" {
		t.Fatal("expected 1 dep version change")
	}
}

func TestDiff_NoDifferences(t *testing.T) {
	bom := &AIBOM{BomID: "same", Models: []ModelProvenance{{ModelID: "m1"}},
		Dependencies: []DependencyEntry{{Name: "dep", Version: "1.0"}}}
	d := Diff(bom, bom)
	if len(d.ModelsAdded)+len(d.ModelsRemoved)+len(d.DepsAdded)+len(d.DepsRemoved)+len(d.DepsChanged) != 0 {
		t.Fatal("expected no differences")
	}
}
