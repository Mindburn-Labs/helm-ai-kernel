package aibom

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerate_BasicBOM(t *testing.T) {
	models := []ModelProvenance{
		{
			ModelID:      "model-1",
			Provider:     "anthropic",
			ModelName:    "claude-sonnet-4",
			ModelVersion: "20250514",
			License:      "proprietary",
			Parameters:   "unknown",
		},
	}
	datasets := []DatasetLineage{
		{
			DatasetID: "ds-1",
			Name:      "eval-set-v1",
			Version:   "1.0.0",
			PIIStatus: "none",
		},
	}

	bom, err := Generate(GenerateConfig{
		Component: "test-component",
		Models:    models,
		Datasets:  datasets,
	})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if bom.FormatVersion != "1.0.0" {
		t.Errorf("expected format_version 1.0.0, got %s", bom.FormatVersion)
	}
	if bom.Component != "test-component" {
		t.Errorf("expected component test-component, got %s", bom.Component)
	}
	if !strings.HasPrefix(bom.BomID, "bom-") {
		t.Errorf("expected bom_id to start with bom-, got %s", bom.BomID)
	}
	if len(bom.Models) != 1 {
		t.Fatalf("expected 1 model, got %d", len(bom.Models))
	}
	if bom.Models[0].ModelID != "model-1" {
		t.Errorf("expected model_id model-1, got %s", bom.Models[0].ModelID)
	}
	if len(bom.Datasets) != 1 {
		t.Fatalf("expected 1 dataset, got %d", len(bom.Datasets))
	}
	if bom.ContentHash == "" {
		t.Fatal("expected non-empty content_hash")
	}
	if !strings.HasPrefix(bom.ContentHash, "sha256:") {
		t.Errorf("expected content_hash to start with sha256:, got %s", bom.ContentHash)
	}

	// Verify the hash is valid.
	if err := Verify(bom); err != nil {
		t.Fatalf("Verify failed on freshly generated BOM: %v", err)
	}
}

func TestFromGoMod(t *testing.T) {
	content := `module example.com/myapp

go 1.25.0

require (
	github.com/foo/bar v1.2.3
	github.com/baz/qux v0.9.0 // indirect
)

require github.com/single/dep v2.0.0
`
	dir := t.TempDir()
	modPath := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(modPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write temp go.mod: %v", err)
	}

	deps, err := FromGoMod(modPath)
	if err != nil {
		t.Fatalf("FromGoMod failed: %v", err)
	}

	if len(deps) != 3 {
		t.Fatalf("expected 3 deps, got %d", len(deps))
	}

	// Block require: direct dep.
	if deps[0].Name != "github.com/foo/bar" || deps[0].Version != "v1.2.3" {
		t.Errorf("unexpected dep[0]: %+v", deps[0])
	}
	if deps[0].Type != "go-module" {
		t.Errorf("expected type go-module, got %s", deps[0].Type)
	}
	if deps[0].SPDXID != "" {
		t.Errorf("expected empty SPDXID for direct dep, got %s", deps[0].SPDXID)
	}

	// Block require: indirect dep.
	if deps[1].Name != "github.com/baz/qux" || deps[1].Version != "v0.9.0" {
		t.Errorf("unexpected dep[1]: %+v", deps[1])
	}
	if deps[1].SPDXID != "indirect" {
		t.Errorf("expected SPDXID indirect, got %s", deps[1].SPDXID)
	}

	// Single-line require.
	if deps[2].Name != "github.com/single/dep" || deps[2].Version != "v2.0.0" {
		t.Errorf("unexpected dep[2]: %+v", deps[2])
	}
}

func TestGenerate_ContentHash(t *testing.T) {
	// Generate two BOMs with different content and verify hashes differ.
	bom1, err := Generate(GenerateConfig{
		Component: "component-a",
		Models: []ModelProvenance{
			{ModelID: "m1", Provider: "openai", ModelName: "gpt-4", ModelVersion: "v1"},
		},
	})
	if err != nil {
		t.Fatalf("Generate bom1 failed: %v", err)
	}

	bom2, err := Generate(GenerateConfig{
		Component: "component-b",
		Models: []ModelProvenance{
			{ModelID: "m2", Provider: "anthropic", ModelName: "claude", ModelVersion: "v2"},
		},
	})
	if err != nil {
		t.Fatalf("Generate bom2 failed: %v", err)
	}

	if bom1.ContentHash == bom2.ContentHash {
		t.Error("expected different content hashes for different BOMs")
	}
}
