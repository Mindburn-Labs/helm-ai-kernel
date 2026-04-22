package pack_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/pack"
)

func TestFSRegistry(t *testing.T) {
	// Setup temporary directory
	tmpDir, err := os.MkdirTemp("", "pack-registry-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test pack
	packName := "test-pack-fs"
	version := "1.0.0"
	manifest := pack.PackManifest{
		PackID:        packName,
		Version:       version,
		Name:          "Test Pack FS",
		SchemaVersion: "1.0",
		Capabilities:  []string{"fs.read"},
	}

	packDir := filepath.Join(tmpDir, packName, version)
	if err := os.MkdirAll(packDir, 0755); err != nil {
		t.Fatal(err)
	}

	data, _ := json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(packDir, "manifest.json"), data, 0644); err != nil {
		t.Fatal(err)
	}

	// Test Registry
	registry := pack.NewFSRegistry(tmpDir)
	ctx := context.Background()

	// 1. GetPack
	p, err := registry.GetPack(ctx, packName)
	if err != nil {
		t.Fatalf("GetPack failed: %v", err)
	}
	if p.Manifest.Version != version {
		t.Errorf("Expected version %s, got %s", version, p.Manifest.Version)
	}

	// 2. FindByCapability
	packs, err := registry.FindByCapability(ctx, "fs.read")
	if err != nil {
		t.Fatalf("FindByCapability failed: %v", err)
	}
	if len(packs) != 1 {
		t.Errorf("Expected 1 pack, got %d", len(packs))
	}
	if packs[0].PackID != packName {
		t.Errorf("Expected pack %s, got %s", packName, packs[0].PackID)
	}

	// 3. ListVersions
	versions, err := registry.ListVersions(ctx, packName)
	if err != nil {
		t.Fatalf("ListVersions failed: %v", err)
	}
	if len(versions) != 1 {
		t.Errorf("Expected 1 version, got %d", len(versions))
	}
}

func TestLedgerTelemetryHook(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "telemetry-ledger-test.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	hook := pack.NewLedgerTelemetryHook(tmpFile.Name())
	ctx := context.Background()

	// Record Execution
	hook.RecordExecution(ctx, "pack-1", "1.0.0", true, 100*time.Millisecond)

	// Verify file content
	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	if len(content) == 0 {
		t.Error("Ledger file is empty")
	}

	// Record Incident
	hook.RecordIncident(ctx, "pack-1", "1.0.0", "CRITICAL")

	// Read again
	content, err = os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	// Check for 2 lines
	lines := 0
	for _, b := range content {
		if b == '\n' {
			lines++
		}
	}
	if lines != 2 {
		t.Errorf("Expected 2 lines, got %d", lines)
	}
}
