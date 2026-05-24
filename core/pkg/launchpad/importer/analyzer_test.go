package importer

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAnalyzerImportBuildsOpenHumanStyleHybridGraph(t *testing.T) {
	root := writeHybridRepo(t)
	record, err := NewAnalyzer(DefaultAdapters(), nil).Import(context.Background(), ImportRequest{RepoURL: root, Ref: "test"}, time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if record.ID == "" {
		t.Fatal("import id missing")
	}
	if record.SourceSnapshot.Provider != "local" {
		t.Fatalf("provider=%s", record.SourceSnapshot.Provider)
	}
	for _, want := range []string{"desktopUI", "compose", "mcpTools", "agui", "secrets", "network"} {
		if !contains(record.CapabilityGraph.Capabilities, want) {
			t.Fatalf("capability %q missing from %#v", want, record.CapabilityGraph.Capabilities)
		}
	}
	if len(record.CapabilityGraph.Modules) < 2 {
		t.Fatalf("expected multi-module detection, got %#v", record.CapabilityGraph.Modules)
	}
	if got := record.LaunchRecipe.GeneratedAppSpecs[0].Trusted; got {
		t.Fatal("generated AppSpec must remain untrusted")
	}
	if record.LaunchRecipe.GeneratedAppSpecs[0].AppSpec.Availability != "oss_candidate" {
		t.Fatalf("availability=%s", record.LaunchRecipe.GeneratedAppSpecs[0].AppSpec.Availability)
	}
	assertTarget(t, record.LaunchRecipe.TargetPlans, "local")
	assertTarget(t, record.LaunchRecipe.TargetPlans, "cloud")
	assertTarget(t, record.LaunchRecipe.TargetPlans, "hosted-sandbox")
}

func TestBuildStrategyPrefersFrameworkAdapterBeforeComposeFallback(t *testing.T) {
	source := SourceSnapshot{LicenseSPDX: "MIT", Files: []SourceFileSummary{
		{Path: "langgraph.json", Content: `{"graphs":{"agent":"./agent.py:graph"}}`},
		{Path: "docker-compose.yml", Content: "services:\n  app:\n    build: .\n"},
		{Path: "pyproject.toml", Content: `[project]`},
	}}
	adapters := DefaultAdapters()
	graph := BuildCapabilityGraph(source, adapters)
	strategy := SelectBuildStrategy(source, graph, adapters)
	if strategy.Strategy != "native" {
		t.Fatalf("strategy=%s reason=%s", strategy.Strategy, strategy.Reason)
	}
	if len(strategy.ManifestSources) == 0 || strategy.ManifestSources[0] != "langgraph.json" {
		t.Fatalf("manifest sources=%#v", strategy.ManifestSources)
	}
}

func TestPreflightKeepsGeneratedImportBlockedUntilEvidenceCompletes(t *testing.T) {
	record := ImportRecord{
		ID:    "imp_test",
		State: StateImported,
		SourceSnapshot: SourceSnapshot{
			RepoURL:     "https://github.com/example/agent",
			Provider:    "github",
			LicenseSPDX: "MIT",
		},
		EvidenceLedger: ImportEvidenceLedger{Status: "generated_untrusted"},
	}
	record = Preflight(record, time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC))
	if record.Preflight == nil {
		t.Fatal("preflight missing")
	}
	if record.Preflight.Status != "ESCALATE" {
		t.Fatalf("status=%s blocked=%#v", record.Preflight.Status, record.Preflight.BlockedReasons)
	}
	if record.State == StatePromotable {
		t.Fatal("pending SBOM/scan/smoke evidence must not make imports promotable")
	}
}

func writeHybridRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"scripts":{"dev":"vite --host 127.0.0.1 --port 5173","tauri":"tauri dev"},"dependencies":{"@tauri-apps/api":"latest","@ag-ui/client":"latest"}}`)
	writeFile(t, root, "src/mcp-tools.ts", `export const mcpServer = "local";`)
	writeFile(t, root, "src-tauri/Cargo.toml", `[package]
name = "desktop-shell"
version = "0.1.0"
edition = "2021"
`)
	writeFile(t, root, "docker-compose.yml", `services:
  app:
    build: .
    ports:
      - "3000:3000"
`)
	writeFile(t, root, ".env.example", "OPENAI_API_KEY=\nGITHUB_TOKEN=\n")
	writeFile(t, root, "README.md", "OpenHuman-style agentic desktop with MCP tools, AG-UI stream, and GitHub OAuth.")
	writeFile(t, root, "LICENSE", "MIT License\n")
	return root
}

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertTarget(t *testing.T, targets []TargetPlan, id string) {
	t.Helper()
	for _, target := range targets {
		if target.TargetID == id {
			return
		}
	}
	t.Fatalf("target %q missing from %#v", id, targets)
}
