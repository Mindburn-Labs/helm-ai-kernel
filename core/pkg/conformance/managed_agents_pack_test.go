package conformance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestClaudeManagedAgentsConformancePackIntegrity(t *testing.T) {
	root := filepath.Join("..", "..", "..", "protocols", "conformance", "managed-agents", "claude-self-hosted", "v1")
	data, err := os.ReadFile(filepath.Join(root, "conformance-pack.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pack struct {
		PackID   string                `json:"pack_id"`
		Status   string                `json:"status"`
		Modes    []struct{ ID string } `json:"modes"`
		Fixtures map[string]string     `json:"fixtures"`
	}
	if err := json.Unmarshal(data, &pack); err != nil {
		t.Fatal(err)
	}
	if pack.PackID != "helm-claude-managed-agents-self-hosted-v1" {
		t.Fatalf("pack_id = %q", pack.PackID)
	}
	if pack.Status != "preview" {
		t.Fatalf("status = %q, want preview", pack.Status)
	}
	requiredModes := []string{"observe-only", "enforceable-worker", "tunneled-mcp-capable", "provider-verified"}
	seenModes := map[string]bool{}
	for _, mode := range pack.Modes {
		seenModes[mode.ID] = true
	}
	for _, mode := range requiredModes {
		if !seenModes[mode] {
			t.Fatalf("missing conformance mode %q", mode)
		}
	}
	requiredFixtures := []string{
		"allowed_bash",
		"allowed_file_write",
		"denied_egress",
		"denied_raw_mcp_tunnel",
		"denied_memory",
		"denied_unpinned_skill",
		"stopped_ambiguous_session",
	}
	for _, name := range requiredFixtures {
		rel, ok := pack.Fixtures[name]
		if !ok {
			t.Fatalf("missing fixture %q", name)
		}
		fixtureData, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("fixture %q missing: %v", name, err)
		}
		var fixture map[string]any
		if err := json.Unmarshal(fixtureData, &fixture); err != nil {
			t.Fatalf("fixture %q invalid JSON: %v", name, err)
		}
		if fixture["case_id"] == "" || fixture["expected_verdict"] == "" {
			t.Fatalf("fixture %q missing case_id or expected_verdict", name)
		}
		if _, ok := fixture["must_bind_evidence"].([]any); !ok {
			t.Fatalf("fixture %q missing must_bind_evidence", name)
		}
	}
}
