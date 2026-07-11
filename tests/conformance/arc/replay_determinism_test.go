package arc_conformance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier"
)

// TestReplayDeterminism ensures replay determinism fails closed when the bundle
// declares G2 replay proof but omits the required tape evidence.
func TestReplayDeterminism(t *testing.T) {
	dir := t.TempDir()

	writeJSON(t, filepath.Join(dir, "manifest.json"), map[string]any{
		"session_id":  "arc-replay",
		"version":     "1.0.0",
		"exported_at": "2026-01-01T00:00:00Z",
	})
	writeJSON(t, filepath.Join(dir, "00_INDEX.json"), map[string]any{
		"version": "1.0.0",
		"gates":   []string{"G0", "G1", "G2"},
	})
	writeJSON(t, filepath.Join(dir, "proofgraph.json"), map[string]any{
		"version": "1.0.0",
		"nodes":   []any{},
		"edges":   []any{},
	})
	receiptsDir := filepath.Join(dir, "receipts")
	if err := os.MkdirAll(receiptsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(receiptsDir, "receipt-001.json"), map[string]any{
		"receipt_id":    "rcpt-001",
		"decision_id":   "dec-001",
		"decision_hash": "sha256:abc123",
		"status":        "APPLIED",
		"lamport_clock": 1,
	})

	report, err := verifier.VerifyBundle(dir)
	if err != nil {
		t.Fatalf("verify bundle: %v", err)
	}
	if report.Verified {
		t.Fatal("bundle should fail when replay evidence is declared but missing")
	}

	for _, check := range report.Checks {
		if check.Name == "replay_determinism" {
			if check.Pass {
				t.Fatalf("replay_determinism should fail closed: %+v", check)
			}
			if check.Reason == "" {
				t.Fatalf("replay_determinism failure should explain missing proof: %+v", check)
			}
			return
		}
	}
	t.Fatal("missing replay_determinism check")
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
