package gates

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conform"
)

func TestG2ReplayMalformedEvidenceBranches(t *testing.T) {
	ctx := setupSparseGateContext(t)

	writeGateJSON(t, filepath.Join(ctx.EvidenceDir, "08_TAPES", "tape_manifest.json"), map[string]any{
		"entries": []any{},
	})
	writeGateFile(t, filepath.Join(ctx.EvidenceDir, "05_DIFFS", "diff.txt"), []byte("changed"))
	writeGateJSON(t, filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "determinism_manifest.json"), map[string]any{
		"live_hash":   "sha256:live",
		"replay_hash": "sha256:replay",
	})

	receiptsDir := filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "receipts")
	writeGateJSON(t, filepath.Join(receiptsDir, "01.json"), map[string]any{"lamport_clock": 5})
	writeGateJSON(t, filepath.Join(receiptsDir, "02.json"), map[string]any{"lamport_clock": 3})
	writeGateFile(t, filepath.Join(receiptsDir, "03-invalid.json"), []byte("{"))
	_ = os.Symlink(filepath.Join(receiptsDir, "missing-target"), filepath.Join(receiptsDir, "04-broken.json"))

	decisionsDir := filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "decisions")
	writeGateJSON(t, filepath.Join(decisionsDir, "01-missing-hash.json"), map[string]any{
		"policy_backend": "rego",
	})
	writeGateFile(t, filepath.Join(decisionsDir, "02-invalid.json"), []byte("{"))
	_ = os.Symlink(filepath.Join(decisionsDir, "missing-target"), filepath.Join(decisionsDir, "03-broken.json"))

	result := (&G2Replay{}).Run(ctx)
	if result.Pass {
		t.Fatalf("malformed replay evidence passed unexpectedly: %+v", result)
	}
	for _, want := range []string{
		conform.ReasonReplayHashDivergence,
		"LAMPORT_NOT_MONOTONIC",
		"POLICY_DECISION_HASH_MISSING",
	} {
		if !reasonContains(result.Reasons, want) {
			t.Fatalf("missing reason %q in %+v", want, result.Reasons)
		}
	}
	if result.Metrics.Counts["missing_decision_hashes"] != 1 {
		t.Fatalf("unexpected missing decision hash count: %+v", result.Metrics.Counts)
	}
}
