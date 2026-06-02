package gates

import (
	"os"
	"path/filepath"
	"testing"
)

func TestG14BundleIntegrityMalformedEvidenceBranches(t *testing.T) {
	ctx := setupSparseGateContext(t)
	bundleDir := filepath.Join(ctx.EvidenceDir, "bundles")
	mkdirGate(t, bundleDir)

	result := (&G14BundleIntegrity{}).Run(ctx)
	if result.Pass || !reasonContains(result.Reasons, "No policy bundle files found") {
		t.Fatalf("empty bundle directory result = %+v, want missing bundle failure", result)
	}

	writeGateFile(t, filepath.Join(bundleDir, "invalid.yaml"), []byte("not: [yaml: {{"))
	if err := os.Symlink(filepath.Join(bundleDir, "missing-target"), filepath.Join(bundleDir, "broken.yaml")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	result = (&G14BundleIntegrity{}).Run(ctx)
	if result.Pass {
		t.Fatalf("malformed bundles passed unexpectedly: %+v", result)
	}
	if !reasonContains(result.Reasons, "Invalid bundle: invalid.yaml") {
		t.Fatalf("missing invalid bundle reason: %+v", result.Reasons)
	}
	if !reasonContains(result.Reasons, "Cannot read bundle: broken.yaml") {
		t.Fatalf("missing broken bundle reason: %+v", result.Reasons)
	}
}

func TestG15CondensationMalformedEvidenceBranches(t *testing.T) {
	ctx := setupSparseGateContext(t)
	checkpointDir := filepath.Join(ctx.EvidenceDir, "condensation")
	mkdirGate(t, checkpointDir)

	result := (&G15Condensation{}).Run(ctx)
	if result.Pass || !reasonContains(result.Reasons, "No checkpoint files found") {
		t.Fatalf("empty checkpoint directory result = %+v, want missing checkpoint failure", result)
	}

	writeGateFile(t, filepath.Join(checkpointDir, "invalid.json"), []byte("{"))
	if err := os.Symlink(filepath.Join(checkpointDir, "missing-target"), filepath.Join(checkpointDir, "broken.json")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	result = (&G15Condensation{}).Run(ctx)
	if result.Pass {
		t.Fatalf("malformed checkpoints passed unexpectedly: %+v", result)
	}
	if !reasonContains(result.Reasons, "Invalid checkpoint format: invalid.json") {
		t.Fatalf("missing invalid checkpoint reason: %+v", result.Reasons)
	}
	if !reasonContains(result.Reasons, "Cannot read checkpoint: broken.json") {
		t.Fatalf("missing broken checkpoint reason: %+v", result.Reasons)
	}
}
