package gates

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conform"
)

func TestG1ProofReceiptsEmptyReceiptSetFails(t *testing.T) {
	ctx := setupSparseGateContext(t)

	result := (&G1ProofReceipts{}).Run(ctx)
	if result.Pass || !reasonContains(result.Reasons, conform.ReasonReceiptChainBroken) {
		t.Fatalf("empty receipt set result = %+v, want chain broken failure", result)
	}
}

func TestG1LoadReceiptEnvelopesRejectsUnreadableAndInvalidFiles(t *testing.T) {
	dir := t.TempDir()
	invalidJSON := filepath.Join(dir, "invalid.json")
	writeGateFile(t, invalidJSON, []byte("{"))

	files := []string{invalidJSON}
	brokenLink := filepath.Join(dir, "broken.json")
	if err := os.Symlink(filepath.Join(dir, "missing-target"), brokenLink); err == nil {
		files = append(files, brokenLink)
	}

	result := newReceiptGateResultForCoverage()
	envelopes := (&G1ProofReceipts{}).loadReceiptEnvelopes(result, files)
	if len(envelopes) != 0 {
		t.Fatalf("malformed files produced envelopes: %+v", envelopes)
	}
	if result.Pass || !reasonContains(result.Reasons, conform.ReasonReceiptChainBroken) {
		t.Fatalf("malformed file load result = %+v, want chain broken failure", result)
	}
}

func TestG1ValidateEnvelopeRequiredFieldsAndSequenceEdges(t *testing.T) {
	result := newReceiptGateResultForCoverage()
	validateEnvelopeRequiredFields(result, &ReceiptEnvelope{})

	if result.Pass {
		t.Fatalf("missing required fields passed unexpectedly")
	}
	for _, want := range []string{
		conform.ReasonReceiptChainBroken,
		conform.ReasonTenantIsolationViolation,
		conform.ReasonEnvelopeNotBound,
	} {
		if !reasonContains(result.Reasons, want) {
			t.Fatalf("missing reason %q in %+v", want, result.Reasons)
		}
	}

	result = newReceiptGateResultForCoverage()
	validateEnvelopeMonotonicSeq(result, &ReceiptEnvelope{Seq: 2}, 2, true)
	if result.Pass || !reasonContains(result.Reasons, conform.ReasonReceiptChainBroken) {
		t.Fatalf("non-monotonic sequence result = %+v, want chain broken failure", result)
	}
}

func newReceiptGateResultForCoverage() *conform.GateResult {
	return &conform.GateResult{
		GateID:        "G1",
		Pass:          true,
		Reasons:       []string{},
		EvidencePaths: []string{},
		Metrics:       conform.GateMetrics{Counts: make(map[string]int)},
	}
}
