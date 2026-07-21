package riskscan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/riskenvelope"
)

// writeSummaryPack lays out the two 04_EXPORTS artifacts verifyScanEvidenceSummary
// reads, with a hash consistent across both, and returns the pack dir and hash.
func writeSummaryPack(t *testing.T, summaryBody []byte) (string, string) {
	t.Helper()
	packDir := t.TempDir()
	exports := filepath.Join(packDir, "04_EXPORTS")
	if err := os.MkdirAll(exports, 0o755); err != nil {
		t.Fatal(err)
	}

	// The contract hash is over the canonical form of the summary's first JSON
	// value, which is exactly what trailing bytes leave untouched.
	var summary any
	if err := json.Unmarshal(summaryBody, &summary); err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalize.JCS(summary)
	if err != nil {
		t.Fatal(err)
	}
	wantHash := riskenvelope.SHA256Ref(canonical)

	if err := os.WriteFile(filepath.Join(packDir, scanEvidenceSummaryPath), summaryBody, 0o644); err != nil {
		t.Fatal(err)
	}
	sourceHash, err := json.Marshal(scanEvidenceSourceHash{
		SourcePackHash: wantHash,
		Meaning:        "sha256 of the canonical anonymized projection summary; not a raw source pack hash",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packDir, scanEvidenceSourceHashPath), sourceHash, 0o644); err != nil {
		t.Fatal(err)
	}
	return packDir, wantHash
}

func TestVerifyScanEvidenceSummaryAcceptsExactlyOneValue(t *testing.T) {
	packDir, wantHash := writeSummaryPack(t, []byte(`{"files":2,"servers":1}`))
	if err := verifyScanEvidenceSummary(packDir, wantHash); err != nil {
		t.Fatalf("well-formed summary should verify: %v", err)
	}
}

// A second JSON value appended to the summary does not change the canonical hash
// of the first value, so the contract hash still matches. Only an explicit
// end-of-input check rejects the ambiguous artifact.
func TestVerifyScanEvidenceSummaryRejectsTrailingData(t *testing.T) {
	body := []byte(`{"files":2,"servers":1}`)
	packDir, wantHash := writeSummaryPack(t, body)

	tampered := append(append([]byte{}, body...), []byte("\n{\"files\":99,\"servers\":99}\n")...)
	if err := os.WriteFile(filepath.Join(packDir, scanEvidenceSummaryPath), tampered, 0o644); err != nil {
		t.Fatal(err)
	}

	err := verifyScanEvidenceSummary(packDir, wantHash)
	if err == nil {
		t.Fatal("summary with trailing JSON should be rejected")
	}
	if !strings.Contains(err.Error(), "trailing data") {
		t.Fatalf("expected a trailing-data error, got %v", err)
	}
}
