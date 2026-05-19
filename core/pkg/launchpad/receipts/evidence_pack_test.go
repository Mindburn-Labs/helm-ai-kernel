package receipts

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier"
)

func TestWriteEvidencePackMaterializesRequiredDirectories(t *testing.T) {
	packDir, err := WriteEvidencePack(t.TempDir(), "launch-test", map[string][]byte{
		"receipts/kernel-verdict.json": []byte(`{"receipt_id":"r1","decision_id":"d1","decision_hash":"sha256:test","status":"ALLOW","verdict":"ALLOW","lamport_clock":1}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, keep := range []string{
		"03_TELEMETRY/.keep",
		"05_DIFFS/.keep",
		"06_LOGS/.keep",
		"07_ATTESTATIONS/.keep",
		"08_TAPES/.keep",
		"09_SCHEMAS/.keep",
		"12_REPORTS/.keep",
	} {
		if _, err := os.Stat(filepath.Join(packDir, keep)); err != nil {
			t.Fatalf("required EvidencePack placeholder %s missing: %v", keep, err)
		}
	}
	report, err := verifier.VerifyBundle(packDir)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Verified {
		t.Fatalf("EvidencePack did not verify: %s", report.Summary)
	}
}
