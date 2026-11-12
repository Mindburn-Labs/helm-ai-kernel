// quantum_posture: these tests cover classical Ed25519 receipt signatures
// only and do not claim post-quantum protection.
package workstation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func encodedMap(t *testing.T, value any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// A copy of a receipt is the same decision, not a second one: it is read
// once and the copy is named.
func TestOperatorViewAndScopeAuditCountADuplicatedReceiptOnce(t *testing.T) {
	dir := t.TempDir()
	req := decisionRequest("network", "https://dup.example")
	req.RunID, req.RequestID = "dup", "req-dup"
	receipt, err := Decide(DefaultObserveDraftProfile(), req, DecisionOptions{SigningSeed: workstationTestSigningSeed()})
	if err != nil {
		t.Fatal(err)
	}
	writeJSONFixture(t, filepath.Join(dir, "a.json"), receipt)
	writeJSONFixture(t, filepath.Join(dir, "b-copy.json"), receipt)
	trust := TrustAnchor{PublicKey: workstationTestPublicKey(), Source: "test-anchor.pub"}

	for _, inputs := range [][]string{{dir}, {filepath.Join(dir, "a.json"), filepath.Join(dir, "a.json")}} {
		view, err := BuildOperatorView(trust, inputs...)
		if err != nil {
			t.Fatal(err)
		}
		if len(view.Runs) != 1 || len(view.DeniedTimeline) != 1 {
			t.Fatalf("inputs %v: runs = %d, denied = %d, want one decision", inputs, len(view.Runs), len(view.DeniedTimeline))
		}
		duplicates, _ := encodedMap(t, view.Verification)["duplicate_inputs"].([]any)
		if len(duplicates) != 1 {
			t.Fatalf("inputs %v: verification does not name the one duplicate: %+v", inputs, view.Verification)
		}
	}

	report, err := BuildScopeAudit(trust, dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.InputFiles != 2 || report.Summary.DecisionReceipts != 1 || report.Summary.DeniedActions != 1 || len(report.EvidenceRefs) != 1 {
		t.Fatalf("summary = %+v refs = %d, want two inputs and one decision", report.Summary, len(report.EvidenceRefs))
	}
	if limitations := strings.Join(report.Limitations, "\n"); !strings.Contains(limitations, "b-copy.json") {
		t.Fatalf("limitations do not name the duplicate:\n%s", limitations)
	}
}

// A receipt signed by a key other than the trusted one shows what its signer
// claims. Its actions are counted apart from the workstation's own.
func TestScopeAuditCountsReceiptsOfAnotherSignerSeparately(t *testing.T) {
	dir := verificationInputs(t)
	trust := TrustAnchor{PublicKey: workstationTestPublicKey(), Source: "test-anchor.pub"}
	report, err := BuildScopeAudit(trust, dir)
	if err != nil {
		t.Fatal(err)
	}
	summary := encodedMap(t, report.Summary)
	if summary["decision_receipts"] != 1.0 || summary["denied_actions"] != 1.0 || summary["untrusted_signer_receipts"] != 2.0 || summary["untrusted_signer_actions"] != 2.0 {
		t.Fatalf("summary = %v, want the trusted receipt in the totals and the other two apart", summary)
	}
	attempts, err := json.Marshal(report.OutOfScopeAttempts)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(attempts), "other-key") || !strings.Contains(string(attempts), "trusted") {
		t.Fatalf("out-of-scope attempts = %s, want only the trusted signer's", attempts)
	}

	// Without an anchor no signer can be told apart, so every receipt whose
	// signature holds is counted, as the limitations say.
	report, err = BuildScopeAudit(TrustAnchor{}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if summary := encodedMap(t, report.Summary); summary["decision_receipts"] != 3.0 || summary["untrusted_signer_receipts"] != 0.0 {
		t.Fatalf("summary without an anchor = %v", summary)
	}
}

// The pack directory is the export's own: a used one is refused before any
// file is written, so a link planted in it is never written through.
func TestExportEvidencePackRefusesADirectoryThatIsNotEmpty(t *testing.T) {
	imported, err := ImportArtifactDir(filepath.Join(repoRoot(t), "fixtures", "workstation", "denied-memory"), workstationTestImportOptions())
	if err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(t.TempDir(), "pack")
	if _, err := ExportEvidencePack(imported, outDir); err != nil {
		t.Fatal(err)
	}
	if _, err := ExportEvidencePack(imported, outDir); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("a second export into the same directory = %v, want a refusal", err)
	}

	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.MkdirAll(empty, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := ExportEvidencePack(imported, empty); err != nil {
		t.Fatalf("an empty directory was refused: %v", err)
	}

	linked := filepath.Join(t.TempDir(), "linked")
	if err := os.MkdirAll(linked, 0o750); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(linked, "01_SCORE.json")); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	if _, err := ExportEvidencePack(imported, linked); err == nil {
		t.Fatal("export into a directory holding a hard link succeeded")
	}
	if data, _ := os.ReadFile(outside); string(data) != "keep" {
		t.Fatalf("the hard-linked file was written through: %q", data)
	}
}

// Pack files are created, never opened over: a name that exists already, as
// a link to a file elsewhere would, is refused, and so are two names that one
// case-insensitive filesystem would store as one file.
func TestPackWriterCreatesEveryFileNew(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(dir, "linked.json")); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	writer := newPackWriter(root)
	if err := writer.create("linked.json", []byte("score")); err == nil {
		t.Fatal("an existing name was opened and written")
	}
	if data, _ := os.ReadFile(outside); string(data) != "keep" {
		t.Fatalf("the linked file was written through: %q", data)
	}
	if err := writer.create("receipts-arr_ABC.json", []byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := writer.create("receipts-arr_abc.json", []byte("b")); err == nil || !strings.Contains(err.Error(), "case-insensitive") {
		t.Fatalf("two names equal under case folding = %v, want a refusal", err)
	}
}
