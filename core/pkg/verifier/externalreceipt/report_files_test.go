package externalreceipt

import (
	"reflect"
	"testing"
)

// A report that parses is left out of chain verification and listed, so a
// caller can say which files it did not read as chains.
func TestVerifyBundleListsReportFilesItDidNotReadAsChains(t *testing.T) {
	root := t.TempDir()
	writeHostFile(t, root, "host_evidence/correlation.json", `{"bundle":"x","host_receipts":2,"results":[]}`)
	writeHostFile(t, root, "11_HOST_EVIDENCE/a/verification.json", `{"verified":true,"receipt_count":2,"checks":[]}`)

	report := VerifyBundle(root)
	if report.Found || len(report.Checks) != 0 || len(report.ChainFiles) != 0 {
		t.Fatalf("report files were treated as host evidence: %#v", report)
	}
	want := []string{"11_HOST_EVIDENCE/a/verification.json", "host_evidence/correlation.json"}
	if !reflect.DeepEqual(report.ReportFiles, want) {
		t.Fatalf("ReportFiles = %v, want %v", report.ReportFiles, want)
	}
}
