package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestProofReportClipboardFallback verifies the proof report HTML
// contains the execCommand('copy') fallback for non-HTTPS contexts.
func TestProofReportClipboardFallback(t *testing.T) {
	dir := t.TempDir()
	os.Chdir(dir)

	var out bytes.Buffer
	code := runDemoCompany([]string{"--template", "starter", "--provider", "mock"}, &out, &out)
	if code != 0 {
		t.Fatalf("demo failed with code %d", code)
	}

	htmlPath := filepath.Join(dir, "data", "evidence", "run-report.html")
	data, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	html := string(data)

	// Must have the fallback function
	if !strings.Contains(html, "helmCopyFallback") {
		t.Error("report missing helmCopyFallback function")
	}
	if !strings.Contains(html, "execCommand") {
		t.Error("report missing execCommand('copy') fallback")
	}
	// Must try clipboard API first, then fallback
	if !strings.Contains(html, "navigator.clipboard") {
		t.Error("report missing navigator.clipboard check")
	}
}

// TestProofReportVerifyState verifies data-verify-state and
// data-receipt-count attributes are present and correct.
func TestProofReportVerifyState(t *testing.T) {
	dir := t.TempDir()
	os.Chdir(dir)

	var out bytes.Buffer
	code := runDemoCompany([]string{"--template", "starter", "--provider", "mock"}, &out, &out)
	if code != 0 {
		t.Fatalf("demo failed with code %d", code)
	}

	htmlPath := filepath.Join(dir, "data", "evidence", "run-report.html")
	data, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	html := string(data)

	// data-verify-state must be present and contain a valid state
	if !strings.Contains(html, `data-verify-state="`) {
		t.Error("report missing data-verify-state attribute")
	}
	// For a valid demo, state should be "✓ Verified"
	if !strings.Contains(html, `data-verify-state="✓ Verified"`) {
		t.Error("expected verify state to be '✓ Verified' for valid demo chain")
	}

	// data-receipt-count must be present
	if !strings.Contains(html, `data-receipt-count="`) {
		t.Error("report missing data-receipt-count attribute")
	}
	// Receipt count should be > 0
	if strings.Contains(html, `data-receipt-count="0"`) {
		t.Error("data-receipt-count is 0, expected > 0")
	}
}

// TestDemoTerminalSummaryCard verifies the box-drawn summary card
// is printed at the end of the demo with correct paths.
func TestDemoTerminalSummaryCard(t *testing.T) {
	dir := t.TempDir()
	os.Chdir(dir)

	var out bytes.Buffer
	code := runDemoCompany([]string{"--template", "starter", "--provider", "mock"}, &out, &out)
	if code != 0 {
		t.Fatalf("demo failed with code %d", code)
	}

	output := out.String()

	// Must contain the box characters
	if !strings.Contains(output, "╔") || !strings.Contains(output, "╚") {
		t.Error("missing box-drawn summary card (╔/╚ characters)")
	}
	// Must contain the HELM Demo Complete header
	if !strings.Contains(output, "HELM Demo Complete") {
		t.Error("missing 'HELM Demo Complete' in summary card")
	}
	// Must contain report path
	if !strings.Contains(output, "run-report.html") {
		t.Error("missing report path in summary card")
	}
	// Must contain verify command
	if !strings.Contains(output, "helm verify") {
		t.Error("missing verify command in summary card")
	}
	// Must contain provider switch hint
	if !strings.Contains(output, "opensandbox") {
		t.Error("missing provider switch hint in summary card")
	}
}

// TestDenyExplanation verifies the deny receipt in demo output
// includes human explanation, policy clause, and remediation.
func TestDenyExplanation(t *testing.T) {
	dir := t.TempDir()
	os.Chdir(dir)

	var out bytes.Buffer
	code := runDemoCompany([]string{"--template", "starter", "--provider", "mock"}, &out, &out)
	if code != 0 {
		t.Fatalf("demo failed with code %d", code)
	}

	output := out.String()

	// Must include structural deny details box
	if !strings.Contains(output, "Deny Details") {
		t.Error("missing 'Deny Details' section in demo output")
	}
	// Must include the reason code
	if !strings.Contains(output, "ERR_TOOL_NOT_ALLOWED") {
		t.Error("missing reason code in deny details")
	}
	// Must include human explanation
	if !strings.Contains(output, "not in the allowed-tools list") {
		t.Error("missing human explanation in deny details")
	}
	// Must include policy clause reference
	if !strings.Contains(output, "policy.allowed_tools") {
		t.Error("missing policy clause reference in deny details")
	}
	// Must include remediation step
	if !strings.Contains(output, "Add") && !strings.Contains(output, "allowed_tools") {
		t.Error("missing remediation step in deny details")
	}

	// Also verify the proof report contains deny explanation support
	htmlPath := filepath.Join(dir, "data", "evidence", "run-report.html")
	data, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	html := string(data)

	if !strings.Contains(html, "denyExplanations") {
		t.Error("proof report missing denyExplanations JS map")
	}
	if !strings.Contains(html, "helmCopyReceiptJSON") {
		t.Error("proof report missing helmCopyReceiptJSON function")
	}
}
