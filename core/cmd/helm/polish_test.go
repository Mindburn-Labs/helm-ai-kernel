package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// TestDemoTerminalSummaryCard verifies the box-drawn summary card
// is printed at the end of the demo with CLI/auditor paths.
func TestDemoTerminalSummaryCard(t *testing.T) {
	dir := t.TempDir()
	os.Chdir(dir)

	var out bytes.Buffer
	code := runDemoCompany([]string{"--template", "starter", "--provider", "mock"}, &out, &out)
	if code != 0 {
		t.Fatalf("demo failed with code %d", code)
	}

	output := out.String()

	if !strings.Contains(output, "╔") || !strings.Contains(output, "╚") {
		t.Error("missing box-drawn summary card")
	}
	if !strings.Contains(output, "HELM Demo Complete") {
		t.Error("missing 'HELM Demo Complete' in summary card")
	}
	if !strings.Contains(output, "run-report.json") {
		t.Error("missing JSON report path in summary card")
	}
	if strings.Contains(output, "run-report."+"html") {
		t.Error("summary card should not reference HTML reports")
	}
	if !strings.Contains(output, "helm verify") {
		t.Error("missing verify command in summary card")
	}
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

	if !strings.Contains(output, "Deny Details") {
		t.Error("missing 'Deny Details' section in demo output")
	}
	if !strings.Contains(output, "ERR_TOOL_NOT_ALLOWED") {
		t.Error("missing reason code in deny details")
	}
	if !strings.Contains(output, "not in the allowed-tools list") {
		t.Error("missing human explanation in deny details")
	}
	if !strings.Contains(output, "policy.allowed_tools") {
		t.Error("missing policy clause reference in deny details")
	}
	if !strings.Contains(output, "Add") && !strings.Contains(output, "allowed_tools") {
		t.Error("missing remediation step in deny details")
	}
}
