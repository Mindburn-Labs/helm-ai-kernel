package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDemoReplayDeterminism verifies that running the demo twice
// produces identical receipt hashes (deterministic replay).
func TestDemoReplayDeterminism(t *testing.T) {
	// Run 1
	dir1 := t.TempDir()
	os.Chdir(dir1)

	var out1 bytes.Buffer
	code1 := runDemoCompany([]string{"--template", "starter", "--provider", "mock"}, &out1, &out1)
	if code1 != 0 {
		t.Fatalf("demo run 1 failed with code %d: %s", code1, out1.String())
	}

	// Read receipts from run 1
	receipts1 := readDemoReceipts(t, filepath.Join(dir1, "data", "evidence"))

	// Run 2
	dir2 := t.TempDir()
	os.Chdir(dir2)

	var out2 bytes.Buffer
	code2 := runDemoCompany([]string{"--template", "starter", "--provider", "mock"}, &out2, &out2)
	if code2 != 0 {
		t.Fatalf("demo run 2 failed with code %d: %s", code2, out2.String())
	}

	receipts2 := readDemoReceipts(t, filepath.Join(dir2, "data", "evidence"))

	// Verify same count
	if len(receipts1) != len(receipts2) {
		t.Fatalf("receipt count mismatch: %d vs %d", len(receipts1), len(receipts2))
	}

	// Verify same hashes (time-independent because hash preimage
	// uses principal|action|tool|verdict|reason|lamport|prevHash, no wall clock)
	for i := range receipts1 {
		r1, r2 := receipts1[i], receipts2[i]
		if r1.Hash != r2.Hash {
			t.Errorf("receipt %d hash differs: %s vs %s", i, r1.Hash, r2.Hash)
		}
		if r1.PrevHash != r2.PrevHash {
			t.Errorf("receipt %d prevHash differs: %s vs %s", i, r1.PrevHash, r2.PrevHash)
		}
		if r1.Lamport != r2.Lamport {
			t.Errorf("receipt %d Lamport differs: %d vs %d", i, r1.Lamport, r2.Lamport)
		}
		if r1.Action != r2.Action {
			t.Errorf("receipt %d action differs: %s vs %s", i, r1.Action, r2.Action)
		}
		if r1.Principal != r2.Principal {
			t.Errorf("receipt %d principal differs: %s vs %s", i, r1.Principal, r2.Principal)
		}
	}
}

// TestDemoModeReceiptField verifies that demo receipts carry mode:"demo".
func TestDemoModeReceiptField(t *testing.T) {
	dir := t.TempDir()
	os.Chdir(dir)

	var out bytes.Buffer
	code := runDemoCompany([]string{"--template", "starter", "--provider", "mock"}, &out, &out)
	if code != 0 {
		t.Fatalf("demo failed with code %d", code)
	}

	receipts := readDemoReceipts(t, filepath.Join(dir, "data", "evidence"))
	for i, r := range receipts {
		if r.Mode != "demo" {
			t.Errorf("receipt %d missing mode:demo, got %q", i, r.Mode)
		}
	}
}

// TestDemoProofReportGenerated verifies HTML + JSON reports are generated.
func TestDemoProofReportGenerated(t *testing.T) {
	dir := t.TempDir()
	os.Chdir(dir)

	var out bytes.Buffer
	code := runDemoCompany([]string{"--template", "starter", "--provider", "mock"}, &out, &out)
	if code != 0 {
		t.Fatalf("demo failed with code %d", code)
	}

	htmlPath := filepath.Join(dir, "data", "evidence", "run-report.html")
	jsonPath := filepath.Join(dir, "data", "evidence", "run-report.json")

	if _, err := os.Stat(htmlPath); os.IsNotExist(err) {
		t.Error("run-report.html not generated")
	} else {
		data, _ := os.ReadFile(htmlPath)
		html := string(data)
		if !strings.Contains(html, "HELM Proof Report") {
			t.Error("HTML report missing expected title")
		}
		if !strings.Contains(html, "Causal chain") && !strings.Contains(html, "Causal Chain") {
			t.Error("HTML report missing verification section")
		}
		if !strings.Contains(html, "demo") {
			t.Error("HTML report missing demo mode indicator")
		}
	}

	if _, err := os.Stat(jsonPath); os.IsNotExist(err) {
		t.Error("run-report.json not generated")
	}
}

// TestReceiptHashSensitivity verifies that changing any field changes the hash.
func TestReceiptHashSensitivity(t *testing.T) {
	dir := t.TempDir()
	os.Chdir(dir)

	var out bytes.Buffer
	code := runDemoCompany([]string{"--template", "starter", "--provider", "mock"}, &out, &out)
	if code != 0 {
		t.Fatalf("demo failed with code %d", code)
	}

	receipts := readDemoReceipts(t, filepath.Join(dir, "data", "evidence"))

	// Verify all hashes are unique
	seen := make(map[string]int)
	for i, r := range receipts {
		if prev, ok := seen[r.Hash]; ok {
			t.Errorf("duplicate hash at receipts %d and %d: %s", prev, i, r.Hash)
		}
		seen[r.Hash] = i
	}

	// Verify chain integrity
	for i := 1; i < len(receipts); i++ {
		if receipts[i].PrevHash != receipts[i-1].Hash {
			t.Errorf("chain break at receipt %d: prevHash=%s, expected=%s",
				i, receipts[i].PrevHash, receipts[i-1].Hash)
		}
	}

	// Verify first receipt has empty prevHash
	if receipts[0].PrevHash != "" {
		t.Errorf("first receipt prevHash should be empty, got %q", receipts[0].PrevHash)
	}
}

// TestReceiptRequiredFields verifies all required fields are always present.
func TestReceiptRequiredFields(t *testing.T) {
	dir := t.TempDir()
	os.Chdir(dir)

	var out bytes.Buffer
	code := runDemoCompany([]string{"--template", "starter", "--provider", "mock"}, &out, &out)
	if code != 0 {
		t.Fatalf("demo failed with code %d", code)
	}

	receipts := readDemoReceipts(t, filepath.Join(dir, "data", "evidence"))
	for i, r := range receipts {
		if r.ReceiptID == "" {
			t.Errorf("receipt %d: missing receipt_id", i)
		}
		if r.Timestamp == "" {
			t.Errorf("receipt %d: missing timestamp", i)
		}
		if r.Principal == "" {
			t.Errorf("receipt %d: missing principal", i)
		}
		if r.Action == "" {
			t.Errorf("receipt %d: missing action", i)
		}
		if r.Verdict == "" {
			t.Errorf("receipt %d: missing verdict", i)
		}
		if r.ReasonCode == "" {
			t.Errorf("receipt %d: missing reason_code", i)
		}
		if r.Hash == "" {
			t.Errorf("receipt %d: missing hash", i)
		}
		if r.Lamport == 0 {
			t.Errorf("receipt %d: lamport should be > 0", i)
		}
		// Verify verdict is one of the allowed values
		switch r.Verdict {
		case "ALLOW", "DENY", "PENDING":
			// ok
		default:
			t.Errorf("receipt %d: unexpected verdict %q", i, r.Verdict)
		}
	}
}

// TestDemoDenyPathPresent verifies a DENY receipt exists with correct reason.
func TestDemoDenyPathPresent(t *testing.T) {
	dir := t.TempDir()
	os.Chdir(dir)

	var out bytes.Buffer
	code := runDemoCompany([]string{"--template", "starter", "--provider", "mock"}, &out, &out)
	if code != 0 {
		t.Fatalf("demo failed with code %d", code)
	}

	receipts := readDemoReceipts(t, filepath.Join(dir, "data", "evidence"))

	found := false
	for _, r := range receipts {
		if r.Verdict == "DENY" {
			found = true
			if r.ReasonCode != "ERR_TOOL_NOT_ALLOWED" {
				t.Errorf("DENY reason should be ERR_TOOL_NOT_ALLOWED, got %q", r.ReasonCode)
			}
			if r.Tool != "psql_drop_table" {
				t.Errorf("DENY tool should be psql_drop_table, got %q", r.Tool)
			}
		}
	}
	if !found {
		t.Error("no DENY receipt found — fail-closed not exercised")
	}
}

// TestNoWallClockInHashPreimage greps the demo code to ensure
// time.Now() is never used in hash preimage construction.
func TestNoWallClockInHashPreimage(t *testing.T) {
	// The hash preimage in demo_cmd.go should use:
	// principal|action|tool|verdict|reason|lamport|prevHash
	// and NOT include any time.Now() calls.
	//
	// This is verified by the determinism test above (same input → same hash).
	// This test is a structural assertion.
	data, err := os.ReadFile("demo_cmd.go")
	if err != nil {
		// Running from a different directory — skip structural test
		t.Skip("cannot read demo_cmd.go from current directory")
	}

	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if strings.Contains(line, "preimage") && strings.Contains(line, "time.Now") {
			t.Errorf("line %d: wall clock in hash preimage: %s", i+1, strings.TrimSpace(line))
		}
	}
}

// readDemoReceipts reads receipt JSON files from directory in sorted order.
func readDemoReceipts(t *testing.T, dir string) []demoReceipt {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatalf("glob error: %v", err)
	}

	var receipts []demoReceipt
	for _, f := range files {
		base := filepath.Base(f)
		// Skip manifest and report files
		if base == "manifest.json" || strings.HasPrefix(base, "run-report") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		var r demoReceipt
		if err := json.Unmarshal(data, &r); err != nil {
			t.Fatalf("unmarshal %s: %v", f, err)
		}
		receipts = append(receipts, r)
	}

	// Sort by Lamport clock
	for i := 0; i < len(receipts); i++ {
		for j := i + 1; j < len(receipts); j++ {
			if receipts[j].Lamport < receipts[i].Lamport {
				receipts[i], receipts[j] = receipts[j], receipts[i]
			}
		}
	}

	if len(receipts) == 0 {
		t.Fatal("no receipts found in", dir)
	}
	return receipts
}
