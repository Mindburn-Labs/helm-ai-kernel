package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestRunConformNegativeJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runConform([]string{"negative", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d stderr=%s", code, stderr.String())
	}
	var vectors []map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &vectors); err != nil {
		t.Fatalf("parse json: %v\n%s", err, stdout.String())
	}
	if len(vectors) == 0 {
		t.Fatal("expected negative vectors")
	}
}

func TestRunMCPWrapJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runMCPWrap([]string{
		"--server-id", "srv-1",
		"--upstream-command", "node server.js",
		"--policy-epoch", "epoch-42",
		"--json",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d stderr=%s", code, stderr.String())
	}
	var profile map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &profile); err != nil {
		t.Fatalf("parse json: %v\n%s", err, stdout.String())
	}
	if profile["server_id"] != "srv-1" {
		t.Fatalf("server_id = %v", profile["server_id"])
	}
	if profile["quarantine_default"] != "quarantined" {
		t.Fatalf("quarantine_default = %v", profile["quarantine_default"])
	}
}

func TestRunMCPApproveJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runMCPApprove([]string{
		"--server-id", "srv-1",
		"--approver", "user:alice",
		"--receipt-id", "approval-r1",
		"--json",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d stderr=%s", code, stderr.String())
	}
	var record map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &record); err != nil {
		t.Fatalf("parse json: %v\n%s", err, stdout.String())
	}
	if record["state"] != "approved" {
		t.Fatalf("state = %v", record["state"])
	}
	if record["approval_receipt_id"] != "approval-r1" {
		t.Fatalf("approval receipt = %v", record["approval_receipt_id"])
	}
}

func TestRunSandboxInspectJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runSandboxInspect([]string{"--runtime", "wazero", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d stderr=%s", code, stderr.String())
	}
	var grant map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &grant); err != nil {
		t.Fatalf("parse json: %v\n%s", err, stdout.String())
	}
	if grant["runtime"] != "wazero" {
		t.Fatalf("runtime = %v", grant["runtime"])
	}
	if grant["grant_hash"] == "" {
		t.Fatal("grant_hash missing")
	}
}

func TestRunEvidenceExportEnvelopeJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runEvidenceExport([]string{
		"--envelope", "dsse",
		"--native-hash", "sha256:evidence",
		"--manifest-id", "manifest-1",
		"--json",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d stderr=%s", code, stderr.String())
	}
	var manifest map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &manifest); err != nil {
		t.Fatalf("parse json: %v\n%s", err, stdout.String())
	}
	if manifest["native_authority"] != true {
		t.Fatalf("native authority = %v", manifest["native_authority"])
	}
}

func TestRunEvidenceExportBlocksExperimentalWithoutFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runEvidenceExport([]string{
		"--envelope", "scitt",
		"--native-hash", "sha256:evidence",
	}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "experimental") {
		t.Fatalf("stderr did not mention experimental gate: %s", stderr.String())
	}
}
