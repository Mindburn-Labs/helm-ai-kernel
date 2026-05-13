package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "helm-boundary-surfaces-test-*")
	if err == nil {
		_ = os.Setenv("HELM_BOUNDARY_REGISTRY_PATH", filepath.Join(dir, "surfaces.json"))
	}
	code := m.Run()
	if err == nil {
		_ = os.RemoveAll(dir)
	}
	os.Exit(code)
}

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

func TestRunBoundaryStatusJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runBoundarySurfaceCmd([]string{"status", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d stderr=%s", code, stderr.String())
	}
	var status map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		t.Fatalf("parse json: %v\n%s", err, stdout.String())
	}
	if status["mcp_firewall"] != "enabled" {
		t.Fatalf("mcp firewall = %v", status["mcp_firewall"])
	}
}

func TestRunMCPAuthorizeCallDenyJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runMCPAuthorizeCall([]string{
		"--server-id", "srv-1",
		"--tool-name", "file_read",
		"--json",
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d stderr=%s", code, stderr.String())
	}
	var record map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &record); err != nil {
		t.Fatalf("parse json: %v\n%s", err, stdout.String())
	}
	if record["verdict"] != "DENY" {
		t.Fatalf("verdict = %v", record["verdict"])
	}
	if record["record_hash"] == "" {
		t.Fatal("record_hash missing")
	}
}

func TestRunMCPAuthorizeCallUnknownToolDenyJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runMCPAuthorizeCall([]string{
		"--server-id", "srv-cli-unknown-tool",
		"--tool-name", "local.missing",
		"--approved",
		"--json",
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d stderr=%s", code, stderr.String())
	}
	var record map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &record); err != nil {
		t.Fatalf("parse json: %v\n%s", err, stdout.String())
	}
	if record["verdict"] != "DENY" {
		t.Fatalf("verdict = %v", record["verdict"])
	}
}

func TestRunMCPAuthorizeCallMissingSchemaPinDenyJSON(t *testing.T) {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"text": map[string]any{"type": "string"},
		},
		"required": []string{"text"},
	}
	schemaJSON, _ := json.Marshal(schema)
	var stdout, stderr bytes.Buffer
	code := runMCPAuthorizeCall([]string{
		"--server-id", "srv-cli-missing-pin",
		"--tool-name", "local.echo",
		"--approved",
		"--tool-schema-json", string(schemaJSON),
		"--json",
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	var record map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &record); err != nil {
		t.Fatalf("parse json: %v\n%s", err, stdout.String())
	}
	if record["verdict"] != "DENY" {
		t.Fatalf("verdict = %v", record["verdict"])
	}
}

func TestRunMCPAuthorizeCallApprovedPinnedLocalToolAllowJSON(t *testing.T) {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"text": map[string]any{"type": "string"},
		},
		"required": []string{"text"},
	}
	hash, err := mcppkg.ToolSchemaHash(mcppkg.ToolRef{Name: "local.echo", Schema: schema})
	if err != nil {
		t.Fatalf("schema hash: %v", err)
	}
	schemaJSON, _ := json.Marshal(schema)
	var stdout, stderr bytes.Buffer
	code := runMCPAuthorizeCall([]string{
		"--server-id", "srv-cli-allow",
		"--tool-name", "local.echo",
		"--approved",
		"--tool-schema-json", string(schemaJSON),
		"--pinned-schema-hash", hash,
		"--json",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	var record map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &record); err != nil {
		t.Fatalf("parse json: %v\n%s", err, stdout.String())
	}
	if record["verdict"] != "ALLOW" {
		t.Fatalf("verdict = %v", record["verdict"])
	}
	if record["record_hash"] == "" {
		t.Fatal("record_hash missing")
	}
}

func TestRunSandboxPreflightJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runSandboxPreflightSurface([]string{"--runtime", "wazero", "--json"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d stderr=%s", code, stderr.String())
	}
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("parse json: %v\n%s", err, stdout.String())
	}
	if result["verdict"] != "DENY" {
		t.Fatalf("verdict = %v", result["verdict"])
	}
}

func TestRunAuthzCheckJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runAuthzSurfaceCmd([]string{"check", "--subject", "agent:a", "--object", "tool:b", "--relation", "can_call", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d stderr=%s", code, stderr.String())
	}
	var snapshot map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &snapshot); err != nil {
		t.Fatalf("parse json: %v\n%s", err, stdout.String())
	}
	if snapshot["snapshot_hash"] == "" {
		t.Fatal("snapshot_hash missing")
	}
}

func TestRunIntegrateScaffoldJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runIntegrateSurfaceCmd([]string{"scaffold", "--framework", "langgraph", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d stderr=%s", code, stderr.String())
	}
	var scaffold map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &scaffold); err != nil {
		t.Fatalf("parse json: %v\n%s", err, stdout.String())
	}
	if scaffold["mode"] != "pre-dispatch-required" {
		t.Fatalf("mode = %v", scaffold["mode"])
	}
}
