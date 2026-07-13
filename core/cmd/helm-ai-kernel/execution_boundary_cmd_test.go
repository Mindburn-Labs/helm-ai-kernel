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
		_ = os.Setenv("HELM_DATA_DIR", filepath.Join(dir, "data"))
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

func TestRunMCPApproveFailsClosedWithoutCredentialVerifier(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runMCPApprove([]string{
		"--server-id", "srv-1",
		"--approver", "user:alice",
		"--receipt-id", "approval-r1",
		"--tools", "file_read",
		"--reason", "test approval",
		"--json",
	}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "MCP approval verification unavailable") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestRunMCPApproveFailsClosedForAnyScope(t *testing.T) {
	for _, args := range [][]string{
		{"--server-id", "srv-wildcard", "--tools", "*", "--reason", "too broad"},
		{"--server-id", "srv-write", "--tools", "deploy", "--effects", "side_effect", "--ttl", "1h", "--reason", "too long"},
	} {
		var stdout, stderr bytes.Buffer
		code := runMCPApprove(args, &stdout, &stderr)
		if code != 2 {
			t.Fatalf("args %v exit code = %d stdout=%s stderr=%s", args, code, stdout.String(), stderr.String())
		}
		if !strings.Contains(stderr.String(), "MCP approval verification unavailable") {
			t.Fatalf("args %v stderr=%s", args, stderr.String())
		}
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

func TestRunMCPAuthorizeCallEscalateJSON(t *testing.T) {
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
	if record["verdict"] != "ESCALATE" {
		t.Fatalf("verdict = %v", record["verdict"])
	}
	if _, ok := record["approval_command"]; ok {
		t.Fatalf("approval_command must be omitted while credential verification is unavailable: %+v", record)
	}
	if record["decision_receipt_path"] == "" {
		t.Fatal("decision_receipt_path missing")
	}
	if record["record_hash"] == "" {
		t.Fatal("record_hash missing")
	}
}

func TestRunMCPAuthorizeCallEscalateHumanMessage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runMCPAuthorizeCall([]string{
		"--server-id", "shell-mcp-server",
		"--tool-name", "pwd",
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"HELM ESCALATE",
		"decision: mcp-boundary-",
		"reason: unknown MCP server remains quarantined; credential verification is unavailable",
		"receipt:",
		"approval: credential verification unavailable; the server remains quarantined",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func TestRunMCPAuthorizeCallUnknownToolEscalateJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runMCPAuthorizeCall([]string{
		"--server-id", "srv-cli-unknown-tool",
		"--tool-name", "local.missing",
		"--json",
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d stderr=%s", code, stderr.String())
	}
	var record map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &record); err != nil {
		t.Fatalf("parse json: %v\n%s", err, stdout.String())
	}
	if record["verdict"] != "ESCALATE" {
		t.Fatalf("verdict = %v", record["verdict"])
	}
}

func TestRunMCPAuthorizeCallMissingSchemaPinEscalateJSON(t *testing.T) {
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
	if record["verdict"] != "ESCALATE" {
		t.Fatalf("verdict = %v", record["verdict"])
	}
}

func TestRunMCPAuthorizeCallApprovedSeedFailsClosed(t *testing.T) {
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
	if code != 2 {
		t.Fatalf("exit code = %d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stderr.String(), "MCP approval verification unavailable") {
		t.Fatalf("stderr=%s", stderr.String())
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
