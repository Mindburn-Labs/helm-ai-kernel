package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
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

func TestRunMCPApproveJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runMCPApprove([]string{
		"--server-id", "srv-1",
		"--approver", "user:alice",
		"--receipt-id", "approval-r1",
		"--tools", "file_read",
		"--reason", "test approval",
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

func TestRunMCPApproveRejectsUnsafeScopes(t *testing.T) {
	for _, args := range [][]string{
		{"--server-id", "srv-wildcard", "--tools", "*", "--reason", "too broad"},
		{"--server-id", "srv-write", "--tools", "deploy", "--effects", "side_effect", "--ttl", "1h", "--reason", "too long"},
	} {
		var stdout, stderr bytes.Buffer
		code := runMCPApprove(args, &stdout, &stderr)
		if code != 2 {
			t.Fatalf("args %v exit code = %d stdout=%s stderr=%s", args, code, stdout.String(), stderr.String())
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
	if record["approval_command"] == "" {
		t.Fatal("approval_command missing")
	}
	if record["decision_receipt_path"] == "" {
		t.Fatal("decision_receipt_path missing")
	}
	if record["record_hash"] == "" {
		t.Fatal("record_hash missing")
	}
}

func TestRunMCPAuthorizeCallReceiptAuthenticatesFinalRecord(t *testing.T) {
	schema := map[string]any{"type": "object"}
	schemaJSON, _ := json.Marshal(schema)
	allowHash, err := mcppkg.ToolSchemaHash(mcppkg.ToolRef{Name: "local.allow", Schema: schema})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		args    []string
		code    int
		verdict contracts.Verdict
	}{
		{
			name:    "escalate",
			args:    []string{"--server-id", "srv-receipt-escalate", "--tool-name", "file_read", "--json"},
			code:    1,
			verdict: contracts.VerdictEscalate,
		},
		{
			name:    "deny",
			args:    []string{"--server-id", "srv-receipt-deny", "--tool-name", "local.deny", "--approved", "--tool-schema-json", string(schemaJSON), "--pinned-schema-hash", "sha256:wrong", "--json"},
			code:    1,
			verdict: contracts.VerdictDeny,
		},
		{
			name:    "allow",
			args:    []string{"--server-id", "srv-receipt-allow", "--tool-name", "local.allow", "--approved", "--tool-schema-json", string(schemaJSON), "--pinned-schema-hash", allowHash, "--json"},
			code:    0,
			verdict: contracts.VerdictAllow,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := runMCPAuthorizeCall(tt.args, &stdout, &stderr); code != tt.code {
				t.Fatalf("exit code = %d, want %d stderr=%s", code, tt.code, stderr.String())
			}
			var output contracts.ExecutionBoundaryRecord
			if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
				t.Fatalf("parse output: %v\n%s", err, stdout.String())
			}
			if output.Verdict != tt.verdict {
				t.Fatalf("verdict = %s, want %s", output.Verdict, tt.verdict)
			}
			data, err := os.ReadFile(output.DecisionReceiptPath)
			if err != nil {
				t.Fatal(err)
			}
			var receipt struct {
				Record contracts.ExecutionBoundaryRecord `json:"record"`
			}
			if err := json.Unmarshal(data, &receipt); err != nil {
				t.Fatalf("parse receipt: %v", err)
			}
			resealed, err := receipt.Record.Seal()
			if err != nil {
				t.Fatal(err)
			}
			if receipt.Record.RecordHash != resealed.RecordHash {
				t.Fatalf("receipt record hash = %q, want final hash %q", receipt.Record.RecordHash, resealed.RecordHash)
			}
			if receipt.Record.RecordHash != output.RecordHash || receipt.Record.DecisionReceiptPath != output.DecisionReceiptPath {
				t.Fatalf("receipt record does not match output: receipt=%+v output=%+v", receipt.Record, output)
			}
			stored, ok := newLocalSurfaceRegistry().GetRecord(output.RecordID)
			if !ok || stored.RecordHash != output.RecordHash || stored.DecisionReceiptPath != output.DecisionReceiptPath {
				t.Fatalf("stored record does not match output: stored=%+v found=%t output=%+v", stored, ok, output)
			}
		})
	}
}

func TestRunMCPAuthorizeCallClearsReceiptPathWhenWriteFails(t *testing.T) {
	dataFile := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(dataFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HELM_DATA_DIR", dataFile)

	var escalateOut, escalateErr bytes.Buffer
	code := runMCPAuthorizeCall([]string{
		"--server-id", "srv-write-failure",
		"--tool-name", "file_read",
		"--json",
	}, &escalateOut, &escalateErr)
	if code != 1 {
		t.Fatalf("escalate exit code = %d stderr=%s", code, escalateErr.String())
	}
	var escalate contracts.ExecutionBoundaryRecord
	if err := json.Unmarshal(escalateOut.Bytes(), &escalate); err != nil {
		t.Fatalf("parse escalate json: %v\n%s", err, escalateOut.String())
	}
	if escalate.Verdict != contracts.VerdictEscalate || escalate.ReasonCode != contracts.ReasonApprovalRequired {
		t.Fatalf("non-ALLOW verdict changed after receipt failure: %+v", escalate)
	}
	if escalate.DecisionReceiptPath != "" {
		t.Fatalf("escalate decision_receipt_path = %q after write failure, want empty", escalate.DecisionReceiptPath)
	}

	schema := map[string]any{"type": "object"}
	schemaJSON, _ := json.Marshal(schema)
	hash, err := mcppkg.ToolSchemaHash(mcppkg.ToolRef{Name: "local.allow-write-failure", Schema: schema})
	if err != nil {
		t.Fatal(err)
	}
	var allowOut, allowErr bytes.Buffer
	code = runMCPAuthorizeCall([]string{
		"--server-id", "srv-allow-write-failure",
		"--tool-name", "local.allow-write-failure",
		"--approved",
		"--tool-schema-json", string(schemaJSON),
		"--pinned-schema-hash", hash,
		"--json",
	}, &allowOut, &allowErr)
	if code != 1 {
		t.Fatalf("ALLOW receipt failure exit code = %d, want 1 stderr=%s", code, allowErr.String())
	}
	var denied contracts.ExecutionBoundaryRecord
	if err := json.Unmarshal(allowOut.Bytes(), &denied); err != nil {
		t.Fatalf("parse failed-ALLOW json: %v\n%s", err, allowOut.String())
	}
	if denied.Verdict != contracts.VerdictDeny || denied.ReasonCode != contracts.ReasonVerification {
		t.Fatalf("ALLOW without receipt must fail closed, got %+v", denied)
	}
	if denied.DecisionReceiptPath != "" || denied.RecordHash == "" {
		t.Fatalf("failed-ALLOW record must be sealed without a receipt path: %+v", denied)
	}
	stored, ok := newLocalSurfaceRegistry().GetRecord(denied.RecordID)
	if !ok || stored.Verdict != contracts.VerdictDeny || stored.ReasonCode != contracts.ReasonVerification || stored.DecisionReceiptPath != "" {
		t.Fatalf("stored failed-ALLOW record is not fail-closed: stored=%+v found=%t", stored, ok)
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
		"reason: unknown MCP server requires approval",
		"receipt:",
		"next:",
		"helm-ai-kernel mcp approve --server-id shell-mcp-server --tools \"pwd\" --ttl 15m --reason 'read-only repo inspection for local dev'",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func TestRunMCPAuthorizeCallDenyHumanMessageUnifiedShape(t *testing.T) {
	// Approved server, but "ls" is outside the approved tool scope: the DENY
	// must carry the same shape as ESCALATE (verdict, decision, reason,
	// receipt, next-step command) instead of a bare one-liner.
	var seedOut, seedErr bytes.Buffer
	if code := runMCPAuthorizeCall([]string{
		"--server-id", "srv-cli-deny-shape",
		"--tool-name", "pwd",
		"--approved",
		"--json",
	}, &seedOut, &seedErr); code == 2 {
		t.Fatalf("seed approval failed: %s", seedErr.String())
	}
	var stdout, stderr bytes.Buffer
	code := runMCPAuthorizeCall([]string{
		"--server-id", "srv-cli-deny-shape",
		"--tool-name", "ls",
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"HELM DENY",
		"decision: mcp-boundary-",
		"reason: tool is outside the approved scope for this MCP server",
		"receipt:",
		"next:",
		"helm-ai-kernel mcp approve --server-id srv-cli-deny-shape --tools \"ls\"",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func TestRunMCPAuthorizeCallSchemaPinNextStepHumanMessage(t *testing.T) {
	// Approved server + catalog tool + no schema pin: the ESCALATE must print
	// the exact authorize-call rerun command with the schema hash filled in,
	// and following that command must reach ALLOW.
	var stdout, stderr bytes.Buffer
	code := runMCPAuthorizeCall([]string{
		"--server-id", "helm-governance",
		"--tool-name", "file_read",
		"--effect", "side_effect",
		"--args-hash", "sha256:custom-args",
		"--scopes", "files.read,audit.write",
		"--oauth-resource", "https://example.test/mcp",
		"--receipt-id", "receipt-context",
		"--approved",
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"HELM ESCALATE",
		"reason: MCP tool schema requires approval or pinning",
		"receipt:",
		"next:",
		"helm-ai-kernel mcp authorize-call --server-id helm-governance --tool-name file_read",
		"--pinned-schema-hash sha256:",
		"--effect side_effect",
		"--args-hash sha256:custom-args",
		"--scopes files.read,audit.write",
		"--oauth-resource https://example.test/mcp",
		"--receipt-id receipt-context",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}

	// Following the printed next step reaches ALLOW in the unified shape.
	catalog := mcppkg.NewToolCatalog()
	catalog.RegisterCommonTools()
	tool, ok := catalog.Lookup("file_read")
	if !ok {
		t.Fatal("file_read missing from common catalog")
	}
	hash, err := mcppkg.ToolSchemaHash(tool)
	if err != nil {
		t.Fatalf("schema hash: %v", err)
	}
	var allowOut, allowErr bytes.Buffer
	allowCode := runMCPAuthorizeCall([]string{
		"--server-id", "helm-governance",
		"--tool-name", "file_read",
		"--effect", "side_effect",
		"--args-hash", "sha256:custom-args",
		"--scopes", "files.read,audit.write",
		"--oauth-resource", "https://example.test/mcp",
		"--receipt-id", "receipt-context",
		"--approved",
		"--pinned-schema-hash", hash,
	}, &allowOut, &allowErr)
	if allowCode != 0 {
		t.Fatalf("exit code = %d stderr=%s stdout=%s", allowCode, allowErr.String(), allowOut.String())
	}
	allow := allowOut.String()
	for _, want := range []string{"HELM ALLOW", "decision: mcp-boundary-", "reason:", "receipt:"} {
		if !strings.Contains(allow, want) {
			t.Fatalf("output missing %q:\n%s", want, allow)
		}
	}
}

func TestRunMCPAuthorizeCallUnknownToolEscalateJSON(t *testing.T) {
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
	if record["verdict"] != "ESCALATE" {
		t.Fatalf("verdict = %v", record["verdict"])
	}
}

func TestRunMCPAuthorizeCallCustomSchemaNextStepPreservesSchemas(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runMCPAuthorizeCall([]string{
		"--server-id", "srv-cli-custom-schema",
		"--tool-name", "local.echo",
		"--approved",
		"--tool-schema-json", `{"type":"object"}`,
		"--output-schema-json", `{"type":"string"}`,
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"--pinned-schema-hash sha256:",
		`--tool-schema-json '{"type":"object"}'`,
		`--output-schema-json '{"type":"string"}'`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func TestShellTokenQuotesCommandSubstitutionAndComments(t *testing.T) {
	for _, value := range []string{
		"tool`touch /tmp/pwned`",
		"tool# ignored",
		"tool\rnext-command",
		"~other-user/tool",
	} {
		quoted := shellToken(value)
		if quoted == value || !strings.HasPrefix(quoted, "'") || !strings.HasSuffix(quoted, "'") {
			t.Fatalf("shellToken(%q) = %q, want single-quoted token", value, quoted)
		}
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
