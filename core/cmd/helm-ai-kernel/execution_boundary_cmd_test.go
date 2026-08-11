package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
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

func TestRunMCPApproveFailsClosedWithoutVerifier(t *testing.T) {
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
	if stdout.Len() != 0 {
		t.Fatalf("opaque local approval emitted output: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "MCP approval verification unavailable") {
		t.Fatalf("stderr did not explain verification boundary: %s", stderr.String())
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
		if stdout.Len() != 0 || !strings.Contains(stderr.String(), "MCP approval verification unavailable") {
			t.Fatalf("args %v did not fail closed: stdout=%s stderr=%s", args, stdout.String(), stderr.String())
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
		t.Fatalf("opaque local approval command leaked into JSON: %v", record["approval_command"])
	}
	if record["decision_receipt_path"] == "" {
		t.Fatal("decision_receipt_path missing")
	}
	if record["record_hash"] == "" {
		t.Fatal("record_hash missing")
	}
}

func TestRunMCPAuthorizeCallReceiptAuthenticatesFinalRecord(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runMCPAuthorizeCall([]string{"--server-id", "srv-receipt-escalate", "--tool-name", "file_read", "--json"}, &stdout, &stderr); code != 1 {
		t.Fatalf("exit code = %d, want 1 stderr=%s", code, stderr.String())
	}
	var output contracts.ExecutionBoundaryRecord
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("parse output: %v\n%s", err, stdout.String())
	}
	if output.Verdict != contracts.VerdictEscalate {
		t.Fatalf("verdict = %s, want %s", output.Verdict, contracts.VerdictEscalate)
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
		"approval: credential verification unavailable; the server remains quarantined",
		"receipt:",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func TestRunMCPAuthorizeCallOpaqueApprovalInputsCannotAuthorize(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
	}{
		{
			name: "json flag",
			args: []string{"--server-id", "srv-cli-unverified-json", "--tool-name", "pwd", "--approved", "--json"},
		},
		{
			name: "pinned custom schema",
			args: []string{
				"--server-id", "srv-cli-unverified-schema",
				"--tool-name", "local.echo",
				"--effect", "side_effect",
				"--args-hash", "sha256:attempted-local-allow",
				"--scopes", "files.read,audit.write",
				"--receipt-id", "opaque-receipt",
				"--approved",
				"--tool-schema-json", `{"type":"object"}`,
				"--output-schema-json", `{"type":"string"}`,
				"--pinned-schema-hash", "sha256:opaque-local-pin",
				"--json",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := runMCPAuthorizeCall(tt.args, &stdout, &stderr); code != 2 {
				t.Fatalf("exit code = %d, want 2 stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			if stdout.Len() != 0 || !strings.Contains(stderr.String(), "MCP approval verification unavailable") {
				t.Fatalf("opaque approval bypass attempt was not rejected: stdout=%s stderr=%s", stdout.String(), stderr.String())
			}
		})
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

func TestRunSandboxExecRefusesWithoutPolicyEvaluator(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
	}{
		{name: "json", args: []string{"exec", "--provider", "mock", "--json", "--", "echo", "hi"}},
		{name: "text", args: []string{"exec", "--provider", "mock", "--", "echo", "hi"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runSandboxCmd(tt.args, &stdout, &stderr)
			if code != 1 {
				t.Fatalf("exit code = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			combined := stdout.String() + stderr.String()
			for _, forbidden := range []string{"ALLOW", "receipt_id", "preflight_hash", "image_digest", "sha256:"} {
				if strings.Contains(combined, forbidden) {
					t.Fatalf("sandbox exec emitted forbidden synthetic authority %q: stdout=%s stderr=%s", forbidden, stdout.String(), stderr.String())
				}
			}
			if !strings.Contains(combined, sandboxPreflightReasonUnavailable) {
				t.Fatalf("sandbox exec did not report unavailable evaluator: stdout=%s stderr=%s", stdout.String(), stderr.String())
			}
			if tt.name != "json" {
				return
			}
			var result map[string]any
			if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
				t.Fatalf("parse json: %v\n%s", err, stdout.String())
			}
			if result["verdict"] != "DENY" || result["status"] != sandboxPreflightStatusUnavailable {
				t.Fatalf("unexpected refusal envelope: %#v", result)
			}
			preflight, ok := result["preflight"].(map[string]any)
			if !ok {
				t.Fatalf("preflight missing from refusal envelope: %#v", result)
			}
			if preflight["pass"] != false || preflight["status"] != sandboxPreflightStatusUnavailable {
				t.Fatalf("preflight = %#v, want failed unavailable", preflight)
			}
		})
	}
}

func TestRunSandboxConformRefusesWithoutPolicyEvaluator(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runSandboxCmd([]string{"conform", "--provider", "mock", "--tier", "verified", "--json"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	output := stdout.String() + stderr.String()
	for _, forbidden := range []string{`"pass": true`, "ALLOW", "receipt_id", "preflight_hash", "sha256:"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("sandbox conform emitted forbidden synthetic authority %q: stdout=%s stderr=%s", forbidden, stdout.String(), stderr.String())
		}
	}
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("parse json: %v\n%s", err, stdout.String())
	}
	if result["pass"] != false || result["status"] != sandboxPreflightStatusUnavailable {
		t.Fatalf("unexpected conformance result: %#v", result)
	}
	checks, ok := result["checks"].([]any)
	if !ok || len(checks) == 0 {
		t.Fatalf("checks missing: %#v", result)
	}
	for _, raw := range checks {
		check, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("unexpected check payload: %#v", raw)
		}
		if check["pass"] != false || check["status"] != sandboxPreflightStatusUnavailable {
			t.Fatalf("check = %#v, want failed unavailable", check)
		}
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
