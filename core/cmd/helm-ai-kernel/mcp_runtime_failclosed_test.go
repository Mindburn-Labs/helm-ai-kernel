package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
)

func setupProvenNativeCodexProjectForRuntime(t *testing.T) (string, setupSummary) {
	t.Helper()
	dir := chdirTempDir(t)
	dataDir := filepath.Join(dir, "kernel-state")
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--json", "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("setup codex exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	var summary setupSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("decode setup summary: %v\n%s", err, stdout.String())
	}
	return dataDir, summary
}

func TestLocalMCPRuntimeFailsClosedWithoutPolicyGraph(t *testing.T) {
	dir := chdirTempDir(t)
	target := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(target, []byte("sensitive"), 0600); err != nil {
		t.Fatal(err)
	}

	_, executor, err := newLocalMCPRuntime()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := executor(context.Background(), mcppkg.ToolExecutionRequest{
		ToolName:  "file_read",
		SessionID: "mcp-test",
		Arguments: map[string]any{"path": target},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.IsError {
		t.Fatalf("expected local MCP execution to fail closed, got %+v", resp)
	}
	if strings.Contains(resp.Content, "sensitive") {
		t.Fatalf("blocked MCP response leaked file content: %q", resp.Content)
	}
}

func TestLocalMCPStdioRefusesPendingCodexSetupRecovery(t *testing.T) {
	dir := chdirTempDir(t)
	stateDir := filepath.Join(dir, "kernel-state")
	if err := prepareSetupRecoveryDirectory(stateDir); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := inspectSetupKernelBinary(binary)
	if err != nil {
		t.Fatal(err)
	}
	workspacePathHash, err := setupRecoveryWorkspacePathHash()
	if err != nil {
		t.Fatal(err)
	}
	txnID, err := newSetupRecoveryTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	receiptID, err := newSetupLifecycleReceiptID()
	if err != nil {
		t.Fatal(err)
	}
	specs, err := expectedSetupRecoveryPlans("install")
	if err != nil {
		t.Fatal(err)
	}
	plans := make([]setupRecoveryFilePlan, 0, len(specs))
	for _, spec := range specs {
		plans = append(plans, setupRecoveryFilePlan{ID: spec.ID, StageFile: spec.StageFile})
	}
	journal := setupRecoveryJournal{
		SchemaVersion:      setupRecoverySchema,
		TransactionID:      txnID,
		Operation:          "install",
		Target:             "codex",
		Scope:              "project",
		WorkspacePathHash:  workspacePathHash,
		DataDirPathHash:    canonicalize.HashBytes([]byte(stateDir)),
		BinaryPath:         identity.Path,
		BinaryContentHash:  identity.ContentHash,
		LifecycleReceiptID: receiptID,
		Phase:              setupRecoveryPhasePrepared,
		Files:              plans,
	}
	if err := writeSetupRecoveryJournal(stateDir, journal); err != nil {
		t.Fatal(err)
	}
	if err := serveLocalMCPStdioWithDataDir(strings.NewReader(""), io.Discard, stateDir); err == nil || !strings.Contains(err.Error(), "recovery") {
		t.Fatalf("pending recovery did not block MCP stdio startup: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "root.key")); !os.IsNotExist(err) {
		t.Fatalf("recovery-blocked MCP startup initialized signer state: %v", err)
	}
}

func TestLocalMCPRuntimeWithDataDirFailsClosedBeforeFileWrite(t *testing.T) {
	dir := chdirTempDir(t)
	stateDir := filepath.Join(dir, "kernel-state")
	sentinel := filepath.Join(dir, "must-not-exist.sentinel")

	_, executor, err := newLocalMCPRuntimeWithDataDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := executor(context.Background(), mcppkg.ToolExecutionRequest{
		ToolName:  "file_write",
		SessionID: "mcp-test",
		Arguments: map[string]any{
			"path":    sentinel,
			"content": "must not exist",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.IsError {
		t.Fatalf("expected local MCP file_write to fail closed, got %+v", resp)
	}
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatalf("denied MCP file_write created sentinel: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "root.key")); err != nil {
		t.Fatalf("runtime did not use explicit data dir for signer state: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "data", "root.key")); !os.IsNotExist(err) {
		t.Fatalf("runtime unexpectedly used default data dir: %v", err)
	}
}

func TestConfiguredCodexRuntimeRejectsDamagedLifecycleProofWithoutNewAuthority(t *testing.T) {
	cases := []struct {
		name   string
		damage func(t *testing.T, dataDir string, summary setupSummary)
	}{
		{
			name: "missing root key",
			damage: func(t *testing.T, dataDir string, _ setupSummary) {
				t.Helper()
				if err := os.Remove(filepath.Join(dataDir, "root.key")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing install binding",
			damage: func(t *testing.T, dataDir string, _ setupSummary) {
				t.Helper()
				if err := os.Remove(setupCodexProjectBindingPath(dataDir)); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing lifecycle evidence",
			damage: func(t *testing.T, _ string, summary setupSummary) {
				t.Helper()
				if err := os.Remove(summary.LifecycleEvidencePath); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dataDir, summary := setupProvenNativeCodexProjectForRuntime(t)
			tc.damage(t, dataDir, summary)

			if _, _, err := newLocalMCPRuntimeWithDataDir(dataDir); err == nil || !strings.Contains(err.Error(), "provenance") {
				t.Fatalf("direct configured runtime bypassed provenance admission: %v", err)
			}
			if err := serveLocalMCPStdioWithDataDir(strings.NewReader(""), io.Discard, dataDir); err == nil || !strings.Contains(err.Error(), "runtime provenance") {
				t.Fatalf("damaged native lifecycle proof started MCP runtime: %v", err)
			}
			if tc.name == "missing root key" {
				if _, err := os.Stat(filepath.Join(dataDir, "root.key")); !os.IsNotExist(err) {
					t.Fatalf("runtime recreated missing lifecycle authority: %v", err)
				}
			}

			var stdout, stderr bytes.Buffer
			code := runHookPreToolCmd([]string{"--client", "codex", "--data-dir", dataDir}, strings.NewReader(`{"tool_name":"mcp__filesystem__write_file","tool_input":{"path":"/tmp/x"}}`), &stdout, &stderr)
			if code != 0 || !strings.Contains(stdout.String(), `"permissionDecision":"deny"`) || !strings.Contains(stdout.String(), "provenance") {
				t.Fatalf("damaged native lifecycle proof did not deny hook: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
		})
	}
}
