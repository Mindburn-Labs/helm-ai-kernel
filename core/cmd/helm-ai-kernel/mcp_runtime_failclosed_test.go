package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
)

// A compiled serve policy authorizes execution: with a graph that carries an
// EXECUTE_TOOL rule (what the governance firewall evaluates), the same file_read
// that fails closed under the empty-graph default now succeeds. This is the
// behavior `mcp serve --policy` wires in.
func TestLocalMCPRuntimeAuthorizesExecutionWithPolicyGraph(t *testing.T) {
	dir := chdirTempDir(t)
	target := filepath.Join(dir, "allowed.txt")
	if err := os.WriteFile(target, []byte("authorized-content"), 0600); err != nil {
		t.Fatal(err)
	}

	graph := prg.NewGraph()
	// The guardian keys the policy lookup on the tool action (the firewall
	// passes ToolName as the decision Resource), so a serve policy authorizes
	// specific tools by name. An empty requirement set is vacuously satisfied,
	// so this rule allows file_read while every other tool stays fail-closed.
	if err := graph.AddRule("file_read", prg.RequirementSet{ID: "serve-policy:file_read", Logic: prg.AND}); err != nil {
		t.Fatal(err)
	}

	_, executor, err := newLocalMCPRuntimeWithDataDirAndPolicy(dir, graph)
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
	if resp.IsError {
		t.Fatalf("expected policy-authorized execution to succeed, got error: %q", resp.Content)
	}
	if !strings.Contains(resp.Content, "authorized-content") {
		t.Fatalf("expected authorized file content, got %q", resp.Content)
	}
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
