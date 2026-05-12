package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	mcppkg "github.com/Mindburn-Labs/helm-oss/core/pkg/mcp"
)

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
