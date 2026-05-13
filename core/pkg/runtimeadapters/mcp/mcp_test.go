package mcp

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/runtimeadapters"
)

func TestMCPAdapterID(t *testing.T) {
	graph := proofgraph.NewGraph()
	adapter, err := NewMCPAdapter(Config{Graph: graph})
	if err != nil {
		t.Fatal(err)
	}
	if adapter.ID() != "mcp-adapter-v1" {
		t.Errorf("expected mcp-adapter-v1, got %s", adapter.ID())
	}
}

func TestMCPAdapterIntercept(t *testing.T) {
	graph := proofgraph.NewGraph()
	adapter, err := NewMCPAdapter(Config{Graph: graph})
	if err != nil {
		t.Fatal(err)
	}

	req := &runtimeadapters.AdaptedRequest{
		RuntimeType: "mcp",
		ToolName:    "gmail.send",
		Arguments:   map[string]any{"to": "bob@example.com", "subject": "Hello"},
		PrincipalID: "ve-exec-assistant",
	}

	resp, err := adapter.Intercept(context.Background(), req)
	if err != nil {
		t.Fatalf("intercept failed: %v", err)
	}

	// Should create a ProofGraph node
	if resp.ProofGraphNode == "" {
		t.Error("expected proof graph node hash")
	}

	// Verify node exists in graph
	node, ok := graph.Get(resp.ProofGraphNode)
	if !ok {
		t.Fatal("proof node not found in graph")
	}
	if node.Kind != proofgraph.NodeTypeIntent {
		t.Errorf("expected INTENT node, got %s", node.Kind)
	}
	if node.Principal != "ve-exec-assistant" {
		t.Errorf("expected principal ve-exec-assistant, got %s", node.Principal)
	}
}

func TestMCPAdapterRejectsNilRequest(t *testing.T) {
	graph := proofgraph.NewGraph()
	adapter, err := NewMCPAdapter(Config{Graph: graph})
	if err != nil {
		t.Fatal(err)
	}

	_, err = adapter.Intercept(context.Background(), nil)
	if err == nil {
		t.Error("expected error for nil request")
	}
}

func TestMCPAdapterRequiresGraph(t *testing.T) {
	_, err := NewMCPAdapter(Config{})
	if err == nil {
		t.Error("expected error when Graph is nil")
	}
}

// Verify MCPAdapter implements RuntimeAdapter interface
var _ runtimeadapters.RuntimeAdapter = (*MCPAdapter)(nil)
