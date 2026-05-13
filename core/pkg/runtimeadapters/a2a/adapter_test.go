package a2a

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/runtimeadapters"
)

func TestA2AAdapterID(t *testing.T) {
	graph := proofgraph.NewGraph()
	adapter, err := NewA2AAdapter(Config{Graph: graph})
	if err != nil {
		t.Fatal(err)
	}
	if adapter.ID() != "a2a-adapter-v1" {
		t.Errorf("expected a2a-adapter-v1, got %s", adapter.ID())
	}
}

func TestA2AAdapterIntercept(t *testing.T) {
	graph := proofgraph.NewGraph()
	adapter, err := NewA2AAdapter(Config{Graph: graph})
	if err != nil {
		t.Fatal(err)
	}

	req := &runtimeadapters.AdaptedRequest{
		RuntimeType: "a2a",
		ToolName:    "tasks/send",
		Arguments:   map[string]any{"task_id": "task-001", "message": "execute research"},
		PrincipalID: "agent-orchestrator",
		Metadata: map[string]string{
			"a2a.from_agent": "agent-orchestrator",
			"a2a.to_agent":   "agent-researcher",
			"a2a.task_id":    "task-001",
		},
	}

	resp, err := adapter.Intercept(context.Background(), req)
	if err != nil {
		t.Fatalf("intercept failed: %v", err)
	}

	// Should create a ProofGraph node.
	if resp.ProofGraphNode == "" {
		t.Error("expected proof graph node hash")
	}

	// Verify node exists in graph.
	node, ok := graph.Get(resp.ProofGraphNode)
	if !ok {
		t.Fatal("proof node not found in graph")
	}
	if node.Kind != proofgraph.NodeTypeIntent {
		t.Errorf("expected INTENT node, got %s", node.Kind)
	}
	if node.Principal != "agent-orchestrator" {
		t.Errorf("expected principal agent-orchestrator, got %s", node.Principal)
	}
}

func TestA2AAdapterInterceptWithoutMetadata(t *testing.T) {
	graph := proofgraph.NewGraph()
	adapter, err := NewA2AAdapter(Config{Graph: graph})
	if err != nil {
		t.Fatal(err)
	}

	req := &runtimeadapters.AdaptedRequest{
		RuntimeType: "a2a",
		ToolName:    "tasks/get",
		Arguments:   map[string]any{"task_id": "task-002"},
		PrincipalID: "agent-worker",
	}

	resp, err := adapter.Intercept(context.Background(), req)
	if err != nil {
		t.Fatalf("intercept failed: %v", err)
	}
	if resp.ProofGraphNode == "" {
		t.Error("expected proof graph node hash")
	}
}

func TestA2AAdapterRejectsNilRequest(t *testing.T) {
	graph := proofgraph.NewGraph()
	adapter, err := NewA2AAdapter(Config{Graph: graph})
	if err != nil {
		t.Fatal(err)
	}

	_, err = adapter.Intercept(context.Background(), nil)
	if err == nil {
		t.Error("expected error for nil request")
	}
}

func TestA2AAdapterRequiresGraph(t *testing.T) {
	_, err := NewA2AAdapter(Config{})
	if err == nil {
		t.Error("expected error when Graph is nil")
	}
}

// Verify A2AAdapter implements RuntimeAdapter interface.
var _ runtimeadapters.RuntimeAdapter = (*A2AAdapter)(nil)
