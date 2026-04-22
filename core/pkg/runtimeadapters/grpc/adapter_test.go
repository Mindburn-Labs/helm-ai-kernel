package grpc

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/runtimeadapters"
)

func TestGRPCAdapterID(t *testing.T) {
	graph := proofgraph.NewGraph()
	adapter, err := NewGRPCAdapter(Config{Graph: graph})
	if err != nil {
		t.Fatal(err)
	}
	if adapter.ID() != "grpc-adapter-v1" {
		t.Errorf("expected grpc-adapter-v1, got %s", adapter.ID())
	}
}

func TestGRPCAdapterIntercept(t *testing.T) {
	graph := proofgraph.NewGraph()
	adapter, err := NewGRPCAdapter(Config{Graph: graph})
	if err != nil {
		t.Fatal(err)
	}

	req := &runtimeadapters.AdaptedRequest{
		RuntimeType: "grpc",
		ToolName:    "/helm.v1.Governance/Evaluate",
		Arguments:   map[string]any{"intent_id": "int-001", "action": "deploy"},
		PrincipalID: "ve-devops-engineer",
		Metadata: map[string]string{
			"grpc.service":   "helm.v1.Governance",
			"grpc.method":    "Evaluate",
			"grpc.authority": "governance.helm.local",
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
	if node.Principal != "ve-devops-engineer" {
		t.Errorf("expected principal ve-devops-engineer, got %s", node.Principal)
	}
}

func TestGRPCAdapterInterceptWithoutMetadata(t *testing.T) {
	graph := proofgraph.NewGraph()
	adapter, err := NewGRPCAdapter(Config{Graph: graph})
	if err != nil {
		t.Fatal(err)
	}

	req := &runtimeadapters.AdaptedRequest{
		RuntimeType: "grpc",
		ToolName:    "/pkg.Service/SimpleMethod",
		Arguments:   map[string]any{"key": "value"},
		PrincipalID: "service-account-123",
	}

	resp, err := adapter.Intercept(context.Background(), req)
	if err != nil {
		t.Fatalf("intercept failed: %v", err)
	}
	if resp.ProofGraphNode == "" {
		t.Error("expected proof graph node hash")
	}
}

func TestGRPCAdapterRejectsNilRequest(t *testing.T) {
	graph := proofgraph.NewGraph()
	adapter, err := NewGRPCAdapter(Config{Graph: graph})
	if err != nil {
		t.Fatal(err)
	}

	_, err = adapter.Intercept(context.Background(), nil)
	if err == nil {
		t.Error("expected error for nil request")
	}
}

func TestGRPCAdapterRequiresGraph(t *testing.T) {
	_, err := NewGRPCAdapter(Config{})
	if err == nil {
		t.Error("expected error when Graph is nil")
	}
}

// Verify GRPCAdapter implements RuntimeAdapter interface.
var _ runtimeadapters.RuntimeAdapter = (*GRPCAdapter)(nil)
