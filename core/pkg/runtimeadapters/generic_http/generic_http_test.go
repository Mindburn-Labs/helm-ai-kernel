package generic_http

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/runtimeadapters"
)

func TestGenericHTTPAdapterIntercept(t *testing.T) {
	graph := proofgraph.NewGraph()
	adapter, err := NewGenericHTTPAdapter(Config{Graph: graph})
	if err != nil {
		t.Fatal(err)
	}

	if adapter.ID() != "generic-http-adapter-v1" {
		t.Errorf("expected generic-http-adapter-v1, got %s", adapter.ID())
	}

	req := &runtimeadapters.AdaptedRequest{
		RuntimeType: "http",
		ToolName:    "github.create_issue",
		Arguments:   map[string]any{"repo": "helm-oss", "title": "Bug report"},
		PrincipalID: "ve-recruiter",
	}

	resp, err := adapter.Intercept(context.Background(), req)
	if err != nil {
		t.Fatalf("intercept failed: %v", err)
	}

	if resp.ProofGraphNode == "" {
		t.Error("expected proof graph node hash")
	}

	node, ok := graph.Get(resp.ProofGraphNode)
	if !ok {
		t.Fatal("proof node not found")
	}
	if node.Kind != proofgraph.NodeTypeIntent {
		t.Errorf("expected INTENT, got %s", node.Kind)
	}
}

var _ runtimeadapters.RuntimeAdapter = (*GenericHTTPAdapter)(nil)
