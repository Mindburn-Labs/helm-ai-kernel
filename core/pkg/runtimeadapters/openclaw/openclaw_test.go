package openclaw

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/runtimeadapters"
)

func TestOpenClawAdapterIntercept(t *testing.T) {
	graph := proofgraph.NewGraph()
	adapter, err := NewOpenClawAdapter(Config{Graph: graph})
	if err != nil {
		t.Fatal(err)
	}

	if adapter.ID() != "openclaw-adapter-v1" {
		t.Errorf("expected openclaw-adapter-v1, got %s", adapter.ID())
	}

	req := &runtimeadapters.AdaptedRequest{
		RuntimeType: "openclaw",
		ToolName:    "slack.send_message",
		Arguments:   map[string]any{"channel": "#general", "text": "hello"},
		PrincipalID: "ve-customer-success",
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

var _ runtimeadapters.RuntimeAdapter = (*OpenClawAdapter)(nil)
