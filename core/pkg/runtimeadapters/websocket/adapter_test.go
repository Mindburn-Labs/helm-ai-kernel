package websocket

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/runtimeadapters"
)

func TestWebSocketAdapterID(t *testing.T) {
	graph := proofgraph.NewGraph()
	adapter, err := NewWebSocketAdapter(Config{Graph: graph})
	if err != nil {
		t.Fatal(err)
	}
	if adapter.ID() != "websocket-adapter-v1" {
		t.Errorf("expected websocket-adapter-v1, got %s", adapter.ID())
	}
}

func TestWebSocketAdapterInterceptInbound(t *testing.T) {
	graph := proofgraph.NewGraph()
	adapter, err := NewWebSocketAdapter(Config{Graph: graph})
	if err != nil {
		t.Fatal(err)
	}

	req := &runtimeadapters.AdaptedRequest{
		RuntimeType: "websocket",
		ToolName:    "agent.tool_call",
		Arguments:   map[string]any{"tool": "file_write", "path": "/tmp/output.txt"},
		PrincipalID: "ve-code-assistant",
		Metadata: map[string]string{
			"ws.message_type":  "text",
			"ws.direction":     "inbound",
			"ws.connection_id": "conn-abc-123",
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
	if node.Principal != "ve-code-assistant" {
		t.Errorf("expected principal ve-code-assistant, got %s", node.Principal)
	}
}

func TestWebSocketAdapterInterceptOutbound(t *testing.T) {
	graph := proofgraph.NewGraph()
	adapter, err := NewWebSocketAdapter(Config{Graph: graph})
	if err != nil {
		t.Fatal(err)
	}

	req := &runtimeadapters.AdaptedRequest{
		RuntimeType: "websocket",
		ToolName:    "agent.response",
		Arguments:   map[string]any{"content": "Here is the result..."},
		PrincipalID: "ve-analyst",
		Metadata: map[string]string{
			"ws.message_type":  "text",
			"ws.direction":     "outbound",
			"ws.connection_id": "conn-xyz-789",
		},
	}

	resp, err := adapter.Intercept(context.Background(), req)
	if err != nil {
		t.Fatalf("intercept failed: %v", err)
	}
	if resp.ProofGraphNode == "" {
		t.Error("expected proof graph node hash")
	}
}

func TestWebSocketAdapterInterceptWithoutMetadata(t *testing.T) {
	graph := proofgraph.NewGraph()
	adapter, err := NewWebSocketAdapter(Config{Graph: graph})
	if err != nil {
		t.Fatal(err)
	}

	req := &runtimeadapters.AdaptedRequest{
		RuntimeType: "websocket",
		ToolName:    "chat.message",
		Arguments:   map[string]any{"text": "hello"},
		PrincipalID: "user-anon",
	}

	resp, err := adapter.Intercept(context.Background(), req)
	if err != nil {
		t.Fatalf("intercept failed: %v", err)
	}
	if resp.ProofGraphNode == "" {
		t.Error("expected proof graph node hash")
	}
}

func TestWebSocketAdapterRejectsNilRequest(t *testing.T) {
	graph := proofgraph.NewGraph()
	adapter, err := NewWebSocketAdapter(Config{Graph: graph})
	if err != nil {
		t.Fatal(err)
	}

	_, err = adapter.Intercept(context.Background(), nil)
	if err == nil {
		t.Error("expected error for nil request")
	}
}

func TestWebSocketAdapterRequiresGraph(t *testing.T) {
	_, err := NewWebSocketAdapter(Config{})
	if err == nil {
		t.Error("expected error when Graph is nil")
	}
}

// Verify WebSocketAdapter implements RuntimeAdapter interface.
var _ runtimeadapters.RuntimeAdapter = (*WebSocketAdapter)(nil)
