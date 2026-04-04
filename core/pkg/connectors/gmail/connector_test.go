package gmail

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/effects"
)

func TestNewConnector_DefaultID(t *testing.T) {
	c := NewConnector(Config{})
	if c.ID() != "gmail-v1" {
		t.Errorf("ID() = %q, want %q", c.ID(), "gmail-v1")
	}
}

func TestNewConnector_CustomID(t *testing.T) {
	c := NewConnector(Config{ConnectorID: "gmail-custom"})
	if c.ID() != "gmail-custom" {
		t.Errorf("ID() = %q, want %q", c.ID(), "gmail-custom")
	}
}

func TestNewConnector_GateInitialized(t *testing.T) {
	c := NewConnector(Config{})
	if c.gate == nil {
		t.Fatal("ZeroTrust gate not initialized")
	}
}

func TestNewConnector_GraphInitialized(t *testing.T) {
	c := NewConnector(Config{})
	g := c.Graph()
	if g == nil {
		t.Fatal("ProofGraph not initialized")
	}
	if g.Len() != 0 {
		t.Errorf("fresh graph should be empty, got %d nodes", g.Len())
	}
}

func TestExecute_Send_DispatchesToSendPath(t *testing.T) {
	c := NewConnector(Config{BaseURL: "http://localhost:0"})
	ctx := context.Background()
	permit := &effects.EffectPermit{}

	// The client is a stub, so it will return an error, but the test verifies
	// that the correct code path is taken (gate check passes, intent node created).
	_, err := c.Execute(ctx, permit, "gmail.send", map[string]any{
		"to":      []any{"test@example.com"},
		"subject": "Test",
		"body":    "Hello",
	})
	if err == nil {
		t.Fatal("expected error from stub client")
	}

	// Verify INTENT node was created before the client error
	if c.Graph().Len() < 1 {
		t.Error("expected at least 1 INTENT node in graph")
	}
}

func TestExecute_ReadThread_DispatchesToReadPath(t *testing.T) {
	c := NewConnector(Config{BaseURL: "http://localhost:0"})
	ctx := context.Background()
	permit := &effects.EffectPermit{}

	_, err := c.Execute(ctx, permit, "gmail.read_thread", map[string]any{
		"thread_id": "thread-123",
	})
	if err == nil {
		t.Fatal("expected error from stub client")
	}

	if c.Graph().Len() < 1 {
		t.Error("expected at least 1 INTENT node in graph")
	}
}

func TestExecute_ListThreads_DispatchesToListPath(t *testing.T) {
	c := NewConnector(Config{BaseURL: "http://localhost:0"})
	ctx := context.Background()
	permit := &effects.EffectPermit{}

	_, err := c.Execute(ctx, permit, "gmail.list_threads", map[string]any{
		"query":       "is:unread",
		"max_results": 10,
	})
	if err == nil {
		t.Fatal("expected error from stub client")
	}

	if c.Graph().Len() < 1 {
		t.Error("expected at least 1 INTENT node in graph")
	}
}

func TestExecute_CreateDraft_DispatchesToDraftPath(t *testing.T) {
	c := NewConnector(Config{BaseURL: "http://localhost:0"})
	ctx := context.Background()
	permit := &effects.EffectPermit{}

	_, err := c.Execute(ctx, permit, "gmail.create_draft", map[string]any{
		"to":      []any{"test@example.com"},
		"subject": "Draft",
		"body":    "Draft body",
	})
	if err == nil {
		t.Fatal("expected error from stub client")
	}

	if c.Graph().Len() < 1 {
		t.Error("expected at least 1 INTENT node in graph")
	}
}

func TestExecute_UnknownTool_ReturnsError(t *testing.T) {
	c := NewConnector(Config{})
	ctx := context.Background()
	permit := &effects.EffectPermit{}

	_, err := c.Execute(ctx, permit, "gmail.unknown_tool", map[string]any{})
	if err == nil {
		t.Fatal("expected error for unknown tool")
	}
	expected := `gmail: unknown tool "gmail.unknown_tool"`
	if err.Error() != expected {
		t.Errorf("error = %q, want %q", err.Error(), expected)
	}
}

func TestExecute_GateBlocksOnRateLimit(t *testing.T) {
	c := NewConnector(Config{})
	ctx := context.Background()
	permit := &effects.EffectPermit{}

	// Exhaust the rate limit (60/min for gmail)
	for i := 0; i < 60; i++ {
		_, _ = c.Execute(ctx, permit, "gmail.send", map[string]any{
			"to":      []any{"test@example.com"},
			"subject": "Test",
			"body":    "Hello",
		})
	}

	// 61st call should be rate limited
	_, err := c.Execute(ctx, permit, "gmail.send", map[string]any{
		"to":      []any{"test@example.com"},
		"subject": "Test",
		"body":    "Hello",
	})
	if err == nil {
		t.Fatal("expected rate limit error")
	}
	if err.Error() == `gmail: unknown tool "gmail.send"` {
		t.Fatal("wrong error type - should be gate denial, not unknown tool")
	}
	// The error should contain "gate denied" and "RATE_LIMIT"
	if !containsStr(err.Error(), "gate denied") {
		t.Errorf("expected gate denied error, got: %v", err)
	}
}

func TestExecute_IntentAndEffectNodes(t *testing.T) {
	// This test verifies that on a tool call, at least one INTENT node is created.
	// Since the stub client returns an error, the EFFECT node won't be created,
	// but the INTENT node should be.
	c := NewConnector(Config{BaseURL: "http://localhost:0"})
	ctx := context.Background()
	permit := &effects.EffectPermit{}

	_, _ = c.Execute(ctx, permit, "gmail.send", map[string]any{
		"to":      []any{"user@test.com"},
		"subject": "Test",
		"body":    "Body",
	})

	nodes := c.Graph().AllNodes()
	if len(nodes) == 0 {
		t.Fatal("expected at least one node in proof graph")
	}

	// Verify the node is an INTENT node
	foundIntent := false
	for _, n := range nodes {
		if n.Kind == "INTENT" {
			foundIntent = true
			break
		}
	}
	if !foundIntent {
		t.Error("expected to find an INTENT node in the proof graph")
	}
}

func TestAllowedDataClasses(t *testing.T) {
	classes := AllowedDataClasses()
	expected := map[string]bool{
		"gmail.send.outbound":  true,
		"gmail.read.inbound":   true,
		"gmail.draft.internal": true,
		"gmail.list.inbound":   true,
	}
	if len(classes) != len(expected) {
		t.Fatalf("got %d data classes, want %d", len(classes), len(expected))
	}
	for _, dc := range classes {
		if !expected[dc] {
			t.Errorf("unexpected data class: %s", dc)
		}
	}
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && searchStr(s, substr)
}

func searchStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
