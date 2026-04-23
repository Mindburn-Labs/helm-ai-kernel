package slack

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/effects"
)

func TestNewConnector_DefaultID(t *testing.T) {
	c := NewConnector(Config{})
	if c.ID() != "slack-v1" {
		t.Errorf("ID() = %q, want %q", c.ID(), "slack-v1")
	}
}

func TestNewConnector_CustomID(t *testing.T) {
	c := NewConnector(Config{ConnectorID: "slack-custom"})
	if c.ID() != "slack-custom" {
		t.Errorf("ID() = %q, want %q", c.ID(), "slack-custom")
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

func TestExecute_SendMessage_DispatchesToSendPath(t *testing.T) {
	c := NewConnector(Config{})
	ctx := context.Background()
	permit := &effects.EffectPermit{}

	_, err := c.Execute(ctx, permit, "slack.send_message", map[string]any{
		"channel_id": "C123",
		"text":       "Hello",
	})
	if err == nil {
		t.Fatal("expected error from fake client")
	}

	if c.Graph().Len() < 1 {
		t.Error("expected at least 1 INTENT node in graph")
	}
}

func TestExecute_ReadChannel_DispatchesToReadPath(t *testing.T) {
	c := NewConnector(Config{})
	ctx := context.Background()
	permit := &effects.EffectPermit{}

	_, err := c.Execute(ctx, permit, "slack.read_channel", map[string]any{
		"channel_id": "C123",
	})
	if err == nil {
		t.Fatal("expected error from fake client")
	}

	if c.Graph().Len() < 1 {
		t.Error("expected at least 1 INTENT node in graph")
	}
}

func TestExecute_ListChannels_DispatchesToListPath(t *testing.T) {
	c := NewConnector(Config{})
	ctx := context.Background()
	permit := &effects.EffectPermit{}

	_, err := c.Execute(ctx, permit, "slack.list_channels", map[string]any{})
	if err == nil {
		t.Fatal("expected error from fake client")
	}

	if c.Graph().Len() < 1 {
		t.Error("expected at least 1 INTENT node in graph")
	}
}

func TestExecute_UpdateMessage_DispatchesToUpdatePath(t *testing.T) {
	c := NewConnector(Config{})
	ctx := context.Background()
	permit := &effects.EffectPermit{}

	_, err := c.Execute(ctx, permit, "slack.update_message", map[string]any{
		"channel_id": "C123",
		"message_ts": "1234567890.123456",
		"text":       "Updated text",
	})
	if err == nil {
		t.Fatal("expected error from fake client")
	}

	if c.Graph().Len() < 1 {
		t.Error("expected at least 1 INTENT node in graph")
	}
}

func TestExecute_UnknownTool_ReturnsError(t *testing.T) {
	c := NewConnector(Config{})
	ctx := context.Background()
	permit := &effects.EffectPermit{}

	_, err := c.Execute(ctx, permit, "slack.unknown_tool", map[string]any{})
	if err == nil {
		t.Fatal("expected error for unknown tool")
	}
	expected := `slack: unknown tool "slack.unknown_tool"`
	if err.Error() != expected {
		t.Errorf("error = %q, want %q", err.Error(), expected)
	}
}

func TestExecute_GateBlocksOnRateLimit(t *testing.T) {
	c := NewConnector(Config{})
	ctx := context.Background()
	permit := &effects.EffectPermit{}

	// Exhaust the rate limit (120/min for slack)
	for i := 0; i < 120; i++ {
		_, _ = c.Execute(ctx, permit, "slack.send_message", map[string]any{
			"channel_id": "C123",
			"text":       "Hello",
		})
	}

	// 121st call should be rate limited
	_, err := c.Execute(ctx, permit, "slack.send_message", map[string]any{
		"channel_id": "C123",
		"text":       "Hello",
	})
	if err == nil {
		t.Fatal("expected rate limit error")
	}
	if !containsStr(err.Error(), "gate denied") {
		t.Errorf("expected gate denied error, got: %v", err)
	}
}

func TestExecute_IntentAndEffectNodes(t *testing.T) {
	c := NewConnector(Config{})
	ctx := context.Background()
	permit := &effects.EffectPermit{}

	_, _ = c.Execute(ctx, permit, "slack.send_message", map[string]any{
		"channel_id": "C123",
		"text":       "Test",
	})

	nodes := c.Graph().AllNodes()
	if len(nodes) == 0 {
		t.Fatal("expected at least one node in proof graph")
	}

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
		"slack.message.send":   true,
		"slack.message.read":   true,
		"slack.channel.list":   true,
		"slack.message.update": true,
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
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
