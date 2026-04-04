package gcalendar

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/effects"
)

func TestNewConnector_DefaultID(t *testing.T) {
	c := NewConnector(Config{})
	if c.ID() != "gcalendar-v1" {
		t.Errorf("ID() = %q, want %q", c.ID(), "gcalendar-v1")
	}
}

func TestNewConnector_CustomID(t *testing.T) {
	c := NewConnector(Config{ConnectorID: "gcalendar-custom"})
	if c.ID() != "gcalendar-custom" {
		t.Errorf("ID() = %q, want %q", c.ID(), "gcalendar-custom")
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

func TestExecute_CreateEvent_DispatchesToCreatePath(t *testing.T) {
	c := NewConnector(Config{BaseURL: "http://localhost:0"})
	ctx := context.Background()
	permit := &effects.EffectPermit{}

	_, err := c.Execute(ctx, permit, "gcalendar.create_event", map[string]any{
		"title":       "Team Meeting",
		"description": "Weekly sync",
		"start_time":  "2026-04-04T10:00:00Z",
		"end_time":    "2026-04-04T11:00:00Z",
	})
	if err == nil {
		t.Fatal("expected error from stub client")
	}

	if c.Graph().Len() < 1 {
		t.Error("expected at least 1 INTENT node in graph")
	}
}

func TestExecute_ReadAvailability_DispatchesToReadPath(t *testing.T) {
	c := NewConnector(Config{BaseURL: "http://localhost:0"})
	ctx := context.Background()
	permit := &effects.EffectPermit{}

	_, err := c.Execute(ctx, permit, "gcalendar.read_availability", map[string]any{
		"start_time": "2026-04-04T09:00:00Z",
		"end_time":   "2026-04-04T17:00:00Z",
	})
	if err == nil {
		t.Fatal("expected error from stub client")
	}

	if c.Graph().Len() < 1 {
		t.Error("expected at least 1 INTENT node in graph")
	}
}

func TestExecute_UpdateEvent_DispatchesToUpdatePath(t *testing.T) {
	c := NewConnector(Config{BaseURL: "http://localhost:0"})
	ctx := context.Background()
	permit := &effects.EffectPermit{}

	_, err := c.Execute(ctx, permit, "gcalendar.update_event", map[string]any{
		"event_id": "evt-123",
		"title":    "Updated Meeting",
	})
	if err == nil {
		t.Fatal("expected error from stub client")
	}

	if c.Graph().Len() < 1 {
		t.Error("expected at least 1 INTENT node in graph")
	}
}

func TestExecute_ListEvents_DispatchesToListPath(t *testing.T) {
	c := NewConnector(Config{BaseURL: "http://localhost:0"})
	ctx := context.Background()
	permit := &effects.EffectPermit{}

	_, err := c.Execute(ctx, permit, "gcalendar.list_events", map[string]any{
		"start_time":  "2026-04-04T00:00:00Z",
		"end_time":    "2026-04-04T23:59:59Z",
		"max_results": 10,
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

	_, err := c.Execute(ctx, permit, "gcalendar.unknown_tool", map[string]any{})
	if err == nil {
		t.Fatal("expected error for unknown tool")
	}
	expected := `gcalendar: unknown tool "gcalendar.unknown_tool"`
	if err.Error() != expected {
		t.Errorf("error = %q, want %q", err.Error(), expected)
	}
}

func TestExecute_GateBlocksOnRateLimit(t *testing.T) {
	c := NewConnector(Config{})
	ctx := context.Background()
	permit := &effects.EffectPermit{}

	// Exhaust the rate limit (60/min for gcalendar)
	for i := 0; i < 60; i++ {
		_, _ = c.Execute(ctx, permit, "gcalendar.create_event", map[string]any{
			"title":      "Event",
			"start_time": "2026-04-04T10:00:00Z",
			"end_time":   "2026-04-04T11:00:00Z",
		})
	}

	// 61st call should be rate limited
	_, err := c.Execute(ctx, permit, "gcalendar.create_event", map[string]any{
		"title":      "Event",
		"start_time": "2026-04-04T10:00:00Z",
		"end_time":   "2026-04-04T11:00:00Z",
	})
	if err == nil {
		t.Fatal("expected rate limit error")
	}
	if !containsStr(err.Error(), "gate denied") {
		t.Errorf("expected gate denied error, got: %v", err)
	}
}

func TestExecute_IntentAndEffectNodes(t *testing.T) {
	c := NewConnector(Config{BaseURL: "http://localhost:0"})
	ctx := context.Background()
	permit := &effects.EffectPermit{}

	_, _ = c.Execute(ctx, permit, "gcalendar.create_event", map[string]any{
		"title":      "Test Event",
		"start_time": "2026-04-04T10:00:00Z",
		"end_time":   "2026-04-04T11:00:00Z",
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
		"gcalendar.event.create":      true,
		"gcalendar.event.read":        true,
		"gcalendar.event.update":      true,
		"gcalendar.availability.read": true,
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
