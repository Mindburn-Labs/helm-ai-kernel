package gdocs_drive

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/connector"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/effects"
)

func validPermit() *effects.EffectPermit {
	return &effects.EffectPermit{
		PermitID:    "permit-001",
		IntentHash:  "sha256:aaa",
		VerdictHash: "sha256:bbb",
		EffectType:  effects.EffectTypeRead,
		ConnectorID: ConnectorID,
		Scope: effects.EffectScope{
			AllowedAction: "gdocs.read_document",
		},
		ExpiresAt: time.Now().Add(5 * time.Minute),
		SingleUse: true,
		Nonce:     "nonce-001",
		IssuedAt:  time.Now(),
		IssuerID:  "gateway-1",
	}
}

func TestNewConnector(t *testing.T) {
	c := NewConnector(Config{BaseURL: "https://docs.googleapis.com"})
	if c.ID() != ConnectorID {
		t.Fatalf("ID() = %q, want %q", c.ID(), ConnectorID)
	}
	if c.graph == nil {
		t.Fatal("ProofGraph not initialized")
	}
	if c.gate == nil {
		t.Fatal("ZeroTrust gate not initialized")
	}
	if c.Graph().Len() != 0 {
		t.Fatalf("fresh graph should be empty, got %d nodes", c.Graph().Len())
	}
}

func TestNewConnector_CustomID(t *testing.T) {
	c := NewConnector(Config{BaseURL: "https://example.com", ConnectorID: "custom-gdocs"})
	if c.ID() != "custom-gdocs" {
		t.Fatalf("ID() = %q, want %q", c.ID(), "custom-gdocs")
	}
}

func TestDispatch_AllTools(t *testing.T) {
	c := NewConnector(Config{BaseURL: "https://docs.googleapis.com"})
	ctx := context.Background()

	tests := []struct {
		tool   string
		params map[string]any
	}{
		{"gdocs.read_document", map[string]any{"document_id": "doc-1"}},
		{"gdocs.create_document", map[string]any{"title": "Test", "body": "Hello"}},
		{"gdocs.append_to_document", map[string]any{"document_id": "doc-1", "content": "more"}},
		{"gdrive.list_files", map[string]any{}},
		{"gdrive.get_file", map[string]any{"file_id": "file-1"}},
	}

	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			permit := validPermit()
			permit.Scope.AllowedAction = tt.tool

			_, err := c.Execute(ctx, permit, tt.tool, tt.params)
			// All calls should fail with "not connected" since client is a stub
			if err == nil {
				t.Fatal("expected error from stub client")
			}
			if !strings.Contains(err.Error(), "not connected: requires OAuth2 credentials") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestDispatch_UnknownTool(t *testing.T) {
	c := NewConnector(Config{BaseURL: "https://docs.googleapis.com"})
	ctx := context.Background()
	permit := validPermit()

	_, err := c.Execute(ctx, permit, "gdocs.unknown_tool", map[string]any{})
	if err == nil {
		t.Fatal("expected error for unknown tool")
	}
	if !strings.Contains(err.Error(), "unknown tool") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecute_PermitConnectorIDMismatch(t *testing.T) {
	c := NewConnector(Config{BaseURL: "https://docs.googleapis.com"})
	ctx := context.Background()

	permit := validPermit()
	permit.ConnectorID = "wrong-connector"

	_, err := c.Execute(ctx, permit, "gdocs.read_document", map[string]any{"document_id": "doc-1"})
	if err == nil {
		t.Fatal("expected error for mismatched connector ID")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecute_GateEnforcesDataClass(t *testing.T) {
	c := NewConnector(Config{BaseURL: "https://docs.googleapis.com"})
	ctx := context.Background()

	// Reconfigure gate with a restricted policy that only allows reads
	c.gate.SetPolicy(&restrictedPolicy)

	permit := validPermit()
	_, err := c.Execute(ctx, permit, "gdocs.create_document", map[string]any{"title": "Test"})
	if err == nil {
		t.Fatal("expected gate denial for disallowed data class")
	}
	if !strings.Contains(err.Error(), "gate denied") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecute_GateEnforcesRateLimit(t *testing.T) {
	now := time.Now()
	c := NewConnector(Config{BaseURL: "https://docs.googleapis.com"})

	// Override gate with a very low rate limit and fixed clock
	c.gate = newTestGateWithRateLimit(c.connectorID, 2, now)

	ctx := context.Background()
	permit := validPermit()

	// First two calls pass the gate (fail at client stub)
	for i := 0; i < 2; i++ {
		_, err := c.Execute(ctx, permit, "gdocs.read_document", map[string]any{"document_id": "doc-1"})
		if err == nil {
			t.Fatal("expected stub error")
		}
		if strings.Contains(err.Error(), "gate denied") {
			t.Fatalf("call %d should not be rate limited", i+1)
		}
	}

	// Third call should hit rate limit
	_, err := c.Execute(ctx, permit, "gdocs.read_document", map[string]any{"document_id": "doc-1"})
	if err == nil {
		t.Fatal("expected rate limit error")
	}
	if !strings.Contains(err.Error(), "gate denied") || !strings.Contains(err.Error(), "RATE_LIMIT") {
		t.Fatalf("expected rate limit error, got: %v", err)
	}
}

func TestExecute_ProofGraphNodes(t *testing.T) {
	c := NewConnector(Config{BaseURL: "https://docs.googleapis.com"})
	ctx := context.Background()
	permit := validPermit()

	// Execute will fail at client level but should still produce ProofGraph nodes
	_, _ = c.Execute(ctx, permit, "gdocs.read_document", map[string]any{"document_id": "doc-1"})

	// Should have 2 nodes: INTENT + EFFECT
	if c.Graph().Len() != 2 {
		t.Fatalf("expected 2 ProofGraph nodes, got %d", c.Graph().Len())
	}

	// Validate the chain integrity
	heads := c.Graph().Heads()
	if len(heads) != 1 {
		t.Fatalf("expected 1 head, got %d", len(heads))
	}
	if err := c.Graph().ValidateChain(heads[0]); err != nil {
		t.Fatalf("chain validation failed: %v", err)
	}
}

func TestExecute_ProofGraphMultipleCalls(t *testing.T) {
	c := NewConnector(Config{BaseURL: "https://docs.googleapis.com"})
	ctx := context.Background()
	permit := validPermit()

	// Execute three tool calls
	for i := 0; i < 3; i++ {
		_, _ = c.Execute(ctx, permit, "gdocs.read_document", map[string]any{"document_id": "doc-1"})
	}

	// Should have 6 nodes: 3 INTENT + 3 EFFECT
	if c.Graph().Len() != 6 {
		t.Fatalf("expected 6 ProofGraph nodes, got %d", c.Graph().Len())
	}

	// Validate the chain integrity
	heads := c.Graph().Heads()
	if len(heads) != 1 {
		t.Fatalf("expected 1 head, got %d", len(heads))
	}
	if err := c.Graph().ValidateChain(heads[0]); err != nil {
		t.Fatalf("chain validation failed: %v", err)
	}
}

func TestDispatch_MissingRequiredParams(t *testing.T) {
	c := NewConnector(Config{BaseURL: "https://docs.googleapis.com"})
	ctx := context.Background()
	permit := validPermit()

	tests := []struct {
		tool          string
		params        map[string]any
		expectContain string
	}{
		{"gdocs.read_document", map[string]any{}, "missing required param document_id"},
		{"gdocs.create_document", map[string]any{}, "missing required param title"},
		{"gdocs.append_to_document", map[string]any{}, "missing required param document_id"},
		{"gdrive.get_file", map[string]any{}, "missing required param file_id"},
	}

	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			_, err := c.Execute(ctx, permit, tt.tool, tt.params)
			if err == nil {
				t.Fatal("expected error for missing params")
			}
			if !strings.Contains(err.Error(), tt.expectContain) {
				t.Fatalf("expected error containing %q, got: %v", tt.expectContain, err)
			}
		})
	}
}

func TestAllowedDataClasses(t *testing.T) {
	classes := AllowedDataClasses()
	expected := map[string]bool{
		"gdocs.document.read":   true,
		"gdocs.document.create": true,
		"gdocs.document.append": true,
		"gdrive.file.list":      true,
		"gdrive.file.get":       true,
	}
	if len(classes) != len(expected) {
		t.Fatalf("got %d data classes, want %d", len(classes), len(expected))
	}
	for _, c := range classes {
		if !expected[c] {
			t.Errorf("unexpected data class: %s", c)
		}
	}
}

// --- test helpers ---

var restrictedPolicy = connector.TrustPolicy{
	ConnectorID:        ConnectorID,
	TrustLevel:         connector.TrustLevelVerified,
	MaxTTLSeconds:      3600,
	AllowedDataClasses: []string{"gdocs.document.read"},
	RateLimitPerMinute: 60,
}

func newTestGateWithRateLimit(connectorID string, rateLimit int, fixedNow time.Time) *connector.ZeroTrustGate {
	gate := connector.NewZeroTrustGate().WithClock(func() time.Time { return fixedNow })
	gate.SetPolicy(&connector.TrustPolicy{
		ConnectorID:        connectorID,
		TrustLevel:         connector.TrustLevelVerified,
		MaxTTLSeconds:      3600,
		AllowedDataClasses: AllowedDataClasses(),
		RateLimitPerMinute: rateLimit,
	})
	return gate
}
