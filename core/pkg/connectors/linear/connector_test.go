package linear

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
		EffectType:  effects.EffectTypeWrite,
		ConnectorID: ConnectorID,
		Scope: effects.EffectScope{
			AllowedAction: "linear.create_issue",
		},
		ExpiresAt: time.Now().Add(5 * time.Minute),
		SingleUse: true,
		Nonce:     "nonce-001",
		IssuedAt:  time.Now(),
		IssuerID:  "gateway-1",
	}
}

func TestNewConnector(t *testing.T) {
	c := NewConnector(Config{BaseURL: "https://api.linear.app"})
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
	c := NewConnector(Config{BaseURL: "https://example.com", ConnectorID: "custom-linear"})
	if c.ID() != "custom-linear" {
		t.Fatalf("ID() = %q, want %q", c.ID(), "custom-linear")
	}
}

func TestDispatch_AllTools(t *testing.T) {
	c := NewConnector(Config{BaseURL: "https://api.linear.app"})
	ctx := context.Background()

	tests := []struct {
		tool   string
		params map[string]any
	}{
		{"linear.create_issue", map[string]any{"team_id": "team-1", "title": "Bug fix"}},
		{"linear.update_issue", map[string]any{"issue_id": "issue-1", "state": "done"}},
		{"linear.list_issues", map[string]any{"team_id": "team-1"}},
		{"linear.add_comment", map[string]any{"issue_id": "issue-1", "body": "Working on it"}},
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
			if !strings.Contains(err.Error(), "not connected: requires API key") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestDispatch_UnknownTool(t *testing.T) {
	c := NewConnector(Config{BaseURL: "https://api.linear.app"})
	ctx := context.Background()
	permit := validPermit()

	_, err := c.Execute(ctx, permit, "linear.unknown_tool", map[string]any{})
	if err == nil {
		t.Fatal("expected error for unknown tool")
	}
	if !strings.Contains(err.Error(), "unknown tool") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecute_PermitConnectorIDMismatch(t *testing.T) {
	c := NewConnector(Config{BaseURL: "https://api.linear.app"})
	ctx := context.Background()

	permit := validPermit()
	permit.ConnectorID = "wrong-connector"

	_, err := c.Execute(ctx, permit, "linear.create_issue", map[string]any{"team_id": "t", "title": "x"})
	if err == nil {
		t.Fatal("expected error for mismatched connector ID")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecute_GateEnforcesDataClass(t *testing.T) {
	c := NewConnector(Config{BaseURL: "https://api.linear.app"})
	ctx := context.Background()

	// Reconfigure gate with a restricted policy that only allows listing
	c.gate.SetPolicy(&connector.TrustPolicy{
		ConnectorID:        ConnectorID,
		TrustLevel:         connector.TrustLevelVerified,
		MaxTTLSeconds:      3600,
		AllowedDataClasses: []string{"linear.issue.list"},
		RateLimitPerMinute: 60,
	})

	permit := validPermit()
	_, err := c.Execute(ctx, permit, "linear.create_issue", map[string]any{"team_id": "t", "title": "x"})
	if err == nil {
		t.Fatal("expected gate denial for disallowed data class")
	}
	if !strings.Contains(err.Error(), "gate denied") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecute_GateEnforcesRateLimit(t *testing.T) {
	now := time.Now()
	c := NewConnector(Config{BaseURL: "https://api.linear.app"})

	// Override gate with a very low rate limit and fixed clock
	c.gate = connector.NewZeroTrustGate().WithClock(func() time.Time { return now })
	c.gate.SetPolicy(&connector.TrustPolicy{
		ConnectorID:        ConnectorID,
		TrustLevel:         connector.TrustLevelVerified,
		MaxTTLSeconds:      3600,
		AllowedDataClasses: AllowedDataClasses(),
		RateLimitPerMinute: 2,
	})

	ctx := context.Background()
	permit := validPermit()

	// First two calls pass the gate (fail at client stub)
	for i := 0; i < 2; i++ {
		_, err := c.Execute(ctx, permit, "linear.list_issues", map[string]any{})
		if err == nil {
			t.Fatal("expected stub error")
		}
		if strings.Contains(err.Error(), "gate denied") {
			t.Fatalf("call %d should not be rate limited", i+1)
		}
	}

	// Third call should hit rate limit
	_, err := c.Execute(ctx, permit, "linear.list_issues", map[string]any{})
	if err == nil {
		t.Fatal("expected rate limit error")
	}
	if !strings.Contains(err.Error(), "gate denied") || !strings.Contains(err.Error(), "RATE_LIMIT") {
		t.Fatalf("expected rate limit error, got: %v", err)
	}
}

func TestExecute_ProofGraphNodes(t *testing.T) {
	c := NewConnector(Config{BaseURL: "https://api.linear.app"})
	ctx := context.Background()
	permit := validPermit()

	// Execute will fail at client level but should still produce ProofGraph nodes
	_, _ = c.Execute(ctx, permit, "linear.list_issues", map[string]any{})

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
	c := NewConnector(Config{BaseURL: "https://api.linear.app"})
	ctx := context.Background()
	permit := validPermit()

	// Execute three tool calls
	for i := 0; i < 3; i++ {
		_, _ = c.Execute(ctx, permit, "linear.list_issues", map[string]any{})
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
	c := NewConnector(Config{BaseURL: "https://api.linear.app"})
	ctx := context.Background()
	permit := validPermit()

	tests := []struct {
		tool          string
		params        map[string]any
		expectContain string
	}{
		{"linear.create_issue", map[string]any{}, "missing required param team_id"},
		{"linear.create_issue", map[string]any{"team_id": "t"}, "missing required param title"},
		{"linear.update_issue", map[string]any{}, "missing required param issue_id"},
		{"linear.add_comment", map[string]any{}, "missing required param issue_id"},
		{"linear.add_comment", map[string]any{"issue_id": "i"}, "missing required param body"},
	}

	for _, tt := range tests {
		t.Run(tt.tool+"_"+tt.expectContain, func(t *testing.T) {
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
		"linear.issue.create":  true,
		"linear.issue.update":  true,
		"linear.issue.list":    true,
		"linear.comment.add":   true,
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

func TestStringSliceParam(t *testing.T) {
	// []any is the common case from JSON decode
	params := map[string]any{"label_ids": []any{"label-1", "label-2"}}
	result := stringSliceParam(params, "label_ids")
	if len(result) != 2 || result[0] != "label-1" || result[1] != "label-2" {
		t.Fatalf("stringSliceParam = %v, want [label-1 label-2]", result)
	}
}

func TestStringSliceParam_Native(t *testing.T) {
	params := map[string]any{"label_ids": []string{"label-1"}}
	result := stringSliceParam(params, "label_ids")
	if len(result) != 1 || result[0] != "label-1" {
		t.Fatalf("stringSliceParam = %v, want [label-1]", result)
	}
}

func TestStringSliceParam_Missing(t *testing.T) {
	params := map[string]any{}
	result := stringSliceParam(params, "label_ids")
	if result != nil {
		t.Fatalf("expected nil, got %v", result)
	}
}

func TestUpdateIssue_OptionalFields(t *testing.T) {
	c := NewConnector(Config{BaseURL: "https://api.linear.app"})
	ctx := context.Background()
	permit := validPermit()

	// Only issue_id + state, no other optional fields
	_, err := c.Execute(ctx, permit, "linear.update_issue", map[string]any{
		"issue_id": "issue-123",
		"state":    "done",
	})
	if err == nil {
		t.Fatal("expected stub error")
	}
	if !strings.Contains(err.Error(), "not connected: requires API key") {
		t.Fatalf("unexpected error: %v", err)
	}
}
