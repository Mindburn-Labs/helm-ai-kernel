package github

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
			AllowedAction: "github.list_prs",
		},
		ExpiresAt: time.Now().Add(5 * time.Minute),
		SingleUse: true,
		Nonce:     "nonce-001",
		IssuedAt:  time.Now(),
		IssuerID:  "gateway-1",
	}
}

func TestNewConnector(t *testing.T) {
	c := NewConnector(Config{BaseURL: "https://api.github.com"})
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
	c := NewConnector(Config{BaseURL: "https://example.com", ConnectorID: "custom-github"})
	if c.ID() != "custom-github" {
		t.Fatalf("ID() = %q, want %q", c.ID(), "custom-github")
	}
}

func TestDispatch_AllTools(t *testing.T) {
	c := NewConnector(Config{BaseURL: "https://api.github.com"})
	ctx := context.Background()

	tests := []struct {
		tool   string
		params map[string]any
	}{
		{"github.list_prs", map[string]any{"repo": "owner/repo", "state": "open"}},
		{"github.read_pr", map[string]any{"repo": "owner/repo", "number": 42}},
		{"github.create_issue", map[string]any{"repo": "owner/repo", "title": "Bug", "body": "Description"}},
		{"github.add_comment", map[string]any{"repo": "owner/repo", "issue_number": 1, "body": "LGTM"}},
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
			if !strings.Contains(err.Error(), "not connected: requires personal access token") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestDispatch_UnknownTool(t *testing.T) {
	c := NewConnector(Config{BaseURL: "https://api.github.com"})
	ctx := context.Background()
	permit := validPermit()

	_, err := c.Execute(ctx, permit, "github.unknown_tool", map[string]any{})
	if err == nil {
		t.Fatal("expected error for unknown tool")
	}
	if !strings.Contains(err.Error(), "unknown tool") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecute_PermitConnectorIDMismatch(t *testing.T) {
	c := NewConnector(Config{BaseURL: "https://api.github.com"})
	ctx := context.Background()

	permit := validPermit()
	permit.ConnectorID = "wrong-connector"

	_, err := c.Execute(ctx, permit, "github.list_prs", map[string]any{"repo": "owner/repo"})
	if err == nil {
		t.Fatal("expected error for mismatched connector ID")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecute_GateEnforcesDataClass(t *testing.T) {
	c := NewConnector(Config{BaseURL: "https://api.github.com"})
	ctx := context.Background()

	// Reconfigure gate with a restricted policy that only allows PR reads
	c.gate.SetPolicy(&connector.TrustPolicy{
		ConnectorID:        ConnectorID,
		TrustLevel:         connector.TrustLevelVerified,
		MaxTTLSeconds:      3600,
		AllowedDataClasses: []string{"github.pr.list"},
		RateLimitPerMinute: 30,
	})

	permit := validPermit()
	_, err := c.Execute(ctx, permit, "github.create_issue", map[string]any{"repo": "owner/repo", "title": "Bug"})
	if err == nil {
		t.Fatal("expected gate denial for disallowed data class")
	}
	if !strings.Contains(err.Error(), "gate denied") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecute_GateEnforcesRateLimit(t *testing.T) {
	now := time.Now()
	c := NewConnector(Config{BaseURL: "https://api.github.com"})

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
		_, err := c.Execute(ctx, permit, "github.list_prs", map[string]any{"repo": "owner/repo"})
		if err == nil {
			t.Fatal("expected stub error")
		}
		if strings.Contains(err.Error(), "gate denied") {
			t.Fatalf("call %d should not be rate limited", i+1)
		}
	}

	// Third call should hit rate limit
	_, err := c.Execute(ctx, permit, "github.list_prs", map[string]any{"repo": "owner/repo"})
	if err == nil {
		t.Fatal("expected rate limit error")
	}
	if !strings.Contains(err.Error(), "gate denied") || !strings.Contains(err.Error(), "RATE_LIMIT") {
		t.Fatalf("expected rate limit error, got: %v", err)
	}
}

func TestExecute_ProofGraphNodes(t *testing.T) {
	c := NewConnector(Config{BaseURL: "https://api.github.com"})
	ctx := context.Background()
	permit := validPermit()

	// Execute will fail at client level but should still produce ProofGraph nodes
	_, _ = c.Execute(ctx, permit, "github.list_prs", map[string]any{"repo": "owner/repo"})

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
	c := NewConnector(Config{BaseURL: "https://api.github.com"})
	ctx := context.Background()
	permit := validPermit()

	// Execute three tool calls
	for i := 0; i < 3; i++ {
		_, _ = c.Execute(ctx, permit, "github.list_prs", map[string]any{"repo": "owner/repo"})
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
	c := NewConnector(Config{BaseURL: "https://api.github.com"})
	ctx := context.Background()
	permit := validPermit()

	tests := []struct {
		tool          string
		params        map[string]any
		expectContain string
	}{
		{"github.list_prs", map[string]any{}, "missing required param repo"},
		{"github.read_pr", map[string]any{}, "missing required param repo"},
		{"github.read_pr", map[string]any{"repo": "owner/repo"}, "missing required param number"},
		{"github.create_issue", map[string]any{}, "missing required param repo"},
		{"github.create_issue", map[string]any{"repo": "owner/repo"}, "missing required param title"},
		{"github.add_comment", map[string]any{}, "missing required param issue_number"},
		{"github.add_comment", map[string]any{"issue_number": 1}, "missing required param repo"},
		{"github.add_comment", map[string]any{"issue_number": 1, "repo": "owner/repo"}, "missing required param body"},
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
		"github.pr.list":     true,
		"github.pr.read":     true,
		"github.issue.create": true,
		"github.comment.add":  true,
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

func TestIntParam_Float64(t *testing.T) {
	// JSON numbers are decoded as float64
	params := map[string]any{"number": float64(42)}
	v, ok := intParam(params, "number")
	if !ok || v != 42 {
		t.Fatalf("intParam(float64) = (%d, %v), want (42, true)", v, ok)
	}
}

func TestIntParam_Int(t *testing.T) {
	params := map[string]any{"number": 42}
	v, ok := intParam(params, "number")
	if !ok || v != 42 {
		t.Fatalf("intParam(int) = (%d, %v), want (42, true)", v, ok)
	}
}

func TestIntParam_Missing(t *testing.T) {
	params := map[string]any{}
	_, ok := intParam(params, "number")
	if ok {
		t.Fatal("expected missing param")
	}
}

func TestStringSliceParam(t *testing.T) {
	// []any is the common case from JSON decode
	params := map[string]any{"labels": []any{"bug", "critical"}}
	result := stringSliceParam(params, "labels")
	if len(result) != 2 || result[0] != "bug" || result[1] != "critical" {
		t.Fatalf("stringSliceParam = %v, want [bug critical]", result)
	}
}

func TestStringSliceParam_Native(t *testing.T) {
	params := map[string]any{"labels": []string{"bug"}}
	result := stringSliceParam(params, "labels")
	if len(result) != 1 || result[0] != "bug" {
		t.Fatalf("stringSliceParam = %v, want [bug]", result)
	}
}

func TestStringSliceParam_Missing(t *testing.T) {
	params := map[string]any{}
	result := stringSliceParam(params, "labels")
	if result != nil {
		t.Fatalf("expected nil, got %v", result)
	}
}
