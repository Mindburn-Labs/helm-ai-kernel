package linear

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connector"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effects"
)

func permitTemplate(toolName, nonce string) *effects.EffectPermit {
	effectType, ok := toolEffectTypeMap[toolName]
	if !ok {
		effectType = effects.EffectTypeRead
	}
	now := time.Now().UTC()
	return &effects.EffectPermit{
		PermitID:    "permit-001",
		IntentHash:  "sha256:aaa",
		VerdictHash: "sha256:bbb",
		EffectType:  effectType,
		ConnectorID: ConnectorID,
		Scope: effects.EffectScope{
			AllowedAction: toolName,
		},
		ExpiresAt: now.Add(5 * time.Minute),
		SingleUse: true,
		Nonce:     nonce,
		IssuedAt:  now,
		IssuerID:  "gateway-1",
	}
}

func permitFor(t testing.TB, toolName, nonce string, params map[string]any) *effects.EffectPermit {
	t.Helper()
	c := NewConnector(Config{})
	effectType, scope, resourceRef, err := c.PermitScope(toolName, params)
	if err != nil {
		t.Fatalf("permit scope for %s: %v", toolName, err)
	}
	permit := permitTemplate(toolName, nonce)
	permit.EffectType = effectType
	permit.Scope = scope
	permit.ResourceRef = resourceRef
	return permit
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
		{"linear.get_issue", map[string]any{"issue_id": "issue-1"}},
		{"linear.list_issues", map[string]any{"team_id": "team-1"}},
		{"linear.add_comment", map[string]any{"issue_id": "issue-1", "body": "Working on it"}},
	}

	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			permit := permitFor(t, tt.tool, "nonce-dispatch-"+tt.tool, tt.params)

			_, err := c.Execute(ctx, permit, tt.tool, tt.params)
			// All calls should fail with "not connected" since client is a fake
			if err == nil {
				t.Fatal("expected error from fake client")
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
	permit := permitTemplate("linear.create_issue", "nonce-unknown")

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

	params := map[string]any{"team_id": "t", "title": "x"}
	permit := permitFor(t, "linear.create_issue", "nonce-connector-mismatch", params)
	permit.ConnectorID = "wrong-connector"

	_, err := c.Execute(ctx, permit, "linear.create_issue", params)
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

	params := map[string]any{"team_id": "t", "title": "x"}
	permit := permitFor(t, "linear.create_issue", "nonce-gate-class", params)
	_, err := c.Execute(ctx, permit, "linear.create_issue", params)
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
	params := map[string]any{"team_id": "team-1"}

	// First two calls pass the gate (fail at client fake)
	for i := 0; i < 2; i++ {
		permit := permitFor(t, "linear.list_issues", fmt.Sprintf("nonce-rate-%d", i), params)
		_, err := c.Execute(ctx, permit, "linear.list_issues", params)
		if err == nil {
			t.Fatal("expected fake error")
		}
		if strings.Contains(err.Error(), "gate denied") {
			t.Fatalf("call %d should not be rate limited", i+1)
		}
	}

	// Third call should hit rate limit
	permit := permitFor(t, "linear.list_issues", "nonce-rate-final", params)
	_, err := c.Execute(ctx, permit, "linear.list_issues", params)
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
	params := map[string]any{"team_id": "team-1"}
	permit := permitFor(t, "linear.list_issues", "nonce-proof", params)

	// Execute will fail at client level but should still produce ProofGraph nodes
	_, _ = c.Execute(ctx, permit, "linear.list_issues", params)

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
	params := map[string]any{"team_id": "team-1"}

	// Execute three tool calls
	for i := 0; i < 3; i++ {
		permit := permitFor(t, "linear.list_issues", fmt.Sprintf("nonce-proof-%d", i), params)
		_, _ = c.Execute(ctx, permit, "linear.list_issues", params)
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
	tests := []struct {
		tool          string
		params        map[string]any
		expectContain string
	}{
		{"linear.create_issue", map[string]any{}, "requires team_id"},
		{"linear.create_issue", map[string]any{"team_id": "t"}, "missing required param title"},
		{"linear.update_issue", map[string]any{}, "requires issue_id"},
		{"linear.get_issue", map[string]any{}, "requires issue_id"},
		{"linear.add_comment", map[string]any{}, "requires issue_id"},
		{"linear.add_comment", map[string]any{"issue_id": "i"}, "missing required param body"},
	}

	for _, tt := range tests {
		t.Run(tt.tool+"_"+tt.expectContain, func(t *testing.T) {
			permit := permitTemplate(tt.tool, "nonce-missing-"+tt.tool)
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
		"linear.issue.create": true,
		"linear.issue.update": true,
		"linear.issue.read":   true,
		"linear.issue.list":   true,
		"linear.comment.add":  true,
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
	// Only issue_id + state, no other optional fields
	params := map[string]any{
		"issue_id": "issue-123",
		"state":    "done",
	}
	permit := permitFor(t, "linear.update_issue", "nonce-update-optional", params)
	_, err := c.Execute(ctx, permit, "linear.update_issue", params)
	if err == nil {
		t.Fatal("expected fake error")
	}
	if !strings.Contains(err.Error(), "not connected: requires API key") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPermitScopeRejectsAmbiguousAndUnsupportedValues(t *testing.T) {
	c := NewConnector(Config{})
	params := map[string]any{"issue_id": "issue-1", "body": "line one\n"}
	permit := permitFor(t, "linear.add_comment", "nonce-scope-roundtrip", params)
	if err := c.validatePermit(permit, "linear.add_comment", effects.EffectTypeWrite, params); err != nil {
		t.Fatalf("connector rejected its own declared scope: %v", err)
	}
	if !strings.Contains(strings.Join(permit.Scope.AllowedParams, "\n"), `"type":"string"`) {
		t.Fatalf("scope does not retain a type tag: %#v", permit.Scope.AllowedParams)
	}

	keyOnly := permitFor(t, "linear.add_comment", "nonce-key-only", params)
	keyOnly.Scope.AllowedParams = []string{"issue_id"}
	if err := c.validatePermit(keyOnly, "linear.add_comment", effects.EffectTypeWrite, params); err == nil || !strings.Contains(err.Error(), "must bind an exact value") {
		t.Fatalf("expected key-only scope denial, got %v", err)
	}

	typed := permitFor(t, "linear.add_comment", "nonce-typed", map[string]any{"issue_id": "issue-1", "body": "true"})
	if err := c.validatePermit(typed, "linear.add_comment", effects.EffectTypeWrite, map[string]any{"issue_id": "issue-1", "body": true}); err == nil || !strings.Contains(err.Error(), "must be a string") {
		t.Fatalf("expected typed value denial, got %v", err)
	}

	if _, _, _, err := c.PermitScope("linear.create_issue", map[string]any{"team_id": "team-1", "title": "Ship", "label_ids_typo": []string{"x"}}); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("expected unsupported parameter denial, got %v", err)
	}
}

func TestPermitScopeRejectsInvalidExpiryOrderAndResource(t *testing.T) {
	c := NewConnector(Config{})
	params := map[string]any{"team_id": "team-1", "state": "Todo"}
	permit := permitFor(t, "linear.list_issues", "nonce-expiry", params)
	permit.ExpiresAt = permit.IssuedAt
	if err := c.validatePermit(permit, "linear.list_issues", effects.EffectTypeRead, params); err == nil || !strings.Contains(err.Error(), "after issued_at") {
		t.Fatalf("expected expiry-order denial, got %v", err)
	}

	permit = permitFor(t, "linear.list_issues", "nonce-resource", params)
	permit.ResourceRef = "team:other-team"
	if err := c.validatePermit(permit, "linear.list_issues", effects.EffectTypeRead, params); err == nil || !strings.Contains(err.Error(), "does not authorize") {
		t.Fatalf("expected resource denial, got %v", err)
	}
}

func TestExecuteRejectsReplayBeforeGateAndPrunesExpiredNonces(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"issues":{"nodes":[]}}}`))
	}))
	defer server.Close()

	now := time.Now().UTC()
	c := NewConnector(Config{BaseURL: server.URL, Token: "lin_api_test"})
	c.client.httpClient = server.Client()
	c.now = func() time.Time { return now }
	c.gate = connector.NewZeroTrustGate().WithClock(func() time.Time { return now })
	c.gate.SetPolicy(&connector.TrustPolicy{ConnectorID: ConnectorID, TrustLevel: connector.TrustLevelVerified, MaxTTLSeconds: 3600, AllowedDataClasses: AllowedDataClasses(), RateLimitPerMinute: 2})
	params := map[string]any{"team_id": "team-1"}
	permit := permitFor(t, "linear.list_issues", "nonce-replay", params)
	permit.IssuedAt = now.Add(-time.Second)
	permit.ExpiresAt = now.Add(time.Minute)

	if _, err := c.Execute(context.Background(), permit, "linear.list_issues", params); err != nil {
		t.Fatalf("first execute: %v", err)
	}
	if _, err := c.Execute(context.Background(), permit, "linear.list_issues", params); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("expected replay denial, got %v", err)
	}
	fresh := permitFor(t, "linear.list_issues", "nonce-fresh", params)
	fresh.IssuedAt = now.Add(-time.Second)
	fresh.ExpiresAt = now.Add(time.Minute)
	if _, err := c.Execute(context.Background(), fresh, "linear.list_issues", params); err != nil {
		t.Fatalf("fresh permit after replay: %v", err)
	}
	if requests != 2 {
		t.Fatalf("Linear requests = %d, want 2", requests)
	}

	for i := 0; i < 4097; i++ {
		if err := c.reservePermitNonce(fmt.Sprintf("nonce-burst-%d", i), now.Add(time.Second)); err != nil {
			t.Fatalf("expiry-bounded tracker rejected burst entry %d: %v", i, err)
		}
	}
	now = now.Add(time.Second)
	if err := c.reservePermitNonce("nonce-after-expiry", now.Add(time.Second)); err != nil {
		t.Fatalf("expired nonces were not pruned: %v", err)
	}
}

func TestExecuteGateDenialReleasesFreshPermit(t *testing.T) {
	c := NewConnector(Config{})
	params := map[string]any{"team_id": "team-1"}
	permit := permitFor(t, "linear.list_issues", "nonce-gate-release", params)

	c.gate.SetPolicy(&connector.TrustPolicy{ConnectorID: ConnectorID, TrustLevel: connector.TrustLevelUntrusted})
	if _, err := c.Execute(context.Background(), permit, "linear.list_issues", params); err == nil || !strings.Contains(err.Error(), "gate denied") {
		t.Fatalf("expected gate denial, got %v", err)
	}
	c.gate.SetPolicy(&connector.TrustPolicy{
		ConnectorID: ConnectorID, TrustLevel: connector.TrustLevelVerified, MaxTTLSeconds: 3600,
		AllowedDataClasses: AllowedDataClasses(), RateLimitPerMinute: 60,
	})
	if _, err := c.Execute(context.Background(), permit, "linear.list_issues", params); err == nil || strings.Contains(err.Error(), "already used") {
		t.Fatalf("gate denial consumed permit: %v", err)
	}
}
