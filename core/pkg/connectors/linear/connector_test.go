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

func validPermit() *effects.EffectPermit {
	return permitFor("linear.create_issue", "nonce-001", allowedParamsForTool("linear.create_issue")...)
}

func permitFor(toolName, nonce string, allowedParams ...string) *effects.EffectPermit {
	effectType, ok := toolEffectTypeMap[toolName]
	if !ok {
		effectType = effects.EffectTypeRead
	}
	return &effects.EffectPermit{
		PermitID:    "permit-001",
		IntentHash:  "sha256:aaa",
		VerdictHash: "sha256:bbb",
		EffectType:  effectType,
		ConnectorID: ConnectorID,
		Scope: effects.EffectScope{
			AllowedAction: toolName,
			AllowedParams: allowedParams,
		},
		ExpiresAt: time.Now().Add(5 * time.Minute),
		SingleUse: true,
		Nonce:     nonce,
		IssuedAt:  time.Now(),
		IssuerID:  "gateway-1",
	}
}

func permitWithEffect(toolName, nonce string, effectType effects.EffectType, allowedParams ...string) *effects.EffectPermit {
	permit := permitFor(toolName, nonce, allowedParams...)
	permit.EffectType = effectType
	return permit
}

func expiredPermit(toolName, nonce string, allowedParams ...string) *effects.EffectPermit {
	permit := permitFor(toolName, nonce, allowedParams...)
	permit.IssuedAt = time.Now().Add(-10 * time.Minute)
	permit.ExpiresAt = time.Now().Add(-5 * time.Minute)
	return permit
}

func allowedParamsForTool(toolName string) []string {
	switch toolName {
	case "linear.create_issue":
		return []string{"team_id", "title", "description", "priority", "assignee_id", "label_ids"}
	case "linear.update_issue":
		return []string{"issue_id", "title", "description", "state", "priority", "assignee_id"}
	case "linear.get_issue":
		return []string{"issue_id"}
	case "linear.list_issues":
		return []string{"team_id", "state"}
	case "linear.add_comment":
		return []string{"issue_id", "body"}
	default:
		return nil
	}
}

func bindPermitResource(permit *effects.EffectPermit, params map[string]any) {
	if teamID, _ := params["team_id"].(string); teamID != "" {
		permit.ResourceRef = "team:" + teamID
		return
	}
	if issueID, _ := params["issue_id"].(string); issueID != "" {
		permit.ResourceRef = "issue:" + issueID
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
		{"linear.get_issue", map[string]any{"issue_id": "issue-1"}},
		{"linear.list_issues", map[string]any{"team_id": "team-1"}},
		{"linear.add_comment", map[string]any{"issue_id": "issue-1", "body": "Working on it"}},
	}

	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			permit := permitFor(tt.tool, "nonce-dispatch-"+tt.tool, allowedParamsForTool(tt.tool)...)
			bindPermitResource(permit, tt.params)

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
	params := map[string]any{"team_id": "t", "title": "x"}
	bindPermitResource(permit, params)
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

	// First two calls pass the gate (fail at client fake)
	for i := 0; i < 2; i++ {
		permit := permitFor("linear.list_issues", fmt.Sprintf("nonce-rate-%d", i), allowedParamsForTool("linear.list_issues")...)
		_, err := c.Execute(ctx, permit, "linear.list_issues", map[string]any{})
		if err == nil {
			t.Fatal("expected fake error")
		}
		if strings.Contains(err.Error(), "gate denied") {
			t.Fatalf("call %d should not be rate limited", i+1)
		}
	}

	// Third call should hit rate limit
	permit := permitFor("linear.list_issues", "nonce-rate-2", allowedParamsForTool("linear.list_issues")...)
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
	permit := permitFor("linear.list_issues", "nonce-proof", allowedParamsForTool("linear.list_issues")...)

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

	// Execute three tool calls
	for i := 0; i < 3; i++ {
		permit := permitFor("linear.list_issues", fmt.Sprintf("nonce-proof-%d", i), allowedParamsForTool("linear.list_issues")...)
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

	tests := []struct {
		tool          string
		params        map[string]any
		expectContain string
	}{
		{"linear.create_issue", map[string]any{}, "missing required param team_id"},
		{"linear.create_issue", map[string]any{"team_id": "t"}, "missing required param title"},
		{"linear.update_issue", map[string]any{}, "missing required param issue_id"},
		{"linear.get_issue", map[string]any{}, "missing required param issue_id"},
		{"linear.add_comment", map[string]any{}, "missing required param issue_id"},
		{"linear.add_comment", map[string]any{"issue_id": "i"}, "missing required param body"},
	}

	for _, tt := range tests {
		t.Run(tt.tool+"_"+tt.expectContain, func(t *testing.T) {
			permit := permitFor(tt.tool, "nonce-missing-"+tt.tool+"-"+tt.expectContain, allowedParamsForTool(tt.tool)...)
			bindPermitResource(permit, tt.params)
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
	permit := permitFor("linear.update_issue", "nonce-update-optional", allowedParamsForTool("linear.update_issue")...)
	params := map[string]any{
		"issue_id": "issue-123",
		"state":    "done",
	}
	bindPermitResource(permit, params)

	// Only issue_id + state, no other optional fields
	_, err := c.Execute(ctx, permit, "linear.update_issue", params)
	if err == nil {
		t.Fatal("expected fake error")
	}
	if !strings.Contains(err.Error(), "not connected: requires API key") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecute_DeniesPermitScopeBeforeLinearRequest(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Error(w, "unexpected request", http.StatusTeapot)
	}))
	defer server.Close()

	tests := []struct {
		name    string
		tool    string
		params  map[string]any
		permit  *effects.EffectPermit
		wantErr string
	}{
		{
			name:    "action mismatch",
			tool:    "linear.create_issue",
			params:  map[string]any{"team_id": "team-1", "title": "Bug"},
			permit:  permitFor("linear.list_issues", "nonce-scope-action", allowedParamsForTool("linear.list_issues")...),
			wantErr: "does not authorize",
		},
		{
			name:    "read permit cannot write",
			tool:    "linear.create_issue",
			params:  map[string]any{"team_id": "team-1", "title": "Bug"},
			permit:  permitWithEffect("linear.create_issue", "nonce-scope-effect", effects.EffectTypeRead, allowedParamsForTool("linear.create_issue")...),
			wantErr: "effect_type",
		},
		{
			name:    "expired permit",
			tool:    "linear.list_issues",
			params:  map[string]any{"team_id": "team-1"},
			permit:  expiredPermit("linear.list_issues", "nonce-scope-expired", allowedParamsForTool("linear.list_issues")...),
			wantErr: "expired",
		},
		{
			name:    "extra param outside scope",
			tool:    "linear.list_issues",
			params:  map[string]any{"team_id": "team-1", "state": "Todo"},
			permit:  permitFor("linear.list_issues", "nonce-scope-param", "team_id"),
			wantErr: "not authorized",
		},
		{
			name:    "write missing param scope",
			tool:    "linear.create_issue",
			params:  map[string]any{"team_id": "team-1", "title": "Bug"},
			permit:  permitFor("linear.create_issue", "nonce-scope-empty"),
			wantErr: "requires allowed_params",
		},
		{
			name:    "team resource mismatch",
			tool:    "linear.create_issue",
			params:  map[string]any{"team_id": "team-1", "title": "Bug"},
			permit:  permitFor("linear.create_issue", "nonce-scope-resource", allowedParamsForTool("linear.create_issue")...),
			wantErr: "resource_ref",
		},
		{
			name:   "team resource omitted",
			tool:   "linear.list_issues",
			params: map[string]any{"state": "Todo"},
			permit: func() *effects.EffectPermit {
				permit := permitFor("linear.list_issues", "nonce-scope-team-omitted", allowedParamsForTool("linear.list_issues")...)
				permit.ResourceRef = "team:team-1"
				return permit
			}(),
			wantErr: "requires team_id",
		},
		{
			name:   "issue resource omitted",
			tool:   "linear.get_issue",
			params: map[string]any{},
			permit: func() *effects.EffectPermit {
				permit := permitFor("linear.get_issue", "nonce-scope-issue-omitted", allowedParamsForTool("linear.get_issue")...)
				permit.ResourceRef = "linear:issue:issue-1"
				return permit
			}(),
			wantErr: "requires issue_id",
		},
		{
			name:    "exact param mismatch",
			tool:    "linear.add_comment",
			params:  map[string]any{"issue_id": "issue-1", "body": "LGTM"},
			permit:  permitFor("linear.add_comment", "nonce-scope-exact", "issue_id=issue-1", "body=Needs changes"),
			wantErr: "does not match permit scope",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requests = 0
			c := NewConnector(Config{BaseURL: server.URL, Token: "lin_api_test"})
			c.client.httpClient = server.Client()

			_, err := c.Execute(context.Background(), tt.permit, tt.tool, tt.params)
			if err == nil {
				t.Fatal("expected permit scope error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
			if requests != 0 {
				t.Fatalf("permit denial reached Linear server %d times", requests)
			}
		})
	}
}

func TestExecute_RejectsPermitNonceReplayBeforeLinearRequest(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"issues":{"nodes":[]}}}`))
	}))
	defer server.Close()

	c := NewConnector(Config{BaseURL: server.URL, Token: "lin_api_test"})
	c.client.httpClient = server.Client()
	now := time.Now()
	c.gate = connector.NewZeroTrustGate().WithClock(func() time.Time { return now })
	c.gate.SetPolicy(&connector.TrustPolicy{
		ConnectorID:        ConnectorID,
		TrustLevel:         connector.TrustLevelVerified,
		MaxTTLSeconds:      3600,
		AllowedDataClasses: AllowedDataClasses(),
		RateLimitPerMinute: 2,
	})
	permit := permitFor("linear.list_issues", "nonce-replay", allowedParamsForTool("linear.list_issues")...)
	params := map[string]any{"team_id": "team-1"}

	if _, err := c.Execute(context.Background(), permit, "linear.list_issues", params); err != nil {
		t.Fatalf("first execute should pass permit validation: %v", err)
	}
	if requests != 1 {
		t.Fatalf("first execute reached Linear server %d times, want 1", requests)
	}
	if _, err := c.Execute(context.Background(), permit, "linear.list_issues", params); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("expected replay denial, got %v", err)
	}
	if requests != 1 {
		t.Fatalf("replayed permit reached Linear server; requests=%d", requests)
	}

	// The replay must not consume the second rate-limit slot. A fresh permit
	// therefore still reaches Linear.
	freshPermit := permitFor("linear.list_issues", "nonce-replay-fresh", allowedParamsForTool("linear.list_issues")...)
	if _, err := c.Execute(context.Background(), freshPermit, "linear.list_issues", params); err != nil {
		t.Fatalf("fresh permit should pass the gate after replay denial: %v", err)
	}
	if requests != 2 {
		t.Fatalf("fresh permit reached Linear server %d times, want 2", requests)
	}
}

func TestExecute_GateDenialDoesNotConsumePermitNonce(t *testing.T) {
	c := NewConnector(Config{BaseURL: "https://api.linear.app"})
	permit := permitFor("linear.list_issues", "nonce-gate-denied", allowedParamsForTool("linear.list_issues")...)

	c.gate.SetPolicy(&connector.TrustPolicy{
		ConnectorID: ConnectorID,
		TrustLevel:  connector.TrustLevelUntrusted,
	})
	if _, err := c.Execute(context.Background(), permit, "linear.list_issues", nil); err == nil || !strings.Contains(err.Error(), "gate denied") {
		t.Fatalf("expected gate denial, got %v", err)
	}

	c.gate.SetPolicy(&connector.TrustPolicy{
		ConnectorID:        ConnectorID,
		TrustLevel:         connector.TrustLevelVerified,
		MaxTTLSeconds:      3600,
		AllowedDataClasses: AllowedDataClasses(),
		RateLimitPerMinute: 60,
	})
	if _, err := c.Execute(context.Background(), permit, "linear.list_issues", nil); err == nil || strings.Contains(err.Error(), "already used") {
		t.Fatalf("gate denial must not consume the permit nonce, got %v", err)
	}
}

func TestPermitNonceTrackerBoundsAndPrunesExpiredEntries(t *testing.T) {
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	c := NewConnector(Config{BaseURL: "https://api.linear.app"})
	c.now = func() time.Time { return now }
	expiresAt := now.Add(time.Minute)

	for i := 0; i < linearPermitNonceMaxEntries; i++ {
		if err := c.reservePermitNonce(fmt.Sprintf("nonce-bound-%d", i), expiresAt); err != nil {
			t.Fatalf("reserve nonce %d: %v", i, err)
		}
	}
	if err := c.reservePermitNonce("nonce-overflow", expiresAt); err == nil || !strings.Contains(err.Error(), "tracker is full") {
		t.Fatalf("expected bounded tracker rejection, got %v", err)
	}

	now = expiresAt
	if err := c.reservePermitNonce("nonce-after-expiry", now.Add(time.Minute)); err != nil {
		t.Fatalf("expired nonce entries should be pruned: %v", err)
	}
}
