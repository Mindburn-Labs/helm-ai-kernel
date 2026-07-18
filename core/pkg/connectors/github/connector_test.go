package github

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connector"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effects"
)

type recordingExecutionLifecycle struct {
	mu     sync.Mutex
	states []string
	meta   []effects.ExecutionLifecycleMeta
}

func (r *recordingExecutionLifecycle) append(state string, meta effects.ExecutionLifecycleMeta) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.states = append(r.states, state)
	r.meta = append(r.meta, meta)
	return nil
}

func (r *recordingExecutionLifecycle) MarkStarted(_ context.Context, meta effects.ExecutionLifecycleMeta) error {
	return r.append("STARTED", meta)
}

func (r *recordingExecutionLifecycle) MarkNotStarted(_ context.Context, meta effects.ExecutionLifecycleMeta) error {
	return r.append("NOT_STARTED", meta)
}

func (r *recordingExecutionLifecycle) MarkUncertain(_ context.Context, meta effects.ExecutionLifecycleMeta) error {
	return r.append("UNCERTAIN", meta)
}

func (r *recordingExecutionLifecycle) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.states...)
}

func validPermit() *effects.EffectPermit {
	return permitFor("github.list_prs", "nonce-001", allowedParamsForTool("github.list_prs")...)
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
		ResourceRef: "owner/repo",
		ExpiresAt:   time.Now().Add(5 * time.Minute),
		SingleUse:   true,
		Nonce:       nonce,
		IssuedAt:    time.Now(),
		IssuerID:    "gateway-1",
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

func permitForOtherRepo(toolName, nonce string, allowedParams ...string) *effects.EffectPermit {
	permit := permitFor(toolName, nonce, allowedParams...)
	permit.ResourceRef = "other/repo"
	return permit
}

func allowedParamsForTool(toolName string) []string {
	switch toolName {
	case "github.list_prs":
		return []string{"repo", "state"}
	case "github.read_pr":
		return []string{"repo", "number"}
	case "github.create_issue":
		return []string{"repo", "title", "body", "labels", "assignees"}
	case "github.add_comment":
		return []string{"repo", "issue_number", "body"}
	default:
		return nil
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

func TestPermitScopeBindsExactGitHubWrite(t *testing.T) {
	c := NewConnector(Config{ConnectorID: "github"})
	effectType, scope, resourceRef, err := c.PermitScope("github.create_issue", map[string]any{
		"repo": "owner/repo", "title": "Ship it", "labels": []any{"release"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if effectType != effects.EffectTypeWrite || resourceRef != "owner/repo" || scope.AllowedAction != "github.create_issue" {
		t.Fatalf("permit scope = type=%s resource=%q scope=%+v", effectType, resourceRef, scope)
	}
	joined := strings.Join(scope.AllowedParams, "|")
	for _, exact := range []string{"repo=owner/repo", "title=Ship it", `labels=["release"]`} {
		if !strings.Contains(joined, exact) {
			t.Fatalf("exact permit scope %q missing %q", joined, exact)
		}
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
			permit := permitFor(tt.tool, "nonce-dispatch-"+tt.tool, allowedParamsForTool(tt.tool)...)

			_, err := c.Execute(ctx, permit, tt.tool, tt.params)
			// All calls should fail with "not connected" since client is a fake
			if err == nil {
				t.Fatal("expected error from fake client")
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

	permit := permitFor("github.create_issue", "nonce-gate-data-class", allowedParamsForTool("github.create_issue")...)
	_, err := c.Execute(ctx, permit, "github.create_issue", map[string]any{"repo": "owner/repo", "title": "Bug"})
	if err == nil {
		t.Fatal("expected gate denial for disallowed data class")
	}
	if !strings.Contains(err.Error(), "gate denied") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteWithLifecycleMarksLastPreNetworkSeam(t *testing.T) {
	lifecycle := &recordingExecutionLifecycle{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if states := lifecycle.snapshot(); len(states) != 1 || states[0] != "STARTED" {
			t.Errorf("request reached GitHub before durable STARTED: %v", states)
			http.Error(w, "missing durable start", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"number":11,"html_url":"https://github.test/owner/repo/issues/11"}`))
	}))
	defer server.Close()
	connector := NewConnector(Config{BaseURL: server.URL, Token: "ghp-test"})
	connector.client.httpClient = server.Client()
	permit := permitFor("github.create_issue", "nonce-lifecycle-success", allowedParamsForTool("github.create_issue")...)
	if _, err := connector.ExecuteWithLifecycle(context.Background(), permit, "github.create_issue", map[string]any{
		"repo": "owner/repo", "title": "Lifecycle proof",
	}, lifecycle); err != nil {
		t.Fatalf("ExecuteWithLifecycle(): %v", err)
	}
	if states := lifecycle.snapshot(); len(states) != 1 || states[0] != "STARTED" {
		t.Fatalf("success lifecycle states = %v, want STARTED", states)
	}
}

func TestExecuteWithLifecycleDistinguishesNotStartedAndUncertain(t *testing.T) {
	precheck := &recordingExecutionLifecycle{}
	connector := NewConnector(Config{BaseURL: "https://api.github.com", Token: "ghp-test"})
	wrongPermit := permitFor("github.create_issue", "nonce-lifecycle-precheck", allowedParamsForTool("github.create_issue")...)
	wrongPermit.ConnectorID = "other"
	if _, err := connector.ExecuteWithLifecycle(context.Background(), wrongPermit, "github.create_issue", map[string]any{
		"repo": "owner/repo", "title": "Denied",
	}, precheck); err == nil {
		t.Fatal("expected precheck denial")
	}
	if states := precheck.snapshot(); len(states) != 1 || states[0] != "NOT_STARTED" {
		t.Fatalf("precheck lifecycle states = %v, want NOT_STARTED", states)
	}

	clientPreflight := &recordingExecutionLifecycle{}
	malformedRepoPermit := permitFor("github.create_issue", "nonce-lifecycle-client-preflight", allowedParamsForTool("github.create_issue")...)
	malformedRepoPermit.ResourceRef = "malformed-repo"
	if _, err := connector.ExecuteWithLifecycle(context.Background(), malformedRepoPermit, "github.create_issue", map[string]any{
		"repo": "malformed-repo", "title": "Denied before HTTP",
	}, clientPreflight); err == nil || !strings.Contains(err.Error(), "must be 'owner/name'") {
		t.Fatalf("expected deterministic client preflight denial, got %v", err)
	}
	if states := clientPreflight.snapshot(); len(states) != 1 || states[0] != "NOT_STARTED" {
		t.Fatalf("client preflight lifecycle states = %v, want NOT_STARTED", states)
	}

	baseURLPreflight := &recordingExecutionLifecycle{}
	malformedBaseURLConnector := NewConnector(Config{BaseURL: "://malformed", Token: "ghp-test"})
	malformedBaseURLPermit := permitFor("github.create_issue", "nonce-lifecycle-base-url", allowedParamsForTool("github.create_issue")...)
	if _, err := malformedBaseURLConnector.ExecuteWithLifecycle(context.Background(), malformedBaseURLPermit, "github.create_issue", map[string]any{
		"repo": "owner/repo", "title": "Denied before HTTP",
	}, baseURLPreflight); err == nil || !strings.Contains(err.Error(), "invalid base URL") {
		t.Fatalf("expected base URL preflight denial, got %v", err)
	}
	if states := baseURLPreflight.snapshot(); len(states) != 1 || states[0] != "NOT_STARTED" {
		t.Fatalf("base URL preflight lifecycle states = %v, want NOT_STARTED", states)
	}

	uncertain := &recordingExecutionLifecycle{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream ambiguity", http.StatusBadGateway)
	}))
	defer server.Close()
	connector = NewConnector(Config{BaseURL: server.URL, Token: "ghp-test"})
	connector.client.httpClient = server.Client()
	permit := permitFor("github.create_issue", "nonce-lifecycle-uncertain", allowedParamsForTool("github.create_issue")...)
	if _, err := connector.ExecuteWithLifecycle(context.Background(), permit, "github.create_issue", map[string]any{
		"repo": "owner/repo", "title": "Ambiguous",
	}, uncertain); err == nil {
		t.Fatal("expected dispatch error")
	}
	states := uncertain.snapshot()
	if len(states) != 2 || states[0] != "STARTED" || states[1] != "UNCERTAIN" {
		t.Fatalf("dispatch error lifecycle states = %v, want STARTED -> UNCERTAIN", states)
	}
}

func TestExecuteWithLifecycleRejectsLossyParamsBeforeStart(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}))
	defer server.Close()
	connector := NewConnector(Config{BaseURL: server.URL, Token: "ghp-test"})
	connector.client.httpClient = server.Client()

	tests := []struct {
		tool   string
		nonce  string
		params map[string]any
	}{
		{tool: "github.add_comment", nonce: "nonce-fractional-issue", params: map[string]any{
			"repo": "owner/repo", "issue_number": 1.9, "body": "must not truncate",
		}},
		{tool: "github.create_issue", nonce: "nonce-mixed-labels", params: map[string]any{
			"repo": "owner/repo", "title": "must not filter", "labels": []any{"bug", 7},
		}},
	}
	for _, test := range tests {
		lifecycle := &recordingExecutionLifecycle{}
		permit := permitFor(test.tool, test.nonce, allowedParamsForTool(test.tool)...)
		if _, err := connector.ExecuteWithLifecycle(context.Background(), permit, test.tool, test.params, lifecycle); err == nil {
			t.Fatalf("%s accepted lossy params", test.tool)
		}
		if states := lifecycle.snapshot(); len(states) != 1 || states[0] != "NOT_STARTED" {
			t.Fatalf("%s lifecycle states = %v, want NOT_STARTED", test.tool, states)
		}
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("lossy params reached GitHub %d times", got)
	}
}

func TestExecute_DeniesPermitScopeBeforeGitHubRequest(t *testing.T) {
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
			tool:    "github.create_issue",
			params:  map[string]any{"repo": "owner/repo", "title": "Bug"},
			permit:  permitFor("github.list_prs", "nonce-scope-action", allowedParamsForTool("github.list_prs")...),
			wantErr: "does not authorize",
		},
		{
			name:    "read permit cannot write",
			tool:    "github.create_issue",
			params:  map[string]any{"repo": "owner/repo", "title": "Bug"},
			permit:  permitWithEffect("github.create_issue", "nonce-scope-effect", effects.EffectTypeRead, allowedParamsForTool("github.create_issue")...),
			wantErr: "effect_type",
		},
		{
			name:    "expired permit",
			tool:    "github.list_prs",
			params:  map[string]any{"repo": "owner/repo"},
			permit:  expiredPermit("github.list_prs", "nonce-scope-expired", allowedParamsForTool("github.list_prs")...),
			wantErr: "expired",
		},
		{
			name:    "extra param outside scope",
			tool:    "github.list_prs",
			params:  map[string]any{"repo": "owner/repo", "state": "open"},
			permit:  permitFor("github.list_prs", "nonce-scope-param", "repo"),
			wantErr: "not authorized",
		},
		{
			name:    "write missing param scope",
			tool:    "github.create_issue",
			params:  map[string]any{"repo": "owner/repo", "title": "Bug"},
			permit:  permitFor("github.create_issue", "nonce-scope-empty"),
			wantErr: "requires allowed_params",
		},
		{
			name:    "repo resource mismatch",
			tool:    "github.create_issue",
			params:  map[string]any{"repo": "owner/repo", "title": "Bug"},
			permit:  permitForOtherRepo("github.create_issue", "nonce-scope-resource", allowedParamsForTool("github.create_issue")...),
			wantErr: "resource_ref",
		},
		{
			name:    "exact param mismatch",
			tool:    "github.add_comment",
			params:  map[string]any{"repo": "owner/repo", "issue_number": 8, "body": "LGTM"},
			permit:  permitFor("github.add_comment", "nonce-scope-exact", "repo", "issue_number=7", "body"),
			wantErr: "does not match permit scope",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requests = 0
			c := NewConnector(Config{BaseURL: server.URL, Token: "ghp-test"})
			c.client.httpClient = server.Client()

			_, err := c.Execute(context.Background(), tt.permit, tt.tool, tt.params)
			if err == nil {
				t.Fatal("expected permit scope error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
			if requests != 0 {
				t.Fatalf("permit denial reached GitHub server %d times", requests)
			}
		})
	}
}

func TestExecute_RejectsPermitNonceReplayBeforeGitHubRequest(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	c := NewConnector(Config{BaseURL: server.URL, Token: "ghp-test"})
	c.client.httpClient = server.Client()
	permit := permitFor("github.list_prs", "nonce-replay", allowedParamsForTool("github.list_prs")...)
	params := map[string]any{"repo": "owner/repo"}

	if _, err := c.Execute(context.Background(), permit, "github.list_prs", params); err != nil {
		t.Fatalf("first execute should pass permit validation: %v", err)
	}
	if requests != 1 {
		t.Fatalf("first execute reached GitHub server %d times, want 1", requests)
	}
	if _, err := c.Execute(context.Background(), permit, "github.list_prs", params); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("expected replay denial, got %v", err)
	}
	if requests != 1 {
		t.Fatalf("replayed permit reached GitHub server; requests=%d", requests)
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
	// First two calls pass the gate (fail at client fake)
	for i := 0; i < 2; i++ {
		permit := permitFor("github.list_prs", fmt.Sprintf("nonce-rate-%d", i), allowedParamsForTool("github.list_prs")...)
		_, err := c.Execute(ctx, permit, "github.list_prs", map[string]any{"repo": "owner/repo"})
		if err == nil {
			t.Fatal("expected fake error")
		}
		if strings.Contains(err.Error(), "gate denied") {
			t.Fatalf("call %d should not be rate limited", i+1)
		}
	}

	// Third call should hit rate limit
	permit := permitFor("github.list_prs", "nonce-rate-3", allowedParamsForTool("github.list_prs")...)
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

	// Execute three tool calls
	for i := 0; i < 3; i++ {
		permit := permitFor("github.list_prs", fmt.Sprintf("nonce-graph-%d", i), allowedParamsForTool("github.list_prs")...)
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
			permit := permitFor(tt.tool, "nonce-missing-"+tt.expectContain, allowedParamsForTool(tt.tool)...)
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
		"github.pr.list":      true,
		"github.pr.read":      true,
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

func TestIntParamRejectsLossyJSONNumbers(t *testing.T) {
	for _, value := range []any{float64(1.9), math.NaN(), math.Inf(1), math.Ldexp(1, strconv.IntSize-1)} {
		if got, ok := intParam(map[string]any{"number": value}, "number"); ok {
			t.Fatalf("intParam(%v) = %d,true; want rejection", value, got)
		}
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
	result, ok := stringSliceParam(params, "labels")
	if !ok || len(result) != 2 || result[0] != "bug" || result[1] != "critical" {
		t.Fatalf("stringSliceParam = %v, want [bug critical]", result)
	}
}

func TestStringSliceParam_Native(t *testing.T) {
	params := map[string]any{"labels": []string{"bug"}}
	result, ok := stringSliceParam(params, "labels")
	if !ok || len(result) != 1 || result[0] != "bug" {
		t.Fatalf("stringSliceParam = %v, want [bug]", result)
	}
}

func TestStringSliceParam_Missing(t *testing.T) {
	params := map[string]any{}
	result, ok := stringSliceParam(params, "labels")
	if !ok || result != nil {
		t.Fatalf("expected nil, got %v", result)
	}
}

func TestStringSliceParamRejectsMixedArrays(t *testing.T) {
	if result, ok := stringSliceParam(map[string]any{"labels": []any{"bug", 7}}, "labels"); ok || result != nil {
		t.Fatalf("mixed labels = %v,%t; want rejection", result, ok)
	}
}
