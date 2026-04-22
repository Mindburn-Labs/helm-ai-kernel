package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/guardian"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDelegationScope_ToolInScope verifies that a tool within the delegation
// scope passes through to the Guardian evaluator.
func TestDelegationScope_ToolInScope(t *testing.T) {
	eval := &mockEvaluator{verdict: guardian.VerdictAllow}
	fw := NewGovernanceFirewall(eval, nil)

	err := fw.InterceptToolExecution(context.Background(), ToolExecutionRequest{
		ToolName:               "file_read",
		SessionID:              "sess-delegate",
		DelegationSessionID:    "deleg-001",
		DelegationAllowedTools: []string{"file_read", "file_write"},
	})
	assert.NoError(t, err, "in-scope tool should pass pre-Guardian check")
}

// TestDelegationScope_ToolNotInScope verifies that a tool outside the
// delegation scope is rejected BEFORE reaching the Guardian.
func TestDelegationScope_ToolNotInScope(t *testing.T) {
	// Evaluator should never be called — scope check fires first.
	eval := &mockEvaluator{verdict: guardian.VerdictAllow}
	fw := NewGovernanceFirewall(eval, nil)

	err := fw.InterceptToolExecution(context.Background(), ToolExecutionRequest{
		ToolName:               "shell_exec",
		SessionID:              "sess-delegate",
		DelegationSessionID:    "deleg-001",
		DelegationAllowedTools: []string{"file_read", "file_write"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delegation scope violation")
	assert.Contains(t, err.Error(), "shell_exec")
}

// TestDelegationScope_NoDelegation verifies backwards compatibility:
// when no delegation context is set, all tools are allowed through.
func TestDelegationScope_NoDelegation(t *testing.T) {
	eval := &mockEvaluator{verdict: guardian.VerdictAllow}
	fw := NewGovernanceFirewall(eval, nil)

	// No DelegationAllowedTools set → no scope restriction
	err := fw.InterceptToolExecution(context.Background(), ToolExecutionRequest{
		ToolName:  "shell_exec",
		SessionID: "sess-regular",
	})
	assert.NoError(t, err, "no delegation context should not restrict tools")
}

// TestDelegationScope_ContextForwarded verifies that delegation metadata
// is forwarded into the Guardian DecisionRequest context.
func TestDelegationScope_ContextForwarded(t *testing.T) {
	var capturedCtx map[string]interface{}
	eval := &capturingEvaluator{
		verdict: guardian.VerdictAllow,
		capture: func(req guardian.DecisionRequest) {
			capturedCtx = req.Context
		},
	}
	fw := NewGovernanceFirewall(eval, nil)

	err := fw.InterceptToolExecution(context.Background(), ToolExecutionRequest{
		ToolName:               "file_read",
		SessionID:              "sess-delegate",
		DelegationSessionID:    "deleg-001",
		DelegationVerifier:     "verifier-xyz",
		DelegationAllowedTools: []string{"file_read"},
		Arguments: map[string]interface{}{
			"path": "/tmp/test.txt",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, capturedCtx)
	assert.Equal(t, "deleg-001", capturedCtx["delegation_session_id"])
	assert.Equal(t, "verifier-xyz", capturedCtx["delegation_verifier"])
	assert.Equal(t, "/tmp/test.txt", capturedCtx["path"])
}

// TestDelegationScope_CapabilitiesFiltered verifies that the /mcp/v1/capabilities
// endpoint filters tools when delegation headers are present.
func TestDelegationScope_CapabilitiesFiltered(t *testing.T) {
	catalog := NewInMemoryCatalog()
	catalog.RegisterCommonTools() // registers file_read, file_write

	gw := NewGateway(catalog, GatewayConfig{})
	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)

	// Without delegation header → see all tools
	reqAll := httptest.NewRequest(http.MethodGet, "/mcp/v1/capabilities", nil)
	wAll := httptest.NewRecorder()
	mux.ServeHTTP(wAll, reqAll)
	assert.Equal(t, http.StatusOK, wAll.Code)
	assert.Contains(t, wAll.Body.String(), "file_read")
	assert.Contains(t, wAll.Body.String(), "file_write")

	// With delegation header → only see file_read
	reqScoped := httptest.NewRequest(http.MethodGet, "/mcp/v1/capabilities", nil)
	reqScoped.Header.Set("X-HELM-Delegation-Allowed-Tools", "file_read")
	wScoped := httptest.NewRecorder()
	mux.ServeHTTP(wScoped, reqScoped)
	assert.Equal(t, http.StatusOK, wScoped.Code)
	assert.Contains(t, wScoped.Body.String(), "file_read")
	assert.NotContains(t, wScoped.Body.String(), "file_write")
}

// TestDelegationScope_WrapHandler_OutOfScope verifies that WrapToolHandler
// blocks execution for out-of-scope tools before the handler runs.
func TestDelegationScope_WrapHandler_OutOfScope(t *testing.T) {
	eval := &mockEvaluator{verdict: guardian.VerdictAllow}
	fw := NewGovernanceFirewall(eval, nil)

	executed := false
	handler := func(ctx context.Context, req ToolExecutionRequest) (ToolExecutionResponse, error) {
		executed = true
		return ToolExecutionResponse{Content: "should not reach here"}, nil
	}

	wrapped := fw.WrapToolHandler(handler)
	resp, err := wrapped(context.Background(), ToolExecutionRequest{
		ToolName:               "shell_exec",
		SessionID:              "sess-delegate",
		DelegationAllowedTools: []string{"file_read"},
	})
	require.NoError(t, err)
	assert.False(t, executed, "handler must NOT be called for out-of-scope tool")
	assert.True(t, resp.IsError)
	assert.Contains(t, resp.Content, "delegation scope violation")
}

// ── Test helpers ──────────────────────────────────────────────

// capturingEvaluator captures the DecisionRequest for inspection.
type capturingEvaluator struct {
	verdict string
	capture func(guardian.DecisionRequest)
}

func (m *capturingEvaluator) EvaluateDecision(_ context.Context, req guardian.DecisionRequest) (*contracts.DecisionRecord, error) {
	if m.capture != nil {
		m.capture(req)
	}
	return &contracts.DecisionRecord{
		ID:      "test-cap-decision",
		Verdict: m.verdict,
	}, nil
}
