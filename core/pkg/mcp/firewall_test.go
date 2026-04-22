package mcp

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/guardian"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockEvaluator implements PolicyEvaluator for testing.
type mockEvaluator struct {
	verdict string
	reason  string
	err     error
}

func (m *mockEvaluator) EvaluateDecision(_ context.Context, _ guardian.DecisionRequest) (*contracts.DecisionRecord, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &contracts.DecisionRecord{
		ID:      "test-decision",
		Verdict: m.verdict,
		Reason:  m.reason,
	}, nil
}

func TestGovernanceFirewall_Intercept_Allow(t *testing.T) {
	eval := &mockEvaluator{verdict: guardian.VerdictAllow}
	fw := NewGovernanceFirewall(eval, nil)

	err := fw.InterceptToolExecution(context.Background(), ToolExecutionRequest{
		ToolName:  "test-tool",
		SessionID: "sess-1",
	})
	assert.NoError(t, err)
}

func TestGovernanceFirewall_Intercept_Block(t *testing.T) {
	eval := &mockEvaluator{verdict: guardian.VerdictBlock, reason: "policy violation"}
	fw := NewGovernanceFirewall(eval, nil)

	err := fw.InterceptToolExecution(context.Background(), ToolExecutionRequest{
		ToolName:  "dangerous-tool",
		SessionID: "sess-2",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "governance blocked execution")
	assert.Contains(t, err.Error(), "policy violation")
}

func TestGovernanceFirewall_Intercept_Intervene(t *testing.T) {
	eval := &mockEvaluator{verdict: guardian.VerdictIntervene, reason: "human approval required"}
	fw := NewGovernanceFirewall(eval, nil)

	err := fw.InterceptToolExecution(context.Background(), ToolExecutionRequest{
		ToolName:  "high-risk-tool",
		SessionID: "sess-3",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "governance requires approval")
}

func TestGovernanceFirewall_Intercept_EvaluatorError(t *testing.T) {
	eval := &mockEvaluator{err: assert.AnError}
	fw := NewGovernanceFirewall(eval, nil)

	err := fw.InterceptToolExecution(context.Background(), ToolExecutionRequest{
		ToolName: "any-tool",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "governance check failed")
}

func TestGovernanceFirewall_WrapHandler_Allow(t *testing.T) {
	eval := &mockEvaluator{verdict: guardian.VerdictAllow}
	catalog := NewInMemoryCatalog()
	fw := NewGovernanceFirewall(eval, catalog)

	executed := false
	handler := func(ctx context.Context, req ToolExecutionRequest) (ToolExecutionResponse, error) {
		executed = true
		return ToolExecutionResponse{Content: "success"}, nil
	}

	wrapped := fw.WrapToolHandler(handler)
	resp, err := wrapped(context.Background(), ToolExecutionRequest{ToolName: "test", SessionID: "s1"})
	require.NoError(t, err)

	assert.True(t, executed, "handler should have been executed")
	assert.Equal(t, "success", resp.Content)
	assert.True(t, resp.Evaluated)
	assert.False(t, resp.IsError)
}

func TestGovernanceFirewall_WrapHandler_Block(t *testing.T) {
	eval := &mockEvaluator{verdict: guardian.VerdictBlock, reason: "blocked"}
	fw := NewGovernanceFirewall(eval, nil)

	executed := false
	handler := func(ctx context.Context, req ToolExecutionRequest) (ToolExecutionResponse, error) {
		executed = true
		return ToolExecutionResponse{Content: "success"}, nil
	}

	wrapped := fw.WrapToolHandler(handler)
	resp, err := wrapped(context.Background(), ToolExecutionRequest{ToolName: "test", SessionID: "s2"})
	require.NoError(t, err)

	assert.False(t, executed, "handler should NOT have been executed")
	assert.True(t, resp.IsError)
	assert.Contains(t, resp.Content, "Access Denied")
	assert.True(t, resp.Evaluated)
}

func TestGovernanceFirewall_Intercept_Pending(t *testing.T) {
	eval := &mockEvaluator{verdict: string(contracts.VerdictEscalate), reason: "needs approval"}
	fw := NewGovernanceFirewall(eval, nil)

	err := fw.InterceptToolExecution(context.Background(), ToolExecutionRequest{
		ToolName:  "risky-tool",
		SessionID: "sess-4",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "governance requires approval")
}

type smartMockEvaluator struct {
	decisions map[string]string // ToolName -> Verdict
}

func (m *smartMockEvaluator) EvaluateDecision(_ context.Context, req guardian.DecisionRequest) (*contracts.DecisionRecord, error) {
	v, ok := m.decisions[req.Resource]
	if !ok {
		v = string(contracts.VerdictAllow)
	}
	return &contracts.DecisionRecord{Verdict: v}, nil
}

func TestGovernanceFirewall_InterceptPlan(t *testing.T) {
	eval := &smartMockEvaluator{
		decisions: map[string]string{
			"tool-pass":    string(contracts.VerdictAllow),
			"tool-fail":    string(contracts.VerdictDeny),
			"tool-pending": string(contracts.VerdictEscalate),
		},
	}
	fw := NewGovernanceFirewall(eval, nil)

	// Scenario 1: All Pass
	planPass := ToolExecutionPlan{
		PlanID: "plan-1",
		Steps: []ToolExecutionRequest{
			{ToolName: "tool-pass"},
			{ToolName: "tool-pass"},
		},
	}
	decision, err := fw.InterceptPlan(context.Background(), planPass)
	require.NoError(t, err)
	assert.Equal(t, string(contracts.VerdictAllow), decision.Status)
	assert.Len(t, decision.Decisions, 2)

	// Scenario 2: One Fail blocks everything
	planFail := ToolExecutionPlan{
		PlanID: "plan-2",
		Steps: []ToolExecutionRequest{
			{ToolName: "tool-pass"},
			{ToolName: "tool-fail"}, // This should fail the plan
			{ToolName: "tool-pending"},
		},
	}
	decision, err = fw.InterceptPlan(context.Background(), planFail)
	require.NoError(t, err)
	assert.Equal(t, string(contracts.VerdictDeny), decision.Status)

	// Scenario 3: Pending triggers pending status (if no fail)
	planPending := ToolExecutionPlan{
		PlanID: "plan-3",
		Steps: []ToolExecutionRequest{
			{ToolName: "tool-pass"},
			{ToolName: "tool-pending"},
		},
	}
	decision, err = fw.InterceptPlan(context.Background(), planPending)
	require.NoError(t, err)
	assert.Equal(t, string(contracts.VerdictEscalate), decision.Status)
}
