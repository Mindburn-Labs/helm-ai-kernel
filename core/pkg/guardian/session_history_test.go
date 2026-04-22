package guardian

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	pkg_artifact "github.com/Mindburn-Labs/helm-oss/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/prg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newSessionHistoryGuardian creates a minimal Guardian suitable for session history tests.
func newSessionHistoryGuardian(t *testing.T) *Guardian {
	t.Helper()
	mockStore := NewMockStore()
	registry := pkg_artifact.NewRegistry(mockStore, nil)
	signer := &MockSigner{}
	ruleGraph := prg.NewGraph()

	// Add a permissive rule so default-deny doesn't mask session tests
	_ = ruleGraph.AddRule("*", prg.RequirementSet{
		ID:           "allow-all",
		Requirements: []prg.Requirement{}, // Empty = always pass
	})

	return NewGuardian(signer, ruleGraph, registry)
}

func TestDecisionRequest_EmptySessionHistory(t *testing.T) {
	g := newSessionHistoryGuardian(t)

	req := DecisionRequest{
		Principal: "agent-1",
		Action:    "READ",
		Resource:  "file:///tmp/test.txt",
		Context:   map[string]interface{}{"env": "test"},
	}

	decision, err := g.EvaluateDecision(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, decision)
	// Empty session history must not cause errors
	assert.NotEmpty(t, decision.ID)
}

func TestDecisionRequest_NilSessionHistory(t *testing.T) {
	g := newSessionHistoryGuardian(t)

	req := DecisionRequest{
		Principal:      "agent-1",
		Action:         "READ",
		Resource:       "file:///tmp/test.txt",
		SessionHistory: nil,
	}

	decision, err := g.EvaluateDecision(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, decision)
	assert.NotEmpty(t, decision.ID)
}

func TestSessionAction_JSONRoundTrip(t *testing.T) {
	sa := SessionAction{
		Action:    "EXECUTE_TOOL",
		Resource:  "github:create-issue",
		Verdict:   "ALLOW",
		Timestamp: 1712000000000,
	}

	data, err := json.Marshal(sa)
	require.NoError(t, err)

	var decoded SessionAction
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, sa.Action, decoded.Action)
	assert.Equal(t, sa.Resource, decoded.Resource)
	assert.Equal(t, sa.Verdict, decoded.Verdict)
	assert.Equal(t, sa.Timestamp, decoded.Timestamp)
}

func TestDecisionRequest_SessionHistoryJSON(t *testing.T) {
	req := DecisionRequest{
		Principal: "agent-1",
		Action:    "EXECUTE_TOOL",
		Resource:  "slack:post-message",
		Context:   map[string]interface{}{"channel": "#general"},
		SessionHistory: []SessionAction{
			{Action: "READ", Resource: "file:///etc/passwd", Verdict: "DENY", Timestamp: 1712000000000},
			{Action: "READ", Resource: "file:///tmp/data.json", Verdict: "ALLOW", Timestamp: 1712000001000},
		},
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded DecisionRequest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, req.Principal, decoded.Principal)
	assert.Len(t, decoded.SessionHistory, 2)
	assert.Equal(t, "DENY", decoded.SessionHistory[0].Verdict)
	assert.Equal(t, "ALLOW", decoded.SessionHistory[1].Verdict)
}

func TestDecisionRequest_SessionHistoryOmittedWhenEmpty(t *testing.T) {
	req := DecisionRequest{
		Principal: "agent-1",
		Action:    "READ",
		Resource:  "file:///tmp/test.txt",
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	// session_history should be omitted from JSON when nil
	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)
	_, exists := raw["session_history"]
	assert.False(t, exists, "session_history should be omitted when nil")
}

func TestSessionHistory_DenyCountComputation(t *testing.T) {
	g := newSessionHistoryGuardian(t)

	history := []SessionAction{
		{Action: "EXECUTE_TOOL", Resource: "github:create-issue", Verdict: "ALLOW", Timestamp: 1712000000000},
		{Action: "EXECUTE_TOOL", Resource: "slack:post-message", Verdict: "DENY", Timestamp: 1712000001000},
		{Action: "READ", Resource: "file:///etc/shadow", Verdict: "DENY", Timestamp: 1712000002000},
		{Action: "EXECUTE_TOOL", Resource: "github:merge-pr", Verdict: "ALLOW", Timestamp: 1712000003000},
		{Action: "WRITE", Resource: "file:///tmp/payload", Verdict: "DENY", Timestamp: 1712000004000},
	}

	req := DecisionRequest{
		Principal:      "agent-1",
		Action:         "READ",
		Resource:       "file:///tmp/safe.txt",
		SessionHistory: history,
	}

	decision, err := g.EvaluateDecision(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, decision)

	// Verify the context was enriched with session metadata
	assert.Equal(t, 5, decision.InputContext["session_action_count"])
	assert.Equal(t, 3, decision.InputContext["session_deny_count"])
	assert.NotNil(t, decision.InputContext["session_history"])
}

func TestSessionHistory_ZeroDenyCount(t *testing.T) {
	g := newSessionHistoryGuardian(t)

	history := []SessionAction{
		{Action: "READ", Resource: "file:///tmp/a.txt", Verdict: "ALLOW", Timestamp: 1712000000000},
		{Action: "READ", Resource: "file:///tmp/b.txt", Verdict: "ALLOW", Timestamp: 1712000001000},
	}

	req := DecisionRequest{
		Principal:      "agent-1",
		Action:         "READ",
		Resource:       "file:///tmp/c.txt",
		SessionHistory: history,
	}

	decision, err := g.EvaluateDecision(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, decision)

	assert.Equal(t, 2, decision.InputContext["session_action_count"])
	assert.Equal(t, 0, decision.InputContext["session_deny_count"])
}

func TestSessionHistory_ContextInjectionDoesNotOverwriteExisting(t *testing.T) {
	g := newSessionHistoryGuardian(t)

	req := DecisionRequest{
		Principal: "agent-1",
		Action:    "READ",
		Resource:  "file:///tmp/test.txt",
		Context: map[string]interface{}{
			"env":     "production",
			"team_id": "eng-42",
		},
		SessionHistory: []SessionAction{
			{Action: "READ", Resource: "file:///tmp/a.txt", Verdict: "ALLOW", Timestamp: 1712000000000},
		},
	}

	decision, err := g.EvaluateDecision(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, decision)

	// Original context keys must survive
	assert.Equal(t, "production", decision.InputContext["env"])
	assert.Equal(t, "eng-42", decision.InputContext["team_id"])
	// Session keys must be injected
	assert.Equal(t, 1, decision.InputContext["session_action_count"])
}

func TestSessionAction_FieldAccess(t *testing.T) {
	now := time.Now().UnixMilli()
	sa := SessionAction{
		Action:    "WRITE",
		Resource:  "s3://bucket/key",
		Verdict:   "ESCALATE",
		Timestamp: now,
	}

	assert.Equal(t, "WRITE", sa.Action)
	assert.Equal(t, "s3://bucket/key", sa.Resource)
	assert.Equal(t, "ESCALATE", sa.Verdict)
	assert.Equal(t, now, sa.Timestamp)
}

func TestSessionHistory_EscalateNotCountedAsDeny(t *testing.T) {
	g := newSessionHistoryGuardian(t)

	history := []SessionAction{
		{Action: "WRITE", Resource: "db://users", Verdict: "ESCALATE", Timestamp: 1712000000000},
		{Action: "WRITE", Resource: "db://orders", Verdict: "ESCALATE", Timestamp: 1712000001000},
	}

	req := DecisionRequest{
		Principal:      "agent-1",
		Action:         "READ",
		Resource:       "file:///tmp/test.txt",
		SessionHistory: history,
	}

	decision, err := g.EvaluateDecision(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, decision)

	// ESCALATE should not count as DENY
	assert.Equal(t, 0, decision.InputContext["session_deny_count"])
	assert.Equal(t, 2, decision.InputContext["session_action_count"])
}

func TestDecisionRequest_WithSessionHistory_VerdictStillDecided(t *testing.T) {
	g := newSessionHistoryGuardian(t)

	// Providing session history should not change the fact that the Guardian
	// still produces a verdict — it's context enrichment, not short-circuiting.
	req := DecisionRequest{
		Principal: "agent-1",
		Action:    "READ",
		Resource:  "file:///tmp/test.txt",
		SessionHistory: []SessionAction{
			{Action: "READ", Resource: "file:///etc/passwd", Verdict: "DENY", Timestamp: 1712000000000},
		},
	}

	decision, err := g.EvaluateDecision(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, decision)

	// Must have a real verdict (not empty)
	assert.Contains(t,
		[]string{string(contracts.VerdictAllow), string(contracts.VerdictDeny), string(contracts.VerdictEscalate)},
		decision.Verdict,
	)
}
