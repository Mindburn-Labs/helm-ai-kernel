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

type sessionRiskTestClock struct {
	t time.Time
}

func (c *sessionRiskTestClock) Now() time.Time { return c.t }

func newSessionRiskTestGuardian(t *testing.T, opts ...GuardianOption) *Guardian {
	t.Helper()
	mockStore := NewMockStore()
	registry := pkg_artifact.NewRegistry(mockStore, nil)
	ruleGraph := prg.NewGraph()
	allowAll := prg.RequirementSet{ID: "allow-all", Requirements: []prg.Requirement{}}
	require.NoError(t, ruleGraph.AddRule("READ", allowAll))
	require.NoError(t, ruleGraph.AddRule("EXECUTE_TOOL", allowAll))

	return NewGuardian(&MockSigner{}, ruleGraph, registry, opts...)
}

func TestSessionRiskMemorySnapshotStable(t *testing.T) {
	clk := &sessionRiskTestClock{t: time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)}
	history := []SessionAction{
		{Action: "READ", Resource: "db://customer-records", Verdict: "ALLOW", Timestamp: 1712000000000},
		{Action: "EXPORT", Resource: "customer pii report", Verdict: "ALLOW", Timestamp: 1712000001000},
	}
	req := DecisionRequest{
		Principal: "agent-1",
		Action:    "EXECUTE_TOOL",
		Resource:  "webhook:external-upload",
		Context:   map[string]interface{}{"destination": "https://external.example/upload"},
	}

	srm1 := NewSessionRiskMemory(WithSessionRiskClock(clk))
	srm2 := NewSessionRiskMemory(WithSessionRiskClock(clk))
	snap1 := srm1.Evaluate("session-1", history, req)
	snap2 := srm2.Evaluate("session-1", history, req)

	assert.Equal(t, snap1.SessionCentroidHash, snap2.SessionCentroidHash)
	assert.Equal(t, snap1.TrajectoryRiskScore, snap2.TrajectoryRiskScore)
	assert.Equal(t, 3, snap1.RiskAccumulationWindow)
	assert.NotEmpty(t, snap1.SessionCentroidHash)
	assert.Greater(t, snap1.TrajectoryRiskScore, 0.0)
}

func TestGuardianSessionRiskMemoryLowRiskAllowsWithSnapshot(t *testing.T) {
	clk := &sessionRiskTestClock{t: time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)}
	srm := NewSessionRiskMemory(WithSessionRiskClock(clk))
	g := newSessionRiskTestGuardian(t, WithClock(clk), WithSessionRiskMemory(srm))

	decision, err := g.EvaluateDecision(context.Background(), DecisionRequest{
		Principal: "agent-1",
		Action:    "READ",
		Resource:  "docs://runbook",
		Context:   map[string]interface{}{"session_id": "safe-session"},
		SessionHistory: []SessionAction{
			{Action: "READ", Resource: "docs://overview", Verdict: "ALLOW", Timestamp: 1712000000000},
			{Action: "READ", Resource: "docs://faq", Verdict: "ALLOW", Timestamp: 1712000001000},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, decision)

	assert.Equal(t, string(contracts.VerdictAllow), decision.Verdict)
	assert.NotEmpty(t, decision.Signature)
	assert.NotEmpty(t, decision.SessionCentroidHash)
	assert.Equal(t, 3, decision.RiskAccumulationWindow)
	assert.Equal(t, decision.TrajectoryRiskScore, decision.InputContext["trajectory_risk_score"])
	assert.Equal(t, decision.SessionCentroidHash, decision.InputContext["session_centroid_hash"])
}

func TestGuardianSessionRiskMemorySlowBurnDeny(t *testing.T) {
	clk := &sessionRiskTestClock{t: time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)}
	srm := NewSessionRiskMemory(WithSessionRiskClock(clk))
	g := newSessionRiskTestGuardian(t, WithClock(clk), WithSessionRiskMemory(srm))

	decision, err := g.EvaluateDecision(context.Background(), DecisionRequest{
		Principal: "agent-1",
		Action:    "EXECUTE_TOOL",
		Resource:  "webhook:post",
		Context: map[string]interface{}{
			"session_id":  "slow-burn-session",
			"destination": "https://external.example/webhook",
			"payload":     "customer pii export archive",
		},
		SessionHistory: []SessionAction{
			{Action: "READ", Resource: "db://customer database", Verdict: "ALLOW", Timestamp: 1712000000000},
			{Action: "EXPORT", Resource: "customer records partial dump", Verdict: "ALLOW", Timestamp: 1712000001000},
			{Action: "EXECUTE_TOOL", Resource: "external upload customer sample", Verdict: "ALLOW", Timestamp: 1712000002000},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, decision)

	assert.Equal(t, string(contracts.VerdictDeny), decision.Verdict)
	assert.Equal(t, string(contracts.ReasonSessionRiskDeny), decision.ReasonCode)
	assert.NotEmpty(t, decision.Signature)
	assert.GreaterOrEqual(t, decision.TrajectoryRiskScore, 0.38)
	assert.NotEmpty(t, decision.SessionCentroidHash)
	assert.Equal(t, 4, decision.RiskAccumulationWindow)
}

func TestDecisionRecordSessionRiskJSONRoundTrip(t *testing.T) {
	record := contracts.DecisionRecord{
		ID:                     "dec-srm",
		Verdict:                string(contracts.VerdictDeny),
		Reason:                 "session risk",
		TrajectoryRiskScore:    0.42,
		SessionCentroidHash:    "sha256:abc",
		RiskAccumulationWindow: 4,
		Timestamp:              time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC),
	}
	data, err := json.Marshal(record)
	require.NoError(t, err)

	var decoded contracts.DecisionRecord
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, record.TrajectoryRiskScore, decoded.TrajectoryRiskScore)
	assert.Equal(t, record.SessionCentroidHash, decoded.SessionCentroidHash)
	assert.Equal(t, record.RiskAccumulationWindow, decoded.RiskAccumulationWindow)
}
