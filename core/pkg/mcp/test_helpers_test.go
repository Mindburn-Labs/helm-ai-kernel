package mcp

import (
	"context"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/guardian"
)

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

type smartMockEvaluator struct {
	decisions map[string]string
}

func (m *smartMockEvaluator) EvaluateDecision(_ context.Context, req guardian.DecisionRequest) (*contracts.DecisionRecord, error) {
	verdict, ok := m.decisions[req.Resource]
	if !ok {
		verdict = string(contracts.VerdictAllow)
	}
	return &contracts.DecisionRecord{Verdict: verdict}, nil
}
