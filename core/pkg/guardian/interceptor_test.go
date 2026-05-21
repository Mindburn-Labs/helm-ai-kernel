package guardian

import (
	"context"
	"errors"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/stretchr/testify/assert"
)

type mockInterceptor struct {
	name  string
	calls *[]string
	deny  bool
	err   error
}

func (m *mockInterceptor) Evaluate(ctx context.Context, evalCtx *EvaluationContext, next Handler) (*contracts.DecisionRecord, error) {
	*m.calls = append(*m.calls, m.name)
	if m.deny {
		return &contracts.DecisionRecord{
			Verdict:    string(contracts.VerdictDeny),
			ReasonCode: "DENIED_BY_" + m.name,
		}, nil
	}
	if m.err != nil {
		return nil, m.err
	}
	return next(ctx, evalCtx)
}

func TestInterceptorChain_ExecutionFlowAndShortCircuit(t *testing.T) {
	t.Run("Standard sequence execution", func(t *testing.T) {
		calls := []string{}
		i1 := &mockInterceptor{name: "first", calls: &calls}
		i2 := &mockInterceptor{name: "second", calls: &calls}
		i3 := &mockInterceptor{name: "third", calls: &calls}

		finalCalled := false
		finalHandler := func(ctx context.Context, evalCtx *EvaluationContext) (*contracts.DecisionRecord, error) {
			finalCalled = true
			return &contracts.DecisionRecord{Verdict: string(contracts.VerdictAllow)}, nil
		}

		chain := NewInterceptorChain([]BoundaryInterceptor{i1, i2, i3}, finalHandler)
		evalCtx := &EvaluationContext{}

		dec, err := chain.Execute(context.Background(), evalCtx)
		assert.NoError(t, err)
		assert.Equal(t, string(contracts.VerdictAllow), dec.Verdict)
		assert.True(t, finalCalled)
		assert.Equal(t, []string{"first", "second", "third"}, calls)
	})

	t.Run("Short-circuiting on deny", func(t *testing.T) {
		calls := []string{}
		i1 := &mockInterceptor{name: "first", calls: &calls}
		i2 := &mockInterceptor{name: "second", calls: &calls, deny: true}
		i3 := &mockInterceptor{name: "third", calls: &calls}

		finalCalled := false
		finalHandler := func(ctx context.Context, evalCtx *EvaluationContext) (*contracts.DecisionRecord, error) {
			finalCalled = true
			return &contracts.DecisionRecord{Verdict: string(contracts.VerdictAllow)}, nil
		}

		chain := NewInterceptorChain([]BoundaryInterceptor{i1, i2, i3}, finalHandler)
		evalCtx := &EvaluationContext{}

		dec, err := chain.Execute(context.Background(), evalCtx)
		assert.NoError(t, err)
		assert.Equal(t, string(contracts.VerdictDeny), dec.Verdict)
		assert.Equal(t, "DENIED_BY_second", dec.ReasonCode)
		assert.False(t, finalCalled)
		assert.Equal(t, []string{"first", "second"}, calls)
	})

	t.Run("Short-circuiting on error", func(t *testing.T) {
		calls := []string{}
		i1 := &mockInterceptor{name: "first", calls: &calls}
		i2 := &mockInterceptor{name: "second", calls: &calls, err: errors.New("aborted")}
		i3 := &mockInterceptor{name: "third", calls: &calls}

		finalHandler := func(ctx context.Context, evalCtx *EvaluationContext) (*contracts.DecisionRecord, error) {
			return &contracts.DecisionRecord{Verdict: string(contracts.VerdictAllow)}, nil
		}

		chain := NewInterceptorChain([]BoundaryInterceptor{i1, i2, i3}, finalHandler)
		evalCtx := &EvaluationContext{}

		_, err := chain.Execute(context.Background(), evalCtx)
		assert.Error(t, err)
		assert.Equal(t, "aborted", err.Error())
		assert.Equal(t, []string{"first", "second"}, calls)
	})
}

func TestTaintInterceptorEgressBlock(t *testing.T) {
	t.Run("Tainted flow egress block", func(t *testing.T) {
		t.Setenv("HELM_TAINT_TRACKING", "1")
		g := newMinimalGuardian()

		req := DecisionRequest{
			Principal: "untrusted-agent",
			Action:    "EXECUTE_TOOL",
			Resource:  "http.post",
			Context: map[string]interface{}{
				"destination": "https://external.egress.com/upload",
				"taint":       []string{contracts.TaintCredential},
			},
		}

		dec, err := g.EvaluateDecision(context.Background(), req)
		assert.NoError(t, err)
		assert.Equal(t, string(contracts.VerdictDeny), dec.Verdict)
		assert.Equal(t, string(contracts.ReasonTaintedEgressDeny), dec.ReasonCode)
	})
}
