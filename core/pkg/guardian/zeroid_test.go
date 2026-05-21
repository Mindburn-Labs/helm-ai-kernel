package guardian

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/stretchr/testify/assert"
)

func TestZeroIDContinuousEvaluation(t *testing.T) {
	t.Run("Valid SPIFFE URI passes through", func(t *testing.T) {
		g := newMinimalGuardian()
		interceptor := NewZeroIDInterceptor(g, nil)

		evalCtx := &EvaluationContext{
			Request: DecisionRequest{
				Principal: "spiffe://highflame.com/agent-x",
				Action:    "EXECUTE_TOOL",
				Resource:  "http.get",
				Context: map[string]interface{}{
					"zeroid_token": "token_valid_123",
					"spiffe_uri":   "spiffe://highflame.com/agent-x",
				},
			},
		}

		calledNext := false
		next := func(ctx context.Context, eCtx *EvaluationContext) (*contracts.DecisionRecord, error) {
			calledNext = true
			return &contracts.DecisionRecord{Verdict: string(contracts.VerdictAllow)}, nil
		}

		dec, err := interceptor.Evaluate(context.Background(), evalCtx, next)
		assert.NoError(t, err)
		assert.True(t, calledNext)
		assert.Equal(t, string(contracts.VerdictAllow), dec.Verdict)
		assert.Equal(t, "spiffe://highflame.com/agent-x", evalCtx.Request.Principal)
		assert.Equal(t, "zeroid_verified", evalCtx.PDPBackend)
	})

	t.Run("Invalid SPIFFE URI format is denied fail-closed", func(t *testing.T) {
		g := newMinimalGuardian()
		interceptor := NewZeroIDInterceptor(g, nil)

		evalCtx := &EvaluationContext{
			Request: DecisionRequest{
				Principal: "spiffe://highflame.com/agent-x",
				Action:    "EXECUTE_TOOL",
				Resource:  "http.get",
				Context: map[string]interface{}{
					"zeroid_token": "token_valid_123",
					"spiffe_uri":   "invalid-spiffe-format://highflame.com/agent-x",
				},
			},
		}

		calledNext := false
		next := func(ctx context.Context, eCtx *EvaluationContext) (*contracts.DecisionRecord, error) {
			calledNext = true
			return &contracts.DecisionRecord{Verdict: string(contracts.VerdictAllow)}, nil
		}

		dec, err := interceptor.Evaluate(context.Background(), evalCtx, next)
		assert.NoError(t, err)
		assert.False(t, calledNext)
		assert.Equal(t, string(contracts.VerdictDeny), dec.Verdict)
		assert.Equal(t, string(contracts.ReasonIdentityIsolationViolation), dec.ReasonCode)
	})

	t.Run("Revoked token is denied fail-closed via CAEP", func(t *testing.T) {
		g := newMinimalGuardian()
		interceptor := NewZeroIDInterceptor(g, nil)
		interceptor.IngestCAEPRevocation("revoked_token_456")

		evalCtx := &EvaluationContext{
			Request: DecisionRequest{
				Principal: "spiffe://highflame.com/agent-x",
				Action:    "EXECUTE_TOOL",
				Resource:  "http.get",
				Context: map[string]interface{}{
					"zeroid_token": "revoked_token_456",
					"spiffe_uri":   "spiffe://highflame.com/agent-x",
				},
			},
		}

		calledNext := false
		next := func(ctx context.Context, eCtx *EvaluationContext) (*contracts.DecisionRecord, error) {
			calledNext = true
			return &contracts.DecisionRecord{Verdict: string(contracts.VerdictAllow)}, nil
		}

		dec, err := interceptor.Evaluate(context.Background(), evalCtx, next)
		assert.NoError(t, err)
		assert.False(t, calledNext)
		assert.Equal(t, string(contracts.VerdictDeny), dec.Verdict)
		assert.Equal(t, string(contracts.ReasonTaintedCredentialDeny), dec.ReasonCode)
	})
}
