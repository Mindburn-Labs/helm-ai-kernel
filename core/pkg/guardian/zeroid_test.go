package guardian

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/stretchr/testify/assert"
)

func TestZeroIDContinuousEvaluation(t *testing.T) {
	// F-04 regression. This case previously asserted that a well-formed but
	// entirely unverified SPIFFE URI was copied over Request.Principal and
	// labelled "zeroid_verified" — i.e. it locked in a cross-tenant
	// impersonation primitive as intended behaviour. A ZeroID envelope that
	// cannot be verified must be denied, and the authenticated principal must
	// never be replaced by request-supplied data.
	t.Run("Unverifiable ZeroID envelope is denied and never rebinds the principal", func(t *testing.T) {
		g := newMinimalGuardian()
		interceptor := NewZeroIDInterceptor(g)

		const authenticated = "spiffe://tenant-a.example/low-privilege-agent"
		evalCtx := &EvaluationContext{
			Request: DecisionRequest{
				Principal: authenticated,
				Action:    "EXECUTE_TOOL",
				Resource:  "payments.transfer",
				Context: map[string]interface{}{
					"zeroid_token": "token_valid_123",
					"spiffe_uri":   "spiffe://tenant-b.example/admin",
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
		assert.False(t, calledNext, "an unverifiable envelope must not reach the rest of the chain")
		assert.Equal(t, string(contracts.VerdictDeny), dec.Verdict)
		assert.Equal(t, string(contracts.ReasonIdentityIsolationViolation), dec.ReasonCode)
		assert.Equal(t, authenticated, evalCtx.Request.Principal,
			"the authenticated principal must survive untouched")
		assert.NotEqual(t, "zeroid_verified", evalCtx.PDPBackend,
			"nothing was verified, so nothing may be labelled verified")
	})

	t.Run("Requests with no ZeroID envelope pass through untouched", func(t *testing.T) {
		g := newMinimalGuardian()
		interceptor := NewZeroIDInterceptor(g)

		const authenticated = "spiffe://tenant-a.example/agent"
		evalCtx := &EvaluationContext{
			Request: DecisionRequest{
				Principal: authenticated,
				Action:    "EXECUTE_TOOL",
				Resource:  "http.get",
				Context:   map[string]interface{}{},
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
		assert.Equal(t, authenticated, evalCtx.Request.Principal)
	})

	t.Run("Invalid SPIFFE URI format is denied fail-closed", func(t *testing.T) {
		g := newMinimalGuardian()
		interceptor := NewZeroIDInterceptor(g)

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
		interceptor := NewZeroIDInterceptor(g)
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
