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

func TestTaintEgressOverrideRequiresTrustedContext(t *testing.T) {
	t.Run("caller-set override without trusted context is ignored", func(t *testing.T) {
		t.Setenv("HELM_TAINT_TRACKING", "1")
		g := newMinimalGuardian()

		dec, err := g.EvaluateDecision(context.Background(), DecisionRequest{
			Principal: "untrusted-agent",
			Action:    "EXECUTE_TOOL",
			Resource:  "http.post",
			Context: map[string]interface{}{
				"destination":          "https://external.egress.com/upload",
				"taint":                []string{contracts.TaintCredential},
				"allow_tainted_egress": true, // attacker-controlled: must not bypass
			},
		})
		assert.NoError(t, err)
		assert.Equal(t, string(contracts.VerdictDeny), dec.Verdict)
		assert.Equal(t, string(contracts.ReasonTaintedEgressDeny), dec.ReasonCode)
	})

	t.Run("override honored only from trusted security context", func(t *testing.T) {
		t.Setenv("HELM_TAINT_TRACKING", "1")
		g := newMinimalGuardian()

		dec, err := g.EvaluateDecision(context.Background(), DecisionRequest{
			Principal: "trusted-adapter",
			Action:    "EXECUTE_TOOL",
			Resource:  "http.post",
			Context: map[string]interface{}{
				ContextSecurityTrusted: true, // bound by trusted transport boundary
				"destination":          "https://external.egress.com/upload",
				"taint":                []string{contracts.TaintCredential},
				"allow_tainted_egress": true,
			},
		})
		assert.NoError(t, err)
		// Gate bypassed: evaluation proceeds to PRG, which has no rule.
		assert.Equal(t, string(contracts.ReasonNoPolicy), dec.ReasonCode)
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

// Tainted-egress enforcement defaults to ON.
//
// Previously HELM_TAINT_TRACKING had to be set to "1"/"true" to enforce, so with
// it unset the `&&` at the call site short-circuited and TAINTED_DATA_EGRESS_DENY
// never evaluated. That left the implementation weaker than its own proof:
// proofs/GuardianPipeline.tla:52-53 asserts TaintSafeEgress unconditionally, it
// is enforced as an INVARIANT in guardian.cfg, and it is model-checked on every
// PR. These cases pin the code to the proof.
func TestTaintEgressEnforcementDefault(t *testing.T) {
	taintedRequest := func() DecisionRequest {
		return DecisionRequest{
			Principal: "untrusted-agent",
			Action:    "EXECUTE_TOOL",
			Resource:  "http.post",
			Context: map[string]interface{}{
				"destination": "https://external.egress.com/upload",
				"taint":       []string{contracts.TaintCredential},
			},
		}
	}

	t.Run("unset enforces", func(t *testing.T) {
		t.Setenv("HELM_TAINT_TRACKING", "")
		g := newMinimalGuardian()

		dec, err := g.EvaluateDecision(context.Background(), taintedRequest())
		assert.NoError(t, err)
		assert.Equal(t, string(contracts.VerdictDeny), dec.Verdict,
			"unset must enforce: an unconfigured kernel had no tainted-egress boundary")
		assert.Equal(t, string(contracts.ReasonTaintedEgressDeny), dec.ReasonCode)
	})

	t.Run("unparseable value enforces", func(t *testing.T) {
		// A typo must not silently open a security boundary.
		t.Setenv("HELM_TAINT_TRACKING", "yes")
		g := newMinimalGuardian()

		dec, err := g.EvaluateDecision(context.Background(), taintedRequest())
		assert.NoError(t, err)
		assert.Equal(t, string(contracts.VerdictDeny), dec.Verdict,
			"only an explicit 0/false may disable enforcement")
		assert.Equal(t, string(contracts.ReasonTaintedEgressDeny), dec.ReasonCode)
	})

	t.Run("explicit opt-out disables", func(t *testing.T) {
		// Retained for incident response; logged once at construction.
		t.Setenv("HELM_TAINT_TRACKING", "0")
		g := newMinimalGuardian()

		dec, err := g.EvaluateDecision(context.Background(), taintedRequest())
		assert.NoError(t, err)
		// Equal, not NotEqual: NotEqual would pass for any other reason code,
		// including unrelated breakage. Skipped gate falls through to PRG.
		assert.Equal(t, string(contracts.ReasonNoPolicy), dec.ReasonCode,
			"explicit opt-out must skip the deny and fall through to PRG")
	})

	t.Run("false also disables", func(t *testing.T) {
		t.Setenv("HELM_TAINT_TRACKING", "FALSE")
		g := newMinimalGuardian()

		dec, err := g.EvaluateDecision(context.Background(), taintedRequest())
		assert.NoError(t, err)
		assert.Equal(t, string(contracts.ReasonNoPolicy), dec.ReasonCode)
	})
}

// allow_tainted_egress is a security decision and must be bound by the transport,
// never accepted as a caller argument. fee619c9 required a trusted context before
// honouring the override but left the key out of IsReservedSecurityContextKey, so
// any transport that copies non-reserved arguments into the decision context and
// then marks it trusted -- pkg/mcp/server.go does this -- let a caller smuggle the
// override in and self-approve its own tainted egress.
func TestAllowTaintedEgressIsReservedSecurityContextKey(t *testing.T) {
	if !IsReservedSecurityContextKey(ContextAllowTaintedEgress) {
		t.Fatal("allow_tainted_egress must be transport-bound: a caller argument could otherwise self-approve tainted egress")
	}
	if taintedEgressDenied(map[string]interface{}{
		ContextDestination: "https://external.example.com", ContextAllowTaintedEgress: true, ContextSecurityTrusted: true,
	}, []string{contracts.TaintSecret}) {
		t.Fatal("transport-bound override must still suppress the deny")
	}
	if !taintedEgressDenied(map[string]interface{}{
		ContextDestination: "https://external.example.com", ContextAllowTaintedEgress: true,
	}, []string{contracts.TaintSecret}) {
		t.Fatal("untrusted override must not suppress the deny")
	}
}

// Taint labelling is unconditional; the variable gates only the built-in deny.
func TestTaintLabellingIsUnconditional(t *testing.T) {
	t.Setenv("HELM_TAINT_TRACKING", "0")
	evalCtx := &EvaluationContext{Request: DecisionRequest{
		Principal: "agent", Action: "EXECUTE_TOOL", Resource: "http.post",
		Context: map[string]interface{}{
			ContextDestination: "https://external.egress.com/upload",
			"taint":            []string{contracts.TaintPII},
		},
	}}
	passThrough := func(context.Context, *EvaluationContext) (*contracts.DecisionRecord, error) {
		return &contracts.DecisionRecord{Verdict: string(contracts.VerdictAllow)}, nil
	}
	_, err := NewTaintEgressInterceptor(newMinimalGuardian()).Evaluate(context.Background(), evalCtx, passThrough)
	assert.NoError(t, err)
	assert.True(t, evalCtx.Tainted, "taint labelling must run even with enforcement disabled")
	assert.NotNil(t, evalCtx.Request.Context["taint"], "taint labels must reach the CEL input")
}
