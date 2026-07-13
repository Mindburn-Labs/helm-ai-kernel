package guardian

import (
	"context"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/safedep"
)

func TestEvaluateDecisionResolvesSafeDepAuthorityForCanonicalDecisionEffect(t *testing.T) {
	clock := newFixedClock()
	var received []safedep.AuthorityRequest
	resolver := safedep.AuthorityResolverFunc(func(_ context.Context, request safedep.AuthorityRequest) (safedep.GateRequest, error) {
		received = append(received, request)
		return safedep.GateRequest{}, nil
	})
	guardian := NewGuardian(
		&testSigner{},
		allowGraphFor("connector.rotate"),
		nil,
		WithClock(clock),
		WithSafeDepController(safedep.NewController(safedep.ControllerConfig{Clock: clock.Now})),
		WithSafeDepAuthorityResolver(resolver),
	)
	request := DecisionRequest{
		Principal:   "principal-a",
		Action:      "EXECUTE_TOOL",
		Resource:    "connector.rotate",
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		SessionID:   "session-a",
		Context:     map[string]interface{}{"target": "staging"},
	}

	decision, err := guardian.EvaluateDecision(context.Background(), request)
	if err != nil {
		t.Fatalf("EvaluateDecision: %v", err)
	}
	if decision.Verdict != string(contracts.VerdictAllow) {
		t.Fatalf("decision verdict = %s, want ALLOW: %+v", decision.Verdict, decision)
	}
	if len(received) != 1 {
		t.Fatalf("SafeDep resolver calls = %d, want 1", len(received))
	}
	got := received[0]
	if got.DecisionID != decision.ID || got.EffectDigestHash != decision.EffectDigest || got.EffectDigestHash == "" {
		t.Fatalf("SafeDep authority was not bound to signed decision/effect: got=%+v decision=%+v", got, decision)
	}
	if got.TenantID != decision.TenantID || got.WorkspaceID != decision.WorkspaceID || got.SessionID != decision.SessionID || got.SubjectID != decision.SubjectID {
		t.Fatalf("SafeDep authority scope = %+v, want decision scope %+v", got, decision)
	}
	if got.EffectType != "EXECUTE_TOOL" || got.Action != "EXECUTE_TOOL" || got.ToolName != "connector.rotate" {
		t.Fatalf("SafeDep authority effect tuple = %+v", got)
	}
	if _, found := request.Context["safe_deprecation_state"]; found {
		t.Fatalf("SafeDep classification mutated the effect context after digesting it: %#v", request.Context)
	}
}

func TestIssueExecutionIntentFailsClosedForDegradedSafeDepAuthority(t *testing.T) {
	clock := newFixedClock()
	resolverCalls := 0
	resolver := safedep.AuthorityResolverFunc(func(_ context.Context, request safedep.AuthorityRequest) (safedep.GateRequest, error) {
		resolverCalls++
		if request.DecisionID == "" || request.EffectDigestHash == "" {
			t.Fatalf("SafeDep resolver received unbound request: %+v", request)
		}
		return safedep.GateRequest{Signal: safedep.Signal{
			HazardCode:  contracts.HazardCredentialExpired,
			ActiveClock: true,
		}}, nil
	})
	guardian := NewGuardian(
		&testSigner{},
		allowGraphFor("connector.rotate"),
		nil,
		WithClock(clock),
		WithSafeDepController(safedep.NewController(safedep.ControllerConfig{Clock: clock.Now})),
		WithSafeDepAuthorityResolver(resolver),
	)
	request := DecisionRequest{
		Principal:   "principal-a",
		Action:      "EXECUTE_TOOL",
		Resource:    "connector.rotate",
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		SessionID:   "session-a",
		Context:     map[string]interface{}{"target": "staging"},
	}
	decision, err := guardian.EvaluateDecision(context.Background(), request)
	if err != nil {
		t.Fatalf("EvaluateDecision: %v", err)
	}
	if decision.Verdict != string(contracts.VerdictAllow) {
		t.Fatalf("degraded state should be held at intent issuance, got %+v", decision)
	}
	effect := &contracts.Effect{
		EffectID:   "effect-degraded-safedep",
		EffectType: request.Action,
		Params:     request.Context,
	}
	intent, err := guardian.IssueExecutionIntent(context.Background(), decision, effect)
	if err == nil || !strings.Contains(err.Error(), "activation is required") {
		t.Fatalf("degraded SafeDep authority issued executable intent=%+v err=%v", intent, err)
	}
	if intent != nil || resolverCalls != 2 {
		t.Fatalf("degraded SafeDep did not fail closed at issuance: intent=%+v resolver_calls=%d", intent, resolverCalls)
	}
}
