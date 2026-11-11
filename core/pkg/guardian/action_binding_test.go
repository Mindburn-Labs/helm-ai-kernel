package guardian

import (
	"context"
	"testing"

	pkg_artifact "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
)

// The action id a policy rule is selected by is authority. It comes from the
// typed request tuple the Guardian signs, never from the free-form context a
// caller sends with it.

func actionBindingGuardian(t *testing.T, allowedActions ...string) *Guardian {
	t.Helper()
	graph := prg.NewGraph()
	for _, action := range allowedActions {
		if err := graph.AddRule(action, prg.RequirementSet{
			ID:    "allow-" + action,
			Logic: prg.AND,
			Requirements: []prg.Requirement{
				{ID: "allow", Expression: "true"},
			},
		}); err != nil {
			t.Fatal(err)
		}
	}
	return NewGuardian(&testSigner{}, graph, pkg_artifact.NewRegistry(newTestStore(), nil))
}

func TestEvaluateDecisionIgnoresCallerSuppliedToolNameForPolicyAction(t *testing.T) {
	for _, tc := range []struct {
		name    string
		request DecisionRequest
	}{
		{
			name: "evaluate body names an allowed tool",
			request: DecisionRequest{
				Principal: "agent-1",
				Action:    "db.drop_database",
				Resource:  "E4",
				Context:   map[string]interface{}{"tool_name": "local.echo"},
			},
		},
		{
			name: "proxied request body names an allowed tool",
			request: DecisionRequest{
				Principal: "agent-1",
				Action:    "LLM_INFERENCE",
				Resource:  "model-1",
				Context:   map[string]interface{}{"model": "model-1", "tool_name": "local.echo"},
			},
		},
		{
			name: "execute tool binds the resource over caller context",
			request: DecisionRequest{
				Principal: "agent-1",
				Action:    "EXECUTE_TOOL",
				Resource:  "db.drop_database",
				Context:   map[string]interface{}{"tool_name": "local.echo"},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := actionBindingGuardian(t, "local.echo")
			decision, err := g.EvaluateDecision(context.Background(), tc.request)
			if err != nil {
				t.Fatal(err)
			}
			if decision.Verdict != string(contracts.VerdictDeny) || decision.ReasonCode != string(contracts.ReasonNoPolicy) {
				t.Fatalf("caller-supplied tool_name selected the policy rule: verdict=%s reason=%s action=%s resource=%s",
					decision.Verdict, decision.ReasonCode, decision.Action, decision.Resource)
			}
			if decision.Action != tc.request.Action || decision.Resource != tc.request.Resource {
				t.Fatalf("signed tuple = %s/%s, want the evaluated request %s/%s",
					decision.Action, decision.Resource, tc.request.Action, tc.request.Resource)
			}
		})
	}
}

func TestEvaluateDecisionSelectsPolicyByGuardianBoundAction(t *testing.T) {
	for _, tc := range []struct {
		name    string
		request DecisionRequest
	}{
		{
			name: "execute tool is evaluated as its resource",
			request: DecisionRequest{
				Principal: "agent-1",
				Action:    "EXECUTE_TOOL",
				Resource:  "local.echo",
				Context:   map[string]interface{}{"tool_name": "db.drop_database"},
			},
		},
		{
			name: "any other action is evaluated as itself",
			request: DecisionRequest{
				Principal: "agent-1",
				Action:    "status.read",
				Resource:  "E0",
				Context:   map[string]interface{}{"tool_name": "db.drop_database"},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := actionBindingGuardian(t, "local.echo", "status.read")
			decision, err := g.EvaluateDecision(context.Background(), tc.request)
			if err != nil {
				t.Fatal(err)
			}
			if decision.Verdict != string(contracts.VerdictAllow) {
				t.Fatalf("verdict=%s reason=%s, want ALLOW from the rule for the bound action", decision.Verdict, decision.ReasonCode)
			}
		})
	}
}

// An execution intent authorizes dispatch. It may name only the action the
// policy decision was evaluated for.
func TestExecutionIntentAllowsOnlyThePolicyEvaluatedAction(t *testing.T) {
	for _, tc := range []struct {
		name       string
		effectType string
		toolName   string
		want       string
	}{
		{name: "non-tool effect ignores a tool_name param", effectType: "status.read", toolName: "db.drop_database", want: "status.read"},
		{name: "execute tool is bound to its tool", effectType: "EXECUTE_TOOL", toolName: "local.echo", want: "local.echo"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := actionBindingGuardian(t, "status.read", "local.echo")
			effect := &contracts.Effect{
				EffectID:   "eff-intent-binding",
				EffectType: tc.effectType,
				Params:     map[string]any{"tool_name": tc.toolName},
			}
			decision := testDecisionAuthority(&contracts.DecisionRecord{ID: "dec-intent-binding"})
			if err := g.SignDecision(context.Background(), decision, effect, nil, nil); err != nil {
				t.Fatal(err)
			}
			if decision.Verdict != string(contracts.VerdictAllow) {
				t.Fatalf("verdict=%s reason=%s, want ALLOW from the rule for %s", decision.Verdict, decision.ReasonCode, tc.want)
			}
			intent, err := g.IssueExecutionIntent(context.Background(), decision, effect)
			if err != nil {
				t.Fatal(err)
			}
			if intent.AllowedTool != tc.want {
				t.Fatalf("intent allows %q, but policy was evaluated for %q", intent.AllowedTool, tc.want)
			}
		})
	}
}

func TestSignDecisionHonoursToolNameOnlyForExecuteTool(t *testing.T) {
	g := actionBindingGuardian(t, "local.echo")

	denied := testDecisionAuthority(&contracts.DecisionRecord{ID: "dec-action-binding-deny"})
	if err := g.SignDecision(context.Background(), denied, &contracts.Effect{
		EffectID:   "eff-action-binding-deny",
		EffectType: "db.drop_database",
		Params:     map[string]any{"tool_name": "local.echo"},
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if denied.Verdict != string(contracts.VerdictDeny) || denied.ReasonCode != string(contracts.ReasonNoPolicy) {
		t.Fatalf("tool_name param selected the rule for a non-tool effect: verdict=%s reason=%s", denied.Verdict, denied.ReasonCode)
	}

	allowed := testDecisionAuthority(&contracts.DecisionRecord{ID: "dec-action-binding-allow"})
	if err := g.SignDecision(context.Background(), allowed, &contracts.Effect{
		EffectID:   "eff-action-binding-allow",
		EffectType: "EXECUTE_TOOL",
		Params:     map[string]any{"tool_name": "local.echo"},
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if allowed.Verdict != string(contracts.VerdictAllow) {
		t.Fatalf("verdict=%s reason=%s, want ALLOW for the bound tool", allowed.Verdict, allowed.ReasonCode)
	}
}

// CALL_TOOL is the other effect type whose contract carries the tool in
// params. On the evaluated-request path its tool is the request resource too.
func TestEvaluateDecisionBindsCallToolToTheRequestResource(t *testing.T) {
	g := actionBindingGuardian(t, "local.echo")
	denied, err := g.EvaluateDecision(context.Background(), DecisionRequest{
		Principal: "agent-1",
		Action:    contracts.EffectTypeCallTool,
		Resource:  "db.drop_database",
		Context:   map[string]interface{}{"tool_name": "local.echo"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if denied.Verdict != string(contracts.VerdictDeny) || denied.ReasonCode != string(contracts.ReasonNoPolicy) {
		t.Fatalf("caller-supplied tool_name selected the rule for CALL_TOOL: verdict=%s reason=%s", denied.Verdict, denied.ReasonCode)
	}
	allowed, err := g.EvaluateDecision(context.Background(), DecisionRequest{
		Principal: "agent-1",
		Action:    contracts.EffectTypeCallTool,
		Resource:  "local.echo",
		Context:   map[string]interface{}{"tool_name": "db.drop_database"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if allowed.Verdict != string(contracts.VerdictAllow) {
		t.Fatalf("verdict=%s reason=%s, want ALLOW from the rule for the request resource", allowed.Verdict, allowed.ReasonCode)
	}
}

// An effect built by trusted in-process code names its tool in params for
// both tool-call effect types, and the intent allows exactly that tool.
func TestBoundActionIDReadsToolNameForBothToolCallEffectTypes(t *testing.T) {
	for _, effectType := range []string{"EXECUTE_TOOL", contracts.EffectTypeCallTool} {
		got := boundActionID(&contracts.Effect{EffectType: effectType, Params: map[string]any{"tool_name": "local.echo"}})
		if got != "local.echo" {
			t.Fatalf("boundActionID(%s) = %q, want the params tool", effectType, got)
		}
	}
	if got := boundActionID(&contracts.Effect{EffectType: "LLM_INFERENCE", Params: map[string]any{"tool_name": "local.echo"}}); got != "LLM_INFERENCE" {
		t.Fatalf("boundActionID(LLM_INFERENCE) = %q, want the effect type", got)
	}
}
