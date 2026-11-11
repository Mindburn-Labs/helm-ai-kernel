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
// params, set by the in-process code that builds the effect. An evaluated
// request has no typed field for it, so a tool_name in its context is the
// caller's: the request is evaluated as CALL_TOOL, whatever the context or the
// resource says.
func TestEvaluateDecisionEvaluatesCallToolRequestsAsTheirType(t *testing.T) {
	for _, tc := range []struct {
		name     string
		rules    []string
		resource string
		verdict  contracts.Verdict
	}{
		{"context tool_name does not select a rule", []string{"local.echo"}, "step-1", contracts.VerdictDeny},
		{"the resource does not select a rule", []string{"local.echo"}, "local.echo", contracts.VerdictDeny},
		{"the rule for CALL_TOOL decides", []string{contracts.EffectTypeCallTool}, "step-1", contracts.VerdictAllow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := actionBindingGuardian(t, tc.rules...)
			requestContext := map[string]interface{}{"tool_name": "local.echo"}
			decision, err := g.EvaluateDecision(context.Background(), DecisionRequest{
				Principal: "agent-1",
				Action:    contracts.EffectTypeCallTool,
				Resource:  tc.resource,
				Context:   requestContext,
			})
			if err != nil {
				t.Fatal(err)
			}
			if decision.Verdict != string(tc.verdict) {
				t.Fatalf("verdict=%s reason=%s, want %s", decision.Verdict, decision.ReasonCode, tc.verdict)
			}
			if _, kept := requestContext["tool_name"]; kept {
				t.Fatal("the caller's tool_name stayed in the context that gates and the policy decision point read")
			}
		})
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

// The context every gate and the policy decision point reads holds the tool
// Guardian bound, before any of them runs.
func TestBindRequestToolRunsBeforeTheContextIsRead(t *testing.T) {
	for _, tc := range []struct {
		action, resource string
		context          map[string]interface{}
		want             any
		present          bool
	}{
		{"EXECUTE_TOOL", "local.echo", map[string]interface{}{"tool_name": "db.drop_database"}, "local.echo", true},
		{"EXECUTE_TOOL", "local.echo", nil, "local.echo", true},
		{contracts.EffectTypeCallTool, "step-1", map[string]interface{}{"tool_name": "db.drop_database"}, nil, false},
		{"LLM_INFERENCE", "model-1", map[string]interface{}{"tool_name": "kept: content, not authority"}, "kept: content, not authority", true},
	} {
		bound := bindRequestTool(tc.action, tc.resource, tc.context)
		got, present := bound["tool_name"]
		if present != tc.present || got != tc.want {
			t.Fatalf("bindRequestTool(%s, %s) tool_name = %v (present %v), want %v (present %v)", tc.action, tc.resource, got, present, tc.want, tc.present)
		}
	}
}

// The keys that carry the effect class and its provenance are bound by a
// trusted transport only; a caller's copy is stripped (CTL-022).
func TestEffectClassProvenanceKeysAreReserved(t *testing.T) {
	for _, key := range []string{ContextEffectClass, ContextEffectClassSource, ContextEffectClassDeclared} {
		if !IsReservedSecurityContextKey(key) {
			t.Fatalf("%q is not a reserved security context key: a caller could assert it", key)
		}
	}
}
