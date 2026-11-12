package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/extauthz"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/pdp"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
)

// These tests decide through a real managed policy, so they hold the verdict a
// bound class leads to and not only the class.

const effectClassPolicySourceHash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

var (
	allowE1ForEffectClassTest = pdp.ManagedPolicyRule{
		ID: "p1-e1", Layer: pdp.ManagedPolicyLayerP1, EffectClass: "E1", Verdict: contracts.VerdictAllow, Reason: "E1 is allowed",
	}
	denyCallerDeclaredForEffectClassTest = pdp.ManagedPolicyRule{
		ID: "p0-declared", Layer: pdp.ManagedPolicyLayerP0, Pattern: `"effect_class_source":"caller_declared"`,
		Verdict: contracts.VerdictDeny, Reason: "only kernel-classified effects",
	}
)

// managedPolicyForEffectClassTest denies E4, allows E0 and escalates E3, plus
// the given rules.
func managedPolicyForEffectClassTest(t *testing.T, extra ...pdp.ManagedPolicyRule) *pdp.ManagedPolicyPDP {
	t.Helper()
	rules := append([]pdp.ManagedPolicyRule{
		{ID: "p0-e4", Layer: pdp.ManagedPolicyLayerP0, EffectClass: "E4", Verdict: contracts.VerdictDeny, Reason: "irreversible effects are denied"},
		{ID: "p1-e0", Layer: pdp.ManagedPolicyLayerP1, EffectClass: "E0", Verdict: contracts.VerdictAllow, Reason: "read-only effects are allowed"},
		{ID: "p1-e3", Layer: pdp.ManagedPolicyLayerP1, EffectClass: "E3", Verdict: contracts.VerdictEscalate, Reason: "external effects require approval"},
	}, extra...)
	data, err := json.Marshal(pdp.ManagedPolicyBundle{
		P0Ceilings:           json.RawMessage(`{"version":"1.0.0"}`),
		P1Bundle:             json.RawMessage(`{"version":"1.0.0"}`),
		P2Overlay:            json.RawMessage(`{"version":"1.0.0"}`),
		ApprovalRoutes:       json.RawMessage(`{"E3_default":{"level":"SINGLE_HUMAN"}}`),
		SourceLanguage:       "cel-dp",
		SourceHash:           effectClassPolicySourceHash,
		CompiledArtifactKind: pdp.ManagedPolicyArtifactKind,
		KernelRuntime: pdp.ManagedPolicyRuntime{
			SchemaVersion:  pdp.ManagedPolicySchemaV1,
			DefaultVerdict: contracts.VerdictDeny,
			Rules:          rules,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := pdp.NewManagedPolicyPDP(data, []string{effectClassPolicySourceHash})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

// recordingManagedPolicy keeps the context the managed policy was asked about
// and lets the policy decide.
type recordingManagedPolicy struct {
	*pdp.ManagedPolicyPDP
	seen map[string]any
}

func (p *recordingManagedPolicy) Evaluate(ctx context.Context, req *pdp.DecisionRequest) (*pdp.DecisionResponse, error) {
	p.seen = make(map[string]any, len(req.Context))
	for key, value := range req.Context {
		p.seen[key] = value
	}
	return p.ManagedPolicyPDP.Evaluate(ctx, req)
}

func (p *recordingManagedPolicy) requireEffectClass(t *testing.T, class, source string, declared any) {
	t.Helper()
	if p.seen == nil {
		t.Fatal("the request did not reach the policy decision point; the case proves nothing")
	}
	requireEffectClassBinding(t, p.seen, class, source, declared)
}

func effectClassPolicyServices(t *testing.T, extra ...pdp.ManagedPolicyRule) (*Services, *recordingManagedPolicy) {
	t.Helper()
	signer, err := helmcrypto.NewEd25519Signer("effect-class-policy-test")
	if err != nil {
		t.Fatal(err)
	}
	policy := &recordingManagedPolicy{ManagedPolicyPDP: managedPolicyForEffectClassTest(t, extra...)}
	return &Services{
		Guardian:      guardian.NewGuardian(signer, prg.NewGraph(), artifacts.NewRegistry(nil, nil), guardian.WithPDP(policy)),
		ReceiptStore:  &captureReceiptStore{},
		ReceiptSigner: signer,
	}, policy
}

func evaluateWithEffectClassPolicy(t *testing.T, svc *Services, body string) api.EvaluateResponse {
	t.Helper()
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-trusted")
	t.Setenv(runtimePrincipalIDEnv, "principal-trusted")
	mux := http.NewServeMux()
	registerReceiptRoutes(mux, svc)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	req.Header.Set(tenantHeader, "tenant-trusted")
	req.Header.Set(principalHeader, "principal-trusted")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("evaluate status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response api.EvaluateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func extAuthzWithEffectClassPolicy(t *testing.T, svc *Services, policy *recordingManagedPolicy, action, toolURN, class string) extauthz.AuthorizationResponse {
	t.Helper()
	fixture := extAuthzRouteFixture("req-effect-class-policy", "tenant-a", "")
	fixture.PolicyHash = policy.PolicyHash()
	fixture.ActionURN, fixture.ToolURN, fixture.EffectClass = action, toolURN, class
	ctx := auth.WithAuthenticatedCredential(t.Context(), "extauthz-credential")
	resp, err := authorizeExtAuthzRequest(ctx, svc, fixture, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// A catalogued effect named as the resource says nothing about an action the
// catalog does not know. If it classed the action, a caller would pick the
// class of any action by naming an E1 effect beside it, and the signed effect
// would call the caller's choice catalogued.
func TestCataloguedResourceDoesNotClassAnActionTheCatalogDoesNotKnow(t *testing.T) {
	const declaredByCaller = guardian.EffectClassSourceCallerDeclared
	t.Run("evaluate", func(t *testing.T) {
		for _, tc := range []struct {
			name, body string
			verdict    contracts.Verdict
			class      string
		}{
			{"an uncatalogued action with a catalogued effect as its effect_level",
				`{"tool":"db.drop_database","effect_level":"CREATE_TASK","session_id":"s-1"}`, contracts.VerdictDeny, contracts.EffectTypeCreateTask},
			{"a generic tool call whose tool is only in args",
				`{"tool":"CALL_TOOL","effect_level":"CREATE_TASK","session_id":"s-1","args":{"tool":"db.drop_database"}}`, contracts.VerdictDeny, contracts.EffectTypeCreateTask},
			{"the same action with the class declared outright",
				`{"tool":"db.drop_database","effect_level":"E1","session_id":"s-1"}`, contracts.VerdictAllow, "E1"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				svc, policy := effectClassPolicyServices(t, allowE1ForEffectClassTest)
				response := evaluateWithEffectClassPolicy(t, svc, tc.body)
				policy.requireEffectClass(t, tc.class, declaredByCaller, nil)
				if response.Verdict != string(tc.verdict) {
					t.Fatalf("verdict=%s reason=%s, want %s", response.Verdict, response.ReasonCode, tc.verdict)
				}
			})
		}
	})
	t.Run("ext-authz", func(t *testing.T) {
		for _, tc := range []struct {
			name, action, toolURN, declared string
			verdict                         string
			class                           string
			kept                            any
		}{
			{"a label is not replaced by the resource's class", "db.drop_database", contracts.EffectTypeCreateTask, "ticket.write", extauthz.VerdictDeny, "ticket.write", nil},
			{"a declared class at the resource's class stays the caller's", "db.drop_database", contracts.EffectTypeCreateTask, "E1", extauthz.VerdictAllow, "E1", nil},
			{"a declared class above the resource's is not lowered", "db.drop_database", contracts.EffectTypeCreateTask, "E2", extauthz.VerdictDeny, "E2", nil},
			{"a declared class below the resource's is raised and kept", "db.drop_database", contracts.EffectTypeExecutePayment, "E0", extauthz.VerdictDeny, "E4", "E0"},
			{"a generic tool call is raised the same way", contracts.EffectTypeCallTool, contracts.EffectTypeExecutePayment, "E0", extauthz.VerdictDeny, "E4", "E0"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				svc, policy := effectClassPolicyServices(t, allowE1ForEffectClassTest)
				response := extAuthzWithEffectClassPolicy(t, svc, policy, tc.action, tc.toolURN, tc.declared)
				policy.requireEffectClass(t, tc.class, declaredByCaller, tc.kept)
				if response.Verdict != tc.verdict {
					t.Fatalf("verdict=%s reason=%s, want %s", response.Verdict, response.ReasonCode, tc.verdict)
				}
			})
		}
	})
	// A policy that admits only kernel-classified effects refuses every one of
	// these: none of them is.
	t.Run("a rule that refuses caller_declared refuses them all", func(t *testing.T) {
		for _, level := range []string{"E1", contracts.EffectTypeCreateTask} {
			svc, policy := effectClassPolicyServices(t, allowE1ForEffectClassTest, denyCallerDeclaredForEffectClassTest)
			response := evaluateWithEffectClassPolicy(t, svc, `{"tool":"db.drop_database","effect_level":"`+level+`","session_id":"s-1"}`)
			policy.requireEffectClass(t, level, declaredByCaller, nil)
			if response.Verdict != string(contracts.VerdictDeny) {
				t.Fatalf("effect_level=%s: verdict=%s, want DENY from the caller_declared rule", level, response.Verdict)
			}
		}
		svc, policy := effectClassPolicyServices(t, allowE1ForEffectClassTest, denyCallerDeclaredForEffectClassTest)
		response := extAuthzWithEffectClassPolicy(t, svc, policy, "db.drop_database", contracts.EffectTypeCreateTask, "E1")
		if response.Verdict != extauthz.VerdictDeny {
			t.Fatalf("ext-authz verdict=%s, want DENY from the caller_declared rule", response.Verdict)
		}
	})
}

// effect_level is documented as a policy resource. A caller whose resource is
// spelled like a catalogued effect id keeps the rule that names it.
func TestEffectLevelSpelledLikeACataloguedEffectStaysAPolicyResource(t *testing.T) {
	svc, policy := effectClassPolicyServices(t, pdp.ManagedPolicyRule{
		ID: "p1-pay", Layer: pdp.ManagedPolicyLayerP1, Action: "pay", Resource: contracts.EffectTypeExecutePayment,
		Verdict: contracts.VerdictAllow, Reason: "pay on this policy resource is allowed",
	})
	response := evaluateWithEffectClassPolicy(t, svc, `{"tool":"pay","effect_level":"EXECUTE_PAYMENT","session_id":"s-1"}`)
	policy.requireEffectClass(t, contracts.EffectTypeExecutePayment, guardian.EffectClassSourceCallerDeclared, nil)
	if response.Verdict != string(contracts.VerdictAllow) {
		t.Fatalf("verdict=%s reason=%s, want ALLOW from the rule for pay on EXECUTE_PAYMENT", response.Verdict, response.ReasonCode)
	}
}

// Guardian evaluates the resource of EXECUTE_TOOL as the tool, so there the
// catalog's class for the resource is the class of what is evaluated.
func TestExecuteToolTakesTheCatalogClassOfItsTool(t *testing.T) {
	svc, policy := effectClassPolicyServices(t, allowE1ForEffectClassTest, denyCallerDeclaredForEffectClassTest)
	response := evaluateWithEffectClassPolicy(t, svc, `{"tool":"EXECUTE_TOOL","effect_level":"CREATE_TASK","session_id":"s-1"}`)
	policy.requireEffectClass(t, "E1", guardian.EffectClassSourceEffectCatalog, contracts.EffectTypeCreateTask)
	if response.Verdict != string(contracts.VerdictAllow) {
		t.Fatalf("verdict=%s reason=%s, want ALLOW for the catalogued E1 tool", response.Verdict, response.ReasonCode)
	}
}

// A deny pattern written when effect_class was followed by the next context
// member still matches now that effect_class_source sorts between them.
func TestEvaluateRouteDenyPatternWrittenBeforeTheProvenanceMembersStillMatches(t *testing.T) {
	svc, policy := effectClassPolicyServices(t, allowE1ForEffectClassTest, pdp.ManagedPolicyRule{
		ID: "p0-adjacent", Layer: pdp.ManagedPolicyLayerP0, Pattern: `"effect_class":"E1","principal_id":"principal-trusted"`,
		Verdict: contracts.VerdictDeny, Reason: "this principal may not run E1",
	})
	response := evaluateWithEffectClassPolicy(t, svc, `{"tool":"local.echo","effect_level":"E1","session_id":"s-1"}`)
	policy.requireEffectClass(t, "E1", guardian.EffectClassSourceCallerDeclared, nil)
	if response.Verdict != string(contracts.VerdictDeny) || response.ReasonCode != string(contracts.ReasonPDPDeny) {
		t.Fatalf("verdict=%s reason=%s, want DENY/PDP_DENY from the adjacency pattern", response.Verdict, response.ReasonCode)
	}
}

// Only EXECUTE_TOOL has a tool Guardian binds. For any other action a
// tool_name in the context is the caller's, and policy never reads it.
func TestEvaluateRoutePolicyNeverSeesACallersToolName(t *testing.T) {
	allowEcho := pdp.ManagedPolicyRule{
		ID: "p1-echo", Layer: pdp.ManagedPolicyLayerP1, Pattern: `"tool_name":"local\.echo"`,
		Verdict: contracts.VerdictAllow, Reason: "echo is allowed",
	}
	for _, tool := range []string{"db.drop_database", contracts.EffectTypeCallTool, contracts.EffectTypeSendEmail} {
		t.Run(tool, func(t *testing.T) {
			svc, policy := effectClassPolicyServices(t, allowEcho)
			response := evaluateWithEffectClassPolicy(t, svc,
				`{"tool":"`+tool+`","effect_level":"E1","session_id":"s-1","context":{"tool_name":"local.echo"}}`)
			if policy.seen == nil {
				t.Fatal("the request did not reach the policy decision point; the case proves nothing")
			}
			if got, present := policy.seen["tool_name"]; present {
				t.Fatalf("policy received the caller's tool_name %v", got)
			}
			if response.Verdict != string(contracts.VerdictDeny) {
				t.Fatalf("verdict=%s reason=%s: the caller's tool_name matched the allow rule for local.echo", response.Verdict, response.ReasonCode)
			}
		})
	}
	t.Run("EXECUTE_TOOL reads the bound tool", func(t *testing.T) {
		svc, policy := effectClassPolicyServices(t, allowEcho)
		response := evaluateWithEffectClassPolicy(t, svc,
			`{"tool":"EXECUTE_TOOL","effect_level":"local.echo","session_id":"s-1","context":{"tool_name":"db.drop_database"}}`)
		if policy.seen["tool_name"] != "local.echo" || response.Verdict != string(contracts.VerdictAllow) {
			t.Fatalf("tool_name=%v verdict=%s, want the request resource and ALLOW", policy.seen["tool_name"], response.Verdict)
		}
	})
}
