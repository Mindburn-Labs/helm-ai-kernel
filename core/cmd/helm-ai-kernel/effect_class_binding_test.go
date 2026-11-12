package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/extauthz"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
)

// The effect class a policy ceiling selects on is authority. A request can
// only declare one. The declaration is bound as it is and marked
// caller_declared, unless the kernel's catalog knows the evaluated action:
// then the bound class is never below the catalog's, and the replaced
// declaration is kept beside it. The evaluated action is the request's action,
// or the resource of EXECUTE_TOOL. The resource of any other action is the
// caller's description: it raises a declared class and does nothing else.
func TestResolveEffectClass(t *testing.T) {
	const (
		declaredByCaller = guardian.EffectClassSourceCallerDeclared
		fromCatalog      = guardian.EffectClassSourceEffectCatalog
	)
	for _, tc := range []struct {
		name, action, resource, declared string
		class, source, replaced          string
	}{
		{"declared class, action unknown to the kernel", "local.echo", "E1", "E1", "E1", declaredByCaller, ""},
		{"declared class is trimmed", "local.echo", "", " E2 ", "E2", declaredByCaller, ""},
		{"a policy label is bound as it is", "local.echo", "ticket:123", "ticket:123", "ticket:123", declaredByCaller, ""},
		{"a value outside the closed set is a label", "urn:tool:pay", "urn:tool:pay", "E9", "E9", declaredByCaller, ""},
		{"nothing declared, nothing catalogued", "local.echo", "", "", "", "", ""},
		{"catalogued action declared below its class", contracts.EffectTypeInfraDestroy, "E0", "E0", "E4", fromCatalog, "E0"},
		{"catalogued action with a label in place of a class", contracts.EffectTypeExecutePayment, "invoice:42", "invoice:42", "E4", fromCatalog, "invoice:42"},
		{"catalogued action with nothing declared", contracts.EffectTypeInfraDestroy, "", "", "E4", fromCatalog, ""},
		{"catalogued action declared at its class", contracts.EffectTypeSendChatMessage, "E1", "E1", "E1", fromCatalog, ""},
		{"catalogued action declared above its class", contracts.EffectTypeSendChatMessage, "E3", "E3", "E3", declaredByCaller, ""},
		{"catalogued effect named as the resource of EXECUTE_TOOL", "EXECUTE_TOOL", contracts.EffectTypeExecutePayment, "E0", "E4", fromCatalog, "E0"},
		{"catalogued effect named as the resource of EXECUTE_TOOL on the evaluate route", "EXECUTE_TOOL", contracts.EffectTypeInfraDestroy, contracts.EffectTypeInfraDestroy, "E4", fromCatalog, contracts.EffectTypeInfraDestroy},
		{"a reserved preview effect is known to the kernel", contracts.EffectTypeProviderTeardown, "E0", "E0", "E4", fromCatalog, "E0"},
		// The resource of an action other than EXECUTE_TOOL.
		{"a catalogued resource raises a lower declared class of CALL_TOOL", contracts.EffectTypeCallTool, contracts.EffectTypeInfraDestroy, "E0", "E4", declaredByCaller, "E0"},
		{"a catalogued resource raises a lower declared class of an unknown action", "db.drop_database", contracts.EffectTypeExecutePayment, "E0", "E4", declaredByCaller, "E0"},
		{"a catalogued resource never lowers a declared class", "db.drop_database", contracts.EffectTypeCreateTask, "E3", "E3", declaredByCaller, ""},
		{"a catalogued resource at the declared class changes nothing", "db.drop_database", contracts.EffectTypeCreateTask, "E1", "E1", declaredByCaller, ""},
		{"a catalogued resource never replaces a label", "db.drop_database", contracts.EffectTypeCreateTask, "ticket.write", "ticket.write", declaredByCaller, ""},
		{"a catalogued effect id as the effect_level of an unknown action is a label", "db.drop_database", contracts.EffectTypeCreateTask, contracts.EffectTypeCreateTask, contracts.EffectTypeCreateTask, declaredByCaller, ""},
		{"a catalogued effect id as the effect_level of CALL_TOOL is a label", contracts.EffectTypeCallTool, contracts.EffectTypeCreateTask, contracts.EffectTypeCreateTask, contracts.EffectTypeCreateTask, declaredByCaller, ""},
		{"a catalogued resource with nothing declared binds nothing", "db.drop_database", contracts.EffectTypeCreateTask, "", "", "", ""},
		{"a resource above the action's catalog class raises the declared class", contracts.EffectTypeSendChatMessage, contracts.EffectTypeExecutePayment, "E1", "E4", declaredByCaller, "E1"},
		{"a resource raise below the action's catalog class leaves the catalog's", contracts.EffectTypeInfraDestroy, contracts.EffectTypeCreateTask, "E0", "E4", fromCatalog, "E0"},
		{"a resource does not class a label on a catalogued action", contracts.EffectTypeSendChatMessage, contracts.EffectTypeExecutePayment, "invoice:42", "E1", fromCatalog, "invoice:42"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			class, source, replaced := resolveEffectClass(tc.action, tc.resource, tc.declared)
			if class != tc.class || source != tc.source || replaced != tc.replaced {
				t.Fatalf("resolveEffectClass(%q, %q, %q) = %q from %q replacing %q, want %q from %q replacing %q",
					tc.action, tc.resource, tc.declared, class, source, replaced, tc.class, tc.source, tc.replaced)
			}
		})
	}
}

func allowGraphForEffectClassTest(t *testing.T, actions ...string) *prg.Graph {
	t.Helper()
	graph := prg.NewGraph()
	for _, action := range actions {
		if err := graph.AddRule(action, prg.RequirementSet{
			ID: "allow-" + action, Logic: prg.AND,
			Requirements: []prg.Requirement{{ID: "allow", Expression: "true"}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	return graph
}

// evaluateRouteDecisionContext sends one evaluate request and returns the
// context the policy decision point received.
func evaluateRouteDecisionContext(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-trusted")
	t.Setenv(runtimePrincipalIDEnv, "principal-trusted")
	signer, err := helmcrypto.NewEd25519Signer("effect-class-binding-test")
	if err != nil {
		t.Fatal(err)
	}
	capturing := &evaluateRouteCapturingPDP{}
	svc := &Services{
		Guardian: guardian.NewGuardian(signer,
			allowGraphForEffectClassTest(t, "local.echo", contracts.EffectTypeInfraDestroy),
			artifacts.NewRegistry(nil, nil), guardian.WithPDP(capturing)),
		ReceiptStore:  &captureReceiptStore{},
		ReceiptSigner: signer,
	}
	mux := http.NewServeMux()
	registerReceiptRoutes(mux, svc)

	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	req.Header.Set(tenantHeader, "tenant-trusted")
	req.Header.Set(principalHeader, "principal-trusted")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("evaluate status = %d body=%s", rec.Code, rec.Body.String())
	}
	if capturing.request == nil {
		t.Fatal("the request did not reach the policy decision point; the case proves nothing")
	}
	return capturing.request.Context
}

func requireEffectClassBinding(t *testing.T, decisionContext map[string]any, class, source string, declared any) {
	t.Helper()
	if decisionContext[guardian.ContextEffectClass] != class || decisionContext[guardian.ContextEffectClassSource] != source ||
		decisionContext[guardian.ContextEffectClassDeclared] != declared {
		t.Fatalf("policy received effect_class=%v source=%v declared=%v, want %q from %q declared %v",
			decisionContext[guardian.ContextEffectClass], decisionContext[guardian.ContextEffectClassSource],
			decisionContext[guardian.ContextEffectClassDeclared], class, source, declared)
	}
}

func TestEvaluateRouteBindsCatalogEffectClassOverCallerDeclaration(t *testing.T) {
	decisionContext := evaluateRouteDecisionContext(t, map[string]any{
		"tool": contracts.EffectTypeInfraDestroy, "effect_level": "E0", "session_id": "s-1",
	})
	requireEffectClassBinding(t, decisionContext, "E4", guardian.EffectClassSourceEffectCatalog, "E0")
}

// Naming the catalogued effect as the tool of an EXECUTE_TOOL request selects
// its policy rule, so it must select its class too.
func TestEvaluateRouteBindsCatalogEffectClassForAToolCallEnvelope(t *testing.T) {
	decisionContext := evaluateRouteDecisionContext(t, map[string]any{
		"tool": "EXECUTE_TOOL", "effect_level": contracts.EffectTypeInfraDestroy, "session_id": "s-1",
	})
	requireEffectClassBinding(t, decisionContext, "E4", guardian.EffectClassSourceEffectCatalog, contracts.EffectTypeInfraDestroy)
}

func TestEvaluateRouteMarksDeclaredEffectClassAsCallerDeclared(t *testing.T) {
	for _, level := range []string{"E1", "ticket:123", "E9"} {
		t.Run(level, func(t *testing.T) {
			decisionContext := evaluateRouteDecisionContext(t, map[string]any{
				"tool": "local.echo", "effect_level": level, "session_id": "s-1",
				// A caller cannot attest its own declaration, or plant another.
				"context": map[string]any{
					"effect_class":          "E0",
					"effect_class_source":   guardian.EffectClassSourceEffectCatalog,
					"effect_class_declared": "E0",
				},
			})
			requireEffectClassBinding(t, decisionContext, level, guardian.EffectClassSourceCallerDeclared, nil)
		})
	}
}

// The policy decision point reads the tool Guardian bound from the typed
// request, not the caller's context value.
func TestEvaluateRoutePolicySeesTheBoundToolName(t *testing.T) {
	decisionContext := evaluateRouteDecisionContext(t, map[string]any{
		"tool": "EXECUTE_TOOL", "effect_level": "local.echo", "session_id": "s-1",
		"context": map[string]any{"tool_name": "db.drop_database"},
	})
	if decisionContext["tool_name"] != "local.echo" {
		t.Fatalf("policy received tool_name=%v, want the request resource", decisionContext["tool_name"])
	}
}

// extAuthzDecisionContext authorizes one ext-authz request and returns the
// context the policy decision point received.
func extAuthzDecisionContext(t *testing.T, mutate func(*extauthz.AuthorizationRequest)) map[string]any {
	t.Helper()
	signer, err := helmcrypto.NewEd25519Signer("extauthz-effect-class-test")
	if err != nil {
		t.Fatal(err)
	}
	capturing := &evaluateRouteCapturingPDP{}
	svc := &Services{
		Guardian: guardian.NewGuardian(signer,
			allowGraphForEffectClassTest(t, "local.echo", contracts.EffectTypeExecutePayment, contracts.EffectTypeCallTool),
			artifacts.NewRegistry(nil, nil), guardian.WithPDP(capturing)),
		ReceiptSigner: signer,
	}
	fixture := extAuthzRouteFixture("req-effect-class", "tenant-a", "epoch-1")
	mutate(&fixture)
	ctx := auth.WithAuthenticatedCredential(t.Context(), "extauthz-credential")
	if _, err := authorizeExtAuthzRequest(ctx, svc, fixture, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if capturing.request == nil {
		t.Fatal("the request did not reach the policy decision point; the case proves nothing")
	}
	return capturing.request.Context
}

func TestExtAuthzBindsEffectClassLikeTheEvaluateRoute(t *testing.T) {
	t.Run("a label is bound as it is and marked caller_declared", func(t *testing.T) {
		decisionContext := extAuthzDecisionContext(t, func(req *extauthz.AuthorizationRequest) { req.EffectClass = "ticket.write" })
		requireEffectClassBinding(t, decisionContext, "ticket.write", guardian.EffectClassSourceCallerDeclared, nil)
	})
	t.Run("a catalogued effect named as the tool of EXECUTE_TOOL takes its catalog class", func(t *testing.T) {
		decisionContext := extAuthzDecisionContext(t, func(req *extauthz.AuthorizationRequest) {
			req.ActionURN, req.ToolURN, req.EffectClass = "EXECUTE_TOOL", contracts.EffectTypeExecutePayment, "E0"
		})
		requireEffectClassBinding(t, decisionContext, "E4", guardian.EffectClassSourceEffectCatalog, "E0")
	})
	// CALL_TOOL has no tool Guardian binds: its resource raises the declared
	// class, and the class stays the caller's.
	t.Run("a catalogued effect named as the resource of CALL_TOOL raises the declared class", func(t *testing.T) {
		decisionContext := extAuthzDecisionContext(t, func(req *extauthz.AuthorizationRequest) {
			req.ActionURN, req.ToolURN, req.EffectClass = contracts.EffectTypeCallTool, contracts.EffectTypeExecutePayment, "E0"
		})
		requireEffectClassBinding(t, decisionContext, "E4", guardian.EffectClassSourceCallerDeclared, "E0")
	})
}

// The governed proxy evaluates one fixed kind of effect and assigns its class
// itself; the record says so.
func TestGovernedOpenAIProxyMarksItsEffectClassAsRouteAssigned(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[]}`))
	}))
	defer upstream.Close()
	t.Setenv("HELM_UPSTREAM_URL", upstream.URL)
	signer, err := helmcrypto.NewEd25519Signer("openai-effect-class-test")
	if err != nil {
		t.Fatal(err)
	}
	capturing := &evaluateRouteCapturingPDP{}
	svc := &Services{
		Guardian: guardian.NewGuardian(signer, allowGraphForEffectClassTest(t, "LLM_INFERENCE"),
			artifacts.NewRegistry(nil, nil), guardian.WithPDP(capturing)),
		ReceiptStore:  &captureReceiptStore{},
		ReceiptSigner: signer,
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(
		`{"model":"gpt-test","messages":[],"effect_class":"E0","effect_class_source":"caller_declared"}`,
	))
	req.Header.Set("Authorization", "Bearer provider-secret")
	req.Header.Set(workspaceHeader, "workspace-a")
	ctx := auth.WithPrincipal(req.Context(), &auth.BasePrincipal{ID: "proxy-agent", TenantID: "tenant-a"})
	ctx = auth.WithAuthenticatedCredential(ctx, "proxy-credential")
	handleGovernedOpenAIProxy(httptest.NewRecorder(), req.WithContext(ctx), svc)
	if capturing.request == nil {
		t.Fatal("the request did not reach the policy decision point; the case proves nothing")
	}
	requireEffectClassBinding(t, capturing.request.Context,
		contracts.EffectRiskClass(contracts.EffectTypeDataEgress), guardian.EffectClassSourceKernelRoute, nil)
}
