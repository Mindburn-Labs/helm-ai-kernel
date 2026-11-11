package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
)

// The effect class a policy ceiling selects on is authority. A request can
// only declare one: the declaration is bound when it is one of E0..E4, never
// below the class the kernel's own catalog gives the action, and always with
// who asserted it.
func TestResolveEffectClass(t *testing.T) {
	for _, tc := range []struct {
		name, action, declared, class, source string
	}{
		{"declared class for an action the kernel has no record of", "local.echo", "E1", "E1", guardian.EffectClassSourceCallerDeclared},
		{"declared class is trimmed", "local.echo", " E2 ", "E2", guardian.EffectClassSourceCallerDeclared},
		{"a policy resource is not a class", "local.echo", "ticket:123", "", ""},
		{"a value outside the closed set is not a class", "local.echo", "E9", "", ""},
		{"lower case is not a class", "local.echo", "e4", "", ""},
		{"catalogued action declared below its class", contracts.EffectTypeInfraDestroy, "E0", "E4", guardian.EffectClassSourceEffectCatalog},
		{"catalogued action with a resource in place of a class", contracts.EffectTypeExecutePayment, "invoice:42", "E4", guardian.EffectClassSourceEffectCatalog},
		{"catalogued action declared at its class", contracts.EffectTypeSendChatMessage, "E1", "E1", guardian.EffectClassSourceEffectCatalog},
		{"catalogued action declared above its class", contracts.EffectTypeSendChatMessage, "E3", "E3", guardian.EffectClassSourceCallerDeclared},
	} {
		t.Run(tc.name, func(t *testing.T) {
			class, source := resolveEffectClass(tc.action, tc.declared)
			if class != tc.class || source != tc.source {
				t.Fatalf("resolveEffectClass(%q, %q) = %q from %q, want %q from %q", tc.action, tc.declared, class, source, tc.class, tc.source)
			}
		})
	}
}

// evaluateEffectClassContext sends one evaluate request and returns the
// effect class and its source as the policy decision point received them.
func evaluateEffectClassContext(t *testing.T, body map[string]any) (class, source any, bound bool) {
	t.Helper()
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-trusted")
	t.Setenv(runtimePrincipalIDEnv, "principal-trusted")
	signer, err := helmcrypto.NewEd25519Signer("effect-class-binding-test")
	if err != nil {
		t.Fatal(err)
	}
	graph := prg.NewGraph()
	for _, action := range []string{"local.echo", contracts.EffectTypeInfraDestroy} {
		if err := graph.AddRule(action, prg.RequirementSet{
			ID: "allow-" + action, Logic: prg.AND,
			Requirements: []prg.Requirement{{ID: "allow", Expression: "true"}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	capturing := &evaluateRouteCapturingPDP{}
	svc := &Services{
		Guardian:      guardian.NewGuardian(signer, graph, artifacts.NewRegistry(nil, nil), guardian.WithPDP(capturing)),
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
	class, bound = capturing.request.Context[guardian.ContextEffectClass]
	return class, capturing.request.Context[guardian.ContextEffectClassSource], bound
}

func TestEvaluateRouteBindsCatalogEffectClassOverCallerDeclaration(t *testing.T) {
	class, source, _ := evaluateEffectClassContext(t, map[string]any{
		"tool": contracts.EffectTypeInfraDestroy, "effect_level": "E0", "session_id": "s-1",
	})
	if class != "E4" || source != guardian.EffectClassSourceEffectCatalog {
		t.Fatalf("a catalogued E4 effect declared as E0 reached policy as %v from %v", class, source)
	}
}

func TestEvaluateRouteMarksDeclaredEffectClassAsCallerDeclared(t *testing.T) {
	class, source, _ := evaluateEffectClassContext(t, map[string]any{
		"tool": "local.echo", "effect_level": "E1", "session_id": "s-1",
		// A caller cannot attest its own declaration.
		"context": map[string]any{"effect_class_source": guardian.EffectClassSourceEffectCatalog, "effect_class": "E0"},
	})
	if class != "E1" || source != guardian.EffectClassSourceCallerDeclared {
		t.Fatalf("declared class reached policy as %v from %v, want E1 marked caller_declared", class, source)
	}
}

func TestEvaluateRouteBindsNoEffectClassForAPolicyResource(t *testing.T) {
	for _, level := range []string{"ticket:123", "E9", "e4", "critical"} {
		t.Run(level, func(t *testing.T) {
			class, source, bound := evaluateEffectClassContext(t, map[string]any{
				"tool": "local.echo", "effect_level": level, "session_id": "s-1",
				"context": map[string]any{"effect_class": "E0"},
			})
			if bound || source != nil {
				t.Fatalf("effect_level %q was bound as trusted effect_class %v from %v", level, class, source)
			}
		})
	}
}
