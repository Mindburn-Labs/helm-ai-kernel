package gateway

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

func TestExecuteOllamaDiscoversDigestAndCallsAPI(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/version", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"version": "0.5.0"})
	})
	mux.HandleFunc("/api/tags", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"models": []map[string]string{{"name": "test-model", "digest": "sha256:abc"}}})
	})
	mux.HandleFunc("/api/chat", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"message": map[string]string{"content": "ok"}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	r := newGatewayRouterWithReceiptTrust()
	if err := r.RouteWithConfig(context.Background(), RouteConfig{Provider: ProviderOllama, BaseURL: srv.URL, ModelName: "test-model"}); err != nil {
		t.Fatal(err)
	}
	res, err := r.Execute(context.Background(), gatewayExecContext(ProviderOllama, "test-model", gatewayAllowSpendDecision(), ExecContext{Prompt: "hello", JSONMode: true}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Content != "ok" || res.ModelHash != "sha256:abc" || res.RuntimeVersion != "0.5.0" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.BudgetVerdict != economic.BudgetVerdictAllow || res.SpendDecisionHash == "" {
		t.Fatalf("missing spend decision evidence on result: %+v", res)
	}
	if res.SpendReceiptHash == "" {
		t.Fatalf("missing spend receipt evidence on result: %+v", res)
	}
}

func TestExecuteOpenAICompatibleRequiresModelHash(t *testing.T) {
	srv := newOpenAICompatibleServer(t, "server-version")
	defer srv.Close()

	r := newGatewayRouterWithReceiptTrust()
	if err := r.RouteWithConfig(context.Background(), RouteConfig{Provider: ProviderVLLM, BaseURL: srv.URL, ModelName: "test-model"}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Execute(context.Background(), gatewayExecContext(ProviderVLLM, "test-model", gatewayAllowSpendDecision(), ExecContext{Prompt: "hello"})); err == nil {
		t.Fatal("expected model hash error")
	}
}

func TestExecuteOpenAICompatibleProviders(t *testing.T) {
	for _, provider := range []ProviderType{ProviderLlamaCPP, ProviderVLLM, ProviderLMStudio} {
		t.Run(string(provider), func(t *testing.T) {
			srv := newOpenAICompatibleServer(t, "server-version")
			defer srv.Close()

			r := newGatewayRouterWithReceiptTrust()
			if err := r.RouteWithConfig(context.Background(), RouteConfig{
				Provider:  provider,
				BaseURL:   srv.URL,
				ModelName: "test-model",
				ModelHash: "sha256:def",
			}); err != nil {
				t.Fatal(err)
			}
			res, err := r.Execute(context.Background(), gatewayExecContext(provider, "test-model", gatewayAllowSpendDecision(), ExecContext{Prompt: "hello"}))
			if err != nil {
				t.Fatal(err)
			}
			if res.Content != "ok" || res.ModelHash != "sha256:def" {
				t.Fatalf("unexpected result: %+v", res)
			}
		})
	}
}

func TestExecuteRejectsEnginePinMismatchBeforeDispatch(t *testing.T) {
	dispatched := false
	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"version": "server-version"})
	})
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, _ *http.Request) {
		dispatched = true
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []map[string]any{{"message": map[string]string{"content": "ok"}}}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	r := newGatewayRouterWithReceiptTrust()
	err := r.RouteWithConfig(context.Background(), RouteConfig{
		Provider:       ProviderVLLM,
		BaseURL:        srv.URL,
		ModelName:      "test-model",
		ModelHash:      "sha256:def",
		RuntimeVersion: "server-version",
		EnginePin: &EnginePin{
			Provider:       ProviderVLLM,
			BaseURL:        srv.URL,
			ModelName:      "test-model",
			ModelHash:      "sha256:def",
			RuntimeVersion: "other-version",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Execute(context.Background(), gatewayExecContext(ProviderVLLM, "test-model", gatewayAllowSpendDecision(), ExecContext{Prompt: "hello"}))
	if err == nil || !strings.Contains(err.Error(), "engine pin mismatch") {
		t.Fatalf("expected engine pin mismatch, got %v", err)
	}
	if dispatched {
		t.Fatal("provider dispatch occurred after engine pin mismatch")
	}
}

func TestExecuteAcceptsEnginePinWithVerifierAndMeasurement(t *testing.T) {
	srv := newOpenAICompatibleServer(t, "server-version")
	defer srv.Close()

	r := newGatewayRouterWithReceiptTrust()
	err := r.RouteWithConfig(context.Background(), RouteConfig{
		Provider:            ProviderVLLM,
		BaseURL:             srv.URL,
		ModelName:           "test-model",
		ModelHash:           "sha256:def",
		RuntimeVersion:      "server-version",
		VerifierProfileID:   "nitro-prod",
		AttestedMeasurement: "sha256:measurement",
		AlternateProfileID:  "nitro-prod-v2",
		EnginePin: &EnginePin{
			Provider:                   ProviderVLLM,
			BaseURL:                    srv.URL,
			ModelName:                  "test-model",
			ModelHash:                  "sha256:def",
			RuntimeVersion:             "server-version",
			VerifierProfileID:          "nitro-prod",
			AttestedMeasurement:        "sha256:measurement",
			ApprovedAlternateProfileID: "nitro-prod-v2",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Execute(context.Background(), gatewayExecContext(ProviderVLLM, "test-model", gatewayAllowSpendDecision(), ExecContext{Prompt: "hello"}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Content != "ok" || res.RuntimeVersion != "server-version" || res.ModelHash != "sha256:def" {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestExecuteRequiresSpendAuthorityAllowBeforeProviderDispatch(t *testing.T) {
	for _, tc := range []struct {
		name     string
		decision *economic.SpendAuthorityDecision
		want     string
	}{
		{name: "missing", decision: nil, want: "spend authority decision required"},
		{name: "deny", decision: gatewaySpendDecision(economic.BudgetVerdictDeny, economic.SpendReasonBalanceInsufficient), want: "provider dispatch requires ALLOW"},
		{name: "escalate", decision: gatewaySpendDecision(economic.BudgetVerdictEscalate, economic.SpendReasonApprovalRequired), want: "provider dispatch requires ALLOW"},
		{name: "allow with deny reason", decision: gatewaySpendDecision(economic.BudgetVerdictAllow, economic.SpendReasonBalanceInsufficient), want: "ALLOW spend authority reason code is invalid"},
		{name: "allow with tampered hash", decision: gatewayTamperedAllowSpendDecision(), want: "spend authority decision hash mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dispatched := false
			mux := http.NewServeMux()
			mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) {
				dispatched = true
				_ = json.NewEncoder(w).Encode(map[string]string{"version": "server-version"})
			})
			mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, _ *http.Request) {
				dispatched = true
				_ = json.NewEncoder(w).Encode(map[string]any{"choices": []map[string]any{{"message": map[string]string{"content": "ok"}}}})
			})
			srv := httptest.NewServer(mux)
			defer srv.Close()

			r := NewGatewayRouter()
			if err := r.RouteWithConfig(context.Background(), RouteConfig{
				Provider:  ProviderVLLM,
				BaseURL:   srv.URL,
				ModelName: "test-model",
				ModelHash: "sha256:def",
			}); err != nil {
				t.Fatal(err)
			}
			_, err := r.Execute(context.Background(), ExecContext{Prompt: "hello", SpendDecision: tc.decision})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected spend verdict error containing %q, got %v", tc.want, err)
			}
			if dispatched {
				t.Fatal("provider dispatch occurred before spend authority ALLOW")
			}
		})
	}
}

func TestExecuteRequiresSignedBudgetVerdictReceiptBeforeProviderDispatch(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(*economic.BudgetVerdictReceipt)
		receipt *economic.BudgetVerdictReceipt
		want    string
	}{
		{name: "missing", receipt: nil, want: "signed BudgetVerdict receipt is required"},
		{name: "unsigned", receipt: gatewayUnsignedSpendReceipt(ProviderVLLM, "test-model", gatewayAllowSpendDecision()), want: "signature_key_id is required"},
		{name: "wrong provider", mutate: func(r *economic.BudgetVerdictReceipt) {
			r.ProviderID = string(ProviderOllama)
			sealGatewayReceipt(r)
		}, want: "BudgetVerdict receipt provider does not match active profile"},
		{name: "wrong model", mutate: func(r *economic.BudgetVerdictReceipt) {
			r.ModelID = "other-model"
			sealGatewayReceipt(r)
		}, want: "BudgetVerdict receipt model does not match active profile"},
		{name: "decision hash mismatch", mutate: func(r *economic.BudgetVerdictReceipt) {
			r.DecisionHash = "sha256:other"
			sealGatewayReceipt(r)
		}, want: "decision_hash does not match decision"},
		{name: "untrusted key id", mutate: func(r *economic.BudgetVerdictReceipt) {
			sealGatewayReceiptWithKey(r, "other-key", gatewayUntrustedReceiptPrivateKey)
		}, want: "trusted BudgetVerdict receipt key not found"},
		{name: "forged trusted key id", mutate: func(r *economic.BudgetVerdictReceipt) {
			sealGatewayReceiptWithKey(r, "gateway-test-key", gatewayUntrustedReceiptPrivateKey)
		}, want: "signature verification failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dispatched := false
			mux := http.NewServeMux()
			mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) {
				dispatched = true
				_ = json.NewEncoder(w).Encode(map[string]string{"version": "server-version"})
			})
			mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, _ *http.Request) {
				dispatched = true
				_ = json.NewEncoder(w).Encode(map[string]any{"choices": []map[string]any{{"message": map[string]string{"content": "ok"}}}})
			})
			srv := httptest.NewServer(mux)
			defer srv.Close()

			decision := gatewayAllowSpendDecision()
			receipt := tc.receipt
			if tc.mutate != nil {
				receipt = gatewaySpendReceipt(ProviderVLLM, "test-model", decision)
				tc.mutate(receipt)
			}

			r := newGatewayRouterWithReceiptTrust()
			if err := r.RouteWithConfig(context.Background(), RouteConfig{
				Provider:  ProviderVLLM,
				BaseURL:   srv.URL,
				ModelName: "test-model",
				ModelHash: "sha256:def",
			}); err != nil {
				t.Fatal(err)
			}
			_, err := r.Execute(context.Background(), ExecContext{Prompt: "hello", SpendDecision: decision, SpendReceipt: receipt})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected spend receipt error containing %q, got %v", tc.want, err)
			}
			if dispatched {
				t.Fatal("provider endpoint was touched before signed BudgetVerdict receipt")
			}
		})
	}
}

func newOpenAICompatibleServer(t *testing.T, version string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"version": version})
	})
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", version)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": "test-model"}}})
	})
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]string{"content": "ok"}}},
		})
	})
	return httptest.NewServer(mux)
}

func gatewayAllowSpendDecision() *economic.SpendAuthorityDecision {
	return gatewaySpendDecision(economic.BudgetVerdictAllow, economic.SpendReasonOKWithinEnvelope)
}

func gatewaySpendDecision(verdict economic.BudgetVerdict, reason economic.SpendReasonCode) *economic.SpendAuthorityDecision {
	decision := &economic.SpendAuthorityDecision{
		Verdict:        verdict,
		ReasonCode:     reason,
		Reason:         "test spend decision",
		RemainingCents: 1000,
		EnvelopeHash:   "sha256:envelope",
	}
	decision.ContentHash = decision.CanonicalContentHash()
	return decision
}

func gatewayTamperedAllowSpendDecision() *economic.SpendAuthorityDecision {
	decision := gatewayAllowSpendDecision()
	decision.ContentHash = "sha256:tampered"
	return decision
}

var (
	gatewayReceiptPrivateKey          = ed25519.NewKeyFromSeed([]byte("0123456789abcdef0123456789abcdef"))
	gatewayUntrustedReceiptPrivateKey = ed25519.NewKeyFromSeed([]byte("fedcba9876543210fedcba9876543210"))
)

func newGatewayRouterWithReceiptTrust() *GatewayRouter {
	router := NewGatewayRouter()
	if err := router.TrustBudgetVerdictReceiptKey("gateway-test-key", gatewayReceiptPrivateKey.Public().(ed25519.PublicKey)); err != nil {
		panic(err)
	}
	return router
}

func gatewayExecContext(provider ProviderType, model string, decision *economic.SpendAuthorityDecision, req ExecContext) ExecContext {
	req.SpendDecision = decision
	req.SpendReceipt = gatewaySpendReceipt(provider, model, decision)
	return req
}

func gatewaySpendReceipt(provider ProviderType, model string, decision *economic.SpendAuthorityDecision) *economic.BudgetVerdictReceipt {
	receipt := gatewayUnsignedSpendReceipt(provider, model, decision)
	sealGatewayReceipt(receipt)
	return receipt
}

func gatewayUnsignedSpendReceipt(provider ProviderType, model string, decision *economic.SpendAuthorityDecision) *economic.BudgetVerdictReceipt {
	if decision == nil {
		return nil
	}
	return economic.NewBudgetVerdictReceipt(
		"verdict-1",
		"tenant-1",
		"spend-1",
		"env-1",
		"agent-1",
		string(provider),
		model,
		100,
		200,
		"USD",
		"sha256:price",
		"sha256:route-policy",
		"evidence://pack-1",
		*decision,
	)
}

func sealGatewayReceipt(receipt *economic.BudgetVerdictReceipt) {
	sealGatewayReceiptWithKey(receipt, "gateway-test-key", gatewayReceiptPrivateKey)
}

func sealGatewayReceiptWithKey(receipt *economic.BudgetVerdictReceipt, keyID string, key ed25519.PrivateKey) {
	if receipt == nil {
		return
	}
	if err := receipt.Seal(keyID, key); err != nil {
		panic(err)
	}
}
