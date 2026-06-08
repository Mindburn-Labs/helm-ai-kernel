package gateway

import (
	"context"
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

	r := NewGatewayRouter()
	if err := r.RouteWithConfig(context.Background(), RouteConfig{Provider: ProviderOllama, BaseURL: srv.URL, ModelName: "test-model"}); err != nil {
		t.Fatal(err)
	}
	res, err := r.Execute(context.Background(), ExecContext{Prompt: "hello", JSONMode: true, SpendDecision: gatewayAllowSpendDecision()})
	if err != nil {
		t.Fatal(err)
	}
	if res.Content != "ok" || res.ModelHash != "sha256:abc" || res.RuntimeVersion != "0.5.0" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.BudgetVerdict != economic.BudgetVerdictAllow || res.SpendDecisionHash == "" {
		t.Fatalf("missing spend decision evidence on result: %+v", res)
	}
}

func TestExecuteOpenAICompatibleRequiresModelHash(t *testing.T) {
	srv := newOpenAICompatibleServer(t, "server-version")
	defer srv.Close()

	r := NewGatewayRouter()
	if err := r.RouteWithConfig(context.Background(), RouteConfig{Provider: ProviderVLLM, BaseURL: srv.URL, ModelName: "test-model"}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Execute(context.Background(), ExecContext{Prompt: "hello", SpendDecision: gatewayAllowSpendDecision()}); err == nil {
		t.Fatal("expected model hash error")
	}
}

func TestExecuteOpenAICompatibleProviders(t *testing.T) {
	for _, provider := range []ProviderType{ProviderLlamaCPP, ProviderVLLM, ProviderLMStudio} {
		t.Run(string(provider), func(t *testing.T) {
			srv := newOpenAICompatibleServer(t, "server-version")
			defer srv.Close()

			r := NewGatewayRouter()
			if err := r.RouteWithConfig(context.Background(), RouteConfig{
				Provider:  provider,
				BaseURL:   srv.URL,
				ModelName: "test-model",
				ModelHash: "sha256:def",
			}); err != nil {
				t.Fatal(err)
			}
			res, err := r.Execute(context.Background(), ExecContext{Prompt: "hello", SpendDecision: gatewayAllowSpendDecision()})
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

	r := NewGatewayRouter()
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
	_, err = r.Execute(context.Background(), ExecContext{Prompt: "hello", SpendDecision: gatewayAllowSpendDecision()})
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

	r := NewGatewayRouter()
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
	res, err := r.Execute(context.Background(), ExecContext{Prompt: "hello", SpendDecision: gatewayAllowSpendDecision()})
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
	return &economic.SpendAuthorityDecision{
		Verdict:        verdict,
		ReasonCode:     reason,
		Reason:         "test spend decision",
		RemainingCents: 1000,
		EnvelopeHash:   "sha256:envelope",
		ContentHash:    "sha256:decision",
	}
}
