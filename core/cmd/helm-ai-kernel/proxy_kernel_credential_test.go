package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
)

// HELM-780: POST /v1/chat/completions forwards Authorization to the model
// provider as the provider credential. A legacy caller authenticates with the
// admin key, as a bearer token or in X-HELM-API-Key; no kernel credential may
// reach the provider, and a provider key sent beside X-HELM-API-Key must.
func TestChatProxyNeverForwardsAKernelCredential(t *testing.T) {
	const (
		serviceKey  = "service-secret"
		providerKey = "provider-secret"
	)
	var (
		mu       sync.Mutex
		received []string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		received = append(received, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[]}`))
	}))
	defer upstream.Close()
	t.Setenv("HELM_UPSTREAM_URL", upstream.URL)
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(serviceAPIKeyEnv, serviceKey)
	t.Setenv(organizationRuntimeAPIKeyEnv, testOrganizationRuntimeAPIKey)

	signer, err := helmcrypto.NewEd25519Signer("chat-proxy-credential-test")
	if err != nil {
		t.Fatal(err)
	}
	svc := &Services{
		Guardian: guardian.NewGuardian(
			signer,
			allowGraphForExtAuthzTest("LLM_INFERENCE"),
			artifacts.NewRegistry(nil, nil),
			guardian.WithPDP(&evaluateRouteCapturingPDP{}),
		),
		ReceiptStore:  &captureReceiptStore{},
		ReceiptSigner: signer,
	}
	mux := http.NewServeMux()
	RegisterSubsystemRoutes(mux, svc)

	for _, tc := range []struct {
		name          string
		apiKeyHeader  string
		authorization string
		want          string
	}{
		{"admin key as the bearer token", "", "Bearer " + testAdminAPIKey, ""},
		{"admin key in both headers", testAdminAPIKey, "Bearer " + testAdminAPIKey, ""},
		{"admin key without a scheme", testAdminAPIKey, testAdminAPIKey, ""},
		{"organization runtime key as the provider key", testAdminAPIKey, "Bearer " + testOrganizationRuntimeAPIKey, ""},
		{"service key as the provider key", testAdminAPIKey, "Bearer " + serviceKey, ""},
		{"provider key beside the kernel key", testAdminAPIKey, "Bearer " + providerKey, "Bearer " + providerKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			received = nil
			mu.Unlock()
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"gpt-test","messages":[]}`))
			if tc.apiKeyHeader != "" {
				req.Header.Set(runtimeAPIKeyHeader, tc.apiKeyHeader)
			}
			req.Header.Set("Authorization", tc.authorization)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
			}
			mu.Lock()
			defer mu.Unlock()
			if len(received) != 1 {
				t.Fatalf("upstream received %d requests, want 1", len(received))
			}
			if received[0] != tc.want {
				t.Fatalf("upstream Authorization = %q, want %q", received[0], tc.want)
			}
		})
	}
}
