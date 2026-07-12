package main

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
)

func TestReadGovernedOpenAIRequestResetsBody(t *testing.T) {
	body := []byte(`{"model":"gpt-test","messages":[]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	gotBody, gotMap, ok := readGovernedOpenAIRequest(rec, req)
	if !ok {
		t.Fatalf("readGovernedOpenAIRequest failed with status %d", rec.Code)
	}
	if !bytes.Equal(gotBody, body) {
		t.Fatalf("body bytes changed: %q", gotBody)
	}
	if gotMap["model"] != "gpt-test" {
		t.Fatalf("model = %v, want gpt-test", gotMap["model"])
	}
	resetBody, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(resetBody, body) {
		t.Fatalf("reset body = %q, want %q", resetBody, body)
	}
}

func TestReadGovernedOpenAIRequestRejectsOversize(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(make([]byte, governedOpenAIRequestMaxBytes+1)))
	rec := httptest.NewRecorder()

	if _, _, ok := readGovernedOpenAIRequest(rec, req); ok {
		t.Fatal("expected oversized request to fail")
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestGovernedOpenAIProxyUnavailableWhenScopedFenceEnabled(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"gpt-test","messages":[]}`))
	rec := httptest.NewRecorder()

	// This route has no authenticated tenant/workspace binding. It must stay
	// unavailable rather than accepting a caller-selected scope in JSON while
	// the scoped fence is active.
	handleGovernedOpenAIProxy(rec, req, &Services{EmergencyStops: &kernel.ScopedStopStore{}})

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
}

func TestGovernedOpenAIProxyFailsClosedWithoutGovernanceDependencies(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"gpt-test","messages":[]}`))
	rec := httptest.NewRecorder()

	handleGovernedOpenAIProxy(rec, req, &Services{})

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
}

func TestGovernedOpenAIProxyFailsClosedWhenReceiptPersistenceFails(t *testing.T) {
	svc, receipts := newEvaluateRouteTestServices(t)
	receipts.storeErr = errors.New("receipt store unavailable")
	upstreamCalled := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	t.Setenv("HELM_UPSTREAM_URL", upstream.URL)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"gpt-test","messages":[]}`))
	rec := httptest.NewRecorder()

	handleGovernedOpenAIProxy(rec, req, svc)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
	if rec.Header().Get("X-Helm-Receipt-ID") != "" {
		t.Fatalf("failed receipt persistence advertised receipt %q", rec.Header().Get("X-Helm-Receipt-ID"))
	}
	if upstreamCalled {
		t.Fatal("receipt persistence failure forwarded the request upstream")
	}
}
