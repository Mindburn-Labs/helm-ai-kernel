package client

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// The kernel pins this body in core/pkg/httperr (TestErrorModelVector).
func TestHelmApiError_ParsesErrorModel(t *testing.T) {
	body, err := os.ReadFile("../../../protocols/specs/errors/error-model-503.json")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	_, err = New(srv.URL).Version()
	var apiErr *HelmApiError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want *HelmApiError", err)
	}
	want := HelmApiError{Status: 503, Message: "emergency-stop fence active", ReasonCode: "EMERGENCY_STOP_FENCED", Code: "unavailable", Retryable: true}
	if *apiErr != want {
		t.Fatalf("got %+v, want %+v", *apiErr, want)
	}
}
