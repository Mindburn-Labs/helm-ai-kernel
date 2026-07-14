package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDesktopReadyRouteIsAbsentWithoutLaunchToken(t *testing.T) {
	t.Setenv(desktopReadyTokenEnv, "")
	mux := http.NewServeMux()
	registerDesktopReadyRoute(mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, desktopReadyPath, nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestDesktopReadyRouteProvesOnlyValidNonceForLaunchToken(t *testing.T) {
	t.Setenv(desktopReadyTokenEnv, "desktop-secret")
	mux := http.NewServeMux()
	registerDesktopReadyRoute(mux)

	req := httptest.NewRequest(http.MethodGet, desktopReadyPath, nil)
	req.Header.Set(desktopReadyNonceHeader, "a1b2c3")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if got, want := rec.Header().Get(desktopReadyProofHeader), desktopReadyProof("desktop-secret", "a1b2c3"); got != want {
		t.Fatalf("proof = %q, want %q", got, want)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("cache-control = %q", got)
	}

	invalid := httptest.NewRequest(http.MethodGet, desktopReadyPath, nil)
	invalid.Header.Set(desktopReadyNonceHeader, "not a hex nonce")
	invalidRec := httptest.NewRecorder()
	mux.ServeHTTP(invalidRec, invalid)
	if invalidRec.Code != http.StatusNotFound {
		t.Fatalf("invalid nonce status = %d, want %d", invalidRec.Code, http.StatusNotFound)
	}
	if invalidRec.Header().Get(desktopReadyProofHeader) != "" {
		t.Fatal("invalid nonce unexpectedly received a proof")
	}
}

func TestDesktopReadyRouteRejectsMutations(t *testing.T) {
	t.Setenv(desktopReadyTokenEnv, "desktop-secret")
	mux := http.NewServeMux()
	registerDesktopReadyRoute(mux)

	req := httptest.NewRequest(http.MethodPost, desktopReadyPath, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
	if got := rec.Header().Get("Allow"); got != "GET, HEAD" {
		t.Fatalf("allow = %q", got)
	}
}
