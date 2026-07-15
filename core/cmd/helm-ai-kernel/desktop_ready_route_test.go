package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
)

const desktopReadyChildProcessEnv = "HELM_TEST_DESKTOP_READY_CHILD"

func TestDesktopReadyRouteIsAbsentWithoutLaunchToken(t *testing.T) {
	mux := http.NewServeMux()
	registerDesktopReadyRoute(mux, "")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, desktopReadyPath, nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestDesktopReadyRouteProvesOnlyValidNonceForLaunchToken(t *testing.T) {
	mux := http.NewServeMux()
	registerDesktopReadyRoute(mux, "desktop-secret")

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
	mux := http.NewServeMux()
	registerDesktopReadyRoute(mux, "desktop-secret")

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

func TestDesktopReadyTokenIsConsumedBeforeSubprocessAndStillBindsRoute(t *testing.T) {
	t.Setenv(desktopReadyTokenEnv, " desktop-secret ")
	token := takeDesktopReadyToken()
	if token != "desktop-secret" {
		t.Fatalf("token = %q, want trimmed launch token", token)
	}
	if _, present := os.LookupEnv(desktopReadyTokenEnv); present {
		t.Fatalf("%s remains in the process environment", desktopReadyTokenEnv)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestDesktopReadyTokenChildProcess$")
	cmd.Env = append(os.Environ(), desktopReadyChildProcessEnv+"=1")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("run child process: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("child inherited Desktop launch token %q", string(out))
	}

	mux := http.NewServeMux()
	registerDesktopReadyRoute(mux, token)
	req := httptest.NewRequest(http.MethodGet, desktopReadyPath, nil)
	req.Header.Set(desktopReadyNonceHeader, "a1b2c3")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if got, want := rec.Header().Get(desktopReadyProofHeader), desktopReadyProof(token, "a1b2c3"); got != want {
		t.Fatalf("proof = %q, want %q", got, want)
	}
}

func TestDesktopReadyTokenChildProcess(t *testing.T) {
	if os.Getenv(desktopReadyChildProcessEnv) != "1" {
		return
	}
	_, _ = os.Stdout.WriteString(os.Getenv(desktopReadyTokenEnv))
	os.Exit(0)
}
