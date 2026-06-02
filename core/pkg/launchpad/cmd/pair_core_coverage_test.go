package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunPairExplicitWorkspaceRoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	saveTestSession(t, Session{
		Token:     "token-1",
		Email:     "operator@example.com",
		TenantID:  "tenant-1",
		ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})

	var out bytes.Buffer
	if err := RunPair(PairOptions{
		WorkspaceID: "ws-explicit",
		APIURL:      "https://api.example.test/",
		Stdout:      &out,
	}); err != nil {
		t.Fatalf("RunPair explicit workspace: %v", err)
	}
	if !contains(out.String(), "ws-explicit") {
		t.Fatalf("output = %q, want workspace id", out.String())
	}

	pairing, err := LoadPairing()
	if err != nil {
		t.Fatalf("LoadPairing: %v", err)
	}
	if pairing.WorkspaceID != "ws-explicit" || pairing.APIURL != "https://api.example.test" {
		t.Fatalf("pairing = %#v", pairing)
	}
}

func TestRunPairAutoDiscoversWorkspace(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	saveTestSession(t, Session{
		Token:     "token-2",
		Email:     "operator@example.com",
		TenantID:  "tenant-1",
		ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/me/entitlements" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer token-2" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(entitlementsResponse{Workspaces: []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}{{ID: "ws-auto", Name: "Auto Workspace"}}})
	}))
	defer server.Close()

	var out bytes.Buffer
	if err := RunPair(PairOptions{APIURL: server.URL, Stdout: &out}); err != nil {
		t.Fatalf("RunPair auto-discover: %v", err)
	}
	pairing, err := LoadPairing()
	if err != nil {
		t.Fatalf("LoadPairing: %v", err)
	}
	if pairing.WorkspaceID != "ws-auto" || !contains(out.String(), "ws-auto") {
		t.Fatalf("pairing = %#v output = %q", pairing, out.String())
	}
}

func TestRunPairSessionAndDiscoveryErrors(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := RunPair(PairOptions{WorkspaceID: "ws"}); err == nil {
		t.Fatal("RunPair without session error = nil")
	}

	saveTestSession(t, Session{Email: "operator@example.com"})
	if err := RunPair(PairOptions{WorkspaceID: "ws"}); err == nil {
		t.Fatal("RunPair empty token error = nil")
	}

	saveTestSession(t, Session{
		Token:     "expired",
		ExpiresAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
	})
	if err := RunPair(PairOptions{WorkspaceID: "ws"}); err == nil {
		t.Fatal("RunPair expired token error = nil")
	}

	saveTestSession(t, Session{
		Token:     "valid",
		ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})
	emptyWorkspaceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(entitlementsResponse{})
	}))
	defer emptyWorkspaceServer.Close()
	if err := RunPair(PairOptions{APIURL: emptyWorkspaceServer.URL}); err == nil {
		t.Fatal("RunPair empty entitlements error = nil")
	}
}

func TestDiscoverWorkspaceErrorBranches(t *testing.T) {
	if _, err := discoverWorkspace("://bad", "token"); err == nil {
		t.Fatal("discoverWorkspace bad URL error = nil")
	}

	unauthorized := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no", http.StatusUnauthorized)
	}))
	defer unauthorized.Close()
	if _, err := discoverWorkspace(unauthorized.URL, "token"); err == nil {
		t.Fatal("discoverWorkspace unauthorized error = nil")
	}

	status := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer status.Close()
	if _, err := discoverWorkspace(status.URL, "token"); err == nil {
		t.Fatal("discoverWorkspace status error = nil")
	}

	invalidJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{"))
	}))
	defer invalidJSON.Close()
	if _, err := discoverWorkspace(invalidJSON.URL, "token"); err == nil {
		t.Fatal("discoverWorkspace JSON error = nil")
	}
}

func TestPairingLoadMissingAndInvalidJSON(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if _, err := LoadPairing(); err == nil {
		t.Fatal("LoadPairing missing error = nil")
	}
	path, err := PairingPath()
	if err != nil {
		t.Fatalf("PairingPath: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatalf("write invalid pairing: %v", err)
	}
	if _, err := LoadPairing(); err == nil {
		t.Fatal("LoadPairing invalid JSON error = nil")
	}
}

func TestResolveConsoleURLPrecedence(t *testing.T) {
	t.Setenv("HELM_CONSOLE_URL", "https://env.example.test///")
	if got := resolveConsoleURL("https://explicit.example.test/"); got != "https://explicit.example.test" {
		t.Fatalf("explicit URL = %q", got)
	}
	if got := resolveConsoleURL(""); got != "https://env.example.test" {
		t.Fatalf("env URL = %q", got)
	}
	t.Setenv("HELM_CONSOLE_URL", "")
	if got := resolveConsoleURL(""); got != defaultConsoleURL {
		t.Fatalf("default URL = %q", got)
	}
}

func TestRunLoginResponseAndPersistenceErrors(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := RunLogin(LoginOptions{Email: "a@example.com", Password: "pw", APIURL: "://bad"}); err == nil {
		t.Fatal("RunLogin bad API URL error = nil")
	}

	invalidJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{"))
	}))
	defer invalidJSON.Close()
	if err := RunLogin(LoginOptions{Email: "a@example.com", Password: "pw", APIURL: invalidJSON.URL}); err == nil {
		t.Fatal("RunLogin invalid JSON error = nil")
	}

	missingToken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(loginResponse{Email: "a@example.com", TenantID: "tenant"})
	}))
	defer missingToken.Close()
	if err := RunLogin(LoginOptions{Email: "a@example.com", Password: "pw", APIURL: missingToken.URL}); err == nil {
		t.Fatal("RunLogin missing token error = nil")
	}

	homeFile := filepath.Join(t.TempDir(), "home-file")
	if err := os.WriteFile(homeFile, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write home file: %v", err)
	}
	t.Setenv("HOME", homeFile)
	okServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(loginResponse{Token: "tok", Email: "a@example.com", TenantID: "tenant"})
	}))
	defer okServer.Close()
	if err := RunLogin(LoginOptions{Email: "a@example.com", Password: "pw", APIURL: okServer.URL}); err == nil {
		t.Fatal("RunLogin persist session error = nil")
	}
}

func TestSessionAndPairingPersistenceErrorBranches(t *testing.T) {
	homeFile := filepath.Join(t.TempDir(), "home-file")
	if err := os.WriteFile(homeFile, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write home file: %v", err)
	}
	t.Setenv("HOME", homeFile)
	if err := SaveSession(Session{Token: "tok"}); err == nil {
		t.Fatal("SaveSession home-file error = nil")
	}
	if err := SavePairing(Pairing{WorkspaceID: "ws"}); err == nil {
		t.Fatal("SavePairing home-file error = nil")
	}

	t.Setenv("HOME", t.TempDir())
	path, err := SessionPath()
	if err != nil {
		t.Fatalf("SessionPath: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatalf("write invalid session: %v", err)
	}
	if _, err := LoadSession(); err == nil {
		t.Fatal("LoadSession invalid JSON error = nil")
	}

	if err := os.Remove(path); err != nil {
		t.Fatalf("remove invalid session: %v", err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("mkdir session path: %v", err)
	}
	if _, err := LoadSession(); err == nil {
		t.Fatal("LoadSession directory read error = nil")
	}
}

func saveTestSession(t *testing.T, session Session) {
	t.Helper()
	if err := SaveSession(session); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}
}
