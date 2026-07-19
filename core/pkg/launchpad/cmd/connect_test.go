package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeCP is a configurable fake control-plane device-auth endpoint set.
type fakeCP struct {
	mu           sync.Mutex
	tokenCalls   int
	tokenScript  []tokenReply // per-call reply for /device/token
	sessionCode  int
	accessToken  string
	refreshToken string
}

type tokenReply struct {
	status int
	body   map[string]any
}

func (f *fakeCP) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/device/code", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("device/code method = %s", r.Method)
		}
		writeJSONTest(w, http.StatusCreated, map[string]any{
			"device_code":               "helm_dc_abc123",
			"user_code":                 "ABCD-EFGH",
			"verification_uri":          "https://console.example/connect",
			"verification_uri_complete": "https://console.example/connect?code=ABCD-EFGH",
			"expires_in":                600,
			"interval":                  1,
		})
	})
	mux.HandleFunc("/api/v1/auth/device/token", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		idx := f.tokenCalls
		f.tokenCalls++
		if idx >= len(f.tokenScript) {
			idx = len(f.tokenScript) - 1
		}
		reply := f.tokenScript[idx]
		writeJSONTest(w, reply.status, reply.body)
	})
	mux.HandleFunc("/api/v1/auth/machine/session", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+f.accessToken {
			t.Errorf("machine/session Authorization = %q", got)
		}
		code := f.sessionCode
		if code == 0 {
			code = http.StatusOK
		}
		writeJSONTest(w, code, map[string]any{
			"credential_id":         "cred-1",
			"subject":               "did:helm:agent:xyz",
			"workspace_id":          "ws-1",
			"approved_by_principal": "user@example.com",
			"client_name":           "HELM AI Kernel CLI",
			"client_type":           "cli",
		})
	})
	return mux
}

func writeJSONTest(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func approvedTokenBody() map[string]any {
	return map[string]any{
		"token_type":         "Bearer",
		"access_token":       "access-SECRET-value",
		"expires_in":         900,
		"refresh_token":      "refresh-SECRET-value",
		"refresh_expires_in": 2592000,
		"scope":              "helm:workspace",
		"credential_id":      "cred-1",
		"subject":            "did:helm:agent:xyz",
		"workspace_id":       "ws-1",
	}
}

func pendingBody() map[string]any {
	return map[string]any{"error": "authorization_pending", "error_description": "not approved yet"}
}

func newConnectOpts(t *testing.T, base string, stdout *bytes.Buffer, sleeps *[]time.Duration) ConnectOptions {
	t.Helper()
	fixed := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	return ConnectOptions{
		CloudBaseURL: base,
		ClientName:   "HELM AI Kernel CLI",
		ClientType:   "cli",
		Stdout:       stdout,
		Stderr:       stdout,
		HTTPClient:   &http.Client{Timeout: 5 * time.Second},
		Now:          func() time.Time { return fixed },
		Sleep:        func(d time.Duration) { *sleeps = append(*sleeps, d) },
		OpenBrowser:  func(string) error { return nil },
	}
}

func TestRunConnectHappyPath(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f := &fakeCP{
		accessToken: "access-SECRET-value",
		tokenScript: []tokenReply{
			{status: http.StatusBadRequest, body: pendingBody()},
			{status: http.StatusOK, body: approvedTokenBody()},
		},
	}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()

	var out bytes.Buffer
	var sleeps []time.Duration
	result, err := RunConnect(newConnectOpts(t, srv.URL, &out, &sleeps))
	if err != nil {
		t.Fatalf("RunConnect: %v", err)
	}
	if result.WorkspaceID != "ws-1" {
		t.Errorf("workspace = %q, want ws-1", result.WorkspaceID)
	}
	if result.Principal != "user@example.com" {
		t.Errorf("principal = %q, want user@example.com (from machine/session)", result.Principal)
	}

	// Credential persisted with tokens.
	mc, err := LoadMachineCredential()
	if err != nil {
		t.Fatalf("LoadMachineCredential: %v", err)
	}
	if mc.AccessToken != "access-SECRET-value" || mc.RefreshToken != "refresh-SECRET-value" {
		t.Errorf("credential tokens not persisted: %+v", mc)
	}
	if mc.APIURL != srv.URL {
		t.Errorf("credential APIURL = %q, want %q", mc.APIURL, srv.URL)
	}

	// 0600 perms on the credential file.
	path, _ := MachineCredentialPath()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat credential: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("credential perms = %o, want 0600", perm)
	}

	// No token material leaked to stdout.
	if strings.Contains(out.String(), "SECRET") {
		t.Errorf("stdout leaked token material:\n%s", out.String())
	}
	// User code was surfaced.
	if !strings.Contains(out.String(), "ABCD-EFGH") {
		t.Errorf("stdout missing user code:\n%s", out.String())
	}
}

func TestRunConnectSlowDownBacksOff(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f := &fakeCP{
		accessToken: "access-SECRET-value",
		tokenScript: []tokenReply{
			{status: http.StatusBadRequest, body: map[string]any{"error": "slow_down", "error_description": "too fast"}},
			{status: http.StatusOK, body: approvedTokenBody()},
		},
	}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()

	var out bytes.Buffer
	var sleeps []time.Duration
	if _, err := RunConnect(newConnectOpts(t, srv.URL, &out, &sleeps)); err != nil {
		t.Fatalf("RunConnect: %v", err)
	}
	if len(sleeps) < 2 {
		t.Fatalf("expected at least 2 poll sleeps, got %d", len(sleeps))
	}
	if sleeps[1] <= sleeps[0] {
		t.Errorf("slow_down did not back off: sleeps=%v", sleeps)
	}
}

func TestRunConnectExpired(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f := &fakeCP{
		tokenScript: []tokenReply{
			{status: http.StatusBadRequest, body: map[string]any{"error": "expired_token", "error_description": "expired"}},
		},
	}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()

	var out bytes.Buffer
	var sleeps []time.Duration
	_, err := RunConnect(newConnectOpts(t, srv.URL, &out, &sleeps))
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired error, got %v", err)
	}
	if _, statErr := LoadMachineCredential(); statErr == nil {
		t.Errorf("expired flow must not persist a credential")
	}
}

func TestRunConnectDenied(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f := &fakeCP{
		tokenScript: []tokenReply{
			{status: http.StatusBadRequest, body: map[string]any{"error": "access_denied", "error_description": "denied"}},
		},
	}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()

	var out bytes.Buffer
	var sleeps []time.Duration
	_, err := RunConnect(newConnectOpts(t, srv.URL, &out, &sleeps))
	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("expected denied error, got %v", err)
	}
}

func TestRunConnectDeadlineExceeded(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f := &fakeCP{
		tokenScript: []tokenReply{
			{status: http.StatusBadRequest, body: pendingBody()},
		},
	}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()

	var out bytes.Buffer
	var sleeps []time.Duration
	opts := newConnectOpts(t, srv.URL, &out, &sleeps)
	// Advancing clock: each Now() call moves forward 10 minutes, so the 600s
	// device-code deadline is exceeded on the client side.
	current := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	opts.Now = func() time.Time {
		current = current.Add(10 * time.Minute)
		return current
	}
	_, err := RunConnect(opts)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected client-side deadline error, got %v", err)
	}
}

func TestRequireSecureBaseURL(t *testing.T) {
	ok := []string{
		"https://api.helm.mindburn.org",
		"https://cloud.example.com/base",
		"http://localhost:7714",
		"http://127.0.0.1:8080",
		"http://[::1]:9000",
	}
	for _, u := range ok {
		if err := requireSecureBaseURL(u); err != nil {
			t.Errorf("requireSecureBaseURL(%q) = %v, want nil", u, err)
		}
	}
	bad := []string{
		"http://api.helm.mindburn.org",
		"http://evil.example.com",
		"ftp://example.com",
		"ws://example.com",
	}
	for _, u := range bad {
		if err := requireSecureBaseURL(u); err == nil {
			t.Errorf("requireSecureBaseURL(%q) = nil, want rejection", u)
		}
	}
}
