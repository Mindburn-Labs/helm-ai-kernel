package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	lpcmd "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/cmd"
)

// bridgeEdge is a fake cloud MCP edge plus device refresh endpoint. The /mcp
// status script uses last-value-repeats semantics.
type bridgeEdge struct {
	mu               sync.Mutex
	mcpAuth          []string
	mcpStatus        []int
	refreshCalls     int
	refreshStatus    int
	rotatedAccess    string
	rotatedRefresh   string
	seenRefreshToken string
}

func (f *bridgeEdge) handler(t *testing.T) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.mcpAuth = append(f.mcpAuth, r.Header.Get("Authorization"))
		idx := len(f.mcpAuth) - 1
		status := http.StatusOK
		if len(f.mcpStatus) > 0 {
			if idx >= len(f.mcpStatus) {
				idx = len(f.mcpStatus) - 1
			}
			status = f.mcpStatus[idx]
		}
		f.mu.Unlock()

		body, _ := io.ReadAll(r.Body)
		var req struct {
			ID any `json:"id"`
		}
		_ = json.Unmarshal(body, &req)

		if status != http.StatusOK {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_token"})
			return
		}
		if req.ID == nil {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"result":  map[string]any{"ok": true},
		})
	})
	mux.HandleFunc("/api/v1/auth/device/refresh", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			GrantType    string `json:"grant_type"`
			RefreshToken string `json:"refresh_token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.GrantType != "refresh_token" {
			t.Errorf("refresh grant_type = %q", body.GrantType)
		}
		f.mu.Lock()
		f.refreshCalls++
		f.seenRefreshToken = body.RefreshToken
		status := f.refreshStatus
		f.mu.Unlock()
		if status != 0 && status != http.StatusOK {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant", "error_description": "refresh rejected"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token_type":         "Bearer",
			"access_token":       f.rotatedAccess,
			"expires_in":         900,
			"refresh_token":      f.rotatedRefresh,
			"refresh_expires_in": 2592000,
			"scope":              "helm:workspace",
			"credential_id":      "cred-1",
			"subject":            "did:helm:agent:xyz",
			"workspace_id":       "ws-1",
		})
	})
	return mux
}

func seedBridgeCredential(t *testing.T, apiURL string, accessExpiry time.Time) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	cred := lpcmd.MachineCredential{
		TokenType:        "Bearer",
		AccessToken:      "access-SECRET-1",
		RefreshToken:     "refresh-SECRET-1",
		Scope:            "helm:workspace",
		WorkspaceID:      "ws-1",
		APIURL:           apiURL,
		AccessExpiresAt:  accessExpiry.UTC().Format(time.RFC3339),
		RefreshExpiresAt: time.Now().Add(720 * time.Hour).UTC().Format(time.RFC3339),
	}
	if err := lpcmd.SaveMachineCredential(cred); err != nil {
		t.Fatal(err)
	}
}

const bridgeTestInput = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
`

func TestMCPBridgeForwardsWithAuthHeaderAndNoTokenLeak(t *testing.T) {
	f := &bridgeEdge{}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	seedBridgeCredential(t, srv.URL, time.Now().Add(1*time.Hour))

	var out bytes.Buffer
	err := runMCPBridgeLoop(strings.NewReader(bridgeTestInput), &out, srv.URL+"/mcp", srv.Client(), time.Now)
	if err != nil {
		t.Fatalf("runMCPBridgeLoop: %v", err)
	}

	if got := len(f.mcpAuth); got != 2 {
		t.Fatalf("remote calls = %d, want 2 (request + notification)", got)
	}
	for _, auth := range f.mcpAuth {
		if auth != "Bearer access-SECRET-1" {
			t.Errorf("Authorization = %q, want the stored bearer", auth)
		}
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("stdout lines = %d, want 1 (no response frame for the notification):\n%s", len(lines), out.String())
	}
	var resp struct {
		ID     any            `json:"id"`
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &resp); err != nil {
		t.Fatalf("parse forwarded response: %v", err)
	}
	if resp.Result["ok"] != true {
		t.Errorf("forwarded result = %+v", resp)
	}
	if strings.Contains(out.String(), "SECRET") {
		t.Errorf("stdout leaked token material:\n%s", out.String())
	}
	if f.refreshCalls != 0 {
		t.Errorf("refreshCalls = %d, want 0", f.refreshCalls)
	}
}

func TestMCPBridge401RefreshRetryOnce(t *testing.T) {
	f := &bridgeEdge{
		mcpStatus:      []int{http.StatusUnauthorized, http.StatusOK},
		rotatedAccess:  "access-SECRET-2",
		rotatedRefresh: "refresh-SECRET-2",
	}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	seedBridgeCredential(t, srv.URL, time.Now().Add(1*time.Hour))

	var out bytes.Buffer
	input := `{"jsonrpc":"2.0","id":7,"method":"tools/list"}` + "\n"
	if err := runMCPBridgeLoop(strings.NewReader(input), &out, srv.URL+"/mcp", srv.Client(), time.Now); err != nil {
		t.Fatalf("runMCPBridgeLoop: %v", err)
	}

	if f.refreshCalls != 1 {
		t.Errorf("refreshCalls = %d, want exactly 1", f.refreshCalls)
	}
	if f.seenRefreshToken != "refresh-SECRET-1" {
		t.Errorf("refresh used token %q, want the stored refresh token", f.seenRefreshToken)
	}
	want := []string{"Bearer access-SECRET-1", "Bearer access-SECRET-2"}
	if len(f.mcpAuth) != 2 || f.mcpAuth[0] != want[0] || f.mcpAuth[1] != want[1] {
		t.Errorf("mcp Authorization sequence = %v, want %v", f.mcpAuth, want)
	}
	if !strings.Contains(out.String(), `"result"`) {
		t.Errorf("retried response not forwarded:\n%s", out.String())
	}
	// Rotated tokens persisted through the standard save path.
	mc, err := lpcmd.LoadMachineCredential()
	if err != nil {
		t.Fatalf("LoadMachineCredential: %v", err)
	}
	if mc.AccessToken != "access-SECRET-2" || mc.RefreshToken != "refresh-SECRET-2" {
		t.Errorf("rotated credential not persisted: access=%q refresh=%q", mc.AccessToken, mc.RefreshToken)
	}
	if strings.Contains(out.String(), "SECRET") {
		t.Errorf("stdout leaked token material:\n%s", out.String())
	}
}

func TestMCPBridgeLocalExpiryRefreshesBeforeSend(t *testing.T) {
	f := &bridgeEdge{
		rotatedAccess:  "access-SECRET-2",
		rotatedRefresh: "refresh-SECRET-2",
	}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	seedBridgeCredential(t, srv.URL, time.Now().Add(-1*time.Minute))

	var out bytes.Buffer
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n"
	if err := runMCPBridgeLoop(strings.NewReader(input), &out, srv.URL+"/mcp", srv.Client(), time.Now); err != nil {
		t.Fatalf("runMCPBridgeLoop: %v", err)
	}
	if f.refreshCalls != 1 {
		t.Errorf("refreshCalls = %d, want 1 (local expiry refreshes before sending)", f.refreshCalls)
	}
	if len(f.mcpAuth) != 1 || f.mcpAuth[0] != "Bearer access-SECRET-2" {
		t.Errorf("mcp Authorization sequence = %v, want only the rotated bearer", f.mcpAuth)
	}
}

func TestMCPBridgeRefreshFailureFailsClosed(t *testing.T) {
	f := &bridgeEdge{
		mcpStatus:     []int{http.StatusUnauthorized},
		refreshStatus: http.StatusBadRequest,
	}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	seedBridgeCredential(t, srv.URL, time.Now().Add(1*time.Hour))

	var out bytes.Buffer
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n"
	err := runMCPBridgeLoop(strings.NewReader(input), &out, srv.URL+"/mcp", srv.Client(), time.Now)
	if err == nil {
		t.Fatal("expected fail-closed error after refresh failure")
	}
	if strings.Contains(err.Error(), "SECRET") {
		t.Errorf("error leaked token material: %v", err)
	}
	// The client got a JSON-RPC error, never a silently-unauthenticated result.
	var resp struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if jsonErr := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &resp); jsonErr != nil {
		t.Fatalf("parse JSON-RPC error frame: %v\n%s", jsonErr, out.String())
	}
	if resp.Error == nil || !strings.Contains(resp.Error.Message, "refresh failed") {
		t.Errorf("JSON-RPC error frame = %+v", resp)
	}
	if strings.Contains(out.String(), "SECRET") {
		t.Errorf("stdout leaked token material:\n%s", out.String())
	}
}

func TestMCPBridge401AfterRefreshFailsClosed(t *testing.T) {
	f := &bridgeEdge{
		mcpStatus:      []int{http.StatusUnauthorized},
		rotatedAccess:  "access-SECRET-2",
		rotatedRefresh: "refresh-SECRET-2",
	}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	seedBridgeCredential(t, srv.URL, time.Now().Add(1*time.Hour))

	var out bytes.Buffer
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n"
	err := runMCPBridgeLoop(strings.NewReader(input), &out, srv.URL+"/mcp", srv.Client(), time.Now)
	if err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("expected fail-closed rejection after single retry, got %v", err)
	}
	if len(f.mcpAuth) != 2 {
		t.Errorf("remote calls = %d, want exactly 2 (original + one retry)", len(f.mcpAuth))
	}
	if f.refreshCalls != 1 {
		t.Errorf("refreshCalls = %d, want exactly 1", f.refreshCalls)
	}
	if strings.Contains(out.String(), "SECRET") {
		t.Errorf("stdout leaked token material:\n%s", out.String())
	}
}

func TestMCPBridgeRejectsInsecureRemoteURL(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runMCPBridge([]string{"--url", "http://evil.example.com/mcp"}, &out, &errOut)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "https") {
		t.Errorf("stderr missing https guidance:\n%s", errOut.String())
	}
}
