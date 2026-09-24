package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
)

func TestIsLoopbackBindAddr(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "127.0.0.2", "::1", "[::1]", "localhost", " LOCALHOST "} {
		if !isLoopbackBindAddr(host) {
			t.Errorf("%q should be loopback", host)
		}
	}
	for _, host := range []string{"", "0.0.0.0", "::", "10.0.0.5", "192.168.1.1", "example.com"} {
		if isLoopbackBindAddr(host) {
			t.Errorf("%q must not be treated as loopback", host)
		}
	}
}

// TestListenerBindIgnoresSharedBindAddr: HELM_BIND_ADDR exposes `serve`; the
// sidecars read only their own variable (S-01, S-02).
func TestListenerBindIgnoresSharedBindAddr(t *testing.T) {
	t.Setenv(sharedBindEnv, "0.0.0.0")
	t.Setenv(proxyBindAddrEnv, "")
	t.Setenv(mcpBindAddrEnv, "")
	if got := listenerBindAddr(proxyBindAddrEnv); got != "127.0.0.1" {
		t.Fatalf("proxy bind = %q, want 127.0.0.1", got)
	}
	server, err := newLocalMCPHTTPServerWithDataDir(9100, "none", t.TempDir())
	if err != nil {
		t.Fatalf("loopback MCP server: %v", err)
	}
	if server.Addr != "127.0.0.1:9100" {
		t.Fatalf("mcp addr = %q, want 127.0.0.1:9100", server.Addr)
	}
	t.Setenv(proxyBindAddrEnv, "10.0.0.5")
	if got := listenerBindAddr(proxyBindAddrEnv); got != "10.0.0.5" {
		t.Fatalf("proxy bind = %q, want its own variable", got)
	}
}

func TestProxyRefusesNonLoopbackBindWithoutToken(t *testing.T) {
	t.Setenv(proxyBindAddrEnv, "0.0.0.0")
	t.Setenv(proxyTokenEnv, "")
	receipts := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := runProxyCmd([]string{"--receipts-dir", receipts}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit = %d, want 2; stderr=%s", code, stderr.String())
	}
	if msg := stderr.String(); !strings.Contains(msg, "not loopback") || !strings.Contains(msg, proxyTokenEnv) {
		t.Fatalf("refusal does not name the fix: %s", msg)
	}
	if entries, _ := os.ReadDir(receipts); len(entries) != 0 {
		t.Fatalf("refused proxy still created state: %v", entries)
	}
}

func TestMCPServeRefusesNonLoopbackBindWithoutAuth(t *testing.T) {
	t.Setenv(mcpBindAddrEnv, "0.0.0.0")

	var stdout, stderr bytes.Buffer
	code := runMCPServe([]string{"--transport", "http", "--port", "9100", "--data-dir", t.TempDir()}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "not loopback") {
		t.Fatalf("mcp serve --auth none on 0.0.0.0: exit=%d stderr=%s", code, stderr.String())
	}

	t.Setenv("HELM_API_KEY", "mcp-static-key")
	server, err := newLocalMCPHTTPServerWithDataDir(9100, "static-header", t.TempDir())
	if err != nil {
		t.Fatalf("authenticated non-loopback MCP server refused: %v", err)
	}
	if server.Addr != "0.0.0.0:9100" {
		t.Fatalf("mcp addr = %q, want 0.0.0.0:9100", server.Addr)
	}
}

func TestWrapProxyAuth(t *testing.T) {
	var seen *http.Request
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r
		w.WriteHeader(http.StatusNoContent)
	})
	handler := wrapProxyAuth(next, "proxy-token")

	serve := func(path, authz string) int {
		seen = nil
		req := httptest.NewRequest(http.MethodPost, path, nil)
		if authz != "" {
			req.Header.Set("Authorization", authz)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	for _, path := range []string{"/v1/chat/completions", "/helm/receipts", "/helm/proofgraph"} {
		if code := serve(path, ""); code != http.StatusUnauthorized {
			t.Fatalf("%s without token: %d", path, code)
		}
		if code := serve(path, "Bearer wrong"); code != http.StatusUnauthorized {
			t.Fatalf("%s with wrong token: %d", path, code)
		}
	}
	if code := serve("/healthz", ""); code != http.StatusNoContent {
		t.Fatalf("health must stay open: %d", code)
	}
	if code := serve("/v1/chat/completions", "Bearer proxy-token"); code != http.StatusNoContent {
		t.Fatalf("valid token rejected: %d", code)
	}
	if got := seen.Header.Get("Authorization"); got != "" {
		t.Fatalf("proxy token would be forwarded upstream: %q", got)
	}
	if _, ok := helmauth.AuthenticatedCredentialHash(seen.Context()); !ok {
		t.Fatal("authenticated request carries no credential evidence")
	}

	// No token configured (loopback only): requests pass untouched, including
	// a client's own provider key.
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer client-provider-key")
	rec := httptest.NewRecorder()
	wrapProxyAuth(next, "").ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || seen.Header.Get("Authorization") != "Bearer client-provider-key" {
		t.Fatalf("unauthenticated loopback proxy altered the request: %d %q", rec.Code, seen.Header.Get("Authorization"))
	}
}

func TestWrapMCPAuth_StaticHeaderRequiresKey(t *testing.T) {
	t.Setenv("HELM_API_KEY", "mcp-static-key")
	handler, err := wrapMCPAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), "static-header", "http://127.0.0.1:9100")
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]int{"": http.StatusUnauthorized, "mcp-static-ke": http.StatusUnauthorized, "mcp-static-key": http.StatusNoContent} {
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		if key != "" {
			req.Header.Set("X-HELM-API-Key", key)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("key %q: status %d, want %d", key, rec.Code, want)
		}
	}
}

// TestMetricsLoopbackOnlyOrAuthenticated (S-07): /metrics shares the API
// bind address, so it answers loopback peers or a configured bearer token.
func TestMetricsLoopbackOnlyOrAuthenticated(t *testing.T) {
	scrape := func(handler http.HandlerFunc, remote, authz string) int {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.RemoteAddr = remote
		if authz != "" {
			req.Header.Set("Authorization", authz)
		}
		rec := httptest.NewRecorder()
		handler(rec, req)
		return rec.Code
	}

	open := protectedMetricsHandler(nil, "")
	if code := scrape(open, "192.0.2.10:4000", ""); code != http.StatusForbidden {
		t.Fatalf("remote scrape without a token configured: %d", code)
	}
	if code := scrape(open, "127.0.0.1:4000", ""); code != http.StatusOK {
		t.Fatalf("loopback scrape: %d", code)
	}

	guarded := protectedMetricsHandler(nil, "metrics-token")
	for authz, want := range map[string]int{"": http.StatusUnauthorized, "Bearer nope": http.StatusUnauthorized, "Bearer metrics-token": http.StatusOK} {
		if code := scrape(guarded, "192.0.2.10:4000", authz); code != want {
			t.Fatalf("remote scrape with %q: %d, want %d", authz, code, want)
		}
	}
}

// TestListenerSecretsUseConstantTimeComparison (S-13) guards the listener
// sources: no credential is compared with == or !=, and the server mounts
// /metrics only through protectedMetricsHandler.
func TestListenerSecretsUseConstantTimeComparison(t *testing.T) {
	secretName := regexp.MustCompile(`(?i)(token|key|secret|provided|credential)`)
	for _, file := range []string{"listener_auth.go", "mcp_runtime.go", "proxy_cmd.go", "main.go"} {
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(parsed, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.BinaryExpr:
				if node.Op != token.EQL && node.Op != token.NEQ {
					return true
				}
				if isLiteralOrNil(node.X) || isLiteralOrNil(node.Y) {
					return true
				}
				for _, side := range []ast.Expr{node.X, node.Y} {
					if id, ok := side.(*ast.Ident); ok && secretName.MatchString(id.Name) {
						t.Errorf("%s: %s compared with %s; use secretEqual", fset.Position(node.Pos()), id.Name, node.Op)
					}
				}
			case *ast.CallExpr:
				if id, ok := node.Fun.(*ast.Ident); ok && id.Name == "metricsHandler" && filepath.Base(file) != "listener_auth.go" {
					t.Errorf("%s: /metrics mounted without protectedMetricsHandler", fset.Position(node.Pos()))
				}
			}
			return true
		})
	}
}

// isLiteralOrNil: a secret is never a compile-time literal, so a comparison
// against one is a presence or mode check, not a credential comparison.
func isLiteralOrNil(expr ast.Expr) bool {
	if _, ok := expr.(*ast.BasicLit); ok {
		return true
	}
	id, ok := expr.(*ast.Ident)
	return ok && id.Name == "nil"
}
