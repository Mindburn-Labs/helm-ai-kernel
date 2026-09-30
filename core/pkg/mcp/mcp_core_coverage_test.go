package mcp

// quantum_posture: tests classical RSA (RS256) JWKS/JWT bearer-token
// validation; no post-quantum claim.

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

type errorCatalog struct{}

func (errorCatalog) Search(context.Context, string) ([]ToolRef, error) {
	return nil, errors.New("catalog failed")
}

func (errorCatalog) Register(context.Context, ToolRef) error {
	return errors.New("catalog failed")
}

func TestCoverageGatewayAndCatalogBranches(t *testing.T) {
	catalog := NewInMemoryCatalog()
	catalog.RegisterGovernanceTools()
	if _, ok := catalog.Lookup("helm.verify"); !ok {
		t.Fatal("governance tool not registered")
	}
	if _, ok := catalog.Lookup("helm.evaluate"); !ok {
		t.Fatal("governance evaluate tool not registered")
	}
	if _, err := catalog.AuditToolCall("bad", map[string]any{"bad": func() {}}, "result"); err == nil {
		t.Fatal("expected audit input marshal error")
	}
	if _, err := catalog.AuditToolCall("bad", map[string]any{}, func() {}); err == nil {
		t.Fatal("expected audit output marshal error")
	}

	toolCatalog := NewInMemoryCatalog()
	if err := toolCatalog.Register(context.Background(), ToolRef{
		Name:        "echo",
		Description: "echo text",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"text": map[string]any{"type": "string"},
			},
			"required": []any{"text"},
		},
	}); err != nil {
		t.Fatalf("register echo: %v", err)
	}

	gateway := NewGateway(toolCatalog, GatewayConfig{AuthMode: "oauth"}, WithBridge(nil))
	mux := http.NewServeMux()
	gateway.RegisterRoutes(mux)

	for name, tc := range map[string]struct {
		method string
		path   string
		body   string
		want   int
	}{
		"index":          {method: http.MethodGet, path: "/mcp", want: http.StatusOK},
		"transport bad":  {method: http.MethodDelete, path: "/mcp", want: http.StatusMethodNotAllowed},
		"execute method": {method: http.MethodGet, path: "/mcp/v1/execute", want: http.StatusMethodNotAllowed},
		"execute json":   {method: http.MethodPost, path: "/mcp/v1/execute", body: `{`, want: http.StatusBadRequest},
		"execute absent": {method: http.MethodPost, path: "/mcp/v1/execute", body: `{"method":"missing"}`, want: http.StatusNotFound},
		"execute schema": {method: http.MethodPost, path: "/mcp/v1/execute", body: `{"method":"echo","params":{}}`, want: http.StatusBadRequest},
		"metadata none":  {method: http.MethodGet, path: "/.well-known/oauth-protected-resource", want: http.StatusOK},
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			mux.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}

	t.Setenv("HELM_OAUTH_AUTHORIZATION_SERVER", "https://auth.example")
	t.Setenv("HELM_OAUTH_SCOPES", "mcp:tools,helm:verify helm:evaluate")
	rec := httptest.NewRecorder()
	gateway.handleProtectedResourceMetadata(rec, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "https://auth.example") || !strings.Contains(rec.Body.String(), "helm:evaluate") {
		t.Fatalf("metadata response status=%d body=%s", rec.Code, rec.Body.String())
	}
	noneGateway := NewGateway(toolCatalog, GatewayConfig{})
	rec = httptest.NewRecorder()
	noneGateway.handleProtectedResourceMetadata(rec, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("non-oauth metadata status=%d", rec.Code)
	}

	localReq := httptest.NewRequest(http.MethodPost, "/mcp/v1/execute", strings.NewReader(`{"method":"echo","params":{"text":"hi"}}`))
	rec = httptest.NewRecorder()
	gateway.handleExecute(rec, localReq)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "local-no-bridge") {
		t.Fatalf("local execute status=%d body=%s", rec.Code, rec.Body.String())
	}

	execGateway := NewGateway(toolCatalog, GatewayConfig{}, WithExecutor(func(_ context.Context, _ ToolExecutionRequest) (ToolExecutionResponse, error) {
		return ToolExecutionResponse{}, errors.New("exec failed")
	}))
	rec = httptest.NewRecorder()
	execGateway.handleExecute(rec, httptest.NewRequest(http.MethodPost, "/mcp/v1/execute", strings.NewReader(`{"method":"echo","params":{"text":"hi"}}`)))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("exec error status=%d body=%s", rec.Code, rec.Body.String())
	}

	denyGateway := NewGateway(toolCatalog, GatewayConfig{}, WithExecutor(func(_ context.Context, _ ToolExecutionRequest) (ToolExecutionResponse, error) {
		return ToolExecutionResponse{Content: "denied", IsError: true, ContentItems: StructuredTextContent(map[string]any{"error": "denied"}, "denied"), StructuredContent: map[string]any{"error": "denied"}}, nil
	}))
	rec = httptest.NewRecorder()
	denyGateway.handleExecute(rec, httptest.NewRequest(http.MethodPost, "/mcp/v1/execute", strings.NewReader(`{"method":"echo","params":{"text":"hi"}}`)))
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "denied") {
		t.Fatalf("exec deny status=%d body=%s", rec.Code, rec.Body.String())
	}

	errGateway := NewGateway(errorCatalog{}, GatewayConfig{})
	rec = httptest.NewRecorder()
	errGateway.handleCapabilities(rec, httptest.NewRequest(http.MethodGet, "/mcp/v1/capabilities", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("capabilities error status=%d", rec.Code)
	}
	if _, ok := findToolRef(errorCatalog{}, "missing"); ok {
		t.Fatal("findToolRef should fail when catalog search errors")
	}
	if _, err := ValidateToolArguments(ToolRef{Name: "no-schema"}, nil); err != nil {
		t.Fatalf("nil schema should allow empty args: %v", err)
	}
	if schema := catalogSchemaToArgSchema("not-map"); schema != nil {
		t.Fatalf("non-map schema should return nil: %+v", schema)
	}
	if schema := catalogSchemaToArgSchema(map[string]any{"type": "object"}); schema != nil {
		t.Fatalf("schema without props should return nil: %+v", schema)
	}
}

func TestCoverageGatewayJSONRPCBranches(t *testing.T) {
	catalog := NewInMemoryCatalog()
	if err := catalog.Register(context.Background(), ToolRef{
		Name:        "echo",
		Description: "echo text",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"text": map[string]any{"type": "string"},
			},
			"required": []string{"text"},
		},
	}); err != nil {
		t.Fatalf("register echo: %v", err)
	}
	gateway := NewGateway(catalog, GatewayConfig{})
	for name, tc := range map[string]struct {
		method string
		params json.RawMessage
		want   int
		errSub string
	}{
		"notification": {method: "notifications/initialized", want: http.StatusAccepted},
		"ping":         {method: "ping", want: http.StatusOK},
		"bad call":     {method: "tools/call", params: json.RawMessage(`{`), want: http.StatusOK, errSub: "invalid tools/call"},
		"missing tool": {method: "tools/call", params: json.RawMessage(`{"name":"missing"}`), want: http.StatusOK, errSub: "not found"},
		"bad args":     {method: "tools/call", params: json.RawMessage(`{"name":"echo","arguments":{}}`), want: http.StatusOK, errSub: "PEP validation"},
		"no exec":      {method: "tools/call", params: json.RawMessage(`{"name":"echo","arguments":{"text":"hi"}}`), want: http.StatusOK, errSub: "executor"},
		"unknown":      {method: "unknown", want: http.StatusOK, errSub: "not found"},
	} {
		t.Run(name, func(t *testing.T) {
			resp, respond, status := gateway.handleJSONRPCRequest(context.Background(), 1, tc.method, tc.params, LatestProtocolVersion)
			if status != tc.want {
				t.Fatalf("status = %d, want %d resp=%+v", status, tc.want, resp)
			}
			if tc.method == "notifications/initialized" {
				if respond {
					t.Fatal("notification should not respond")
				}
				return
			}
			if !respond {
				t.Fatal("expected response")
			}
			if tc.errSub != "" && !strings.Contains(marshalMCPTestValue(t, resp), tc.errSub) {
				t.Fatalf("response missing %q: %+v", tc.errSub, resp)
			}
		})
	}

	execGateway := NewGateway(catalog, GatewayConfig{}, WithExecutor(func(_ context.Context, _ ToolExecutionRequest) (ToolExecutionResponse, error) {
		return ToolExecutionResponse{}, errors.New("exec failed")
	}))
	resp, respond, status := execGateway.handleJSONRPCRequestWithSession(context.Background(), 1, "tools/call", json.RawMessage(`{"name":"echo","arguments":{"text":"hi"}}`), LatestProtocolVersion, "direct-test-session", nil)
	if !respond || status != http.StatusOK || !strings.Contains(marshalMCPTestValue(t, resp), "exec failed") {
		t.Fatalf("exec error JSON-RPC response=%+v respond=%v status=%d", resp, respond, status)
	}
}

// mcpTestClaims is the claim shape the MCP tests sign.
type mcpTestClaims struct {
	Scope       string   `json:"scope"`
	Resource    string   `json:"resource"`
	Resources   []string `json:"resources"`
	TenantID    string   `json:"tenant_id"`
	WorkspaceID string   `json:"workspace_id"`
	jwt.RegisteredClaims
}

func signMCPTestJWT(t *testing.T, privateKey *rsa.PrivateKey, kid string, claims mcpTestClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}
	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return signed
}

func isJWKSKind(err error, kind JWKSValidationErrorKind) bool {
	var typed *JWKSValidationError
	return errors.As(err, &typed) && typed.Kind == kind
}

func marshalMCPTestValue(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return string(data)
}
