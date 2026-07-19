package mcp

// quantum_posture: tests classical RSA (RS256) JWKS/JWT bearer-token
// validation; no post-quantum claim.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

type errorCatalog struct{}

func (errorCatalog) Search(context.Context, string) ([]ToolRef, error) {
	return nil, errors.New("catalog failed")
}

func (errorCatalog) Register(context.Context, ToolRef) error {
	return errors.New("catalog failed")
}

func TestCoverageJWKSValidator(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	jwksBody, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &privateKey.PublicKey, KeyID: "kid-1", Use: "sig", Algorithm: "RS256"},
		{Key: &privateKey.PublicKey, KeyID: "enc-only", Use: "enc"},
	}})
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBody)
	}))
	defer jwksServer.Close()

	config := JWKSConfig{
		JWKSURL:               jwksServer.URL,
		Issuer:                "issuer",
		Audience:              "audience",
		Resource:              "https://resource.example/mcp",
		Scopes:                []string{"mcp:tools", "helm:verify"},
		AllowInsecureLoopback: true,
	}
	validator := NewJWKSValidator(config)
	token := signMCPTestJWT(t, privateKey, "kid-1", jwksClaims{
		Scope:       "mcp:tools helm:verify extra",
		Resource:    "https://resource.example/mcp",
		Resources:   []string{"https://other.example/mcp"},
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "issuer",
			Audience:  jwt.ClaimStrings{"audience"},
			Subject:   "agent-1",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		},
	})

	claims, err := validator.ValidateAuthorization(token)
	if err != nil {
		t.Fatalf("ValidateAuthorization: %v", err)
	}
	if claims.RegisteredClaims.Subject != "agent-1" || claims.TenantID != "tenant-a" || claims.WorkspaceID != "workspace-a" ||
		!containsString(claims.Resources, "https://resource.example/mcp") || !containsString(claims.Scopes, "helm:verify") {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	registered, err := validator.Validate(token)
	if err != nil || registered.Subject != "agent-1" {
		t.Fatalf("Validate registered=%+v err=%v", registered, err)
	}
	// Second validation uses the cached key set and covers the no-refresh branch.
	if _, err := validator.ValidateAuthorization(token); err != nil {
		t.Fatalf("cached ValidateAuthorization: %v", err)
	}

	missingScope := NewJWKSValidator(JWKSConfig{JWKSURL: jwksServer.URL, Issuer: "issuer", Audience: "audience", Scopes: []string{"missing"}, AllowInsecureLoopback: true})
	if _, err := missingScope.ValidateAuthorization(token); !isJWKSKind(err, JWKSErrMissingScope) {
		t.Fatalf("expected missing scope, got %v", err)
	}
	missingResource := NewJWKSValidator(JWKSConfig{JWKSURL: jwksServer.URL, Issuer: "issuer", Audience: "audience", Resource: "https://missing.example/mcp", AllowInsecureLoopback: true})
	if _, err := missingResource.ValidateAuthorization(token); !isJWKSKind(err, JWKSErrInvalidResource) {
		t.Fatalf("expected invalid resource, got %v", err)
	}
	wrongKid := signMCPTestJWT(t, privateKey, "kid-missing", jwksClaims{
		Scope: "mcp:tools",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "issuer",
			Audience:  jwt.ClaimStrings{"audience"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		},
	})
	if _, err := NewJWKSValidator(JWKSConfig{JWKSURL: jwksServer.URL, Issuer: "issuer", Audience: "audience", AllowInsecureLoopback: true}).ValidateAuthorization(wrongKid); err == nil || (!isJWKSKind(err, JWKSErrKeyNotFound) && (!isJWKSKind(err, JWKSErrMalformedToken) || !strings.Contains(err.Error(), "key_not_found"))) {
		t.Fatalf("expected key not found path, got %v", err)
	}
	noKid := signMCPTestJWT(t, privateKey, "", jwksClaims{
		Scope: "mcp:tools",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "issuer",
			Audience:  jwt.ClaimStrings{"audience"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		},
	})
	if _, err := NewJWKSValidator(JWKSConfig{JWKSURL: jwksServer.URL, Issuer: "issuer", Audience: "audience", AllowInsecureLoopback: true}).ValidateAuthorization(noKid); err != nil {
		t.Fatalf("no-kid token should use first available key: %v", err)
	}

	badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusInternalServerError)
	}))
	defer badServer.Close()
	if err := NewJWKSValidator(JWKSConfig{JWKSURL: badServer.URL, AllowInsecureLoopback: true}).refreshKeysIfNeeded(); !isJWKSKind(err, JWKSErrFetchFailed) {
		t.Fatalf("expected fetch failed, got %v", err)
	}
	invalidJWKS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{`))
	}))
	defer invalidJWKS.Close()
	if err := NewJWKSValidator(JWKSConfig{JWKSURL: invalidJWKS.URL, AllowInsecureLoopback: true}).forceRefreshKeys(); !isJWKSKind(err, JWKSErrFetchFailed) {
		t.Fatalf("expected parse JWKS failure, got %v", err)
	}
	if err := NewJWKSValidator(JWKSConfig{JWKSURL: "http://[::1"}).forceRefreshKeys(); !isJWKSKind(err, JWKSErrFetchFailed) {
		t.Fatalf("expected bad URL failure, got %v", err)
	}
	if err := NewJWKSValidator(JWKSConfig{JWKSURL: "http://jwks.example.test/keys"}).forceRefreshKeys(); !isJWKSKind(err, JWKSErrFetchFailed) || !strings.Contains(err.Error(), "https") {
		t.Fatalf("expected non-TLS JWKS endpoint rejection, got %v", err)
	}
	if _, err := NewJWKSValidator(config).ValidateAuthorization("not-a-jwt"); !isJWKSKind(err, JWKSErrMalformedToken) && !isJWKSKind(err, JWKSErrFetchFailed) {
		t.Fatalf("expected malformed token or fetch failure, got %v", err)
	}

	for message, want := range map[string]JWKSValidationErrorKind{
		"token is expired":           JWKSErrExpiredToken,
		"token used before issued":   JWKSErrNotYetValid,
		"token has invalid issuer":   JWKSErrInvalidIssuer,
		"token has invalid audience": JWKSErrInvalidAudience,
		"signature is invalid":       JWKSErrInvalidSignature,
		"something else":             JWKSErrMalformedToken,
	} {
		if err := classifyJWTError(errors.New(message)); !isJWKSKind(err, want) {
			t.Fatalf("classifyJWTError(%q) = %v, want %s", message, err, want)
		}
	}
	if classifyJWTError(nil) != nil {
		t.Fatal("nil JWT error should classify to nil")
	}
	if containsString([]string{"a"}, "b") {
		t.Fatal("containsString false branch failed")
	}
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
	resp, respond, status := execGateway.handleJSONRPCRequest(context.Background(), 1, "tools/call", json.RawMessage(`{"name":"echo","arguments":{"text":"hi"}}`), LatestProtocolVersion)
	if !respond || status != http.StatusOK || !strings.Contains(marshalMCPTestValue(t, resp), "exec failed") {
		t.Fatalf("exec error JSON-RPC response=%+v respond=%v status=%d", resp, respond, status)
	}
}

func signMCPTestJWT(t *testing.T, privateKey *rsa.PrivateKey, kid string, claims jwksClaims) string {
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
