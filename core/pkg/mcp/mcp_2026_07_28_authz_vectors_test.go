package mcp

// Conformance vectors for the MCP 2026-07-28 release candidate
// authorization SEPs (MIN-495). Vector data lives in
// testdata/mcp_2026_07_28_authz_vectors.json; the mapping narrative lives
// in docs/MCP_2026_07_28_AUTHORIZATION_MAPPING.md.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

type authzVectorFile struct {
	Spec     string        `json:"spec"`
	Source   string        `json:"source"`
	Issuer   string        `json:"issuer"`
	Audience string        `json:"audience"`
	Resource string        `json:"resource"`
	Vectors  []authzVector `json:"vectors"`
}

type authzVector struct {
	ID             string   `json:"id"`
	SEP            string   `json:"sep"`
	Kind           string   `json:"kind"`
	Note           string   `json:"note"`
	TokenIssuer    string   `json:"token_issuer,omitempty"`
	TokenResource  string   `json:"token_resource,omitempty"`
	TokenScope     string   `json:"token_scope,omitempty"`
	ExpectedError  string   `json:"expected_error,omitempty"`
	GrantedScopes  []string `json:"granted_scopes,omitempty"`
	RequiredScopes []string `json:"required_scopes,omitempty"`
	ExpectedVerd   string   `json:"expected_verdict,omitempty"`
	ExpectedReason string   `json:"expected_reason,omitempty"`
	Path           string   `json:"path,omitempty"`
	ExpectedFields []string `json:"expected_fields,omitempty"`
}

func loadAuthzVectors(t *testing.T) authzVectorFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "mcp_2026_07_28_authz_vectors.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var file authzVectorFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("vector file is empty")
	}
	return file
}

func TestMCP20260728AuthorizationSEPVectors(t *testing.T) {
	file := loadAuthzVectors(t)

	// Shared JWKS fixture for token vectors.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	jwksBody, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &privateKey.PublicKey, KeyID: "kid-1", Use: "sig", Algorithm: "RS256"},
	}})
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBody)
	}))
	defer jwksServer.Close()

	validator := NewJWKSValidator(JWKSConfig{
		JWKSURL:  jwksServer.URL,
		Issuer:   file.Issuer,
		Audience: file.Audience,
		Resource: file.Resource,
		// httptest serves over http://127.0.0.1 — the explicit loopback
		// opt-in keeps the https-only JWKS rule fail-closed everywhere else.
		AllowInsecureLoopback: true,
	})

	// Shared execution firewall fixture for tool_call vectors.
	ctx := context.Background()
	catalog := NewToolCatalog()
	registry := NewQuarantineRegistry()
	firewall := NewExecutionFirewall(catalog, registry, "epoch-2026-07-28-rc")
	firewall.Clock = boundaryFixedClock()
	if _, err := registry.Discover(ctx, DiscoverServerRequest{ServerID: "srv-rc"}); err != nil {
		t.Fatalf("discover: %v", err)
	}
	if _, err := registry.Approve(ctx, ApprovalDecision{ServerID: "srv-rc", ApproverID: "user:reviewer", ApprovalReceiptID: "approval-rc"}); err != nil {
		t.Fatalf("approve: %v", err)
	}

	// Shared gateway fixture for discovery vectors.
	gateway := NewGateway(catalog, GatewayConfig{AuthMode: "oauth", BaseURL: "https://resource.example"})
	mux := http.NewServeMux()
	gateway.RegisterRoutes(mux)

	covered := map[string]bool{}
	for _, vector := range file.Vectors {
		vector := vector
		covered[vector.SEP] = true
		t.Run(vector.ID, func(t *testing.T) {
			switch vector.Kind {
			case "token":
				runTokenVector(t, validator, privateKey, file, vector)
			case "tool_call":
				runToolCallVector(t, ctx, catalog, firewall, vector)
			case "discovery":
				runDiscoveryVector(t, mux, vector)
			case "client_obligation":
				if vector.Note == "" {
					t.Fatal("client obligation vector must document the obligation")
				}
			default:
				t.Fatalf("unknown vector kind %q", vector.Kind)
			}
		})
	}

	for _, sep := range []string{"SEP-2468", "SEP-837", "SEP-2352", "SEP-2207", "SEP-2350", "SEP-2351"} {
		if !covered[sep] {
			t.Errorf("authorization SEP %s has no conformance vector", sep)
		}
	}
}

func runTokenVector(t *testing.T, validator *JWKSValidator, key *rsa.PrivateKey, file authzVectorFile, vector authzVector) {
	t.Helper()
	token := signMCPTestJWT(t, key, "kid-1", jwksClaims{
		Scope:    vector.TokenScope,
		Resource: vector.TokenResource,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    vector.TokenIssuer,
			Audience:  jwt.ClaimStrings{file.Audience},
			Subject:   "agent-rc",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		},
	})
	claims, err := validator.ValidateAuthorization(token)
	if vector.ExpectedError == "" {
		if err != nil {
			t.Fatalf("expected token to validate, got %v", err)
		}
		if !containsString(claims.Resources, file.Resource) {
			t.Fatalf("validated claims missing bound resource: %+v", claims)
		}
		return
	}
	if !isJWKSKind(err, JWKSValidationErrorKind(vector.ExpectedError)) {
		t.Fatalf("expected %s, got %v", vector.ExpectedError, err)
	}
}

func runToolCallVector(t *testing.T, ctx context.Context, catalog *ToolCatalog, firewall *ExecutionFirewall, vector authzVector) {
	t.Helper()
	tool := ToolRef{
		Name:           "rc." + vector.ID,
		ServerID:       "srv-rc",
		RequiredScopes: vector.RequiredScopes,
		Schema:         map[string]any{"type": "object"},
	}
	if err := catalog.Register(ctx, tool); err != nil {
		t.Fatalf("register tool: %v", err)
	}
	record, err := firewall.AuthorizeToolCall(ctx, ToolCallAuthorization{
		ServerID:      "srv-rc",
		ToolName:      tool.Name,
		ArgsHash:      "sha256:vector-args",
		GrantedScopes: vector.GrantedScopes,
		OAuthResource: "https://resource.example/mcp",
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if string(record.Verdict) != vector.ExpectedVerd {
		t.Fatalf("verdict = %s, want %s", record.Verdict, vector.ExpectedVerd)
	}
	if vector.ExpectedReason != "" && string(record.ReasonCode) != vector.ExpectedReason {
		t.Fatalf("reason = %s, want %s", record.ReasonCode, vector.ExpectedReason)
	}
	// SIEM-ready structured audit: every decision is a sealed, hash-bound
	// record carrying the OAuth authorization context.
	if record.RecordHash == "" {
		t.Fatal("decision record was not sealed")
	}
	if record.RecordID == "" || record.PolicyEpoch == "" || record.CreatedAt.IsZero() {
		t.Fatalf("decision record missing SIEM fields: %+v", record)
	}
	if record.OAuthResource == "" || len(record.OAuthScopes) != len(vector.GrantedScopes) {
		t.Fatalf("decision record missing OAuth context: %+v", record)
	}
	if record.Verdict != contracts.VerdictAllow && record.ReasonCode == "" {
		t.Fatal("deny record missing reason code")
	}
}

func runDiscoveryVector(t *testing.T, mux *http.ServeMux, vector authzVector) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, vector.Path, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", vector.Path, rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("metadata is not JSON: %v", err)
	}
	for _, field := range vector.ExpectedFields {
		if _, ok := body[field]; !ok {
			t.Errorf("metadata missing field %q: %v", field, body)
		}
	}
}
