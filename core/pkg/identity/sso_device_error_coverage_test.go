package identity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestDeviceIdentityValidationFailures(t *testing.T) {
	valid := NewDeviceIdentity("device-1", "tenant-1", "Robot", DeviceClassRobot, "owner-1", []string{"move"})
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate valid device: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*DeviceIdentity)
	}{
		{"missing id", func(d *DeviceIdentity) { d.ID = "" }},
		{"missing tenant", func(d *DeviceIdentity) { d.TenantID = "" }},
		{"missing class", func(d *DeviceIdentity) { d.Class = "" }},
		{"missing owner", func(d *DeviceIdentity) { d.OwnerID = "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			device := *valid
			tt.mutate(&device)
			if err := device.Validate(); err == nil {
				t.Fatal("Validate error = nil")
			}
		})
	}
}

func TestOIDCProviderDiscoveryLoginAndCallbackErrors(t *testing.T) {
	cached := &OIDCProvider{discoveryDoc: &oidcDiscoveryDoc{}}
	if err := cached.discover(context.Background()); err != nil {
		t.Fatalf("cached discover: %v", err)
	}

	if err := NewOIDCProvider("://bad", "client", "secret", "redirect").discover(context.Background()); err == nil {
		t.Fatal("discover bad URL error = nil")
	}

	statusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer statusServer.Close()
	if err := NewOIDCProvider(statusServer.URL, "client", "secret", "redirect").discover(context.Background()); err == nil {
		t.Fatal("discover status error = nil")
	}

	jsonServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{"))
	}))
	defer jsonServer.Close()
	if err := NewOIDCProvider(jsonServer.URL, "client", "secret", "redirect").discover(context.Background()); err == nil {
		t.Fatal("discover JSON error = nil")
	}

	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := NewOIDCProvider(statusServer.URL, "client", "secret", "redirect").discover(cancelCtx); err == nil {
		t.Fatal("discover canceled context error = nil")
	}

	if _, err := NewOIDCProvider("://bad", "client", "secret", "redirect").InitiateLogin(context.Background(), "state"); err == nil {
		t.Fatal("InitiateLogin discovery error = nil")
	}
	if _, err := (&OIDCProvider{
		ClientID:    "client",
		RedirectURL: "redirect",
		discoveryDoc: &oidcDiscoveryDoc{
			AuthorizationEndpoint: "://bad",
		},
	}).InitiateLogin(context.Background(), "state"); err == nil {
		t.Fatal("InitiateLogin bad authorization endpoint error = nil")
	}

	if _, err := NewOIDCProvider("://bad", "client", "secret", "redirect").Callback(context.Background(), "code"); err == nil {
		t.Fatal("Callback discovery error = nil")
	}
	if _, err := (&OIDCProvider{discoveryDoc: &oidcDiscoveryDoc{TokenEndpoint: "://bad"}}).Callback(context.Background(), "code"); err == nil {
		t.Fatal("Callback bad token endpoint error = nil")
	}
	if _, err := (&OIDCProvider{discoveryDoc: &oidcDiscoveryDoc{TokenEndpoint: statusServer.URL}}).Callback(cancelCtx, "code"); err == nil {
		t.Fatal("Callback canceled context error = nil")
	}
	if _, err := (&OIDCProvider{discoveryDoc: &oidcDiscoveryDoc{TokenEndpoint: statusServer.URL}}).Callback(context.Background(), "code"); err == nil {
		t.Fatal("Callback token status error = nil")
	}

	tokenJSONServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{"))
	}))
	defer tokenJSONServer.Close()
	if _, err := (&OIDCProvider{discoveryDoc: &oidcDiscoveryDoc{TokenEndpoint: tokenJSONServer.URL}}).Callback(context.Background(), "code"); err == nil {
		t.Fatal("Callback token JSON error = nil")
	}

	jwksMissingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(oidcTokenResponse{IDToken: "not-a-token"})
	}))
	defer jwksMissingServer.Close()
	if _, err := (&OIDCProvider{discoveryDoc: &oidcDiscoveryDoc{TokenEndpoint: jwksMissingServer.URL}}).Callback(context.Background(), "code"); err == nil {
		t.Fatal("Callback missing JWKS error = nil")
	}
}

func TestJWKSKeyFuncSingleKeyNoMethodMatch(t *testing.T) {
	_, rsaJWK, _ := testJWKs(t)
	rsaJWK.Alg = ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwksDocument{Keys: []jwkKey{rsaJWK}})
	}))
	defer server.Close()

	keyFunc, err := (&OIDCProvider{discoveryDoc: &oidcDiscoveryDoc{JWKSURI: server.URL}}).jwksKeyFunc(context.Background())
	if err != nil {
		t.Fatalf("jwksKeyFunc: %v", err)
	}
	if _, err := keyFunc(&jwt.Token{
		Method: jwt.SigningMethodEdDSA,
		Header: map[string]interface{}{
			"alg": "EdDSA",
		},
	}); err == nil {
		t.Fatal("single-key method mismatch error = nil")
	}

	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (&OIDCProvider{discoveryDoc: &oidcDiscoveryDoc{JWKSURI: server.URL}}).jwksKeyFunc(cancelCtx); err == nil {
		t.Fatal("JWKS canceled context error = nil")
	}
}
