package server

// quantum_posture: exercises token checks with a fake validator and computes
// SHA-256 certificate thumbprints; no post-quantum claim.

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"connectrpc.com/connect"
	"github.com/golang-jwt/jwt/v5"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth/jwks"
	errorsv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/errors/v1"
)

const testActor = "spiffe://helm/control-plane"

type fakeValidator struct {
	claims *jwks.OAuthTokenClaims
	err    error
}

func (f fakeValidator) ValidateAuthorization(string) (*jwks.OAuthTokenClaims, error) {
	return f.claims, f.err
}

func goodClaims() *jwks.OAuthTokenClaims {
	return &jwks.OAuthTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: "human-a", Audience: jwt.ClaimStrings{"helm-gateway:qa"}, ID: "jti-1"},
		Scopes:           []string{ScopePropose},
		TenantID:         "tenant-a",
		WorkspaceID:      "ws-a",
		Actor:            testActor,
	}
}

func bearer() http.Header {
	h := http.Header{}
	h.Set("Authorization", "Bearer a.b.c")
	return h
}

// errorDetail returns the code, reason and retryable flag of a Connect error.
func errorDetail(t *testing.T, err error) (connect.Code, string, bool) {
	t.Helper()
	var ce *connect.Error
	if !errors.As(err, &ce) {
		t.Fatalf("err = %v, want a Connect error", err)
	}
	for _, d := range ce.Details() {
		v, derr := d.Value()
		if detail, ok := v.(*errorsv1.ErrorDetail); derr == nil && ok {
			return ce.Code(), detail.GetReasonCode(), detail.GetRetryable()
		}
	}
	t.Fatalf("%v carries no ErrorDetail", err)
	return 0, "", false
}

func TestAuthenticateTakesIdentityOnlyFromAValidToken(t *testing.T) {
	a := &Authenticator{Validator: fakeValidator{claims: goodClaims()}, Actor: testActor}
	id, err := a.Authenticate(context.Background(), bearer(), ScopePropose)
	if err != nil {
		t.Fatal(err)
	}
	if id.TenantID != "tenant-a" || id.WorkspaceID != "ws-a" || id.PrincipalID != "human-a" || id.ActorID != testActor || id.TokenID != "jti-1" {
		t.Fatalf("identity = %+v", id)
	}
	// A principal's own token, with no actor, is accepted too.
	direct := goodClaims()
	direct.Actor = ""
	if _, err := (&Authenticator{Validator: fakeValidator{claims: direct}, Actor: testActor}).Authenticate(context.Background(), bearer(), ScopePropose); err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticateRefusesBadTokens(t *testing.T) {
	edit := func(f func(*jwks.OAuthTokenClaims)) *jwks.OAuthTokenClaims {
		c := goodClaims()
		f(c)
		return c
	}
	for _, test := range []struct {
		name      string
		header    http.Header
		validator fakeValidator
		scopes    []string
		code      connect.Code
		retryable bool
	}{
		{"no token", http.Header{}, fakeValidator{claims: goodClaims()}, []string{ScopePropose}, connect.CodeUnauthenticated, false},
		{"not a bearer", http.Header{"Authorization": {"Basic abc"}}, fakeValidator{claims: goodClaims()}, []string{ScopePropose}, connect.CodeUnauthenticated, false},
		{"invalid token", bearer(), fakeValidator{err: &jwks.JWKSValidationError{Kind: jwks.JWKSErrInvalidSignature}}, []string{ScopePropose}, connect.CodeUnauthenticated, false},
		{"keys unavailable", bearer(), fakeValidator{err: &jwks.JWKSValidationError{Kind: jwks.JWKSErrFetchFailed}}, []string{ScopePropose}, connect.CodeUnavailable, true},
		{"two audiences", bearer(), fakeValidator{claims: edit(func(c *jwks.OAuthTokenClaims) {
			c.RegisteredClaims.Audience = append(c.RegisteredClaims.Audience, "helm-kernel:qa")
		})}, []string{ScopePropose}, connect.CodeUnauthenticated, false},
		{"no tenant", bearer(), fakeValidator{claims: edit(func(c *jwks.OAuthTokenClaims) { c.TenantID = "" })}, []string{ScopePropose}, connect.CodeUnauthenticated, false},
		{"no workspace", bearer(), fakeValidator{claims: edit(func(c *jwks.OAuthTokenClaims) { c.WorkspaceID = "" })}, []string{ScopePropose}, connect.CodeUnauthenticated, false},
		{"no subject", bearer(), fakeValidator{claims: edit(func(c *jwks.OAuthTokenClaims) { c.RegisteredClaims.Subject = "" })}, []string{ScopePropose}, connect.CodeUnauthenticated, false},
		{"another actor", bearer(), fakeValidator{claims: edit(func(c *jwks.OAuthTokenClaims) { c.Actor = "spiffe://evil" })}, []string{ScopePropose}, connect.CodePermissionDenied, false},
		{"wrong scope", bearer(), fakeValidator{claims: edit(func(c *jwks.OAuthTokenClaims) { c.Scopes = []string{ScopeRead} })}, []string{ScopePropose}, connect.CodePermissionDenied, false},
		{"two scopes", bearer(), fakeValidator{claims: edit(func(c *jwks.OAuthTokenClaims) { c.Scopes = []string{ScopePropose, ScopeRead} })}, []string{ScopePropose}, connect.CodePermissionDenied, false},
		{"kernel scope", bearer(), fakeValidator{claims: edit(func(c *jwks.OAuthTokenClaims) { c.Scopes = []string{"helm.evaluate"} })}, []string{ScopeRead}, connect.CodePermissionDenied, false},
	} {
		a := &Authenticator{Validator: test.validator, Actor: testActor}
		_, err := a.Authenticate(context.Background(), test.header, test.scopes...)
		code, _, retryable := errorDetail(t, err)
		if code != test.code || retryable != test.retryable {
			t.Errorf("%s: code = %v retryable = %v, want %v %v (%v)", test.name, code, retryable, test.code, test.retryable, err)
		}
	}
}

func TestAuthenticateBindsTheTokenToTheClientCertificateWhenRequired(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte("client certificate")}
	other := &x509.Certificate{Raw: []byte("another certificate")}
	claims := goodClaims()
	claims.CertificateThumbprint = thumbprint(cert)
	a := &Authenticator{Validator: fakeValidator{claims: claims}, Actor: testActor, RequireCNF: true}
	with := func(c *x509.Certificate) context.Context {
		return context.WithValue(context.Background(), tlsStateKey{}, &tls.ConnectionState{PeerCertificates: []*x509.Certificate{c}})
	}
	if _, err := a.Authenticate(with(cert), bearer(), ScopePropose); err != nil {
		t.Fatalf("the bound certificate: %v", err)
	}
	for name, ctx := range map[string]context.Context{"another certificate": with(other), "no TLS": context.Background()} {
		if code, _, _ := errorDetail(t, func() error { _, err := a.Authenticate(ctx, bearer(), ScopePropose); return err }()); code != connect.CodeUnauthenticated {
			t.Fatalf("%s: code = %v, want unauthenticated", name, code)
		}
	}
}

// thumbprint is cnf.x5t#S256 for cert (RFC 8705).
func thumbprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestDecisionBinding(t *testing.T) {
	const id = "0192f0c4-7a1e-7c3b-9d2a-5b8e4f1a2c3d"
	good := `[{"type":"helm_effect_decision","attempt_id":"` + id + `","action":"approve"},{"type":"other","x":1}]`
	if err := checkDecisionBinding(json.RawMessage(good), id, "approve"); err != nil {
		t.Fatalf("a bound token: %v", err)
	}
	for name, test := range map[string]struct{ raw, attempt, action string }{
		"no claim":          {"", id, "approve"},
		"not a list":        {`{"type":"helm_effect_decision"}`, id, "approve"},
		"another attempt":   {good, "0192f0c4-7a1e-7c3b-9d2a-000000000000", "approve"},
		"another action":    {good, id, "reject"},
		"no decision entry": {`[{"type":"helm_stop_lift","stop_id":"s"}]`, id, "approve"},
		"two decision entries": {`[{"type":"helm_effect_decision","attempt_id":"` + id + `","action":"approve"},` +
			`{"type":"helm_effect_decision","attempt_id":"x","action":"approve"}]`, id, "approve"},
	} {
		code, reason, _ := errorDetail(t, checkDecisionBinding(json.RawMessage(test.raw), test.attempt, test.action))
		if code != connect.CodePermissionDenied || reason != "INSUFFICIENT_PRIVILEGE" {
			t.Errorf("%s: %v %q, want permission_denied", name, code, reason)
		}
	}
}
