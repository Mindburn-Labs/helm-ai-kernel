package server

// quantum_posture: exercises token checks with a fake validator and computes
// SHA-256 certificate thumbprints; no post-quantum claim.

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/protobuf/proto"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth/jwks"
	errorsv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/errors/v1"
	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"
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

// countingValidator records whether authentication ran.
type countingValidator struct{ calls *int }

func (c countingValidator) ValidateAuthorization(string) (*jwks.OAuthTokenClaims, error) {
	*c.calls++
	return goodClaims(), nil
}

// M2: an oversize request is refused before authentication, whether it is
// oversize as sent or only once decompressed.
func TestOversizeRequestsAreRefusedBeforeAuthentication(t *testing.T) {
	calls := 0
	api := &Server{Auth: &Authenticator{Validator: countingValidator{&calls}, Actor: testActor}}
	mux := http.NewServeMux()
	mux.Handle(api.Handler())
	server := httptest.NewUnstartedServer(mux)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	big := &gatewayv1.ProposeRequest{
		IdempotencyKey: "k",
		Effect:         &gatewayv1.EffectDescriptor{EffectType: "ops.note", Target: "ops", Arguments: bytes.Repeat([]byte("a"), MaxMessageBytes+1)},
	}
	for name, opts := range map[string][]connect.ClientOption{
		"plain":        {connect.WithGRPC()},
		"gzip":         {connect.WithGRPC(), connect.WithSendGzip()},
		"connect gzip": {connect.WithSendGzip()},
	} {
		client := gatewayv1.NewEffectGatewayServiceClient(server.Client(), server.URL, opts...)
		req := connect.NewRequest(big)
		req.Header().Set("Authorization", "Bearer a.b.c")
		_, err := client.Propose(context.Background(), req)
		if code := connect.CodeOf(err); code != connect.CodeResourceExhausted && code != connect.CodeInvalidArgument {
			t.Errorf("%s: an oversize request = %v (%v), want it refused for its size", name, code, err)
		}
	}
	// A valid ProposeRequest of 4 MiB, gzipped far under the wire cap: only
	// the cap after decompression can refuse it.
	bomb, err := proto.Marshal(&gatewayv1.ProposeRequest{
		IdempotencyKey: "k",
		Effect:         &gatewayv1.EffectDescriptor{EffectType: "ops.note", Target: "ops", Arguments: bytes.Repeat([]byte("a"), 4<<20)},
	})
	if err != nil {
		t.Fatal(err)
	}
	var inflated bytes.Buffer
	zw := gzip.NewWriter(&inflated)
	_, _ = zw.Write(bomb)
	_ = zw.Close()
	if inflated.Len() >= MaxBodyBytes {
		t.Fatalf("the gzip bomb is %d bytes on the wire; the test needs it under the body cap", inflated.Len())
	}
	var req *http.Request
	req, err = http.NewRequest(http.MethodPost, server.URL+gatewayv1.EffectGatewayServiceProposeProcedure, &inflated)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/proto")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Authorization", "Bearer a.b.c")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.Header.Get("Content-Type") == "" {
		t.Fatalf("a gzip body that inflates past the cap = %d", resp.StatusCode)
	}
	if calls != 0 {
		t.Fatalf("authentication ran %d times for oversize requests", calls)
	}

	// Known good: a request under the cap reaches authentication.
	small := connect.NewRequest(&gatewayv1.GetAttemptRequest{AttemptId: "x"})
	small.Header().Set("Authorization", "Bearer a.b.c")
	_, _ = gatewayv1.NewEffectGatewayServiceClient(server.Client(), server.URL, connect.WithSendGzip()).GetAttempt(context.Background(), small)
	if calls != 1 {
		t.Fatalf("a small request ran authentication %d times, want 1", calls)
	}
}
