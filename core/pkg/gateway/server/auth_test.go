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
	"encoding/json"
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

	// Propose alone may carry an authority plan, so its cap is the larger one;
	// every other RPC keeps the 128 KiB cap.
	big := &gatewayv1.ProposeRequest{
		IdempotencyKey: "k",
		Effect:         &gatewayv1.EffectDescriptor{EffectType: "ops.note", Target: "ops", Arguments: bytes.Repeat([]byte("a"), MaxProposeMessageBytes+1)},
	}
	bigAttempt := &gatewayv1.GetAttemptRequest{AttemptId: string(bytes.Repeat([]byte("a"), MaxMessageBytes+1))}
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
			t.Errorf("%s: an oversize Propose = %v (%v), want it refused for its size", name, code, err)
		}
		readReq := connect.NewRequest(bigAttempt)
		readReq.Header().Set("Authorization", "Bearer a.b.c")
		_, err = client.GetAttempt(context.Background(), readReq)
		if code := connect.CodeOf(err); code != connect.CodeResourceExhausted && code != connect.CodeInvalidArgument {
			t.Errorf("%s: an oversize GetAttempt = %v (%v), want it refused for its size", name, code, err)
		}
	}
	// A Propose past 128 KiB and under its own cap reaches authentication, so a
	// plan can be proposed; any other RPC of that size is refused before it.
	plan := connect.NewRequest(&gatewayv1.ProposeRequest{
		IdempotencyKey: "k",
		Effect:         &gatewayv1.EffectDescriptor{EffectType: "ops.note", Target: "ops", Arguments: bytes.Repeat([]byte("a"), 2*MaxMessageBytes)},
	})
	plan.Header().Set("Authorization", "Bearer a.b.c")
	_, _ = gatewayv1.NewEffectGatewayServiceClient(server.Client(), server.URL, connect.WithGRPC()).Propose(context.Background(), plan)
	if calls != 1 {
		t.Fatalf("a Propose of %d KiB ran authentication %d times, want 1", 2*MaxMessageBytes>>10, calls)
	}
	calls = 0
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
	if len(bomb) <= MaxProposeMessageBytes {
		t.Fatalf("the gzip bomb inflates to %d bytes; the test needs it over Propose's cap", len(bomb))
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

// A stop token names its object: the stop a Lift lifts, the attempt a Cancel
// withdraws (HELM-751 s3b, L4 of the s2 review).
func TestStopTokenBindings(t *testing.T) {
	const stop, attempt = "0192f0c4-7a1e-7c3b-9d2a-5b8e4f1a2c3d", "0192f0c4-7a1e-7c3b-9d2a-000000000001"
	details := func(entries string) json.RawMessage { return json.RawMessage(entries) }
	if err := checkBinding(details(`[{"type":"helm_stop_lift","stop_id":"`+stop+`"}]`), "helm_stop_lift", map[string]string{"stop_id": stop}); err != nil {
		t.Fatalf("a bound lift token was refused: %v", err)
	}
	if err := checkBinding(details(`[{"type":"helm_effect_cancel","attempt_id":"`+attempt+`"}]`), "helm_effect_cancel", map[string]string{"attempt_id": attempt}); err != nil {
		t.Fatalf("a bound cancel token was refused: %v", err)
	}
	for name, raw := range map[string]string{
		"none":                 ``,
		"not a list":           `{"type":"helm_stop_lift","stop_id":"` + stop + `"}`,
		"another stop":         `[{"type":"helm_stop_lift","stop_id":"` + attempt + `"}]`,
		"a decide entry":       `[{"type":"helm_effect_decision","attempt_id":"` + stop + `","action":"approve"}]`,
		"two lift entries":     `[{"type":"helm_stop_lift","stop_id":"` + stop + `"},{"type":"helm_stop_lift","stop_id":"` + stop + `"}]`,
		"a non-string stop_id": `[{"type":"helm_stop_lift","stop_id":1}]`,
	} {
		if err := checkBinding(details(raw), "helm_stop_lift", map[string]string{"stop_id": stop}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// N1 permits an episode to propose and read its own attempts. This optional
// read scope must not grant dispatch or weaken the single-scope CP profile.
func TestEpisodeProposeAndReadScopes(t *testing.T) {
	for _, test := range []struct {
		name      string
		scopes    []string
		wantError bool
	}{
		{"propose only", []string{ScopePropose}, false},
		{"propose and read", []string{ScopePropose, ScopeRead}, false},
		{"read and propose", []string{ScopeRead, ScopePropose}, false},
		{"execute", []string{ScopePropose, ScopeExecute}, true},
		{"decide", []string{ScopePropose, ScopeDecide}, true},
		{"read only", []string{ScopeRead}, true},
		{"duplicate", []string{ScopePropose, ScopePropose}, true},
		{"duplicate read", []string{ScopePropose, ScopeRead, ScopeRead}, true},
		{"foreign", []string{ScopePropose, "other.read"}, true},
		{"empty", nil, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			claims := goodClaims()
			claims.Episode = &jwks.EpisodeClaim{EpisodeID: "ep-1", WorkItemID: "work-1", OrganizationVersionID: "v-1"}
			claims.Scopes = test.scopes
			a := &Authenticator{Validator: fakeValidator{claims: claims}, Actor: testActor, RequireEpisode: true}
			id, err := a.Authenticate(context.Background(), bearer(), ScopePropose)
			if (err != nil) != test.wantError {
				t.Fatalf("identity=%+v err=%v", id, err)
			}
			if err == nil && id.Scope != ScopePropose {
				t.Fatalf("matched scope=%q", id.Scope)
			}
		})
	}
}

func TestEpisodeScopeMustAuthorizeTheRequestedRoute(t *testing.T) {
	for _, tc := range []struct {
		name      string
		scopes    []string
		requested string
		allowed   bool
	}{
		{"read", []string{ScopePropose, ScopeRead}, ScopeRead, true},
		{"propose cannot read", []string{ScopePropose}, ScopeRead, false},
		{"cannot execute", []string{ScopePropose, ScopeRead}, ScopeExecute, false},
		{"cannot decide", []string{ScopePropose, ScopeRead}, ScopeDecide, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := goodClaims()
			claims.Episode = &jwks.EpisodeClaim{EpisodeID: "ep-1", WorkItemID: "work-1", OrganizationVersionID: "v-1"}
			claims.Scopes = tc.scopes
			auth := &Authenticator{Validator: fakeValidator{claims: claims}, Actor: testActor, RequireEpisode: true}
			id, err := auth.Authenticate(context.Background(), bearer(), tc.requested)
			if (err == nil) != tc.allowed {
				t.Fatalf("identity=%+v err=%v", id, err)
			}
			if err == nil && id.Scope != tc.requested {
				t.Fatalf("matched %q want %q", id.Scope, tc.requested)
			}
		})
	}
}

// The worker listener's profile: a token must name its episode, and a token
// that does is identified with it.
func TestTheWorkerProfileRequiresAnEpisode(t *testing.T) {
	withEpisode := goodClaims()
	withEpisode.Episode = &jwks.EpisodeClaim{EpisodeID: "ep-1", WorkItemID: "work-1", OrganizationVersionID: "v-1"}
	worker := &Authenticator{Validator: fakeValidator{claims: withEpisode}, Actor: testActor, RequireEpisode: true}
	id, err := worker.Authenticate(context.Background(), bearer(), ScopePropose)
	if err != nil {
		t.Fatal(err)
	}
	if id.Episode == nil || id.Episode.EpisodeID != "ep-1" || id.Episode.WorkItemID != "work-1" {
		t.Fatalf("identity = %+v", id)
	}
	// No episode: this listener serves episode tokens only, and the refusal is
	// permission_denied (the token is valid, it is not for here).
	bare := &Authenticator{Validator: fakeValidator{claims: goodClaims()}, Actor: testActor, RequireEpisode: true}
	_, err = bare.Authenticate(context.Background(), bearer(), ScopePropose)
	if code, reason, _ := errorDetail(t, err); code != connect.CodePermissionDenied || reason != "INSUFFICIENT_PRIVILEGE" {
		t.Fatalf("a worker listener given a token with no episode: %v", err)
	}
	// The main profile does not ask for one, and still reports one that is there.
	main := &Authenticator{Validator: fakeValidator{claims: goodClaims()}, Actor: testActor}
	if id, err := main.Authenticate(context.Background(), bearer(), ScopePropose); err != nil || id.Episode != nil {
		t.Fatalf("the main profile: %+v %v", id, err)
	}
	// The episode requirement never replaces the scope check.
	wrongScope := goodClaims()
	wrongScope.Episode = withEpisode.Episode
	wrongScope.Scopes = []string{ScopeRead}
	if _, err := (&Authenticator{Validator: fakeValidator{claims: wrongScope}, Actor: testActor, RequireEpisode: true}).Authenticate(context.Background(), bearer(), ScopePropose); err == nil {
		t.Fatal("an episode token with the wrong scope was accepted")
	}
}
