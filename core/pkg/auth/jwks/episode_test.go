package jwks

// quantum_posture: tests classical RSA (RS256) JWT validation of episode
// tokens; no post-quantum claim.

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// episodeIdentity is an ADR-0005 identity over a JWKS server on loopback, and a
// signer for tokens against it.
func episodeIdentity(t *testing.T) (*ControlPlaneIdentity, func(audience string, lifetime time.Duration, episode any, extra ...jwt.MapClaims) string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "kid-1", Use: "sig", Algorithm: "RS256"}}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	t.Cleanup(srv.Close)
	identity := &ControlPlaneIdentity{Issuer: "helm-workload-identity", Actor: "spiffe://helm/control-plane", config: JWKSConfig{
		JWKSURL: srv.URL, Issuer: "helm-workload-identity", Audience: "helm-gateway:test", Algorithms: []string{"RS256"},
		MaxTokenTTL: CPIdentityMaxTTLCeiling, Leeway: CPIdentityClockSkew, AllowInsecureLoopback: true,
	}}
	sign := func(audience string, lifetime time.Duration, episode any, extra ...jwt.MapClaims) string {
		claims := jwt.MapClaims{
			"iss": "helm-workload-identity", "sub": "agt:seat-1", "aud": audience, "scope": "helm.gateway.propose",
			"tenant_id": "tenant-a", "workspace_id": "ws-a", "act": map[string]string{"sub": identity.Actor}, "jti": "j-1",
			"iat": time.Now().Add(-time.Second).Unix(), "exp": time.Now().Add(-time.Second + lifetime).Unix(),
		}
		if episode != nil {
			claims["helm_episode"] = episode
		}
		for _, fields := range extra {
			for k, v := range fields {
				claims[k] = v
			}
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "kid-1"
		signed, err := token.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	return identity, sign
}

func TestAnEpisodeTokenCarriesItsEpisodeAndAnyOtherTokenNone(t *testing.T) {
	identity, sign := episodeIdentity(t)
	worker, err := identity.WorkerValidator("helm-gateway-worker:test", WorkerTokenMaxTTLCeiling)
	if err != nil {
		t.Fatal(err)
	}
	episode := map[string]string{"episode_id": "ep-7", "work_item_id": "w-9", "organization_version_id": "v-2"}
	claims, err := worker.ValidateAuthorization(sign("helm-gateway-worker:test", 3600*time.Second, episode))
	if err != nil {
		t.Fatal(err)
	}
	if e := claims.Episode; e == nil || e.EpisodeID != "ep-7" || e.WorkItemID != "w-9" || e.OrganizationVersionID != "v-2" || claims.Actor != identity.Actor {
		t.Fatalf("claims = %+v", claims)
	}
	// No claim, no episode.
	plain, err := worker.ValidateAuthorization(sign("helm-gateway-worker:test", time.Hour, nil))
	if err != nil || plain.Episode != nil {
		t.Fatalf("a token without an episode: %+v %v", plain, err)
	}
	// An episode that names nothing usable is a malformed token, not an empty one.
	for name, bad := range map[string]any{
		"no episode id":     map[string]string{"work_item_id": "w-9"},
		"no work item":      map[string]string{"episode_id": "ep-7"},
		"a space in the id": map[string]string{"episode_id": "ep 7", "work_item_id": "w-9"},
		"a slash in the id": map[string]string{"episode_id": "ep/7", "work_item_id": "w-9"},
		"an oversized id":   map[string]string{"episode_id": strings.Repeat("e", 129), "work_item_id": "w-9"},
		"a bad version":     map[string]string{"episode_id": "ep-7", "work_item_id": "w-9", "organization_version_id": "v 2"},
	} {
		if _, err := worker.ValidateAuthorization(sign("helm-gateway-worker:test", time.Hour, bad)); !isJWKSKind(err, JWKSErrMalformedToken) {
			t.Errorf("%s: err = %v, want a malformed token", name, err)
		}
	}
}

func TestTheWorkerValidatorIsTheOnlyOneThatTakesAnEpisodeTokenAndALongLifetime(t *testing.T) {
	identity, sign := episodeIdentity(t)
	worker, err := identity.WorkerValidator("helm-gateway-worker:test", WorkerTokenMaxTTLCeiling)
	if err != nil {
		t.Fatal(err)
	}
	main := identity.Validator(false)
	episode := map[string]string{"episode_id": "ep-7", "work_item_id": "w-9"}

	// An hour-long episode token: valid on the worker listener, not on the main.
	long := sign("helm-gateway-worker:test", 3600*time.Second, episode)
	if _, err := worker.ValidateAuthorization(long); err != nil {
		t.Fatalf("worker listener refused its own token: %v", err)
	}
	if _, err := main.ValidateAuthorization(long); err == nil {
		t.Fatal("the main listener accepted a token minted for the worker audience")
	}
	// A token of the main audience is not valid on the worker listener, whatever
	// its lifetime.
	short := sign("helm-gateway:test", time.Minute, nil)
	if _, err := main.ValidateAuthorization(short); err != nil {
		t.Fatalf("main listener refused its own token: %v", err)
	}
	if _, err := worker.ValidateAuthorization(short); err == nil {
		t.Fatal("the worker listener accepted a token minted for the main audience")
	}
	// Longer than the ceiling is refused even for the worker.
	if _, err := worker.ValidateAuthorization(sign("helm-gateway-worker:test", 3601*time.Second, episode)); !isJWKSKind(err, JWKSErrInvalidLifetime) {
		t.Fatalf("a token past the ceiling: %v", err)
	}
	// And the main listener's ceiling is unchanged: five minutes.
	if _, err := main.ValidateAuthorization(sign("helm-gateway:test", 301*time.Second, nil)); !isJWKSKind(err, JWKSErrInvalidLifetime) {
		t.Fatalf("the main ceiling: %v", err)
	}
}

func TestWorkerValidatorRefusesAConfigurationThatCouldConfuseTheListeners(t *testing.T) {
	identity, _ := episodeIdentity(t)
	for name, test := range map[string]struct {
		audience string
		ttl      time.Duration
	}{
		"no audience":                 {"", time.Hour},
		"a padded audience":           {" helm-gateway-worker:test", time.Hour},
		"the gateway's own audience":  {"helm-gateway:test", time.Hour},
		"no lifetime":                 {"helm-gateway-worker:test", 0},
		"a lifetime past the ceiling": {"helm-gateway-worker:test", 3601 * time.Second},
	} {
		if _, err := identity.WorkerValidator(test.audience, test.ttl); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestExecutorProfileRejectsWorkerAndMalformedCredentials(t *testing.T) {
	identity, sign := episodeIdentity(t)
	executor, err := identity.ExecutorValidator("helm-gateway-executor:test", ExecutorTokenMaxTTLCeiling)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := identity.WorkerValidator("helm-gateway-worker:test", WorkerTokenMaxTTLCeiling)
	if err != nil {
		t.Fatal(err)
	}
	ep := map[string]string{"episode_id": "ep-1", "work_item_id": "work-1", "organization_version_id": "v-1"}
	marker := jwt.MapClaims{"helm_executor": map[string]string{"client": "codex"}}
	for _, client := range []string{"claude-code", "codex", "openclaw"} {
		raw := sign("helm-gateway-executor:test", 900*time.Second, ep, jwt.MapClaims{"helm_executor": map[string]string{"client": client}})
		got, err := executor.ValidateAuthorization(raw)
		if err != nil || got.Executor == nil || got.Executor.Client != client {
			t.Fatalf("%s: %+v %v", client, got, err)
		}
		if _, err := worker.ValidateAuthorization(raw); err == nil {
			t.Fatal("executor credential accepted internally")
		}
	}
	for _, ttl := range []time.Duration{900 * time.Second, time.Hour} {
		raw := sign("helm-gateway-worker:test", ttl, ep)
		if _, err := executor.ValidateAuthorization(raw); err == nil {
			t.Fatalf("worker TTL %s admitted at executor edge", ttl)
		}
		if _, err := worker.ValidateAuthorization(raw); err != nil {
			t.Fatalf("internal worker regressed: %v", err)
		}
	}
	cases := map[string]jwt.MapClaims{
		"missing marker":           {"helm_executor": nil},
		"string marker":            {"helm_executor": "codex"},
		"array marker":             {"helm_executor": []string{"codex"}},
		"unknown client":           {"helm_executor": map[string]string{"client": "other"}},
		"padded client":            {"helm_executor": map[string]string{"client": " codex"}},
		"cased client key":         {"helm_executor": map[string]string{"Client": "codex"}},
		"extra member":             {"helm_executor": map[string]string{"client": "codex", "grant": "all"}},
		"duplicate member":         {"helm_executor": json.RawMessage(`{"client":"codex","client":"codex"}`)},
		"missing episode":          {"helm_episode": nil},
		"missing version":          {"helm_episode": map[string]string{"episode_id": "ep-1", "work_item_id": "work-1"}},
		"padded version":           {"helm_episode": map[string]string{"episode_id": "ep-1", "work_item_id": "work-1", "organization_version_id": " v-1"}},
		"missing actor":            {"act": nil},
		"wrong actor":              {"act": map[string]string{"sub": "spiffe://other"}},
		"human":                    {"sub": "usr:human"},
		"empty seat":               {"sub": "agt:"},
		"missing jti":              {"jti": ""},
		"cnf null":                 {"cnf": nil},
		"cnf empty":                {"cnf": map[string]string{}},
		"cnf thumbprint":           {"cnf": map[string]string{"x5t#S256": "cert"}},
		"mixed audiences":          {"aud": []string{"helm-gateway-executor:test", "helm-gateway-worker:test"}},
		"foreign env":              {"aud": "helm-gateway-executor:prod"},
		"missing iat":              {"iat": nil},
		"missing exp":              {"exp": nil},
		"expired in worker leeway": {"iat": time.Now().Add(-5 * time.Minute).Unix(), "exp": time.Now().Add(-time.Second).Unix()},
		"zero lifetime":            {"iat": time.Now().Unix(), "exp": time.Now().Unix()},
	}
	for name, fields := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := executor.ValidateAuthorization(sign("helm-gateway-executor:test", 900*time.Second, ep, marker, fields)); err == nil {
				t.Fatal("malformed executor admitted")
			}
		})
	}
	if _, err := executor.ValidateAuthorization(sign("helm-gateway-executor:test", 901*time.Second, ep, marker)); !isJWKSKind(err, JWKSErrInvalidLifetime) {
		t.Fatalf("TTL901: %v", err)
	}
	now := time.Now().Truncate(time.Second)
	executor.config.Now = func() time.Time { return now }
	raw := sign("helm-gateway-executor:test", time.Minute, ep, marker, jwt.MapClaims{"iat": now.Add(-time.Minute).Unix(), "exp": now.Unix()})
	if _, err := executor.ValidateAuthorization(raw); !isJWKSKind(err, JWKSErrExpiredToken) {
		t.Fatalf("exact expiry: %v", err)
	}
	// Even a signed mixed-audience credential cannot cross into the internal listener.
	mixed := sign("helm-gateway-worker:test", time.Minute, ep, marker, jwt.MapClaims{"aud": []string{"helm-gateway-worker:test", "helm-gateway-executor:test"}})
	if _, err := worker.ValidateAuthorization(mixed); err == nil {
		t.Fatal("mixed executor admitted internally")
	}
}

func TestExecutorValidatorRefusesUnsafeConfiguration(t *testing.T) {
	identity, _ := episodeIdentity(t)
	for _, aud := range []string{"", "helm-gateway:test", "helm-gateway-worker:test", "helm-gateway-executor:", " helm-gateway-executor:test", "helm-gateway-executor:te st"} {
		if _, err := identity.ExecutorValidator(aud, 15*time.Minute); err == nil {
			t.Errorf("accepted audience %q", aud)
		}
	}
	for _, ttl := range []time.Duration{0, -time.Second, 901 * time.Second} {
		if _, err := identity.ExecutorValidator("helm-gateway-executor:test", ttl); err == nil {
			t.Errorf("accepted ttl %s", ttl)
		}
	}
	if _, err := identity.WorkerValidator("helm-gateway-executor:test", time.Hour); err == nil {
		t.Fatal("executor audience configured internally")
	}
}

// A JWT decoder may reuse a claim pointer across duplicate outer keys. Null
// must not retain an earlier canonical client and turn malformed input valid.
func TestExecutorRejectsNullClientAfterDuplicateOuterMarker(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "kid-1", Use: "sig", Algorithm: "RS256"}}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	defer srv.Close()
	identity := &ControlPlaneIdentity{Actor: "spiffe://helm/control-plane", config: JWKSConfig{JWKSURL: srv.URL, Issuer: "helm-workload-identity", Audience: "helm-gateway:test", Algorithms: []string{"RS256"}, AllowInsecureLoopback: true}}
	validator, err := identity.ExecutorValidator("helm-gateway-executor:test", 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.MapClaims{"iss": "helm-workload-identity", "sub": "agt:seat-1", "aud": "helm-gateway-executor:test", "jti": "j-1", "scope": "helm.gateway.propose", "iat": time.Now().Add(-time.Second).Unix(), "exp": time.Now().Add(time.Minute).Unix(), "act": map[string]string{"sub": identity.Actor}, "tenant_id": "tenant-1", "workspace_id": "ws-1", "helm_episode": map[string]string{"episode_id": "ep-1", "work_item_id": "work-1", "organization_version_id": "v-1"}, "helm_executor": map[string]string{"client": "codex"}}
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw[:len(raw)-1], []byte(`,"helm_executor":{"client":null}}`)...)
	enc := base64.RawURLEncoding.EncodeToString
	payload := enc([]byte(`{"alg":"RS256","kid":"kid-1","typ":"JWT"}`)) + "." + enc(raw)
	signature, err := jwt.SigningMethodRS256.Sign(payload, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validator.ValidateAuthorization(payload + "." + enc(signature)); err == nil {
		t.Fatal("duplicate outer marker retained a null client")
	}
}
