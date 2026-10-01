package jwks

// quantum_posture: tests classical RSA (RS256) JWT validation of episode
// tokens; no post-quantum claim.

import (
	"crypto/rand"
	"crypto/rsa"
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
func episodeIdentity(t *testing.T) (*ControlPlaneIdentity, func(audience string, lifetime time.Duration, episode any) string) {
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
	sign := func(audience string, lifetime time.Duration, episode any) string {
		claims := jwt.MapClaims{
			"iss": "helm-workload-identity", "sub": "agt:seat-1", "aud": audience, "scope": "helm.gateway.propose",
			"tenant_id": "tenant-a", "workspace_id": "ws-a", "act": map[string]string{"sub": identity.Actor}, "jti": "j-1",
			"iat": time.Now().Add(-time.Second).Unix(), "exp": time.Now().Add(-time.Second + lifetime).Unix(),
		}
		if episode != nil {
			claims["helm_episode"] = episode
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
