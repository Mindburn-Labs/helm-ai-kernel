package runtime

// quantum_posture: signs classical RS256 test tokens and serves a JWKS over
// TLS with a test certificate; no post-quantum claim.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
)

// routesFile writes a routes file with one provider and one route, and its key
// file, and returns the routes file's path.
func routesFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	key := filepath.Join(dir, "anthropic")
	if err := os.WriteFile(key, []byte("canary-runtime-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	routes := `{"version": 1,
	 "providers": [{"id": "anthropic", "kind": "anthropic", "base_url": "http://127.0.0.1:9", "key_file": "` + key + `"}],
	 "routes": [{"id": "anthropic/claude-sonnet-5-5", "provider": "anthropic", "model": "claude-sonnet-5-5", "apis": ["anthropic-messages"],
	   "price": {"unit": "usd_micros_per_million_tokens", "input": 3000000, "output": 15000000},
	   "default_max_output_tokens": 8192, "max_output_tokens": 64000}]}`
	path := filepath.Join(dir, "routes.json")
	if err := os.WriteFile(path, []byte(routes), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTheWorkerListenerIsPlainHTTPOnlyOnLoopback(t *testing.T) {
	// With TLS the worker listener may take any address.
	if _, err := parseServeFlags([]string{"--worker-listen", ":8444"}, io.Discard); err != nil {
		t.Fatal(err)
	}
	// With --dev-insecure-listen it is plain HTTP, and only on loopback.
	if _, err := parseServeFlags([]string{"--dev-insecure-listen", "127.0.0.1:0", "--worker-listen", "127.0.0.1:0"}, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"0.0.0.0:8444", ":8444", "10.0.0.5:8444", "localhost:8444"} {
		_, err := parseServeFlags([]string{"--dev-insecure-listen", "127.0.0.1:0", "--worker-listen", address}, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "--worker-listen") {
			t.Fatalf("%s: %v", address, err)
		}
	}
}

func TestServeRefusesAModelGatewayItCannotServe(t *testing.T) {
	routes := routesFile(t)
	db := map[string]string{"HELM_GATEWAY_DATABASE_URL": "postgres://127.0.0.1:1/none?sslmode=disable"}
	plain := []string{"serve", "--dev-insecure-listen", "127.0.0.1:0"}
	worker := append(append([]string{}, plain...), "--worker-listen", "127.0.0.1:0")
	for name, test := range map[string]struct {
		args []string
		env  map[string]string
		want string
	}{
		"a worker listener with nothing to serve": {worker, with(identityEnv, db), "HELM_GATEWAY_MODEL_ROUTES_FILE"},
		"a worker audience with no routes":        {plain, with(identityEnv, with(db, map[string]string{"HELM_GATEWAY_WORKER_AUDIENCE": "helm-gateway-worker:test"})), "without HELM_GATEWAY_MODEL_ROUTES_FILE"},
		"a routes file that is not there":         {plain, with(identityEnv, with(db, map[string]string{"HELM_GATEWAY_MODEL_ROUTES_FILE": "/nonexistent/routes.json"})), "model routes"},
		"a provider key that is not there": {plain, with(identityEnv, with(db, map[string]string{"HELM_GATEWAY_MODEL_ROUTES_FILE": func() string {
			p := filepath.Join(t.TempDir(), "routes.json")
			raw, _ := os.ReadFile(routes)
			_ = os.WriteFile(p, []byte(strings.Replace(string(raw), `"key_file": "`, `"key_file": "/nonexistent/`, 1)), 0o600)
			return p
		}()})), "custody"},
		"a worker listener with no audience":        {worker, with(identityEnv, with(db, map[string]string{"HELM_GATEWAY_MODEL_ROUTES_FILE": routes})), "HELM_GATEWAY_WORKER_AUDIENCE is required"},
		"the gateway's own audience for workers":    {worker, with(identityEnv, with(db, map[string]string{"HELM_GATEWAY_MODEL_ROUTES_FILE": routes, "HELM_GATEWAY_WORKER_AUDIENCE": "helm-gateway:test"})), "must differ"},
		"a worker lifetime past the ceiling":        {worker, with(identityEnv, with(db, map[string]string{"HELM_GATEWAY_MODEL_ROUTES_FILE": routes, "HELM_GATEWAY_WORKER_AUDIENCE": "helm-gateway-worker:test", "HELM_GATEWAY_WORKER_MAX_TTL": "2h"})), "lifetime"},
		"a worker lifetime that is not a duration":  {worker, with(identityEnv, with(db, map[string]string{"HELM_GATEWAY_MODEL_ROUTES_FILE": routes, "HELM_GATEWAY_WORKER_AUDIENCE": "helm-gateway-worker:test", "HELM_GATEWAY_WORKER_MAX_TTL": "soon"})), "HELM_GATEWAY_WORKER_MAX_TTL"},
		"a worker audience with no worker listener": {plain, with(identityEnv, with(db, map[string]string{"HELM_GATEWAY_MODEL_ROUTES_FILE": routes, "HELM_GATEWAY_WORKER_AUDIENCE": "helm-gateway-worker:test"})), "without --worker-listen"},
	} {
		err := Run(context.Background(), test.args, env(test.env), io.Discard)
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%s: err = %v, want one naming %q", name, err, test.want)
		}
	}
}

func TestServeDeclaresModelInferenceOnlyWithModelRoutes(t *testing.T) {
	declares := func(m *models) bool {
		var c admission.Config
		m.install(&c)
		for _, a := range c.Adapters {
			for _, d := range a.Declarations() {
				if d.EffectType == "model.inference" {
					return true
				}
			}
		}
		return false
	}
	if declares(nil) {
		t.Fatal("a gateway with no model routes declares model.inference")
	}
	m, err := modelsFromEnv(env(map[string]string{"HELM_GATEWAY_MODEL_ROUTES_FILE": routesFile(t)}), serveConfig{}, nil)
	if err != nil || m == nil {
		t.Fatalf("modelsFromEnv = %v, %v", m, err)
	}
	if !declares(m) {
		t.Fatal("a gateway with model routes does not declare model.inference")
	}
	if none, err := modelsFromEnv(env(nil), serveConfig{}, nil); err != nil || none != nil {
		t.Fatalf("no routes file: %v %v", none, err)
	}
}

// jwksServer serves a JWKS over TLS and signs tokens for it, and returns the
// environment that points a gateway at it.
func jwksServer(t *testing.T) (map[string]string, func(audience string, lifetime time.Duration, episode map[string]string) string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "kid-1", Use: "sig", Algorithm: "RS256"}}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	t.Cleanup(srv.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	writePEM(t, ca, "CERTIFICATE", srv.Certificate().Raw)
	values := map[string]string{
		"HELM_CP_IDENTITY_JWKS_URL": srv.URL, "HELM_CP_IDENTITY_ISSUER": "helm-workload-identity",
		"HELM_CP_IDENTITY_AUDIENCE": "helm-gateway:test", "HELM_CP_IDENTITY_ACTOR": "spiffe://helm/control-plane",
		"HELM_CP_IDENTITY_OUTBOUND_CA_BUNDLE_FILE": ca,
	}
	sign := func(audience string, lifetime time.Duration, episode map[string]string) string {
		claims := jwt.MapClaims{
			"iss": "helm-workload-identity", "sub": "agt:seat-1", "aud": audience, "scope": "helm.gateway.propose",
			"tenant_id": "tenant-a", "workspace_id": "ws-a", "act": map[string]string{"sub": "spiffe://helm/control-plane"}, "jti": "j-1",
			"iat": time.Now().Add(-time.Second).Unix(), "exp": time.Now().Add(lifetime).Unix(),
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
	return values, sign
}

// Two listeners, two audiences: a token minted for one is not valid on the
// other, and the worker listener serves the model endpoints and nothing else
// (HELM-752 K7).
func TestServeKeepsTheWorkerAndMainListenersApart(t *testing.T) {
	identity, sign := jwksServer(t)
	main, worker := freeAddress(t), freeAddress(t)
	values := with(identity, map[string]string{
		"HELM_GATEWAY_DATABASE_URL":      "postgres://127.0.0.1:1/none?sslmode=disable",
		"HELM_GATEWAY_MODEL_ROUTES_FILE": routesFile(t), "HELM_GATEWAY_WORKER_AUDIENCE": "helm-gateway-worker:test",
	})
	startServe(t, []string{"--dev-insecure-listen", main, "--worker-listen", worker}, values)

	episode := map[string]string{"episode_id": "ep-1", "work_item_id": "work-1", "organization_version_id": "v-1"}
	workerToken, mainToken := sign("helm-gateway-worker:test", 20*time.Minute, episode), sign("helm-gateway:test", time.Minute, nil)
	get := func(base, path, token string) (int, string) {
		req, _ := http.NewRequest(http.MethodGet, "http://"+base+path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}
	// No token: 401 on both, in the OpenAI error format.
	for _, base := range []string{main, worker} {
		if code, body := get(base, "/v1/models", ""); code != 401 || !strings.Contains(body, `"error"`) {
			t.Fatalf("%s without a token: %d %s", base, code, body)
		}
	}
	// The wrong listener's token: 401, before anything is read.
	if code, _ := get(main, "/v1/models", workerToken); code != 401 {
		t.Fatalf("a worker token on the main listener: %d, want 401", code)
	}
	if code, _ := get(worker, "/v1/models", mainToken); code != 401 {
		t.Fatalf("a main token on the worker listener: %d, want 401", code)
	}
	// The right listener's token gets through authentication to the ledger,
	// which this test leaves unreachable: 503, not 401 or 403.
	if code, body := get(worker, "/v1/models", workerToken); code != 503 || !strings.Contains(body, "ledger_unavailable") {
		t.Fatalf("a worker token on the worker listener: %d %s", code, body)
	}
	if code, body := get(main, "/v1/models", mainToken); code != 503 || !strings.Contains(body, "ledger_unavailable") {
		t.Fatalf("a main token on the main listener: %d %s", code, body)
	}
	// A worker token with no episode is refused by the profile.
	if code, _ := get(worker, "/v1/models", sign("helm-gateway-worker:test", 20*time.Minute, nil)); code != 403 {
		t.Fatalf("a worker token with no episode: %d, want 403", code)
	}
	// The worker listener serves no effect API: only the model endpoints.
	req, _ := http.NewRequest(http.MethodPost, "http://"+worker+"/helm.gateway.v1.EffectGatewayService/Propose", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+workerToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("the effect API on the worker listener: %d, want 404", resp.StatusCode)
	}
	// count_tokens is answered 404 in Anthropic's format on both.
	for _, base := range []string{main, worker} {
		req, _ := http.NewRequest(http.MethodPost, "http://"+base+"/v1/messages/count_tokens", strings.NewReader("{}"))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 404 || !strings.Contains(string(body), `"not_found_error"`) {
			t.Fatalf("count_tokens on %s: %d %s", base, resp.StatusCode, body)
		}
	}
}
