package runtime

// quantum_posture: tests classical RS256 and TLS JWKS. No post-quantum claim.

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestServeSeparatesPublicExecutorsFromInternalWorkers(t *testing.T) {
	identity, sign := jwksServer(t)
	main, worker, executor := freeAddress(t), freeAddress(t), freeAddress(t)
	values := with(identity, map[string]string{
		"HELM_GATEWAY_DATABASE_URL":      "postgres://127.0.0.1:1/none?sslmode=disable",
		"HELM_GATEWAY_MODEL_ROUTES_FILE": routesFile(t),
		"HELM_GATEWAY_WORKER_AUDIENCE":   "helm-gateway-worker:test",
		"HELM_GATEWAY_EXECUTOR_AUDIENCE": "helm-gateway-executor:test",
	})
	startServe(t, []string{"--dev-insecure-listen", main, "--worker-listen", worker, "--executor-listen", executor}, values)
	ep := map[string]string{"episode_id": "ep-1", "work_item_id": "work-1", "organization_version_id": "v-1"}
	marker := jwt.MapClaims{"helm_executor": map[string]string{"client": "codex"}, "scope": "helm.gateway.propose helm.gateway.read"}
	executorToken := sign("helm-gateway-executor:test", 15*time.Minute, ep, marker)
	initialize := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"codex","version":"1"}}}`
	request := func(base, path, token string) (int, string) {
		t.Helper()
		method, body := http.MethodGet, ""
		if path != "/v1/models" {
			method, body = http.MethodPost, initialize
		}
		req, err := http.NewRequest(method, "http://"+base+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(raw)
	}
	tokens := map[string]string{
		"worker900":     sign("helm-gateway-worker:test", 15*time.Minute, ep),
		"worker3600":    sign("helm-gateway-worker:test", time.Hour, ep),
		"main":          sign("helm-gateway:test", time.Minute, nil),
		"no client":     sign("helm-gateway-executor:test", 15*time.Minute, ep),
		"over900":       sign("helm-gateway-executor:test", 901*time.Second, ep, marker),
		"no episode":    sign("helm-gateway-executor:test", time.Minute, nil, marker),
		"no version":    sign("helm-gateway-executor:test", time.Minute, map[string]string{"episode_id": "ep", "work_item_id": "w"}, marker),
		"foreign env":   sign("helm-gateway-executor:prod", time.Minute, ep, marker),
		"mixed":         sign("helm-gateway-executor:test", time.Minute, ep, marker, jwt.MapClaims{"aud": []string{"helm-gateway-executor:test", "helm-gateway-worker:test"}}),
		"foreign scope": sign("helm-gateway-executor:test", time.Minute, ep, marker, jwt.MapClaims{"scope": "helm.gateway.propose other.read"}),
		"read alone":    sign("helm-gateway-executor:test", time.Minute, ep, marker, jwt.MapClaims{"scope": "helm.gateway.read"}),
		"execute":       sign("helm-gateway-executor:test", time.Minute, ep, marker, jwt.MapClaims{"scope": "helm.gateway.propose helm.gateway.execute"}),
	}
	for name, token := range tokens {
		for _, path := range []string{"/mcp", "/v1/models"} {
			if code, body := request(executor, path, token); code != 401 && code != 403 {
				t.Errorf("%s %s: %d %s", name, path, code, body)
			}
		}
	}
	for _, ttl := range []time.Duration{15 * time.Minute, time.Hour} {
		if code, body := request(worker, "/mcp", sign("helm-gateway-worker:test", ttl, ep)); code != 200 {
			t.Fatalf("internal worker %s: %d %s", ttl, code, body)
		}
	}
	if code, body := request(executor, "/mcp", executorToken); code != 200 || !strings.Contains(body, `"protocolVersion":"2025-11-25"`) {
		t.Fatalf("executor MCP: %d %s", code, body)
	}
	if code, body := request(executor, "/v1/models", executorToken); code != 503 || !strings.Contains(body, "ledger_unavailable") {
		t.Fatalf("executor model auth: %d %s", code, body)
	}
	for _, base := range []string{main, worker} {
		if code, _ := request(base, "/v1/models", executorToken); code != 401 && code != 403 {
			t.Fatalf("executor on other listener: %d", code)
		}
	}
	for _, path := range []string{"/helm.gateway.v1.EffectGatewayService/Dispatch", "/helm.gateway.v1.AuthorityAdminService/EnsurePrincipals"} {
		if code, _ := request(executor, path, executorToken); code != 404 {
			t.Fatalf("public privileged API %s: %d", path, code)
		}
	}
}

func TestExecutorListenerConfigurationAndExecutorOnlyMode(t *testing.T) {
	identity, _ := jwksServer(t)
	base := with(identity, map[string]string{"HELM_GATEWAY_DATABASE_URL": "postgres://127.0.0.1:1/none?sslmode=disable", "HELM_GATEWAY_MODEL_ROUTES_FILE": routesFile(t), "HELM_GATEWAY_EXECUTOR_AUDIENCE": "helm-gateway-executor:test"})
	for name, tc := range map[string]struct {
		args  []string
		extra map[string]string
		want  string
	}{
		"public plain":     {[]string{"--dev-insecure-listen", "127.0.0.1:0", "--executor-listen", ":8445"}, nil, "loopback"},
		"missing audience": {[]string{"--dev-insecure-listen", "127.0.0.1:0", "--executor-listen", "127.0.0.1:0"}, map[string]string{"HELM_GATEWAY_EXECUTOR_AUDIENCE": ""}, "is required"},
		"no listener":      {[]string{"--dev-insecure-listen", "127.0.0.1:0"}, nil, "without --executor-listen"},
		"missing routes":   {[]string{"--dev-insecure-listen", "127.0.0.1:0", "--executor-listen", "127.0.0.1:0"}, map[string]string{"HELM_GATEWAY_MODEL_ROUTES_FILE": ""}, "needs HELM_GATEWAY_MODEL_ROUTES_FILE"},
		"worker audience":  {[]string{"--dev-insecure-listen", "127.0.0.1:0", "--executor-listen", "127.0.0.1:0"}, map[string]string{"HELM_GATEWAY_EXECUTOR_AUDIENCE": "helm-gateway-worker:test"}, "executor audience"},
		"ttl901":           {[]string{"--dev-insecure-listen", "127.0.0.1:0", "--executor-listen", "127.0.0.1:0"}, map[string]string{"HELM_GATEWAY_EXECUTOR_MAX_TTL": "901s"}, "lifetime"},
	} {
		t.Run(name, func(t *testing.T) {
			err := Run(context.Background(), append([]string{"serve"}, tc.args...), env(with(base, tc.extra)), io.Discard)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}
	// Executor-only deployments still have the ordinary private CP listener;
	// they do not need to expose an internal worker listener publicly.
	startServe(t, []string{"--dev-insecure-listen", freeAddress(t), "--executor-listen", freeAddress(t)}, base)
}
