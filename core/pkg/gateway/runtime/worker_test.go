package runtime

// quantum_posture: signs classical RS256 test tokens for a JWKS served over TLS
// with a test certificate; no post-quantum claim is made.

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The worker listener serves the gateway's effect types as MCP tools at /mcp,
// to the same episode tokens as the model endpoints, and the main listener does
// not serve them at all (HELM-751 K3). This runs the real composition with real
// signed tokens; the ledger is left unreachable, so what it shows is the wiring:
// which listener, which token, which handshake.
func TestServeMountsTheMCPEndpointOnTheWorkerListenerOnly(t *testing.T) {
	identity, sign := jwksServer(t)
	main, worker := freeAddress(t), freeAddress(t)
	values := with(identity, map[string]string{
		"HELM_GATEWAY_DATABASE_URL":      "postgres://127.0.0.1:1/none?sslmode=disable",
		"HELM_GATEWAY_MODEL_ROUTES_FILE": routesFile(t), "HELM_GATEWAY_WORKER_AUDIENCE": "helm-gateway-worker:test",
	})
	startServe(t, []string{"--dev-insecure-listen", main, "--worker-listen", worker}, values)

	episode := map[string]string{"episode_id": "ep-1", "work_item_id": "work-1", "organization_version_id": "v-1"}
	workerToken := sign("helm-gateway-worker:test", 20*time.Minute, episode)
	mainToken := sign("helm-gateway:test", time.Minute, nil)
	noEpisode := sign("helm-gateway-worker:test", 20*time.Minute, nil)

	type answer struct {
		status int
		header http.Header
		body   map[string]any
	}
	send := func(method, base, token, version, body string, extra ...map[string]string) answer {
		t.Helper()
		req, err := http.NewRequest(method, "http://"+base+"/mcp", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if version != "" {
			req.Header.Set("MCP-Protocol-Version", version)
		}
		for _, headers := range extra {
			for name, value := range headers {
				req.Header.Set(name, value)
			}
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		out := answer{status: resp.StatusCode, header: resp.Header}
		_ = json.Unmarshal(raw, &out.body)
		return out
	}
	initialize := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`
	discover := `{"jsonrpc":"2.0","id":"d","method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
	list := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`

	// No token, and the main listener's: 401 with a bearer challenge, before anything is read.
	for name, token := range map[string]string{"no token": "", "a main-listener token": mainToken} {
		got := send(http.MethodPost, worker, token, "", initialize)
		if got.status != 401 || got.header.Get("WWW-Authenticate") != "Bearer" {
			t.Fatalf("%s on the worker listener: %d %v", name, got.status, got.header)
		}
	}
	// A worker token with no episode is not an episode token.
	if got := send(http.MethodPost, worker, noEpisode, "", initialize); got.status != 403 {
		t.Fatalf("a worker token with no episode: %d", got.status)
	}
	// An episode token gets through: the handshake of the older revisions, and
	// discovery of the stateless one, need no ledger.
	got := send(http.MethodPost, worker, workerToken, "", initialize)
	result, _ := got.body["result"].(map[string]any)
	if got.status != 200 || result["protocolVersion"] != "2025-11-25" || result["serverInfo"].(map[string]any)["name"] != "helm-gateway" {
		t.Fatalf("initialize: %d %v", got.status, got.body)
	}
	// The stateless revision mirrors the method in a header, and the real
	// endpoint holds a request to it.
	if got = send(http.MethodPost, worker, workerToken, "2026-07-28", discover); got.status != 400 {
		t.Fatalf("server/discover without its Mcp-Method header: %d %v", got.status, got.body)
	}
	got = send(http.MethodPost, worker, workerToken, "2026-07-28", discover, map[string]string{"Mcp-Method": "server/discover"})
	result, _ = got.body["result"].(map[string]any)
	if got.status != 200 || result["resultType"] != "complete" || result["supportedVersions"] == nil {
		t.Fatalf("server/discover: %d %v", got.status, got.body)
	}
	// Reading tools needs the ledger, which is unreachable: the gateway says to
	// repeat the call, which is neither an authentication nor a permission error.
	got = send(http.MethodPost, worker, workerToken, "2025-11-25", list)
	e, _ := got.body["error"].(map[string]any)
	if got.status != 200 || e == nil || int(e["code"].(float64)) != -32603 {
		t.Fatalf("tools/list with no ledger: %d %v", got.status, got.body)
	}
	// There is no GET stream on the worker listener, and no MCP on the main one.
	if got := send(http.MethodGet, worker, workerToken, "", ""); got.status != http.StatusMethodNotAllowed {
		t.Fatalf("GET /mcp: %d", got.status)
	}
	if got := send(http.MethodPost, main, mainToken, "", initialize); got.status != http.StatusNotFound {
		t.Fatalf("/mcp on the main listener: %d, want 404", got.status)
	}
}
