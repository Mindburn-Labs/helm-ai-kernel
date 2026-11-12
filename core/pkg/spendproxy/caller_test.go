package spendproxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/inferencegateway"
)

const (
	callerTokenLive   = "helm-caller-live-0123456789abcdef"
	callerTokenReplay = "helm-caller-replay-0123456789abcdef"
)

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// callerConfig is the test config with a credential per agent and a second
// principal on env-sub: with credentials, each caller is bound to the agent,
// envelopes and workspaces it may use.
func callerConfig() string {
	cfg := strings.Replace(testConfigJSON, `"agent_id": "agent-replay",
      "principal_id": "principal-test",`, `"agent_id": "agent-replay",
      "principal_id": "principal-bob",`, 1)
	// env-extra is agent-live's too, but the live caller does not cover it.
	cfg = strings.Replace(cfg, `"envelopes": [
    {
      "id": "env-direct",`, `"envelopes": [
    {
      "id": "env-extra",
      "agent_id": "agent-live",
      "principal_id": "principal-test",
      "budget_id": "budget-extra",
      "max_amount_cents": 1000,
      "per_request_max_cents": 50,
      "allowed_providers": ["mockai"],
      "allowed_models": ["base-model"],
      "fallback_routes": [{"provider_id": "mockai", "model_id": "base-model"}]
    },
    {
      "id": "env-direct",`, 1)
	cfg = strings.Replace(cfg, `"request_defaults": {
    "workspace_id": "ws-test",
    "agent_id": "agent-live",
    "principal_id": "principal-test",
    "envelope_id": "env-direct"
  },`, `"callers": [
    {"id": "live", "token_sha256": "`+tokenHash(callerTokenLive)+`", "agent_id": "agent-live", "envelopes": ["env-direct"], "workspaces": ["ws-a"]},
    {"id": "replay", "token_sha256": "`+tokenHash(callerTokenReplay)+`", "agent_id": "agent-replay", "envelopes": ["env-sub"]}
  ],`, 1)
	return cfg
}

// callerPost sends a chat request with the bearer token and headers given.
func (f *proxyFixture) callerPost(t *testing.T, token, model, idem string, headers map[string]string) (int, string) {
	t.Helper()
	body := `{"model":"` + model + `","max_tokens":16,"messages":[{"role":"user","content":"hello"}]}`
	req, _ := http.NewRequest(http.MethodPost, f.http.URL+"/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set(inferencegateway.HeaderIdempotencyKey, idem)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

// TestCallerCredentialBindsTheIdentity (helm-tracker#313 r1, F4): with callers
// configured, a request is served only under a credential, and the agent,
// envelope and workspace it names must be ones its credential covers. The
// principal sealed into its receipts is its envelope's.
func TestCallerCredentialBindsTheIdentity(t *testing.T) {
	f := newProxyFixtureWithConfig(t, callerConfig())
	for name, test := range map[string]struct {
		token   string
		headers map[string]string
		want    int
	}{
		"no credential":                          {"", map[string]string{inferencegateway.HeaderAgent: "agent-live", inferencegateway.HeaderSpendEnvelope: "env-direct"}, http.StatusUnauthorized},
		"an unknown credential":                  {"not-a-token", nil, http.StatusUnauthorized},
		"another caller's envelope":              {callerTokenLive, map[string]string{inferencegateway.HeaderSpendEnvelope: "env-sub"}, http.StatusForbidden},
		"its agent's envelope it does not cover": {callerTokenLive, map[string]string{inferencegateway.HeaderSpendEnvelope: "env-extra"}, http.StatusForbidden},
		"another caller's agent":                 {callerTokenLive, map[string]string{inferencegateway.HeaderAgent: "agent-replay"}, http.StatusForbidden},
		"a workspace it does not cover":          {callerTokenLive, map[string]string{inferencegateway.HeaderWorkspace: "ws-mallory"}, http.StatusForbidden},
		"another principal":                      {callerTokenLive, map[string]string{inferencegateway.HeaderPrincipal: "principal-bob"}, http.StatusForbidden},
	} {
		status, body := f.callerPost(t, test.token, "base-model", "idem-"+strings.ReplaceAll(name, " ", "-"), test.headers)
		if status != test.want {
			t.Errorf("%s: status %d (%s), want %d", name, status, body, test.want)
		}
	}
	if f.upstream.calls.Load() != 0 {
		t.Fatalf("a refused caller reached the provider %d times", f.upstream.calls.Load())
	}

	if status, body := f.callerPost(t, callerTokenLive, "base-model", "idem-live", nil); status != http.StatusOK {
		t.Fatalf("the live caller: status %d (%s)", status, body)
	}
	if status, body := f.callerPost(t, callerTokenReplay, "mini-model", "idem-replay", map[string]string{inferencegateway.HeaderSpendEnvelope: "env-sub", inferencegateway.HeaderWorkspace: ""}); status != http.StatusOK {
		t.Fatalf("the replay caller: status %d (%s)", status, body)
	}
	if auth, _ := f.upstream.lastAuth.Load().(string); auth != "Bearer test-key" {
		t.Fatalf("the provider saw Authorization %q, want only the upstream key", auth)
	}
	principals := map[string]string{}
	workspaces := map[string]string{}
	for _, rec := range f.records(t) {
		if rec.BudgetVerdict != nil {
			principals[rec.BudgetVerdict.EnvelopeID] = rec.BudgetVerdict.PrincipalID
		}
		if rec.Kind == RecordRouteQuote && rec.RouteQuote != nil {
			workspaces[rec.RouteQuote.EnvelopeID] = rec.RouteQuote.Metadata["workspace_id"]
		}
		raw, _ := json.Marshal(rec)
		if strings.Contains(string(raw), "ws-mallory") || strings.Contains(string(raw), callerTokenLive) {
			t.Fatalf("a %s record carries a caller-asserted value: %s", rec.Kind, raw)
		}
	}
	if principals["env-direct"] != "principal-test" || principals["env-sub"] != "principal-bob" {
		t.Fatalf("sealed principals = %v", principals)
	}
	if workspaces["env-direct"] != "ws-a" || workspaces["env-sub"] != "" {
		t.Fatalf("sealed workspaces = %v, want the live caller's ws-a and none for replay", workspaces)
	}
}

// TestWithoutCredentialsTheProxyServesOnePrincipal (F4): with no credential
// configured, headers pick among the envelopes, so the proxy refuses a config
// whose envelopes name more than one principal.
func TestWithoutCredentialsTheProxyServesOnePrincipal(t *testing.T) {
	cfg := strings.Replace(testConfigJSON, `"agent_id": "agent-replay",
      "principal_id": "principal-test",`, `"agent_id": "agent-replay",
      "principal_id": "principal-bob",`, 1)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "principal") {
		t.Fatalf("load = %v, want a refusal of two principals without callers", err)
	}
}

// TestWorkspaceHeaderIsNotSealedUnlessCovered (F4): without credentials, the
// only workspace a receipt can name is the configured one; a request naming
// another is refused and nothing it asserted is sealed.
func TestWorkspaceHeaderIsNotSealedUnlessCovered(t *testing.T) {
	f := newProxyFixture(t)
	status, body := f.callerPost(t, "", "base-model", "idem-ws", map[string]string{
		inferencegateway.HeaderAgent: "agent-live", inferencegateway.HeaderSpendEnvelope: "env-direct", inferencegateway.HeaderWorkspace: "ws-mallory",
	})
	if status != http.StatusForbidden || f.upstream.calls.Load() != 0 {
		t.Errorf("status %d (%s), %d dispatches; want 403 and none", status, body, f.upstream.calls.Load())
	}
	for _, rec := range f.records(t) {
		raw, _ := json.Marshal(rec)
		if strings.Contains(string(raw), "ws-mallory") {
			t.Fatalf("a %s record seals the header's workspace: %s", rec.Kind, raw)
		}
	}
}

// TestCallerConfigRefusesWhatItCannotBind (F4): a caller's token is stored as
// its SHA-256 only, and each caller is bound to declared envelopes of its own
// agent.
func TestCallerConfigRefusesWhatItCannotBind(t *testing.T) {
	good := callerConfig()
	for name, cfg := range map[string]string{
		"a plaintext token":        strings.Replace(good, tokenHash(callerTokenLive), callerTokenLive, 1),
		"an undeclared envelope":   strings.Replace(good, `"envelopes": ["env-direct"]`, `"envelopes": ["env-none"]`, 1),
		"another agent's envelope": strings.Replace(good, `"envelopes": ["env-direct"]`, `"envelopes": ["env-sub"]`, 1),
		"a shared token":           strings.Replace(good, tokenHash(callerTokenReplay), tokenHash(callerTokenLive), 1),
		"defaults beside callers": strings.Replace(good, `"callers": [`, `"request_defaults": {"agent_id": "agent-live", "envelope_id": "env-direct"},
  "callers": [`, 1),
	} {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := LoadConfig(path); err == nil {
			t.Errorf("%s: the config loaded", name)
		}
	}
}

// TestDefaultPrincipalMustBeTheEnvelopes (mutant M38): request_defaults may
// repeat its envelope's principal, never name another.
func TestDefaultPrincipalMustBeTheEnvelopes(t *testing.T) {
	cfg := strings.Replace(testConfigJSON, `"agent_id": "agent-live",
    "principal_id": "principal-test",
    "envelope_id": "env-direct"`, `"agent_id": "agent-live",
    "principal_id": "principal-other",
    "envelope_id": "env-direct"`, 1)
	if cfg == testConfigJSON {
		t.Fatal("the defaults were not found to change")
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "request_defaults.principal_id") {
		t.Fatalf("load = %v, want a refusal naming request_defaults.principal_id", err)
	}
}
