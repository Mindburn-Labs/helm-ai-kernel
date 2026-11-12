// quantum_posture: these tests drive spend-proxy commands whose receipts carry
// classical Ed25519 signatures; they make or verify no signature themselves
// and make no post-quantum claim.

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/spendproxy"
)

func TestSpendProxyRequiresConfig(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runSpendProxyCmd([]string{}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--config is required") {
		t.Fatalf("stderr = %q, want config requirement", stderr.String())
	}
}

func TestSpendProxyRequiresAPIKey(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config.json")
	if err := os.WriteFile(config, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("OPENROUTER_API_KEY", "")
	var stdout, stderr bytes.Buffer
	if code := runSpendProxyCmd([]string{"--config", config}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "API key is required") {
		t.Fatalf("stderr = %q, want api key requirement", stderr.String())
	}
}

func TestSpendProxyRejectsInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config.json")
	if err := os.WriteFile(config, []byte(`{"tenant_id":"t"}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("OPENROUTER_API_KEY", "test-key")
	var stdout, stderr bytes.Buffer
	if code := runSpendProxyCmd([]string{"--config", config}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "treasury_id") {
		t.Fatalf("stderr = %q, want config validation error", stderr.String())
	}
}

// The spend proxy holds the upstream provider key and has no caller
// credential, so it follows the listener rule of `proxy` and `mcp serve`: an
// unauthenticated listener binds loopback only. The config is invalid on
// purpose, so a build without the refusal fails on it instead of serving, and
// this test fails rather than hangs.
func TestSpendProxyRefusesNonLoopbackBind(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config.json")
	if err := os.WriteFile(config, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	receipts := filepath.Join(dir, "receipts")
	t.Setenv("HELM_SPEND_PROXY_UPSTREAM_KEY", "test-key")
	t.Setenv("HELM_SPEND_PROXY_SIGNING_SEED", "")

	run := func(addr string) (int, string) {
		var stdout, stderr bytes.Buffer
		code := runSpendProxyCmd([]string{"--config", config, "--receipts-dir", receipts, "--addr", addr}, &stdout, &stderr)
		return code, stderr.String()
	}

	for _, addr := range []string{"0.0.0.0", "::", "", "10.0.0.5", "example.com"} {
		code, msg := run(addr)
		// The refusal holds with caller credentials too, so it does not
		// blame missing authentication (helm-tracker#313 r2, finding 13).
		if code != 2 || !strings.Contains(msg, "not loopback") || !strings.Contains(msg, "loopback only") || strings.Contains(msg, "no authentication is configured") {
			t.Fatalf("--addr %q: exit = %d, stderr = %q, want a refusal that says why", addr, code, msg)
		}
	}
	if _, err := os.Stat(receipts); !os.IsNotExist(err) {
		t.Fatalf("refused spend-proxy still created state: %v", err)
	}

	for _, addr := range []string{"127.0.0.1", "::1", "localhost"} {
		code, msg := run(addr)
		if code != 2 || strings.Contains(msg, "not loopback") || !strings.Contains(msg, "tenant_id is required") {
			t.Fatalf("--addr %q: exit = %d, stderr = %q, want the loopback bind accepted and the config rejected", addr, code, msg)
		}
	}
}

func TestSpendProxyExampleConfigLoads(t *testing.T) {
	// The checked-in dogfood config must stay loadable: it is the price-book
	// source of record for the HELM-615 capture window.
	path := filepath.Join("..", "..", "..", "examples", "spend-proxy", "dogfood.config.json")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("example config not present in this checkout: %v", err)
	}
	cfg, sourceHash, err := spendproxy.LoadConfig(path)
	if err != nil {
		t.Fatalf("dogfood config failed to load: %v", err)
	}
	if !strings.HasPrefix(sourceHash, "sha256:") {
		t.Fatalf("source hash = %q, want sha256 prefix", sourceHash)
	}
	if len(cfg.Envelopes) < 2 {
		t.Fatalf("dogfood config must declare baseline and substitute envelopes, got %d", len(cfg.Envelopes))
	}
}

func TestSpendProxyExportEmptyLogFails(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runSpendProxyExport([]string{"--receipts-dir", t.TempDir(), "--out", t.TempDir()}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("export on empty receipts dir: exit = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "receipt log is empty") &&
		!strings.Contains(stderr.String(), "nothing to export") {
		t.Fatalf("stderr = %q, want empty-log error", stderr.String())
	}
}

func TestSpendProxyExportFlagErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runSpendProxyCmd([]string{"export", "--bogus-flag"}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit = %d, want 2 for unknown flag", code)
	}
}

func TestSpendProxySavingsExportRequiresFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runSpendProxyCmd([]string{"savings-export"}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--capture and --config are required") {
		t.Fatalf("stderr = %q, want capture/config requirement", stderr.String())
	}
}

func TestSpendProxySavingsVerifyRequiresPack(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runSpendProxyCmd([]string{"savings-verify"}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--pack is required") {
		t.Fatalf("stderr = %q, want pack requirement", stderr.String())
	}
}

func TestSpendProxyGenericUpstreamKeyEnv(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config.json")
	// Invalid config on purpose: with the generic key env set, the command must
	// get PAST the key check and fail on config parsing instead.
	if err := os.WriteFile(config, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("OPENROUTER_API_KEY", "")
	t.Setenv("HELM_SPEND_PROXY_SIGNING_SEED", "")
	t.Setenv("HELM_SPEND_PROXY_UPSTREAM_KEY", "generic-key")
	var stdout, stderr bytes.Buffer
	if code := runSpendProxyCmd([]string{"--config", config}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if strings.Contains(stderr.String(), "upstream API key is required") {
		t.Fatalf("generic env var was not honored: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "tenant_id is required") {
		t.Fatalf("expected config validation failure, got: %q", stderr.String())
	}
}

func TestSpendProxyDOGradientExampleConfigLoads(t *testing.T) {
	// The checked-in DigitalOcean Gradient config must stay loadable: it is the
	// price-book source of record for the HELM-618 savings capture window.
	path := filepath.Join("..", "..", "..", "examples", "spend-proxy", "dogfood.do-gradient.config.json")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("example config not present in this checkout: %v", err)
	}
	cfg, sourceHash, err := spendproxy.LoadConfig(path)
	if err != nil {
		t.Fatalf("DO Gradient config failed to load: %v", err)
	}
	if !strings.HasPrefix(sourceHash, "sha256:") {
		t.Fatalf("source hash = %q, want sha256 prefix", sourceHash)
	}
	if len(cfg.Envelopes) < 4 {
		t.Fatalf("DO Gradient config must declare the baseline and three candidate envelopes, got %d", len(cfg.Envelopes))
	}
	var baseline bool
	for _, env := range cfg.Envelopes {
		if env.ID == "env-baseline" && !env.AllowModelSubstitution {
			baseline = true
		}
		if env.ID != "env-baseline" && !env.AllowModelSubstitution {
			t.Fatalf("candidate envelope %s must allow substitution", env.ID)
		}
	}
	if !baseline {
		t.Fatal("env-baseline with substitution disabled is required")
	}
}

func TestSpendProxyInferenceNetExampleConfigLoads(t *testing.T) {
	// The checked-in Inference.net config is the price-book source of record
	// for the HELM-618 savings capture window.
	path := filepath.Join("..", "..", "..", "examples", "spend-proxy", "dogfood.inference-net.config.json")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("example config not present in this checkout: %v", err)
	}
	cfg, sourceHash, err := spendproxy.LoadConfig(path)
	if err != nil {
		t.Fatalf("Inference.net config failed to load: %v", err)
	}
	if !strings.HasPrefix(sourceHash, "sha256:") {
		t.Fatalf("source hash = %q, want sha256 prefix", sourceHash)
	}
	if len(cfg.Envelopes) < 4 {
		t.Fatalf("config must declare the baseline and three candidate envelopes, got %d", len(cfg.Envelopes))
	}
	if cfg.Balance.OpeningCents > 2000 {
		t.Fatalf("opening balance %d exceeds the $20 capture ceiling", cfg.Balance.OpeningCents)
	}
	for _, env := range cfg.Envelopes {
		if env.PerRequestMaxCents > 50 {
			t.Fatalf("envelope %s per-request cap %d exceeds 50 cents", env.ID, env.PerRequestMaxCents)
		}
		if (env.ID == "env-baseline") == env.AllowModelSubstitution {
			t.Fatalf("envelope %s has the wrong substitution posture", env.ID)
		}
	}
}

// TestSpendProxyExportRefusesAMalformedPublicKey: --public-key must be an
// Ed25519 public key; anything else is a usage error before any export.
func TestSpendProxyExportRefusesAMalformedPublicKey(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runSpendProxyExport([]string{"--receipts-dir", t.TempDir(), "--out", t.TempDir(), "--public-key", "ed25519:abcd"}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "--public-key") {
		t.Fatalf("exit = %d, stderr = %q; want 2 naming --public-key", code, stderr.String())
	}
}

// reconcileConfig is a one-envelope spend-proxy config for the reconcile
// tests.
const reconcileConfig = `{
  "tenant_id": "tenant-test", "treasury_id": "treasury-test", "route_policy_id": "test-policy-v1",
  "currency": "USD", "platform_fee_bps": 0, "quote_ttl_seconds": 300, "price_ttl_hours": 24,
  "balance": {"account_id": "balance-test", "opening_cents": 2000},
  "providers": [{"id": "mockai", "account_mode": "DIRECT", "terms_version": "2026-08-17", "legal_review_ref": "test"}],
  "prices": [{"provider_id": "mockai", "model_id": "base-model", "input_token_micro_cents": 5000, "output_token_micro_cents": 10000}],
  "envelopes": [{"id": "env-direct", "agent_id": "agent-live", "principal_id": "principal-test", "budget_id": "budget-direct",
    "max_amount_cents": 1000, "per_request_max_cents": 50, "allowed_providers": ["mockai"], "allowed_models": ["base-model"],
    "fallback_routes": [{"provider_id": "mockai", "model_id": "base-model"}]}]
}`

const reconcileSeed = "0202020202020202020202020202020202020202020202020202020202020202"

// pendingDispatch runs one request through a spend proxy and cuts the receipt
// log back to its pre-dispatch journal line, as if the process stopped while
// the provider worked. It returns the config path, the receipts dir, the
// intent and its hold.
func pendingDispatch(t *testing.T) (string, string, string, int64) {
	t.Helper()
	return pendingDispatchSigned(t, reconcileSeed)
}

// pendingDispatchSigned is pendingDispatch with the proxy run under seed ("":
// the default mode).
func pendingDispatchSigned(t *testing.T, seed string) (string, string, string, int64) {
	t.Helper()
	dir := t.TempDir()
	config := filepath.Join(dir, "config.json")
	if err := os.WriteFile(config, []byte(reconcileConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"c1","model":"base-model","choices":[],"usage":{"prompt_tokens":10,"completion_tokens":5}}`)
	}))
	defer upstream.Close()
	receipts := filepath.Join(dir, "receipts")
	cfg, sourceHash, err := spendproxy.LoadConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	server, err := spendproxy.NewServer(spendproxy.ServerOptions{Config: cfg, SourceHash: sourceHash, ReceiptsDir: receipts,
		UpstreamBaseURL: upstream.URL + "/v1", UpstreamAPIKey: "k", SigningSecret: seed, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"base-model","max_tokens":4000,"messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("X-HELM-Agent", "agent-live")
	req.Header.Set("X-HELM-Spend-Envelope", "env-direct")
	req.Header.Set("X-HELM-Idempotency-Key", "idem-pending")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	_ = server.Close()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	logPath := filepath.Join(receipts, spendproxy.ReceiptLogName)
	records, err := spendproxy.LoadRecords(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range records {
		if r.Kind == spendproxy.RecordRouteQuote && r.Note == spendproxy.NoteDispatchJournal {
			line, _ := json.Marshal(r)
			if err := os.WriteFile(logPath, append(line, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			return config, receipts, r.SpendIntentID, r.RouteQuote.MaxAmountCents
		}
	}
	t.Fatal("no journal line")
	return "", "", "", 0
}

// restarted opens a spend proxy on receipts and reports what it holds and has
// debited.
func restarted(t *testing.T, config, receipts string) (pending int, held, debited int64) {
	t.Helper()
	cfg, sourceHash, err := spendproxy.LoadConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	server, err := spendproxy.NewServer(spendproxy.ServerOptions{Config: cfg, SourceHash: sourceHash, ReceiptsDir: receipts,
		UpstreamBaseURL: "http://127.0.0.1:9/v1", UpstreamAPIKey: "k", SigningSecret: reconcileSeed, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	summary := server.ReplaySummary()
	return summary.PendingDispatches, summary.PendingCents, 2000 - server.BalanceCents()
}

// TestSpendProxyReconcileClearsAPendingHold (helm-tracker#313 r1, F11): an
// operator settles a pending hold at a stated amount, or releases it with a
// reason; either is journalled and signed, and the next start honours it.
func TestSpendProxyReconcileClearsAPendingHold(t *testing.T) {
	for _, action := range []string{"settle", "release"} {
		t.Run(action, func(t *testing.T) {
			config, receipts, intent, hold := pendingDispatch(t)
			if pending, held, _ := restarted(t, config, receipts); pending != 1 || held != hold {
				t.Fatalf("before reconcile: pending %d holding %d, want 1 holding %d", pending, held, hold)
			}
			args := []string{"reconcile", "--config", config, "--receipts-dir", receipts, "--intent", intent,
				"--reason", "provider console shows the call", "--sign", reconcileSeed}
			if action == "settle" {
				args = append(args, "--settle-cents", "3")
			} else {
				args = append(args, "--release")
			}
			var stdout, stderr bytes.Buffer
			if code := runSpendProxyCmd(args, &stdout, &stderr); code != 0 {
				t.Fatalf("reconcile exit %d: %s", code, stderr.String())
			}
			pending, held, debited := restarted(t, config, receipts)
			want := int64(3)
			if action == "release" {
				want = 0
			}
			if pending != 0 || held != 0 || debited != want {
				t.Fatalf("after reconcile: pending %d holding %d debited %d, want 0, 0, %d", pending, held, debited, want)
			}
			records, err := spendproxy.LoadRecords(filepath.Join(receipts, spendproxy.ReceiptLogName))
			if err != nil {
				t.Fatal(err)
			}
			var signedReason bool
			for _, r := range records[1:] {
				raw, _ := json.Marshal(r)
				if r.PayloadSignature != "" && strings.Contains(string(raw), "provider console shows the call") {
					signedReason = true
				}
			}
			if !signedReason {
				t.Fatalf("no signed record carries the operator's reason: %d records", len(records))
			}
			// A second reconcile of the same intent finds nothing pending.
			if code := runSpendProxyCmd(args, &stdout, &stderr); code == 0 {
				t.Fatal("a reconciled intent was reconciled again")
			}
		})
	}
}

// TestSpendProxyReconcileInTheDefaultMode (helm-tracker#313 r2, finding 5): a
// proxy run without --sign keeps a generated seed in its receipts directory,
// and reconcile without --sign signs with it.
func TestSpendProxyReconcileInTheDefaultMode(t *testing.T) {
	t.Setenv("HELM_SPEND_PROXY_SIGNING_SEED", "")
	config, receipts, intent, _ := pendingDispatchSigned(t, "")
	var stdout, stderr bytes.Buffer
	code := runSpendProxyCmd([]string{"reconcile", "--config", config, "--receipts-dir", receipts, "--intent", intent,
		"--release", "--reason", "the provider has no such request", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("reconcile without --sign: exit %d: %s", code, stderr.String())
	}
	var res map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil || res["action"] != "released" || res["spend_intent_id"] != intent {
		t.Fatalf("reconcile --json = %s (%v)", stdout.String(), err)
	}
}
