package main

import (
	"bytes"
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
		if code != 2 || !strings.Contains(msg, "not loopback") || !strings.Contains(msg, "no caller credential") {
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
