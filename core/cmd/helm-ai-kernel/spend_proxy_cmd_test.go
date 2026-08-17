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
