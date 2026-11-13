package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSpendProxyLiveCommandIsRetired(t *testing.T) {
	t.Setenv("HELM_SPEND_PROXY_UPSTREAM_KEY", "unused-test-provider-key")
	for _, args := range [][]string{nil, {"up"}, {"serve"}, {"--config", "old-config.json"}, {"migrate"}} {
		var stdout, stderr bytes.Buffer
		if code := runSpendProxyCmd(args, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "retired") || !strings.Contains(stderr.String(), "helm-gateway") || stdout.Len() != 0 {
			t.Fatalf("%v: exit %d, %s; want retirement with canonical gateway migration", args, code, &stderr)
		}
	}
}

func TestSpendProxyCannotReconcileAuthorityInLocalFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "spend-receipts.jsonl")
	before := []byte("historical receipt bytes\n")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := runSpendProxyCmd([]string{"reconcile", "--receipts-dir", dir, "--intent", "pending", "--release", "--reason", "provider not called"}, &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "Postgres") {
		t.Fatalf("local reconciliation exit %d: %s", code, &stderr)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("refused reconciliation changed the historical log: %v", err)
	}
}
