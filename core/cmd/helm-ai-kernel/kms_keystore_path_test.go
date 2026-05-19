package main

import (
	"path/filepath"
	"testing"
)

func TestKMSKeystorePathPrefersExplicitDataDir(t *testing.T) {
	t.Setenv("HELM_DATA_DIR", "")
	got := kmsKeystorePath("/var/lib/helm-ai-kernel")
	want := filepath.Join("/var/lib/helm-ai-kernel", "keys", "credentials.keystore.json")
	if got != want {
		t.Fatalf("explicit dataDir not honored: got %q, want %q", got, want)
	}
}

func TestKMSKeystorePathFallsBackToEnv(t *testing.T) {
	t.Setenv("HELM_DATA_DIR", "/data")
	got := kmsKeystorePath("")
	want := filepath.Join("/data", "keys", "credentials.keystore.json")
	if got != want {
		t.Fatalf("HELM_DATA_DIR fallback ignored: got %q, want %q", got, want)
	}
}

func TestKMSKeystorePathFinalFallback(t *testing.T) {
	t.Setenv("HELM_DATA_DIR", "")
	got := kmsKeystorePath("")
	want := filepath.Join("data", "keys", "credentials.keystore.json")
	if got != want {
		t.Fatalf("final fallback wrong: got %q, want %q", got, want)
	}
}
