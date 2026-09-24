package main

import (
	"path/filepath"
	"strings"
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

// 16-02 through the server's wiring: the legacy env key never re-pins the
// active version once an operator has rotated.
func TestOpenCredentialKeystoreKeepsRotationWithLegacyEnvKey(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("CREDENTIALS_ENCRYPTION_KEY", strings.Repeat("ab", 32))

	k, err := openCredentialKeystore(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := k.ActiveVersion(); got != 0 {
		t.Fatalf("new keystore should start from the legacy key as v0, got v%d", got)
	}
	if _, err := k.Rotate(); err != nil {
		t.Fatal(err)
	}
	for boot := 0; boot < 2; boot++ {
		k, err = openCredentialKeystore(dataDir)
		if err != nil {
			t.Fatal(err)
		}
		if got := k.ActiveVersion(); got != 1 {
			t.Fatalf("boot %d re-pinned the legacy key: active v%d, want v1", boot, got)
		}
	}

	t.Setenv("CREDENTIALS_ENCRYPTION_KEY", "not-hex")
	if _, err := openCredentialKeystore(dataDir); err == nil {
		t.Fatal("a malformed CREDENTIALS_ENCRYPTION_KEY was silently ignored")
	}
}
