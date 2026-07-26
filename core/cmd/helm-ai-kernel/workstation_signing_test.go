// quantum_posture: these tests cover the classical Ed25519 local signer and
// make no post-quantum security claim.
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalWorkstationSigningKeyLifecycle(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "helm")
	seed, err := ensureLocalWorkstationSigningSeed(dataDir)
	if err != nil {
		t.Fatalf("ensure signing seed: %v", err)
	}
	if len(seed) != ed25519.SeedSize {
		t.Fatalf("seed length = %d, want %d", len(seed), ed25519.SeedSize)
	}
	keyDir := filepath.Join(dataDir, workstationSigningKeyDirectory)
	if info, err := os.Stat(keyDir); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("key directory permissions = %v/%v, want 0700", info, err)
	}
	seedPath := workstationSigningSeedPath(dataDir)
	if info, err := os.Stat(seedPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("seed permissions = %v/%v, want 0600", info, err)
	}
	publicPath := workstationSigningPublicKeyPath(dataDir)
	publicData, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	publicKey := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if got, want := strings.TrimSpace(string(publicData)), hex.EncodeToString(publicKey); got != want {
		t.Fatalf("public key = %q, want %q", got, want)
	}
	second, err := ensureLocalWorkstationSigningSeed(dataDir)
	if err != nil {
		t.Fatalf("reopen signing seed: %v", err)
	}
	if !bytes.Equal(seed, second) {
		t.Fatal("existing signing seed was replaced")
	}

	if err := os.Chmod(seedPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureLocalWorkstationSigningSeed(dataDir); err == nil || !strings.Contains(err.Error(), "must not be readable") {
		t.Fatalf("insecure seed permissions error = %v, want private-file rejection", err)
	}
}

func TestProductionWorkstationSigningRequiresExplicitSeedFile(t *testing.T) {
	t.Setenv("HELM_PRODUCTION", "true")
	dataDir := filepath.Join(t.TempDir(), "helm")

	if _, err := resolveWorkstationSigningSeed(dataDir, "", ""); err == nil || !strings.Contains(err.Error(), "requires --signing-seed-file") {
		t.Fatalf("production missing signer error = %v, want explicit seed requirement", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, workstationSigningKeyDirectory)); !os.IsNotExist(err) {
		t.Fatalf("production missing signer created local key state: %v", err)
	}

	seedFile := filepath.Join(t.TempDir(), "workstation.seed")
	if err := os.WriteFile(seedFile, []byte(strings.Repeat("1", ed25519.SeedSize*2)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	seed, err := resolveWorkstationSigningSeed(dataDir, "", seedFile)
	if err != nil {
		t.Fatalf("load explicit production signing seed: %v", err)
	}
	if len(seed) != ed25519.SeedSize {
		t.Fatalf("explicit production seed length = %d, want %d", len(seed), ed25519.SeedSize)
	}
}

func TestLocalWorkstationSigningKeyRejectsSymlinkAndMismatchedPublicKey(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "helm")
	keyDir := filepath.Join(dataDir, workstationSigningKeyDirectory)
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target.seed")
	if err := os.WriteFile(target, []byte(strings.Repeat("0", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, workstationSigningSeedPath(dataDir)); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureLocalWorkstationSigningSeed(dataDir); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlink seed error = %v, want regular-file rejection", err)
	}

	dataDir = filepath.Join(t.TempDir(), "mismatched")
	if _, err := ensureLocalWorkstationSigningSeed(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workstationSigningPublicKeyPath(dataDir), []byte(strings.Repeat("f", ed25519.PublicKeySize*2)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureLocalWorkstationSigningSeed(dataDir); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched public key error = %v, want mismatch rejection", err)
	}

	dataDir = filepath.Join(t.TempDir(), "malformed")
	keyDir = filepath.Join(dataDir, workstationSigningKeyDirectory)
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workstationSigningSeedPath(dataDir), []byte("not-a-hex-seed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureLocalWorkstationSigningSeed(dataDir); err == nil || !strings.Contains(err.Error(), "signing seed must be hex") {
		t.Fatalf("malformed seed error = %v, want hex rejection", err)
	}
}

func TestWorkstationSigningRequiresExplicitDataDirWithoutHome(t *testing.T) {
	t.Setenv("HOME", "")
	if _, err := normalizedWorkstationDataDir(""); err == nil || !strings.Contains(err.Error(), "--data-dir is required") {
		t.Fatalf("default data dir error = %v, want explicit data-dir requirement", err)
	}

	fixture := filepath.Join(kernelRepoRoot(t), "fixtures", "workstation", "denied-network")
	workdir := t.TempDir()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(workdir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(previous)
	})
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "workstation", "import", "--artifacts", fixture}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "--data-dir is required") {
		t.Fatalf("HOME-less import = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(workdir, ".helm-ai-kernel")); !os.IsNotExist(err) {
		t.Fatalf("HOME-less import created a cwd key directory: %v", err)
	}
}

func TestWorkstationSigningRejectsRelativeHomeDirectory(t *testing.T) {
	t.Setenv("HOME", ".")
	if got := defaultSetupDataDir(); got != "" {
		t.Fatalf("relative HOME default data dir = %q, want empty", got)
	}
	if _, err := normalizedWorkstationDataDir(""); err == nil || !strings.Contains(err.Error(), "--data-dir is required") {
		t.Fatalf("relative HOME default data dir error = %v, want explicit data-dir requirement", err)
	}
}
