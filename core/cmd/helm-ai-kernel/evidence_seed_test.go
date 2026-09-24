package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

// C-02: the public key that the old literal default ("helm-evidence-bundle")
// derives to. Anyone could sign evidence under it.
const publishedDefaultEvidencePublicKey = "231ab3582fb26d51b890d0592bab1dc0b5228d5841287b358a43c479a148af42"

func evidencePublicKey(t *testing.T, seed string) string {
	t.Helper()
	signer, _, err := helmcrypto.NewEd25519SignerFromSecret(seed, "helm-evidence-bundle")
	if err != nil {
		t.Fatal(err)
	}
	return signer.PublicKey()
}

// Without EVIDENCE_SIGNING_KEY a non-production install signs evidence with
// its own random seed, generated once and kept in the data dir.
func TestEvidenceSigningSeedIsGeneratedPerInstall(t *testing.T) {
	t.Setenv("HELM_PRODUCTION", "")
	t.Setenv("EVIDENCE_SIGNING_KEY", "")

	installA, installB := t.TempDir(), t.TempDir()
	seedA, _, err := evidenceSigningSeed(installA)
	if err != nil {
		t.Fatal(err)
	}
	seedB, _, err := evidenceSigningSeed(installB)
	if err != nil {
		t.Fatal(err)
	}
	if seedA == seedB {
		t.Fatalf("two installs share the evidence seed %q", seedA)
	}
	for _, seed := range []string{seedA, seedB} {
		if pub := evidencePublicKey(t, seed); pub == publishedDefaultEvidencePublicKey {
			t.Fatalf("install signs evidence with the published default key %s", pub)
		}
	}

	// A restart keeps the same key, so exported packs stay verifiable.
	again, persistedAt, err := evidenceSigningSeed(installA)
	if err != nil {
		t.Fatal(err)
	}
	if again != seedA {
		t.Fatal("restart generated a new evidence key")
	}
	if persistedAt != filepath.Join(installA, "evidence.key") {
		t.Fatalf("persistedAt = %q", persistedAt)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(persistedAt)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("evidence.key mode = %o, want 600", perm)
		}
	}
}

// An explicit EVIDENCE_SIGNING_KEY (the Helm chart's per-install Secret) wins
// and writes nothing.
func TestEvidenceSigningSeedPrefersConfiguredKey(t *testing.T) {
	t.Setenv("HELM_PRODUCTION", "")
	configured := strings.Repeat("ab", 32)
	t.Setenv("EVIDENCE_SIGNING_KEY", configured)

	dataDir := t.TempDir()
	seed, persistedAt, err := evidenceSigningSeed(dataDir)
	if err != nil || seed != configured || persistedAt != "" {
		t.Fatalf("seed=%q persistedAt=%q err=%v", seed, persistedAt, err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "evidence.key")); !os.IsNotExist(err) {
		t.Fatalf("configured key still wrote evidence.key: %v", err)
	}
}

// The published literals derive to public keys; refuse them in any mode.
func TestEvidenceSigningSeedRefusesPublishedDefaults(t *testing.T) {
	t.Setenv("HELM_PRODUCTION", "")
	if got := evidencePublicKey(t, "helm-evidence-bundle"); got != publishedDefaultEvidencePublicKey {
		t.Fatalf("old default derives to %s", got)
	}
	for _, literal := range []string{"helm-evidence-bundle", "helm-evidence-dev", "helm-evidence-smoke"} {
		t.Setenv("EVIDENCE_SIGNING_KEY", literal)
		if _, _, err := evidenceSigningSeed(t.TempDir()); err == nil {
			t.Fatalf("accepted the published default %q", literal)
		}
	}
}

func TestEvidenceSigningSeedRejectsUnsafeKeyFile(t *testing.T) {
	t.Setenv("HELM_PRODUCTION", "")
	t.Setenv("EVIDENCE_SIGNING_KEY", "")

	corrupt := t.TempDir()
	if err := os.WriteFile(filepath.Join(corrupt, "evidence.key"), []byte("not-a-seed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := evidenceSigningSeed(corrupt); err == nil {
		t.Fatal("accepted a corrupt evidence.key")
	}

	if runtime.GOOS != "windows" {
		exposed := t.TempDir()
		if _, _, err := evidenceSigningSeed(exposed); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(exposed, "evidence.key"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := evidenceSigningSeed(exposed); err == nil {
			t.Fatal("accepted a world-readable evidence.key")
		}
	}
}
