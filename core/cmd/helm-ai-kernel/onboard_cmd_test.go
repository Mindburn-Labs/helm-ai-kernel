package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOnboardTrustRootMatchesCustomDataDir verifies that `helm onboard --data-dir <dir>`
// advertises a root_public_key in helm.yaml that matches the signer materialized under
// that same data dir, rather than the default "data/" directory. Regression test for the
// onboard trust-root mismatch where step 3 used loadOrGenerateSigner() (hard-coded "data")
// instead of loadOrGenerateSignerWithDataDir(dataDir).
func TestOnboardTrustRootMatchesCustomDataDir(t *testing.T) {
	workDir := chdirTempDir(t)
	dataDir := filepath.Join(workDir, "custom-data")

	var stdout, stderr bytes.Buffer
	if code := runOnboardCmd([]string{"--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("onboard exited %d\nstdout=%s\nstderr=%s", code, stdout.String(), stderr.String())
	}

	// The trust root must be persisted under the custom data dir, never the default "data/".
	if _, err := os.Stat(filepath.Join(dataDir, "root.key")); err != nil {
		t.Fatalf("root.key not written under custom data dir %q: %v", dataDir, err)
	}
	if _, err := os.Stat(filepath.Join("data", "root.key")); err == nil {
		t.Fatal("onboard wrote a root key under the default data/ dir; --data-dir was ignored for the signer")
	}

	configBytes, err := os.ReadFile("helm.yaml")
	if err != nil {
		t.Fatalf("read helm.yaml: %v", err)
	}
	configKey := rootPublicKeyFromConfig(t, string(configBytes))

	// Loading from the same data dir loads the persisted key (no regeneration), so its
	// public key must equal what onboard advertised in helm.yaml.
	signer, err := loadOrGenerateSignerWithDataDir(dataDir)
	if err != nil {
		t.Fatalf("load signer from custom data dir: %v", err)
	}
	wantKey := hex.EncodeToString(signer.PublicKeyBytes())
	if configKey != wantKey {
		t.Fatalf("root_public_key mismatch:\n  helm.yaml:        %s\n  %s signer: %s", configKey, dataDir, wantKey)
	}
}

func rootPublicKeyFromConfig(t *testing.T, config string) string {
	t.Helper()
	const marker = "root_public_key:"
	for _, line := range strings.Split(config, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, marker) {
			continue
		}
		value := strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, marker)), `"`)
		if value == "" {
			t.Fatalf("empty root_public_key in helm.yaml:\n%s", config)
		}
		return value
	}
	t.Fatalf("root_public_key not found in helm.yaml:\n%s", config)
	return ""
}
