package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOnboardUsesCustomDataDirForTrustRoot(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	dataDir := filepath.Join(cwd, "custom-data")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runOnboardCmd([]string{"--data-dir", dataDir, "--yes"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("onboard code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}

	pubKey, err := os.ReadFile(filepath.Join(dataDir, "root.pub"))
	if err != nil {
		t.Fatalf("custom data dir root.pub missing: %v", err)
	}
	config, err := os.ReadFile(filepath.Join(cwd, "helm.yaml"))
	if err != nil {
		t.Fatalf("helm.yaml missing: %v", err)
	}
	if !strings.Contains(string(config), `data_dir: "`+dataDir+`"`) {
		t.Fatalf("helm.yaml did not reference custom data dir: %s", string(config))
	}
	if !strings.Contains(string(config), `root_public_key: "`+strings.TrimSpace(string(pubKey))+`"`) {
		t.Fatalf("helm.yaml trust root did not match custom data dir public key")
	}
	if _, err := os.Stat(filepath.Join(cwd, "data", "root.key")); !os.IsNotExist(err) {
		t.Fatalf("onboard wrote root.key outside custom data dir: %v", err)
	}
}
