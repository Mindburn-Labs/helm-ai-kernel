package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDoctorDefaultsToSetupState(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if err := os.Mkdir(home, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("HELM_DATA_DIR", "")
	t.Setenv("HELM_CONFIG_PATH", "")
	t.Chdir(root)

	legacyData := filepath.Join(root, "data")
	if err := os.MkdirAll(legacyData, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyData, "root.key"), []byte("repo-local"), 0o600); err != nil {
		t.Fatal(err)
	}

	wantDataDir := filepath.Join(home, ".helm-ai-kernel")
	if got := resolveDataDir(); got != wantDataDir {
		t.Fatalf("resolveDataDir()=%q, want %q", got, wantDataDir)
	}
	if result := checkDataDirectory(false); result.Status != statusFail || result.Detail != wantDataDir || result.Suggestion != doctorOnboardingSuggestion {
		t.Fatalf("data directory result=%+v", result)
	}
	if result := checkCryptoKeys(false); result.Status != statusFail || result.Suggestion != doctorOnboardingSuggestion {
		t.Fatalf("crypto result=%+v", result)
	}
	for _, check := range []checkFunc{checkConfig, checkDatabase, checkPolicyBundles, checkEvidenceStore} {
		if result := check(false); result.Suggestion != doctorOnboardingSuggestion {
			t.Fatalf("%s suggestion=%q", result.Name, result.Suggestion)
		}
	}
}

func TestDoctorRecognizesQuickstartPolicyState(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("HELM_DATA_DIR", dataDir)
	t.Setenv("HELM_CONFIG_PATH", "")
	quickstartDir := filepath.Join(dataDir, "quickstart")
	if err := os.MkdirAll(filepath.Join(quickstartDir, "reference_packs"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(quickstartDir, "oss_local_first_run.toml"), []byte("name = \"oss_local_first_run\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(quickstartDir, "reference_packs", "oss_local_first_run.v1.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if result := checkConfig(false); result.Status != statusPass {
		t.Fatalf("configuration result=%+v", result)
	}
	if result := checkPolicyBundles(false); result.Status != statusPass {
		t.Fatalf("policy result=%+v", result)
	}
}
