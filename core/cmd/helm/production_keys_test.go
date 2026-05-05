package main

import (
	"strings"
	"testing"
)

func TestProductionModeRequiresExistingRootKey(t *testing.T) {
	t.Setenv("HELM_PRODUCTION", "true")

	dataDir := t.TempDir()
	_, err := loadOrGenerateSignerWithDataDir(dataDir)
	if err == nil {
		t.Fatal("expected production startup to reject missing root key")
	}
	if !strings.Contains(err.Error(), dataDir) {
		t.Fatalf("error should name the required key path, got %q", err.Error())
	}
}

func TestProductionModeRequiresEvidenceSigningKey(t *testing.T) {
	t.Setenv("HELM_PRODUCTION", "yes")
	t.Setenv("EVIDENCE_SIGNING_KEY", "")

	_, _, err := evidenceSigningSeedFromEnv()
	if err == nil {
		t.Fatal("expected production startup to reject missing evidence signing key")
	}
	if !strings.Contains(err.Error(), "EVIDENCE_SIGNING_KEY") {
		t.Fatalf("error should name EVIDENCE_SIGNING_KEY, got %q", err.Error())
	}
}

func TestDevelopmentModeAllowsDefaultEvidenceSigningKey(t *testing.T) {
	t.Setenv("HELM_PRODUCTION", "")
	t.Setenv("EVIDENCE_SIGNING_KEY", "")

	seed, defaulted, err := evidenceSigningSeedFromEnv()
	if err != nil {
		t.Fatalf("development evidence key fallback returned error: %v", err)
	}
	if seed == "" || !defaulted {
		t.Fatalf("expected default development evidence key, got seed=%q defaulted=%v", seed, defaulted)
	}
}
