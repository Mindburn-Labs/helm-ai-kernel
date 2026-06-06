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

func TestProductionDatabaseURLRequiresPostgresTLS(t *testing.T) {
	for _, dsn := range []string{
		"postgres://helm:secret@db.example/helm?sslmode=require",
		"postgres://helm:secret@db.example/helm?sslmode=verify-ca",
		"postgresql://helm:secret@db.example/helm?sslmode=verify-full",
		"host=db.example dbname=helm user=helm sslmode=require",
		"host=db.example dbname=helm user=helm sslmode='verify-full'",
	} {
		t.Run("allow_"+dsn, func(t *testing.T) {
			if err := validateProductionDatabaseURL(dsn); err != nil {
				t.Fatalf("expected DSN to pass production TLS validation: %v", err)
			}
		})
	}

	for _, dsn := range []string{
		"postgres://helm:secret@db.example/helm",
		"postgres://helm:secret@db.example/helm?sslmode=disable",
		"postgres://helm:secret@db.example/helm?sslmode=allow",
		"postgres://helm:secret@db.example/helm?sslmode=prefer",
		"host=db.example dbname=helm user=helm",
		"host=db.example dbname=helm user=helm sslmode=disable",
	} {
		t.Run("deny_"+dsn, func(t *testing.T) {
			err := validateProductionDatabaseURL(dsn)
			if err == nil {
				t.Fatal("expected insecure production DATABASE_URL to fail")
			}
			if !strings.Contains(err.Error(), "sslmode") {
				t.Fatalf("error should mention sslmode, got %v", err)
			}
		})
	}
}
