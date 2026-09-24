package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/secrettest"
)

// A compose or dev install with no configured keys gets its own admin and
// service keys, stable across restarts, and the keys never reach the logs.
func TestLocalAPIKeysAreGeneratedPerInstallAndNotLogged(t *testing.T) {
	t.Setenv("HELM_PRODUCTION", "")
	t.Setenv("HELM_ADMIN_API_KEY", "")
	t.Setenv("HELM_SERVICE_API_KEY", "")
	logs := secrettest.CaptureLogs(t)

	install := t.TempDir()
	if err := ensureLocalAPIKeys(install, slog.Default()); err != nil {
		t.Fatal(err)
	}
	admin, service := os.Getenv("HELM_ADMIN_API_KEY"), os.Getenv("HELM_SERVICE_API_KEY")
	if len(admin) != 64 || len(service) != 64 || admin == service {
		t.Fatalf("admin=%d chars service=%d chars equal=%v", len(admin), len(service), admin == service)
	}
	secrettest.AssertAbsent(t, admin, map[string]string{"logs": logs.String()})
	secrettest.AssertAbsent(t, service, map[string]string{"logs": logs.String()})

	// Restart: same keys from disk.
	t.Setenv("HELM_ADMIN_API_KEY", "")
	t.Setenv("HELM_SERVICE_API_KEY", "")
	if err := ensureLocalAPIKeys(install, slog.Default()); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("HELM_ADMIN_API_KEY") != admin || os.Getenv("HELM_SERVICE_API_KEY") != service {
		t.Fatal("restart generated new API keys")
	}

	// Another install gets different keys.
	t.Setenv("HELM_ADMIN_API_KEY", "")
	if err := ensureLocalAPIKeys(t.TempDir(), slog.Default()); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("HELM_ADMIN_API_KEY") == admin {
		t.Fatal("two installs share an admin key")
	}
}

func TestLocalAPIKeysKeepConfiguredAndProductionBehaviour(t *testing.T) {
	t.Setenv("HELM_PRODUCTION", "")
	t.Setenv("HELM_ADMIN_API_KEY", "configured-admin-key")
	t.Setenv("HELM_SERVICE_API_KEY", "configured-service-key")
	dir := t.TempDir()
	if err := ensureLocalAPIKeys(dir, slog.Default()); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("HELM_ADMIN_API_KEY") != "configured-admin-key" {
		t.Fatal("configured admin key was replaced")
	}
	if _, err := os.Stat(filepath.Join(dir, "admin.key")); !os.IsNotExist(err) {
		t.Fatalf("configured key still wrote admin.key: %v", err)
	}

	t.Setenv("HELM_PRODUCTION", "1")
	t.Setenv("HELM_ADMIN_API_KEY", "")
	t.Setenv("HELM_SERVICE_API_KEY", "")
	if err := ensureLocalAPIKeys(dir, slog.Default()); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("HELM_ADMIN_API_KEY") != "" {
		t.Fatal("production generated an admin key instead of leaving admin routes closed")
	}
}

func TestLocalAPIKeysRefusePublishedDefaults(t *testing.T) {
	t.Setenv("HELM_PRODUCTION", "")
	for _, env := range []string{"HELM_ADMIN_API_KEY", "HELM_SERVICE_API_KEY"} {
		for _, literal := range publishedAPIKeys {
			t.Setenv("HELM_ADMIN_API_KEY", "x-configured-admin")
			t.Setenv("HELM_SERVICE_API_KEY", "x-configured-service")
			t.Setenv(env, literal)
			if err := ensureLocalAPIKeys(t.TempDir(), slog.Default()); err == nil {
				t.Fatalf("%s=%q accepted", env, literal)
			}
		}
	}
}
