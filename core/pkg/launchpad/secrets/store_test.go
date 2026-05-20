package secrets

import (
	"os"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
)

func TestSecretBindingProjectsLogicalModelGatewayToRuntimeEnv(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HELM_TEST_OPENROUTER", "sk-test-value")
	previous := os.Getenv("OPENROUTER_API_KEY")
	had := previous != ""
	if err := os.Unsetenv("OPENROUTER_API_KEY"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("OPENROUTER_API_KEY", previous)
		} else {
			_ = os.Unsetenv("OPENROUTER_API_KEY")
		}
	})

	store := NewStore(root)
	if _, err := store.Set("model_gateway", "openrouter", "HELM_TEST_OPENROUTER"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	projected, err := store.ApplyAppEnv(registry.AppSpec{
		ModelGatewayEnv: []string{"OPENROUTER_API_KEY"},
		RequiredSecrets: []string{"model_gateway"},
	})
	if err != nil {
		t.Fatalf("ApplyAppEnv: %v", err)
	}
	if projected["OPENROUTER_API_KEY"] != "model_gateway" {
		t.Fatalf("projected = %#v", projected)
	}
	if os.Getenv("OPENROUTER_API_KEY") != "sk-test-value" {
		t.Fatal("OPENROUTER_API_KEY was not projected from the logical binding")
	}
	statuses, err := store.Statuses()
	if err != nil {
		t.Fatalf("Statuses: %v", err)
	}
	if len(statuses) != 1 || !statuses[0].Available || statuses[0].ValueEnv != "HELM_TEST_OPENROUTER" {
		t.Fatalf("unexpected statuses: %#v", statuses)
	}
}

func TestSecretBindingDoesNotStoreUnsetValueEnv(t *testing.T) {
	_, err := NewStore(t.TempDir()).Set("model_gateway", "openrouter", "HELM_TEST_MISSING")
	if err == nil {
		t.Fatal("expected unset value env to fail")
	}
}
