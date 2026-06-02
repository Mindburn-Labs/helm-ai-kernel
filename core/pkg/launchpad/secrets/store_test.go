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
	if projected["OPENROUTER_API_KEY"] != "model_gateway:openrouter" {
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

func TestSecretBindingProjectsProviderSpecificGatewayKeys(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HELM_TEST_OPENROUTER", "sk-openrouter")
	t.Setenv("HELM_TEST_ANTHROPIC", "sk-anthropic")
	for _, envName := range []string{"OPENROUTER_API_KEY", "ANTHROPIC_API_KEY"} {
		previous := os.Getenv(envName)
		had := previous != ""
		if err := os.Unsetenv(envName); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if had {
				_ = os.Setenv(envName, previous)
			} else {
				_ = os.Unsetenv(envName)
			}
		})
	}

	store := NewStore(root)
	if _, err := store.Set("model_gateway", "openrouter", "HELM_TEST_OPENROUTER"); err != nil {
		t.Fatalf("Set openrouter: %v", err)
	}
	if _, err := store.Set("model_gateway", "anthropic", "HELM_TEST_ANTHROPIC"); err != nil {
		t.Fatalf("Set anthropic: %v", err)
	}
	projected, err := store.ApplyAppEnv(registry.AppSpec{
		ModelGatewayEnv: []string{"OPENROUTER_API_KEY", "ANTHROPIC_API_KEY"},
		RequiredSecrets: []string{"model_gateway"},
	})
	if err != nil {
		t.Fatalf("ApplyAppEnv: %v", err)
	}
	if projected["OPENROUTER_API_KEY"] != "model_gateway:openrouter" || os.Getenv("OPENROUTER_API_KEY") != "sk-openrouter" {
		t.Fatalf("OpenRouter projection failed: projected=%#v env=%q", projected, os.Getenv("OPENROUTER_API_KEY"))
	}
	if projected["ANTHROPIC_API_KEY"] != "model_gateway:anthropic" || os.Getenv("ANTHROPIC_API_KEY") != "sk-anthropic" {
		t.Fatalf("Anthropic projection failed: projected=%#v env=%q", projected, os.Getenv("ANTHROPIC_API_KEY"))
	}
}

func TestSecretBindingProjectsCatalogScopedBYOEnv(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HELM_TEST_ANTHROPIC", "sk-anthropic")
	previous := os.Getenv("ANTHROPIC_API_KEY")
	had := previous != ""
	if err := os.Unsetenv("ANTHROPIC_API_KEY"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("ANTHROPIC_API_KEY", previous)
		} else {
			_ = os.Unsetenv("ANTHROPIC_API_KEY")
		}
	})

	store := NewStore(root)
	if _, err := store.Set("model_gateway", "anthropic", "HELM_TEST_ANTHROPIC"); err != nil {
		t.Fatalf("Set anthropic: %v", err)
	}
	projected, err := store.ApplyAppEnv(registry.AppSpec{
		ModelGateway: registry.ModelGatewaySpec{
			Provider:    "byo",
			ProviderIDs: []string{"openai", "anthropic"},
		},
		RequiredSecrets: []string{"model_gateway"},
	})
	if err != nil {
		t.Fatalf("ApplyAppEnv: %v", err)
	}
	if projected["ANTHROPIC_API_KEY"] != "model_gateway:anthropic" || os.Getenv("ANTHROPIC_API_KEY") != "sk-anthropic" {
		t.Fatalf("catalog-scoped BYO projection failed: projected=%#v env=%q", projected, os.Getenv("ANTHROPIC_API_KEY"))
	}
}

func TestSecretBindingDoesNotProjectDynamicEndpointFromCredential(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HELM_TEST_AZURE", "sk-azure")
	t.Setenv("AZURE_OPENAI_API_KEY", "")
	t.Setenv("AZURE_OPENAI_ENDPOINT", "")

	store := NewStore(root)
	if _, err := store.Set("model_gateway", "azure-openai", "HELM_TEST_AZURE"); err != nil {
		t.Fatalf("Set azure-openai: %v", err)
	}
	projected, err := store.ApplyAppEnv(registry.AppSpec{
		ModelGateway: registry.ModelGatewaySpec{
			Provider:    "byo",
			ProviderIDs: []string{"azure-openai"},
		},
		RequiredSecrets: []string{"model_gateway"},
	})
	if err != nil {
		t.Fatalf("ApplyAppEnv: %v", err)
	}
	if projected["AZURE_OPENAI_API_KEY"] != "model_gateway:azure-openai" || os.Getenv("AZURE_OPENAI_API_KEY") != "sk-azure" {
		t.Fatalf("Azure credential projection failed: projected=%#v env=%q", projected, os.Getenv("AZURE_OPENAI_API_KEY"))
	}
	if _, projectedEndpoint := projected["AZURE_OPENAI_ENDPOINT"]; projectedEndpoint || os.Getenv("AZURE_OPENAI_ENDPOINT") != "" {
		t.Fatalf("Azure endpoint must not be projected from credential binding: projected=%#v env=%q", projected, os.Getenv("AZURE_OPENAI_ENDPOINT"))
	}
}

func TestSecretBindingDoesNotStoreUnsetValueEnv(t *testing.T) {
	_, err := NewStore(t.TempDir()).Set("model_gateway", "openrouter", "HELM_TEST_MISSING")
	if err == nil {
		t.Fatal("expected unset value env to fail")
	}
}
