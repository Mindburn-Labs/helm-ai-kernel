package secrets

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
)

func TestSecretBindingProjectsLogicalModelGatewayToRuntimeEnv(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HELM_TEST_OPENROUTER", "sk-test-value")
	t.Setenv("OPENROUTER_API_KEY", "")

	store := NewStore(root)
	if _, err := store.Set("model_gateway", "openrouter", "HELM_TEST_OPENROUTER"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	resolved, err := store.ResolveAppEnv(registry.AppSpec{
		ModelGatewayEnv: []string{"OPENROUTER_API_KEY"},
		RequiredSecrets: []string{"model_gateway"},
	})
	if err != nil {
		t.Fatalf("ResolveAppEnv: %v", err)
	}
	if resolved.RuntimeEnv["OPENROUTER_API_KEY"] != "sk-test-value" {
		t.Fatalf("runtime env = %#v", resolved.RuntimeEnv)
	}
	if os.Getenv("OPENROUTER_API_KEY") != "" {
		t.Fatal("launch-scoped resolution mutated the process environment")
	}
	if len(resolved.Accesses) != 1 || resolved.Accesses[0].SecretRef != "model_gateway:openrouter" || resolved.Accesses[0].Verdict != "ALLOW" {
		t.Fatalf("redacted accesses = %#v", resolved.Accesses)
	}
	encoded, err := json.Marshal(resolved)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "sk-test-value") || strings.Contains(string(encoded), "RuntimeEnv") {
		t.Fatalf("resolution serialization exposed secret material: %s", encoded)
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
		t.Setenv(envName, "")
	}

	store := NewStore(root)
	if _, err := store.Set("model_gateway", "openrouter", "HELM_TEST_OPENROUTER"); err != nil {
		t.Fatalf("Set openrouter: %v", err)
	}
	if _, err := store.Set("model_gateway", "anthropic", "HELM_TEST_ANTHROPIC"); err != nil {
		t.Fatalf("Set anthropic: %v", err)
	}
	resolved, err := store.ResolveAppEnv(registry.AppSpec{
		ModelGatewayEnv: []string{"OPENROUTER_API_KEY", "ANTHROPIC_API_KEY"},
		RequiredSecrets: []string{"model_gateway"},
	})
	if err != nil {
		t.Fatalf("ResolveAppEnv: %v", err)
	}
	if resolved.RuntimeEnv["OPENROUTER_API_KEY"] != "sk-openrouter" || os.Getenv("OPENROUTER_API_KEY") != "" {
		t.Fatalf("OpenRouter resolution failed: runtime=%#v env=%q", resolved.RuntimeEnv, os.Getenv("OPENROUTER_API_KEY"))
	}
	if resolved.RuntimeEnv["ANTHROPIC_API_KEY"] != "sk-anthropic" || os.Getenv("ANTHROPIC_API_KEY") != "" {
		t.Fatalf("Anthropic resolution failed: runtime=%#v env=%q", resolved.RuntimeEnv, os.Getenv("ANTHROPIC_API_KEY"))
	}
}

func TestSecretBindingProjectsCatalogScopedBYOEnv(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HELM_TEST_ANTHROPIC", "sk-anthropic")
	t.Setenv("ANTHROPIC_API_KEY", "")

	store := NewStore(root)
	if _, err := store.Set("model_gateway", "anthropic", "HELM_TEST_ANTHROPIC"); err != nil {
		t.Fatalf("Set anthropic: %v", err)
	}
	resolved, err := store.ResolveAppEnv(registry.AppSpec{
		ModelGateway: registry.ModelGatewaySpec{
			Provider:    "byo",
			ProviderIDs: []string{"openai", "anthropic"},
		},
		RequiredSecrets: []string{"model_gateway"},
	})
	if err != nil {
		t.Fatalf("ResolveAppEnv: %v", err)
	}
	if resolved.RuntimeEnv["ANTHROPIC_API_KEY"] != "sk-anthropic" || os.Getenv("ANTHROPIC_API_KEY") != "" {
		t.Fatalf("catalog-scoped BYO resolution failed: runtime=%#v env=%q", resolved.RuntimeEnv, os.Getenv("ANTHROPIC_API_KEY"))
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
	resolved, err := store.ResolveAppEnv(registry.AppSpec{
		ModelGateway: registry.ModelGatewaySpec{
			Provider:    "byo",
			ProviderIDs: []string{"azure-openai"},
		},
		RequiredSecrets: []string{"model_gateway"},
	})
	if err != nil {
		t.Fatalf("ResolveAppEnv: %v", err)
	}
	if resolved.RuntimeEnv["AZURE_OPENAI_API_KEY"] != "sk-azure" || os.Getenv("AZURE_OPENAI_API_KEY") != "" {
		t.Fatalf("Azure credential resolution failed: runtime=%#v env=%q", resolved.RuntimeEnv, os.Getenv("AZURE_OPENAI_API_KEY"))
	}
	if _, resolvedEndpoint := resolved.RuntimeEnv["AZURE_OPENAI_ENDPOINT"]; resolvedEndpoint || os.Getenv("AZURE_OPENAI_ENDPOINT") != "" {
		t.Fatalf("Azure endpoint must not be resolved from credential binding: runtime=%#v env=%q", resolved.RuntimeEnv, os.Getenv("AZURE_OPENAI_ENDPOINT"))
	}
}

func TestSecretBindingDoesNotStoreUnsetValueEnv(t *testing.T) {
	_, err := NewStore(t.TempDir()).Set("model_gateway", "openrouter", "HELM_TEST_MISSING")
	if err == nil {
		t.Fatal("expected unset value env to fail")
	}
}
