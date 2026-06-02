package readmodel

import (
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/secrets"
)

func TestRegistryAppsExpandsCatalogBackedBYOModelGateway(t *testing.T) {
	app := registry.AppSpec{
		ID:             "openclaw",
		Name:           "OpenClaw",
		Version:        "test",
		Availability:   registry.AvailabilityOSSSupported,
		Redistribution: "oss",
		Install:        registry.InstallSpec{Strategy: "signed_oci"},
		ModelGateway: registry.ModelGatewaySpec{
			LogicalSecret: "model_gateway",
			Provider:      "byo",
			ProviderIDs:   []string{"openai", "anthropic"},
			Mode:          "external_byo",
		},
		RequiredSecrets: []string{"model_gateway"},
		NetworkPolicy:   registry.NetworkPolicy{Default: "deny"},
		MCPPolicy:       registry.MCPPolicy{UnknownServerPolicy: "quarantine", UnknownToolPolicy: "ESCALATE", RequireSchemaPin: true},
		Conformance: registry.ConformanceSpec{
			LicenseVerified:      true,
			ArtifactVerified:     true,
			PolicyPackPresent:    true,
			SandboxVerified:      true,
			HealthcheckPassing:   true,
			E2EPassing:           true,
			TeardownVerified:     true,
			ReceiptVerified:      true,
			EvidencePackVerified: true,
		},
	}

	apps := RegistryApps(&registry.Catalog{Apps: []registry.AppSpec{app}}, []secrets.Status{{
		Name:      "model_gateway",
		Provider:  "openai",
		ValueEnv:  "OPENAI_API_KEY",
		Available: true,
	}}, nil)

	if len(apps) != 1 {
		t.Fatalf("RegistryApps returned %d apps", len(apps))
	}
	if !containsString(apps[0].ModelGatewayEnv, "OPENAI_API_KEY") || !containsString(apps[0].ModelGatewayEnv, "ANTHROPIC_API_KEY") {
		t.Fatalf("catalog-backed env not expanded: %#v", apps[0].ModelGatewayEnv)
	}
	if !containsString(apps[0].NetworkNeeds, "https://api.openai.com/v1") || !containsString(apps[0].NetworkNeeds, "https://api.anthropic.com/v1") {
		t.Fatalf("catalog-backed network needs not expanded: %#v", apps[0].NetworkNeeds)
	}
	if apps[0].Status.State != "ready" || len(apps[0].Status.MissingSecrets) != 0 {
		t.Fatalf("provider-specific model_gateway status did not satisfy BYO any-of secret: %#v", apps[0].Status)
	}
}

func TestRegistryAppsRequiresCompleteDynamicProviderEnvGroup(t *testing.T) {
	t.Setenv("AZURE_OPENAI_ENDPOINT", "")
	app := registry.AppSpec{
		ID:             "openclaw",
		Name:           "OpenClaw",
		Version:        "test",
		Availability:   registry.AvailabilityOSSSupported,
		Redistribution: "oss",
		Install:        registry.InstallSpec{Strategy: "signed_oci"},
		ModelGateway: registry.ModelGatewaySpec{
			LogicalSecret: "model_gateway",
			Provider:      "byo",
			ProviderIDs:   []string{"azure-openai"},
			Mode:          "external_byo",
		},
		RequiredSecrets: []string{"model_gateway"},
		NetworkPolicy:   registry.NetworkPolicy{Default: "deny"},
		MCPPolicy:       registry.MCPPolicy{UnknownServerPolicy: "quarantine", UnknownToolPolicy: "ESCALATE", RequireSchemaPin: true},
		Conformance: registry.ConformanceSpec{
			LicenseVerified:      true,
			ArtifactVerified:     true,
			PolicyPackPresent:    true,
			SandboxVerified:      true,
			HealthcheckPassing:   true,
			E2EPassing:           true,
			TeardownVerified:     true,
			ReceiptVerified:      true,
			EvidencePackVerified: true,
		},
	}
	statuses := []secrets.Status{{
		Name:      "model_gateway",
		Provider:  "azure-openai",
		ValueEnv:  "HELM_TEST_AZURE",
		Available: true,
	}}

	apps := RegistryApps(&registry.Catalog{Apps: []registry.AppSpec{app}}, statuses, nil)
	if apps[0].Status.State == "ready" || len(apps[0].Status.MissingSecrets) == 0 {
		t.Fatalf("Azure key without endpoint must remain missing: %#v", apps[0].Status)
	}

	t.Setenv("AZURE_OPENAI_ENDPOINT", "https://example.openai.azure.com/")
	apps = RegistryApps(&registry.Catalog{Apps: []registry.AppSpec{app}}, statuses, nil)
	if apps[0].Status.State != "ready" || len(apps[0].Status.MissingSecrets) != 0 {
		t.Fatalf("complete Azure group should satisfy BYO readiness: %#v", apps[0].Status)
	}
	if !containsString(apps[0].NetworkNeeds, "https://example.openai.azure.com") {
		t.Fatalf("dynamic Azure endpoint not surfaced in readmodel: %#v", apps[0].NetworkNeeds)
	}
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
