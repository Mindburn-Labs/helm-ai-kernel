package modelproviders

import "testing"

func TestDefaultCatalogCoversUSEUAndChina(t *testing.T) {
	catalog, err := DefaultCatalog()
	if err != nil {
		t.Fatalf("DefaultCatalog: %v", err)
	}
	regions := map[string]bool{}
	for _, provider := range catalog.Providers {
		for _, region := range provider.Regions {
			regions[region] = true
		}
	}
	for _, region := range []string{"US", "EU", "CN"} {
		if !regions[region] {
			t.Fatalf("catalog missing region %s", region)
		}
	}
}

func TestValidateAllowlistAllowsRegisteredProviders(t *testing.T) {
	allowlist := []string{
		"https://api.openai.com/v1",
		"https://api.anthropic.com/v1/messages",
		"https://api.mistral.ai/v1/chat/completions",
		"https://api.deepseek.com/chat/completions",
		"https://open.bigmodel.cn/api/paas/v4/chat/completions",
	}
	if err := ValidateAllowlist(allowlist); err != nil {
		t.Fatalf("registered provider allowlist rejected: %v", err)
	}
}

func TestValidateAllowlistRejectsUnregisteredDestination(t *testing.T) {
	if err := ValidateAllowlist([]string{"https://example.com/v1"}); err == nil {
		t.Fatal("expected unregistered destination to be rejected")
	}
}

func TestCatalogExpandsProviderEnvAndBaseURLs(t *testing.T) {
	catalog, err := DefaultCatalog()
	if err != nil {
		t.Fatalf("DefaultCatalog: %v", err)
	}
	envNames, err := catalog.EnvNamesForProviderIDs([]string{"openai", "anthropic"})
	if err != nil {
		t.Fatalf("EnvNamesForProviderIDs: %v", err)
	}
	if !contains(envNames, "OPENAI_API_KEY") || !contains(envNames, "ANTHROPIC_API_KEY") {
		t.Fatalf("provider env names not expanded: %#v", envNames)
	}
	baseURLs, err := catalog.BaseURLsForProviderIDs([]string{"openai", "anthropic"})
	if err != nil {
		t.Fatalf("BaseURLsForProviderIDs: %v", err)
	}
	if !contains(baseURLs, "https://api.openai.com/v1") || !contains(baseURLs, "https://api.anthropic.com/v1") {
		t.Fatalf("provider base URLs not expanded: %#v", baseURLs)
	}
}

func TestCatalogSupportsDynamicProviderEnvGroupsAndEndpoints(t *testing.T) {
	catalog, err := DefaultCatalog()
	if err != nil {
		t.Fatalf("DefaultCatalog: %v", err)
	}
	envGroups, err := catalog.EnvGroupsForProviderIDs([]string{"azure-openai"})
	if err != nil {
		t.Fatalf("EnvGroupsForProviderIDs: %v", err)
	}
	if len(envGroups) != 1 || !contains(envGroups[0], "AZURE_OPENAI_API_KEY") || !contains(envGroups[0], "AZURE_OPENAI_ENDPOINT") {
		t.Fatalf("azure-openai required env group not exposed: %#v", envGroups)
	}
	baseURLs, err := catalog.BaseURLsForProviderIDsWithEnv([]string{"azure-openai"}, func(name string) (string, bool) {
		if name == "AZURE_OPENAI_ENDPOINT" {
			return "https://example.openai.azure.com/", true
		}
		return "", false
	})
	if err != nil {
		t.Fatalf("BaseURLsForProviderIDsWithEnv: %v", err)
	}
	if !contains(baseURLs, "https://example.openai.azure.com") {
		t.Fatalf("dynamic Azure endpoint not expanded: %#v", baseURLs)
	}
	if !catalog.Allows("https://example.openai.azure.com/openai/deployments/test") {
		t.Fatal("Azure OpenAI suffix endpoint should be allowed")
	}
	if catalog.Allows("https://example.azure.com/openai/deployments/test") {
		t.Fatal("non-Azure-OpenAI endpoint should not be allowed by suffix")
	}
}

func TestProviderRoutingMetadata(t *testing.T) {
	catalog, err := DefaultCatalog()
	if err != nil {
		t.Fatalf("DefaultCatalog: %v", err)
	}
	provider, ok := catalog.ProviderForEnv("YI_API_KEY")
	if !ok {
		t.Fatal("YI_API_KEY provider not found")
	}
	if provider.ID != "01-ai" {
		t.Fatalf("ProviderForEnv returned %s", provider.ID)
	}
	if provider.PreferredBaseURL() != "https://api.01.ai/v1" {
		t.Fatalf("PreferredBaseURL = %q", provider.PreferredBaseURL())
	}
	stepfun, ok := catalog.ProviderForEnv("STEP_API_KEY")
	if !ok {
		t.Fatal("STEP_API_KEY provider not found")
	}
	if !stepfun.HasProtocol("openai-compatible") || !stepfun.HasProtocol("anthropic-compatible") {
		t.Fatalf("stepfun protocols not exposed: %#v", stepfun.Protocols)
	}
	if stepfun.PreferredBaseURL() != "https://api.stepfun.ai/step_plan/v1" {
		t.Fatalf("stepfun PreferredBaseURL = %q", stepfun.PreferredBaseURL())
	}
}

func TestCatalogExposesCredentialAndProbeMetadata(t *testing.T) {
	catalog, err := DefaultCatalog()
	if err != nil {
		t.Fatalf("DefaultCatalog: %v", err)
	}
	azure, ok := catalog.ProviderForID("azure-ai-foundry")
	if !ok {
		t.Fatal("azure-ai-foundry provider not found")
	}
	if !contains(azure.CredentialEnv, "AZURE_INFERENCE_CREDENTIAL") {
		t.Fatalf("azure-ai-foundry credential env not exposed: %#v", azure.CredentialEnv)
	}
	if !contains(azure.BaseURLEnv, "AZURE_AI_FOUNDRY_ENDPOINT") || !contains(azure.BaseURLEnv, "AZURE_AI_INFERENCE_ENDPOINT") {
		t.Fatalf("azure-ai-foundry endpoint env not exposed: %#v", azure.BaseURLEnv)
	}
	githubModels, ok := catalog.ProviderForID("github-models")
	if !ok {
		t.Fatal("github-models provider not found")
	}
	if !contains(githubModels.ProbeURLs, "https://models.github.ai/catalog/models") {
		t.Fatalf("github-models probe URL not exposed: %#v", githubModels.ProbeURLs)
	}
}

func contains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
