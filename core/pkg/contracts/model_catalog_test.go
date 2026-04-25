package contracts

import (
	"testing"
)

func TestKnownModelProviders_NonEmpty(t *testing.T) {
	providers := KnownModelProviders()
	if len(providers) == 0 {
		t.Fatal("expected non-empty model catalog")
	}
}

func TestKnownModelProviders_AllHaveRequiredFields(t *testing.T) {
	for _, p := range KnownModelProviders() {
		if p.ProviderID == "" {
			t.Errorf("provider missing ProviderID: %+v", p)
		}
		if p.Name == "" {
			t.Errorf("provider %s missing Name", p.ProviderID)
		}
		if len(p.Capabilities) == 0 {
			t.Errorf("provider %s missing Capabilities", p.ProviderID)
		}
		if len(p.Regions) == 0 {
			t.Errorf("provider %s missing Regions", p.ProviderID)
		}
		if p.RiskTier == "" {
			t.Errorf("provider %s missing RiskTier", p.ProviderID)
		}
		if p.MaxTokens <= 0 {
			t.Errorf("provider %s has invalid MaxTokens: %d", p.ProviderID, p.MaxTokens)
		}
	}
}

func TestKnownModelProviders_StableExampleModelsPresent(t *testing.T) {
	byID := KnownModelProvidersByID()

	required := []string{
		"example:frontier-reasoning",
		"example:vision-tool",
		"example:local-open-weight",
	}

	for _, id := range required {
		if _, ok := byID[id]; !ok {
			t.Errorf("missing required example model: %s", id)
		}
	}
}

func TestKnownModelProvidersByID_Unique(t *testing.T) {
	providers := KnownModelProviders()
	byID := KnownModelProvidersByID()

	if len(byID) != len(providers) {
		t.Fatalf("duplicate ProviderIDs: %d providers but %d unique IDs", len(providers), len(byID))
	}
}

func TestKnownModelProviders_AllActive(t *testing.T) {
	for _, p := range KnownModelProviders() {
		if !p.Active {
			t.Errorf("provider %s is not active in catalog — remove or activate", p.ProviderID)
		}
	}
}

func TestKnownModelProviders_ReasoningExampleHasToolUse(t *testing.T) {
	byID := KnownModelProvidersByID()
	model := byID["example:frontier-reasoning"]

	hasToolUse := false
	for _, cap := range model.Capabilities {
		if cap == "TOOL_USE" {
			hasToolUse = true
			break
		}
	}
	if !hasToolUse {
		t.Error("frontier reasoning example should have TOOL_USE capability")
	}
}

func TestKnownModelProviders_ExamplesAvoidCurrentProviderClaims(t *testing.T) {
	byID := KnownModelProvidersByID()
	for id := range byID {
		if id == "openai:gpt-5.4" || id == "google:gemini-3-pro" || id == "anthropic:claude-opus-4-6" {
			t.Fatalf("catalog must not contain current-provider claim %s", id)
		}
	}
}
