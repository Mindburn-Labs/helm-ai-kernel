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

func TestKnownModelProviders_FrontierModelsPresent(t *testing.T) {
	byID := KnownModelProvidersByID()

	required := []string{
		"openai:gpt-5.4",
		"google:gemini-3-pro",
		"anthropic:claude-opus-4-6",
		"anthropic:claude-sonnet-4-6",
		"ibm:granite-4.0-3b-vision",
		"qwen:qwen-3.6-plus",
	}

	for _, id := range required {
		if _, ok := byID[id]; !ok {
			t.Errorf("missing required frontier model: %s", id)
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

func TestKnownModelProviders_GPT54HasToolUse(t *testing.T) {
	byID := KnownModelProvidersByID()
	gpt54 := byID["openai:gpt-5.4"]

	hasToolUse := false
	for _, cap := range gpt54.Capabilities {
		if cap == "TOOL_USE" {
			hasToolUse = true
			break
		}
	}
	if !hasToolUse {
		t.Error("GPT-5.4 should have TOOL_USE capability")
	}
}

func TestKnownModelProviders_Gemini3ProHas2MContext(t *testing.T) {
	byID := KnownModelProvidersByID()
	gemini := byID["google:gemini-3-pro"]

	if gemini.MaxTokens < 2000000 {
		t.Errorf("Gemini 3 Pro should have 2M+ context, got %d", gemini.MaxTokens)
	}
}
