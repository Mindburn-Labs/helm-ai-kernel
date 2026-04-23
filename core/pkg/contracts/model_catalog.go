// Package contracts — Known model catalog for HELM governance.
//
// Provides pre-defined ModelProvider entries for frontier models so that
// HELM components (AIBOM, routing, compliance) can reference them without
// hardcoding model metadata in multiple places.
//
// Update this catalog when new frontier models ship.
// Last updated: 2026-04-12 (GPT-5.4, Gemini 3 Pro, Claude Opus 4.6).
package contracts

// KnownModelProviders returns the catalog of known frontier model providers.
// Each entry provides governance-relevant metadata: capabilities, risk tier,
// context limits, and approximate cost.
func KnownModelProviders() []ModelProvider {
	return []ModelProvider{
		// ── Anthropic ──────────────────────────────────────────
		{
			ProviderID:   "anthropic:claude-opus-4-6",
			Name:         "Claude Opus 4.6",
			Capabilities: []string{"TEXT", "CODE", "VISION", "REASONING"},
			Regions:      []string{"US", "EU"},
			RiskTier:     "LOW",
			MaxTokens:    200000,
			CostPerMTok:  15.0,
			Latency95th:  3000,
			Active:       true,
		},
		{
			ProviderID:   "anthropic:claude-sonnet-4-6",
			Name:         "Claude Sonnet 4.6",
			Capabilities: []string{"TEXT", "CODE", "VISION", "REASONING"},
			Regions:      []string{"US", "EU"},
			RiskTier:     "LOW",
			MaxTokens:    200000,
			CostPerMTok:  3.0,
			Latency95th:  1500,
			Active:       true,
		},
		{
			ProviderID:   "anthropic:claude-haiku-4-5",
			Name:         "Claude Haiku 4.5",
			Capabilities: []string{"TEXT", "CODE", "VISION"},
			Regions:      []string{"US", "EU"},
			RiskTier:     "LOW",
			MaxTokens:    200000,
			CostPerMTok:  0.8,
			Latency95th:  800,
			Active:       true,
		},

		// ── OpenAI ────────────────────────────────────────────
		{
			ProviderID:   "openai:gpt-5.4",
			Name:         "GPT-5.4",
			Capabilities: []string{"TEXT", "CODE", "VISION", "REASONING", "TOOL_USE"},
			Regions:      []string{"US", "EU", "APAC"},
			RiskTier:     "LOW",
			MaxTokens:    256000,
			CostPerMTok:  10.0,
			Latency95th:  2500,
			Active:       true,
		},
		{
			ProviderID:   "openai:gpt-4o",
			Name:         "GPT-4o",
			Capabilities: []string{"TEXT", "CODE", "VISION", "TOOL_USE"},
			Regions:      []string{"US", "EU", "APAC"},
			RiskTier:     "LOW",
			MaxTokens:    128000,
			CostPerMTok:  5.0,
			Latency95th:  2000,
			Active:       true,
		},
		{
			ProviderID:   "openai:o3",
			Name:         "o3",
			Capabilities: []string{"TEXT", "CODE", "REASONING"},
			Regions:      []string{"US", "EU"},
			RiskTier:     "LOW",
			MaxTokens:    200000,
			CostPerMTok:  12.0,
			Latency95th:  5000,
			Active:       true,
		},

		// ── Google ────────────────────────────────────────────
		{
			ProviderID:   "google:gemini-3-pro",
			Name:         "Gemini 3 Pro",
			Capabilities: []string{"TEXT", "CODE", "VISION", "REASONING", "TOOL_USE"},
			Regions:      []string{"US", "EU", "APAC"},
			RiskTier:     "LOW",
			MaxTokens:    2000000,
			CostPerMTok:  7.0,
			Latency95th:  2000,
			Active:       true,
		},
		{
			ProviderID:   "google:gemini-2.5-flash",
			Name:         "Gemini 2.5 Flash",
			Capabilities: []string{"TEXT", "CODE", "VISION", "REASONING"},
			Regions:      []string{"US", "EU", "APAC"},
			RiskTier:     "LOW",
			MaxTokens:    1000000,
			CostPerMTok:  0.5,
			Latency95th:  600,
			Active:       true,
		},

		// ── Meta ──────────────────────────────────────────────
		{
			ProviderID:   "meta:llama-4-maverick",
			Name:         "Llama 4 Maverick",
			Capabilities: []string{"TEXT", "CODE", "REASONING"},
			Regions:      []string{"US", "EU", "APAC"},
			RiskTier:     "MEDIUM",
			MaxTokens:    1000000,
			CostPerMTok:  0.0, // Open-weight, self-hosted
			Latency95th:  1000,
			Active:       true,
		},

		// ── Qwen ──────────────────────────────────────────────
		{
			ProviderID:   "qwen:qwen-3.6-plus",
			Name:         "Qwen 3.6 Plus",
			Capabilities: []string{"TEXT", "CODE", "VISION", "REASONING"},
			Regions:      []string{"APAC", "US", "EU"},
			RiskTier:     "MEDIUM",
			MaxTokens:    1048576,
			CostPerMTok:  0.0,
			Latency95th:  1200,
			Active:       true,
		},

		// ── IBM ───────────────────────────────────────────────
		{
			ProviderID:   "ibm:granite-4.0-3b-vision",
			Name:         "IBM Granite 4.0 3B Vision",
			Capabilities: []string{"TEXT", "VISION"},
			Regions:      []string{"US", "EU"},
			RiskTier:     "LOW",
			MaxTokens:    8192,
			CostPerMTok:  0.0,
			Latency95th:  400,
			Active:       true,
		},
	}
}

// KnownModelProvidersByID returns the catalog indexed by ProviderID for O(1) lookup.
func KnownModelProvidersByID() map[string]ModelProvider {
	providers := KnownModelProviders()
	m := make(map[string]ModelProvider, len(providers))
	for _, p := range providers {
		m[p.ProviderID] = p
	}
	return m
}
