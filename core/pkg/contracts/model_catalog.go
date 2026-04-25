// Package contracts provides model routing example metadata.
//
// The OSS repository keeps provider-neutral examples here so public code does
// not drift with commercial provider release cycles. Deployments that need a
// live provider catalog should generate one from verified source metadata.
package contracts

// KnownModelProviders returns provider-neutral examples for routing tests and
// schema demonstrations.
func KnownModelProviders() []ModelProvider {
	return []ModelProvider{
		{
			ProviderID:   "example:frontier-reasoning",
			Name:         "Example Frontier Reasoning Model",
			Capabilities: []string{"TEXT", "CODE", "REASONING", "TOOL_USE"},
			Regions:      []string{"US", "EU"},
			RiskTier:     "LOW",
			MaxTokens:    200000,
			CostPerMTok:  10.0,
			Latency95th:  2500,
			Active:       true,
		},
		{
			ProviderID:   "example:vision-tool",
			Name:         "Example Vision Tool Model",
			Capabilities: []string{"TEXT", "VISION", "TOOL_USE"},
			Regions:      []string{"US", "EU", "APAC"},
			RiskTier:     "LOW",
			MaxTokens:    128000,
			CostPerMTok:  5.0,
			Latency95th:  2000,
			Active:       true,
		},
		{
			ProviderID:   "example:local-open-weight",
			Name:         "Example Local Open Weight Model",
			Capabilities: []string{"TEXT", "CODE"},
			Regions:      []string{"LOCAL"},
			RiskTier:     "MEDIUM",
			MaxTokens:    32768,
			CostPerMTok:  0.0,
			Latency95th:  1000,
			Active:       true,
		},
	}
}

// KnownModelProvidersByID returns the catalog indexed by ProviderID.
func KnownModelProvidersByID() map[string]ModelProvider {
	providers := KnownModelProviders()
	m := make(map[string]ModelProvider, len(providers))
	for _, p := range providers {
		m[p.ProviderID] = p
	}
	return m
}
