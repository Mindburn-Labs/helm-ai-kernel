// Package contracts — Model routing contracts.
//
// Per HELM 2030 Spec §6.1.3:
//
//	OSS MUST include model routing contracts for provider abstraction,
//	fallback chains, and third-party model attestation.
//
// Resolves: GAP-A22.
package contracts

import "time"

// ModelProvider describes a model provider and its capabilities.
type ModelProvider struct {
	ProviderID   string   `json:"provider_id"`
	Name         string   `json:"name"`
	Capabilities []string `json:"capabilities"` // "TEXT", "CODE", "VISION", "EMBEDDING"
	Regions      []string `json:"regions"`
	RiskTier     string   `json:"risk_tier"` // "LOW", "MEDIUM", "HIGH", "CRITICAL"
	MaxTokens    int      `json:"max_tokens,omitempty"`
	CostPerMTok  float64  `json:"cost_per_million_tokens,omitempty"`
	Latency95th  int      `json:"latency_p95_ms,omitempty"`
	Active       bool     `json:"active"`
}

// RoutingPolicy defines how models are selected for tasks.
type RoutingPolicy struct {
	PolicyID        string        `json:"policy_id"`
	Rules           []RoutingRule `json:"rules"`
	DefaultProvider string        `json:"default_provider"`
	FallbackChain   []string      `json:"fallback_chain"` // provider IDs in order
}

// RoutingRule maps a task type or context to allowed providers.
type RoutingRule struct {
	TaskType         string   `json:"task_type"` // "REASONING", "CODE_GEN", "CLASSIFICATION", etc.
	AllowedProviders []string `json:"allowed_providers"`
	MaxRiskTier      string   `json:"max_risk_tier"`
	RequiredRegions  []string `json:"required_regions,omitempty"`
	MaxCostPerMTok   float64  `json:"max_cost_per_million_tokens,omitempty"`
}

// ModelRouter selects a model provider given a task context.
type ModelRouter interface {
	Route(req ModelRouteRequest) (*ModelRouteResult, error)
	ListProviders() ([]ModelProvider, error)
}

// ModelRouteRequest is a request to select a model provider.
type ModelRouteRequest struct {
	TaskType          string `json:"task_type"`
	Region            string `json:"region,omitempty"`
	MaxRiskTier       string `json:"max_risk_tier,omitempty"`
	PreferredProvider string `json:"preferred_provider,omitempty"`
}

// ModelRouteResult is the selected provider and routing metadata.
type ModelRouteResult struct {
	ProviderID   string `json:"provider_id"`
	ProviderName string `json:"provider_name"`
	SelectedBy   string `json:"selected_by"` // "RULE", "FALLBACK", "DEFAULT"
	RuleID       string `json:"rule_id,omitempty"`
}

// ModelAttestation is a third-party attestation about a model.
type ModelAttestation struct {
	AttestationID string    `json:"attestation_id"`
	ProviderID    string    `json:"provider_id"`
	ModelName     string    `json:"model_name"`
	Attester      string    `json:"attester"` // who attests
	Claims        []string  `json:"claims"`   // "SAFE", "EVALUATED", "CERTIFIED"
	ValidFrom     time.Time `json:"valid_from"`
	ValidUntil    time.Time `json:"valid_until"`
	EvidenceHash  string    `json:"evidence_hash"`
	Signature     string    `json:"signature,omitempty"`
}
