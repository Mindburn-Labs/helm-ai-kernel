package config

import (
	"fmt"
	"os"
	"strings"
)

const defaultAgentSafetyBaselineBundleID = "builtin-agent-safety-baseline"

// Config holds server configuration.
type Config struct {
	Port          string
	LogLevel      string
	DatabaseURL   string
	LLMServiceURL string
	ShadowMode    bool
	AgentSafety   AgentSafetyProfile
}

// AgentSafetyProfile is the fail-closed baseline policy posture used by core.
type AgentSafetyProfile struct {
	BaselinePolicyEnabled           bool
	BaselineBundleID                string
	DenyUnknownTools                bool
	DenyUnknownEgress               bool
	RequireManifestValidation       bool
	RequireOutputContractValidation bool
	RequireApprovedArgBinding       bool
	LKSMemoryInfluenceOnly          bool
	RequireA2ASignatures            bool
	EnforceSafeDepGates             bool
	EnforceBudgetCircuitBreakers    bool
	FailClosedOnMissingContext      bool
	ShadowModeObservesOnly          bool
}

// DefaultAgentSafetyProfile returns the production-safe baseline.
func DefaultAgentSafetyProfile() AgentSafetyProfile {
	return AgentSafetyProfile{
		BaselinePolicyEnabled:           true,
		BaselineBundleID:                defaultAgentSafetyBaselineBundleID,
		DenyUnknownTools:                true,
		DenyUnknownEgress:               true,
		RequireManifestValidation:       true,
		RequireOutputContractValidation: true,
		RequireApprovedArgBinding:       true,
		LKSMemoryInfluenceOnly:          true,
		RequireA2ASignatures:            true,
		EnforceSafeDepGates:             true,
		EnforceBudgetCircuitBreakers:    true,
		FailClosedOnMissingContext:      true,
		ShadowModeObservesOnly:          true,
	}
}

// Validate rejects unsafe production profiles. Shadow mode may observe without
// enforcement, but it does not turn missing safety posture into an allow path.
func (p AgentSafetyProfile) Validate(shadowMode bool) error {
	if strings.TrimSpace(p.BaselineBundleID) == "" {
		return fmt.Errorf("agent safety baseline bundle id is required")
	}
	if shadowMode {
		return nil
	}
	required := map[string]bool{
		"baseline_policy_enabled":            p.BaselinePolicyEnabled,
		"deny_unknown_tools":                 p.DenyUnknownTools,
		"deny_unknown_egress":                p.DenyUnknownEgress,
		"require_manifest_validation":        p.RequireManifestValidation,
		"require_output_contract_validation": p.RequireOutputContractValidation,
		"require_approved_arg_binding":       p.RequireApprovedArgBinding,
		"lks_memory_influence_only":          p.LKSMemoryInfluenceOnly,
		"require_a2a_signatures":             p.RequireA2ASignatures,
		"enforce_safedep_gates":              p.EnforceSafeDepGates,
		"enforce_budget_circuit_breakers":    p.EnforceBudgetCircuitBreakers,
		"fail_closed_on_missing_context":     p.FailClosedOnMissingContext,
	}
	for name, enabled := range required {
		if !enabled {
			return fmt.Errorf("agent safety profile disables %s outside shadow mode", name)
		}
	}
	return nil
}

// HardenForRuntime restores fail-closed guards when shadow mode is not active.
func (p AgentSafetyProfile) HardenForRuntime(shadowMode bool) AgentSafetyProfile {
	if strings.TrimSpace(p.BaselineBundleID) == "" {
		p.BaselineBundleID = defaultAgentSafetyBaselineBundleID
	}
	if shadowMode {
		return p
	}
	defaults := DefaultAgentSafetyProfile()
	p.BaselinePolicyEnabled = p.BaselinePolicyEnabled || defaults.BaselinePolicyEnabled
	p.DenyUnknownTools = p.DenyUnknownTools || defaults.DenyUnknownTools
	p.DenyUnknownEgress = p.DenyUnknownEgress || defaults.DenyUnknownEgress
	p.RequireManifestValidation = p.RequireManifestValidation || defaults.RequireManifestValidation
	p.RequireOutputContractValidation = p.RequireOutputContractValidation || defaults.RequireOutputContractValidation
	p.RequireApprovedArgBinding = p.RequireApprovedArgBinding || defaults.RequireApprovedArgBinding
	p.LKSMemoryInfluenceOnly = p.LKSMemoryInfluenceOnly || defaults.LKSMemoryInfluenceOnly
	p.RequireA2ASignatures = p.RequireA2ASignatures || defaults.RequireA2ASignatures
	p.EnforceSafeDepGates = p.EnforceSafeDepGates || defaults.EnforceSafeDepGates
	p.EnforceBudgetCircuitBreakers = p.EnforceBudgetCircuitBreakers || defaults.EnforceBudgetCircuitBreakers
	p.FailClosedOnMissingContext = p.FailClosedOnMissingContext || defaults.FailClosedOnMissingContext
	p.ShadowModeObservesOnly = p.ShadowModeObservesOnly || defaults.ShadowModeObservesOnly
	return p
}

// Load loads configuration from environment variables.
func Load() *Config {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "INFO"
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		// Default to local generic postgres
		dbURL = "postgres://helm@localhost:5433/helm?sslmode=disable"
	}

	llmURL := os.Getenv("LLM_SERVICE_URL")
	if llmURL == "" {
		// Default to LM Studio Local
		llmURL = "http://host.docker.internal:1234/v1/chat/completions"
	}

	shadowMode := os.Getenv("SHADOW_MODE") == "true"
	agentSafety := loadAgentSafetyProfile().HardenForRuntime(shadowMode)

	return &Config{
		Port:          port,
		LogLevel:      logLevel,
		DatabaseURL:   dbURL,
		LLMServiceURL: llmURL,
		ShadowMode:    shadowMode,
		AgentSafety:   agentSafety,
	}
}

func loadAgentSafetyProfile() AgentSafetyProfile {
	profile := DefaultAgentSafetyProfile()
	if bundleID := strings.TrimSpace(os.Getenv("HELM_AGENT_SAFETY_BASELINE_BUNDLE_ID")); bundleID != "" {
		profile.BaselineBundleID = bundleID
	}
	profile.BaselinePolicyEnabled = envBoolDefaultTrue("HELM_AGENT_SAFETY_BASELINE_ENABLED")
	profile.DenyUnknownTools = envBoolDefaultTrue("HELM_AGENT_SAFETY_DENY_UNKNOWN_TOOLS")
	profile.DenyUnknownEgress = envBoolDefaultTrue("HELM_AGENT_SAFETY_DENY_UNKNOWN_EGRESS")
	profile.RequireManifestValidation = envBoolDefaultTrue("HELM_AGENT_SAFETY_REQUIRE_MANIFEST_VALIDATION")
	profile.RequireOutputContractValidation = envBoolDefaultTrue("HELM_AGENT_SAFETY_REQUIRE_OUTPUT_CONTRACT_VALIDATION")
	profile.RequireApprovedArgBinding = envBoolDefaultTrue("HELM_AGENT_SAFETY_REQUIRE_APPROVED_ARG_BINDING")
	profile.LKSMemoryInfluenceOnly = envBoolDefaultTrue("HELM_AGENT_SAFETY_LKS_INFLUENCE_ONLY")
	profile.RequireA2ASignatures = envBoolDefaultTrue("HELM_AGENT_SAFETY_REQUIRE_A2A_SIGNATURES")
	profile.EnforceSafeDepGates = envBoolDefaultTrue("HELM_AGENT_SAFETY_ENFORCE_SAFEDEP_GATES")
	profile.EnforceBudgetCircuitBreakers = envBoolDefaultTrue("HELM_AGENT_SAFETY_ENFORCE_BUDGET_CIRCUIT_BREAKERS")
	profile.FailClosedOnMissingContext = envBoolDefaultTrue("HELM_AGENT_SAFETY_FAIL_CLOSED_ON_MISSING_CONTEXT")
	profile.ShadowModeObservesOnly = envBoolDefaultTrue("HELM_AGENT_SAFETY_SHADOW_MODE_OBSERVES_ONLY")
	return profile
}

func envBoolDefaultTrue(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "0", "false", "no", "off", "disabled":
		return false
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return true
	}
}
