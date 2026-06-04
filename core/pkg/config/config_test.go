package config_test

import (
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/config"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/policybundles"
	"github.com/stretchr/testify/assert"
)

// TestLoad_Defaults verifies that Load() returns sensible defaults
// when no environment variables are set.
// Invariant: System must boot with safe defaults in dev mode.
func TestLoad_Defaults(t *testing.T) {
	// Ensure clean env
	t.Setenv("PORT", "")
	t.Setenv("LOG_LEVEL", "")
	t.Setenv("DATABASE_URL", "")
	t.Setenv("LLM_SERVICE_URL", "")
	t.Setenv("SHADOW_MODE", "")
	t.Setenv("HELM_AGENT_SAFETY_BASELINE_BUNDLE_ID", "")

	cfg := config.Load()

	assert.Equal(t, "8080", cfg.Port)
	assert.Equal(t, "INFO", cfg.LogLevel)
	assert.Contains(t, cfg.DatabaseURL, "localhost") // Default is local
	assert.False(t, cfg.ShadowMode)
	assert.True(t, cfg.AgentSafety.BaselinePolicyEnabled)
	assert.Equal(t, policybundles.AgentSafetyBaselineBundleID, cfg.AgentSafety.BaselineBundleID)
	assert.NoError(t, cfg.AgentSafety.Validate(cfg.ShadowMode))
}

// TestLoad_Overrides verifies that environment variables correctly
// override default values.
// Invariant: Ops can control config via standard 12-factor env vars.
func TestLoad_Overrides(t *testing.T) {
	t.Setenv("PORT", "9090")
	t.Setenv("LOG_LEVEL", "DEBUG")
	t.Setenv("DATABASE_URL", "postgres://production:5432/db")
	t.Setenv("LLM_SERVICE_URL", "http://remote-llm:8080/v1")
	t.Setenv("SHADOW_MODE", "true")
	t.Setenv("HELM_AGENT_SAFETY_BASELINE_BUNDLE_ID", "custom-agent-safety")
	t.Setenv("HELM_AGENT_SAFETY_DENY_UNKNOWN_TOOLS", "false")

	cfg := config.Load()

	assert.Equal(t, "9090", cfg.Port)
	assert.Equal(t, "DEBUG", cfg.LogLevel)
	assert.Equal(t, "postgres://production:5432/db", cfg.DatabaseURL)
	assert.True(t, cfg.ShadowMode)
	assert.Equal(t, "http://remote-llm:8080/v1", cfg.LLMServiceURL)
	assert.Equal(t, "custom-agent-safety", cfg.AgentSafety.BaselineBundleID)
	assert.False(t, cfg.AgentSafety.DenyUnknownTools)
	assert.NoError(t, cfg.AgentSafety.Validate(cfg.ShadowMode))
}

func TestAgentSafetyProfile_DefaultsFailClosed(t *testing.T) {
	profile := config.DefaultAgentSafetyProfile()

	assert.True(t, profile.BaselinePolicyEnabled)
	assert.True(t, profile.DenyUnknownTools)
	assert.True(t, profile.DenyUnknownEgress)
	assert.True(t, profile.RequireManifestValidation)
	assert.True(t, profile.RequireOutputContractValidation)
	assert.True(t, profile.RequireApprovedArgBinding)
	assert.True(t, profile.LKSMemoryInfluenceOnly)
	assert.True(t, profile.RequireA2ASignatures)
	assert.True(t, profile.EnforceSafeDepGates)
	assert.True(t, profile.EnforceBudgetCircuitBreakers)
	assert.True(t, profile.FailClosedOnMissingContext)
	assert.True(t, profile.ShadowModeObservesOnly)
	assert.NoError(t, profile.Validate(false))
}

func TestAgentSafetyProfile_RejectsUnsafeProductionOptOut(t *testing.T) {
	profile := config.DefaultAgentSafetyProfile()
	profile.RequireA2ASignatures = false

	assert.Error(t, profile.Validate(false))
	assert.NoError(t, profile.Validate(true))
}

func TestLoadAgentSafety_InvalidEnvFailsClosed(t *testing.T) {
	t.Setenv("HELM_AGENT_SAFETY_BASELINE_ENABLED", "maybe")
	t.Setenv("HELM_AGENT_SAFETY_DENY_UNKNOWN_EGRESS", "not-a-bool")

	cfg := config.Load()

	assert.True(t, cfg.AgentSafety.BaselinePolicyEnabled)
	assert.True(t, cfg.AgentSafety.DenyUnknownEgress)
	assert.NoError(t, cfg.AgentSafety.Validate(false))
}

func TestLoadAgentSafety_UnsafeProductionOptOutIsHardened(t *testing.T) {
	t.Setenv("SHADOW_MODE", "")
	t.Setenv("HELM_AGENT_SAFETY_BASELINE_ENABLED", "false")
	t.Setenv("HELM_AGENT_SAFETY_REQUIRE_A2A_SIGNATURES", "false")
	t.Setenv("HELM_AGENT_SAFETY_FAIL_CLOSED_ON_MISSING_CONTEXT", "false")

	cfg := config.Load()

	assert.True(t, cfg.AgentSafety.BaselinePolicyEnabled)
	assert.True(t, cfg.AgentSafety.RequireA2ASignatures)
	assert.True(t, cfg.AgentSafety.FailClosedOnMissingContext)
	assert.NoError(t, cfg.AgentSafety.Validate(false))
}
