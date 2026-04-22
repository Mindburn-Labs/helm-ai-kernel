package config_test

import (
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/config"
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

	cfg := config.Load()

	assert.Equal(t, "8080", cfg.Port)
	assert.Equal(t, "INFO", cfg.LogLevel)
	assert.Contains(t, cfg.DatabaseURL, "localhost") // Default is local
	assert.False(t, cfg.ShadowMode)
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

	cfg := config.Load()

	assert.Equal(t, "9090", cfg.Port)
	assert.Equal(t, "DEBUG", cfg.LogLevel)
	assert.Equal(t, "postgres://production:5432/db", cfg.DatabaseURL)
	assert.True(t, cfg.ShadowMode)
	assert.Equal(t, "http://remote-llm:8080/v1", cfg.LLMServiceURL)
}
