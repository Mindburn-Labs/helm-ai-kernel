package e2b

import (
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts/actuators"
)

// runPreflightChecks performs E2B-specific preflight checks.
func runPreflightChecks(cfg Config) []actuators.PreflightCheck {
	var checks []actuators.PreflightCheck

	// Check 1: API key must be configured.
	checks = append(checks, checkAPIKey(cfg))

	// Check 2: API URL must be set.
	checks = append(checks, checkAPIURL(cfg))

	// Check 3: Template ID should be configured.
	checks = append(checks, checkTemplateID(cfg))

	// Check 4: Default timeout must be positive.
	checks = append(checks, checkTimeout(cfg))

	return checks
}

func checkAPIKey(cfg Config) actuators.PreflightCheck {
	check := actuators.PreflightCheck{
		Name:     "api_key_configured",
		Required: true,
	}
	if cfg.APIKey == "" {
		check.Passed = false
		check.Reason = "E2B API key is not configured"
	} else {
		check.Passed = true
		check.Reason = "API key is set"
	}
	return check
}

func checkAPIURL(cfg Config) actuators.PreflightCheck {
	check := actuators.PreflightCheck{
		Name:     "api_url_configured",
		Required: true,
	}
	if cfg.APIURL == "" {
		check.Passed = false
		check.Reason = "E2B API URL is not configured"
	} else {
		check.Passed = true
		check.Reason = "API URL is set"
	}
	return check
}

func checkTemplateID(cfg Config) actuators.PreflightCheck {
	check := actuators.PreflightCheck{
		Name:     "template_id_configured",
		Required: false, // Can be provided per-spec.
	}
	if cfg.TemplateID == "" {
		check.Passed = true // Not required in config.
		check.Reason = "template ID not set in config (will use per-spec runtime)"
	} else {
		check.Passed = true
		check.Reason = "template ID is set"
	}
	return check
}

func checkTimeout(cfg Config) actuators.PreflightCheck {
	check := actuators.PreflightCheck{
		Name:     "timeout_configured",
		Required: true,
	}
	if cfg.DefaultTimeout <= 0 {
		check.Passed = false
		check.Reason = "default timeout must be positive"
	} else {
		check.Passed = true
		check.Reason = "default timeout is set"
	}
	return check
}
