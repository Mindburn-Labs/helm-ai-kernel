package daytona

import (
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts/actuators"
)

// runPreflightChecks performs Daytona-specific preflight checks.
func runPreflightChecks(cfg Config) []actuators.PreflightCheck {
	var checks []actuators.PreflightCheck

	// Check 1: API key must be configured.
	checks = append(checks, checkAPIKey(cfg))

	// Check 2: Base URL must be set.
	checks = append(checks, checkBaseURL(cfg))

	// Check 3: Workspace isolation should be enabled.
	checks = append(checks, checkWorkspaceIsolation(cfg))

	return checks
}

func checkAPIKey(cfg Config) actuators.PreflightCheck {
	check := actuators.PreflightCheck{
		Name:     "api_key_configured",
		Required: true,
	}
	if cfg.APIKey == "" {
		check.Passed = false
		check.Reason = "Daytona API key is not configured"
	} else {
		check.Passed = true
		check.Reason = "API key is set"
	}
	return check
}

func checkBaseURL(cfg Config) actuators.PreflightCheck {
	check := actuators.PreflightCheck{
		Name:     "base_url_configured",
		Required: true,
	}
	if cfg.BaseURL == "" {
		check.Passed = false
		check.Reason = "Daytona base URL is not configured"
	} else {
		check.Passed = true
		check.Reason = "base URL is set"
	}
	return check
}

func checkWorkspaceIsolation(cfg Config) actuators.PreflightCheck {
	check := actuators.PreflightCheck{
		Name:     "workspace_isolation",
		Required: true,
	}
	if !cfg.WorkspaceIsolation {
		check.Passed = false
		check.Reason = "workspace isolation is disabled; HELM requires sandboxes to run in isolated workspaces"
	} else {
		check.Passed = true
		check.Reason = "workspace isolation is enabled"
	}
	return check
}
