package opensandbox

import (
	"strings"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts/actuators"
)

// runPreflightChecks performs all OpenSandbox-specific security checks.
// HELM requires all critical checks to pass before sandbox creation.
func runPreflightChecks(cfg Config) []actuators.PreflightCheck {
	var checks []actuators.PreflightCheck

	// Check 1: API key must be configured.
	// OpenSandbox server auth is optional if config is unset — HELM requires it.
	checks = append(checks, checkAPIKey(cfg))

	// Check 2: TLS must be enabled.
	checks = append(checks, checkTLS(cfg))

	// Check 3: Egress strict mode must be active.
	// OpenSandbox egress sidecar can degrade to Layer-1-only if net_admin is missing.
	checks = append(checks, checkEgressStrictMode(cfg))

	// Check 4: Base URL must be configured.
	checks = append(checks, checkBaseURL(cfg))

	return checks
}

func checkAPIKey(cfg Config) actuators.PreflightCheck {
	check := actuators.PreflightCheck{
		Name:     "api_key_configured",
		Required: true,
	}
	if cfg.APIKey == "" {
		check.Passed = false
		check.Reason = "OpenSandbox API key is not configured; server auth is optional by default but HELM requires it"
	} else {
		check.Passed = true
		check.Reason = "API key is set"
	}
	return check
}

func checkTLS(cfg Config) actuators.PreflightCheck {
	check := actuators.PreflightCheck{
		Name:     "tls_enabled",
		Required: cfg.TLSRequired,
	}
	if cfg.TLSRequired && cfg.BaseURL != "" && !strings.HasPrefix(cfg.BaseURL, "https://") {
		check.Passed = false
		check.Reason = "TLS is required but base URL does not use https://"
	} else {
		check.Passed = true
		check.Reason = "TLS check passed"
	}
	return check
}

func checkEgressStrictMode(cfg Config) actuators.PreflightCheck {
	check := actuators.PreflightCheck{
		Name:     "egress_strict_mode",
		Required: true,
	}
	if !cfg.EgressStrictMode {
		check.Passed = false
		check.Reason = "egress strict mode is disabled; OpenSandbox egress sidecar may degrade to Layer-1-only without net_admin capability"
	} else {
		check.Passed = true
		check.Reason = "egress strict mode is enabled"
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
		check.Reason = "OpenSandbox base URL is not configured"
	} else {
		check.Passed = true
		check.Reason = "base URL is set"
	}
	return check
}
