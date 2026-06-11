package daytona

import (
	"net"
	"net/url"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/actuators"
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
	} else if reason := validateSecureBaseURL(cfg.BaseURL, cfg.AllowInsecureLoopback); reason != "" {
		check.Passed = false
		check.Reason = reason
	} else {
		check.Passed = true
		check.Reason = "base URL is secure"
	}
	return check
}

func validateSecureBaseURL(raw string, allowInsecureLoopback bool) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return "base URL must be a valid absolute URL"
	}
	if parsed.User != nil {
		return "base URL must not include embedded credentials"
	}
	if parsed.Scheme == "https" {
		return ""
	}
	if parsed.Scheme == "http" && allowInsecureLoopback && isLoopbackHost(parsed.Hostname()) {
		return ""
	}
	return "base URL must use https; http is only allowed for explicitly enabled loopback tests"
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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
