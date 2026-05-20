package claudemanaged

import (
	"net/url"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/actuators"
)

func runPreflightChecks(cfg Config) []actuators.PreflightCheck {
	return []actuators.PreflightCheck{
		checkWorkerIdentity(cfg),
		checkWorkerImageDigest(cfg),
		checkSkillManifest(cfg),
		checkEnvironmentKey(cfg),
		checkNoOrgAPIKey(cfg),
		checkEgress(cfg),
		checkLogRetention(cfg),
		checkWorkspaceRoots(cfg),
		checkTLS(cfg),
		checkMCPGateway(cfg),
	}
}

func checkWorkerIdentity(cfg Config) actuators.PreflightCheck {
	check := requiredCheck("worker_identity")
	if cfg.WorkerID == "" {
		check.Reason = "worker identity is missing"
		return check
	}
	check.Passed = true
	check.Reason = "worker identity is configured"
	return check
}

func checkWorkerImageDigest(cfg Config) actuators.PreflightCheck {
	check := requiredCheck("worker_image_digest")
	if !strings.HasPrefix(cfg.WorkerImageDigest, "sha256:") {
		check.Reason = "worker image digest must be pinned as sha256:<hex>"
		return check
	}
	check.Passed = true
	check.Reason = "worker image digest is pinned"
	return check
}

func checkSkillManifest(cfg Config) actuators.PreflightCheck {
	check := requiredCheck("skill_manifest_pinned")
	if !cfg.SkillsPinned || !strings.HasPrefix(cfg.SkillManifestHash, "sha256:") {
		check.Reason = "agent skills must be pinned by manifest hash"
		return check
	}
	check.Passed = true
	check.Reason = "skill manifest is pinned"
	return check
}

func checkEnvironmentKey(cfg Config) actuators.PreflightCheck {
	check := requiredCheck("environment_key_secret")
	if !cfg.EnvironmentKeyConfigured {
		check.Reason = "ANTHROPIC_ENVIRONMENT_KEY is not configured"
		return check
	}
	if !cfg.EnvironmentKeyFromSecretStore {
		check.Reason = "ANTHROPIC_ENVIRONMENT_KEY must come from a secrets manager"
		return check
	}
	check.Passed = true
	check.Reason = "environment key is configured through a secret store"
	return check
}

func checkNoOrgAPIKey(cfg Config) actuators.PreflightCheck {
	check := requiredCheck("org_api_key_absent")
	if cfg.OrganizationAPIKeyPresent {
		check.Reason = "organization-scoped ANTHROPIC_API_KEY must not be present on worker host"
		return check
	}
	check.Passed = true
	check.Reason = "organization API key is absent from worker"
	return check
}

func checkEgress(cfg Config) actuators.PreflightCheck {
	check := requiredCheck("egress_enforced")
	if !cfg.EgressEnforced {
		check.Reason = "network egress enforcement is disabled"
		return check
	}
	check.Passed = true
	check.Reason = "network egress enforcement is enabled"
	return check
}

func checkLogRetention(cfg Config) actuators.PreflightCheck {
	check := requiredCheck("log_retention_enabled")
	if !cfg.LogRetentionEnabled {
		check.Reason = "worker log retention is disabled"
		return check
	}
	check.Passed = true
	check.Reason = "worker log retention is enabled"
	return check
}

func checkWorkspaceRoots(cfg Config) actuators.PreflightCheck {
	check := requiredCheck("workspace_roots_configured")
	if cfg.WorkspaceRoot == "" || cfg.OutputsRoot == "" {
		check.Reason = "workspace and output roots must be configured"
		return check
	}
	check.Passed = true
	check.Reason = "workspace and output roots are configured"
	return check
}

func checkTLS(cfg Config) actuators.PreflightCheck {
	check := requiredCheck("tls_required_for_remote_endpoint")
	if cfg.RemoteEndpoint == "" {
		check.Passed = true
		check.Reason = "no remote endpoint configured"
		return check
	}
	parsed, err := url.Parse(cfg.RemoteEndpoint)
	if err != nil || parsed.Scheme == "" {
		check.Reason = "remote endpoint URL is invalid"
		return check
	}
	if cfg.TLSRequired && parsed.Scheme != "https" {
		check.Reason = "remote endpoint must use HTTPS when TLS is required"
		return check
	}
	check.Passed = true
	check.Reason = "remote endpoint TLS posture is acceptable"
	return check
}

func checkMCPGateway(cfg Config) actuators.PreflightCheck {
	check := requiredCheck("mcp_tunnel_routes_to_helm_gateway")
	if cfg.AllowRawMCPTunnelTargets {
		check.Reason = "raw MCP tunnel targets bypass HELM MCP Gateway"
		return check
	}
	if !cfg.Tunnel.Enabled {
		check.Passed = true
		check.Reason = "no MCP tunnel configured"
		return check
	}
	if cfg.MCPGatewayURL == "" || !cfg.Tunnel.RouteThroughHELMGateway {
		check.Reason = "MCP tunnels must route through HELM MCP Gateway"
		return check
	}
	if cfg.Tunnel.TunnelDomainHash == "" ||
		cfg.Tunnel.UpstreamMCPServerID == "" ||
		cfg.Tunnel.OAuthResource == "" ||
		cfg.Tunnel.ProtocolVersion == "" ||
		cfg.Tunnel.CACertRefHash == "" ||
		cfg.Tunnel.AllowedUpstreamHostHash == "" {
		check.Reason = "MCP tunnel evidence fields are incomplete"
		return check
	}
	if len(cfg.Tunnel.RequiredScopes) == 0 {
		check.Reason = "MCP tunnel required scopes are missing"
		return check
	}
	check.Passed = true
	check.Reason = "MCP tunnel routes through HELM gateway with evidence fields"
	return check
}

func requiredCheck(name string) actuators.PreflightCheck {
	return actuators.PreflightCheck{Name: name, Required: true}
}
