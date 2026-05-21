package plan

import "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"

type LaunchPlan struct {
	LaunchID                string                     `json:"launch_id"`
	AppID                   string                     `json:"app_id"`
	AppVersion              string                     `json:"app_version"`
	SubstrateID             string                     `json:"substrate_id"`
	Principal               string                     `json:"principal"`
	ArtifactImage           string                     `json:"artifact_image,omitempty"`
	ArtifactDigest          string                     `json:"artifact_digest,omitempty"`
	RuntimeCommand          []string                   `json:"runtime_command,omitempty"`
	Healthchecks            []registry.HealthcheckSpec `json:"healthchecks,omitempty"`
	ModelGatewayEnv         []string                   `json:"model_gateway_env,omitempty"`
	ModelGatewayMode        string                     `json:"model_gateway_mode,omitempty"`
	ModelGatewayProvider    string                     `json:"model_gateway_provider,omitempty"`
	RawProviderKeyProjected bool                       `json:"raw_provider_key_projected"`
	RiskClass               string                     `json:"risk_class"`
	PolicyHash              string                     `json:"policy_hash"`
	AppSpecHash             string                     `json:"app_spec_hash"`
	SubstrateSpecHash       string                     `json:"substrate_spec_hash"`
	SandboxProfileHash      string                     `json:"sandbox_profile_hash"`
	RequiredSecretRefs      []string                   `json:"required_secret_refs"`
	NetworkAllowlist        []string                   `json:"network_allowlist"`
	FilesystemMounts        []string                   `json:"filesystem_mounts"`
	StateDirEnv             string                     `json:"state_dir_env,omitempty"`
	MCPPolicy               registry.MCPPolicy         `json:"mcp_policy"`
	Budgets                 registry.BudgetCeiling     `json:"budgets"`
	Nodes                   map[string]any             `json:"nodes"`
	Edges                   []any                      `json:"edges"`
	TeardownPlan            map[string]any             `json:"teardown_plan"`
	EvidenceRequirements    []string                   `json:"evidence_requirements"`
	ActionIR                []ActionIR                 `json:"action_ir"`
	TeardownIR              []ActionIR                 `json:"teardown_ir"`
	CPIOutput               *CPIOutput                 `json:"cpi_output,omitempty"`
	KernelVerdict           string                     `json:"kernel_verdict"`
	Status                  string                     `json:"status"`
	ReasonCode              string                     `json:"reason_code,omitempty"`
	PlanHash                string                     `json:"plan_hash"`
}
