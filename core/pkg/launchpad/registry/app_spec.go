package registry

type Availability string

const (
	AvailabilityOSSSupported               Availability = "oss_supported"
	AvailabilityOSSCandidate               Availability = "oss_candidate"
	AvailabilityExternalProprietaryAdapter Availability = "external_proprietary_adapter"
	AvailabilityBlockedLicense             Availability = "blocked_license"
	AvailabilityBlockedConformance         Availability = "blocked_conformance"
)

type AppSpec struct {
	ID                   string                  `json:"id" yaml:"id"`
	Name                 string                  `json:"name" yaml:"name"`
	Version              string                  `json:"version" yaml:"version"`
	License              LicenseSpec             `json:"license" yaml:"license"`
	Redistribution       string                  `json:"redistribution" yaml:"redistribution"`
	Availability         Availability            `json:"availability" yaml:"availability"`
	Install              InstallSpec             `json:"install" yaml:"install"`
	Runtime              RuntimeSpec             `json:"runtime" yaml:"runtime"`
	ModelGateway         ModelGatewaySpec        `json:"model_gateway,omitempty" yaml:"model_gateway,omitempty"`
	ModelGatewayEnv      []string                `json:"model_gateway_env" yaml:"model_gateway_env"`
	RequiredSecrets      []string                `json:"required_secrets" yaml:"required_secrets"`
	FilesystemPolicy     PolicyRef               `json:"filesystem_policy" yaml:"filesystem_policy"`
	NetworkPolicy        NetworkPolicy           `json:"network_policy" yaml:"network_policy"`
	MCPPolicy            MCPPolicy               `json:"mcp_policy" yaml:"mcp_policy"`
	MCPManifests         []string                `json:"mcp_manifests,omitempty" yaml:"mcp_manifests,omitempty"`
	Healthchecks         []HealthcheckSpec       `json:"healthchecks" yaml:"healthchecks"`
	RiskClass            string                  `json:"risk_class" yaml:"risk_class"`
	BudgetCeiling        BudgetCeiling           `json:"budget_ceiling" yaml:"budget_ceiling"`
	EvidenceRequirements []string                `json:"evidence_requirements" yaml:"evidence_requirements"`
	SupplyChainEvidence  SupplyChainEvidenceSpec `json:"supply_chain_evidence,omitempty" yaml:"supply_chain_evidence,omitempty"`
	PromotionEvidence    PromotionEvidenceSpec   `json:"promotion_evidence,omitempty" yaml:"promotion_evidence,omitempty"`
	Conformance          ConformanceSpec         `json:"conformance" yaml:"conformance"`
	Metadata             map[string]string       `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

type LicenseSpec struct {
	Status string `json:"status" yaml:"status"`
	SPDX   string `json:"spdx,omitempty" yaml:"spdx,omitempty"`
	URL    string `json:"url,omitempty" yaml:"url,omitempty"`
}

type InstallSpec struct {
	Strategy string `json:"strategy" yaml:"strategy"`
	Image    string `json:"image,omitempty" yaml:"image,omitempty"`
	Digest   string `json:"digest,omitempty" yaml:"digest,omitempty"`
	Source   string `json:"source,omitempty" yaml:"source,omitempty"`
	Ref      string `json:"ref,omitempty" yaml:"ref,omitempty"`
}

type RuntimeSpec struct {
	Command []string `json:"command" yaml:"command"`
	Ports   []int    `json:"ports,omitempty" yaml:"ports,omitempty"`
}

type ModelGatewaySpec struct {
	LogicalSecret           string `json:"logical_secret,omitempty" yaml:"logical_secret,omitempty"`
	Provider                string `json:"provider,omitempty" yaml:"provider,omitempty"`
	Mode                    string `json:"mode,omitempty" yaml:"mode,omitempty"`
	RawProviderKeyProjected bool   `json:"raw_provider_key_projected" yaml:"raw_provider_key_projected"`
}

type PolicyRef struct {
	Mode      string   `json:"mode" yaml:"mode"`
	Mounts    []string `json:"mounts,omitempty" yaml:"mounts,omitempty"`
	PolicyRef string   `json:"policy_ref,omitempty" yaml:"policy_ref,omitempty"`
}

type NetworkPolicy struct {
	Default   string   `json:"default" yaml:"default"`
	Allowlist []string `json:"allowlist,omitempty" yaml:"allowlist,omitempty"`
}

type MCPPolicy struct {
	UnknownServerPolicy string `json:"unknown_server_policy" yaml:"unknown_server_policy"`
	UnknownToolPolicy   string `json:"unknown_tool_policy" yaml:"unknown_tool_policy"`
	RequireSchemaPin    bool   `json:"require_schema_pin" yaml:"require_schema_pin"`
}

type MCPServerManifest struct {
	ID               string            `json:"id" yaml:"id"`
	AppID            string            `json:"app_id" yaml:"app_id"`
	ServerID         string            `json:"server_id" yaml:"server_id"`
	Transport        string            `json:"transport" yaml:"transport"`
	Command          []string          `json:"command,omitempty" yaml:"command,omitempty"`
	PackageDigest    string            `json:"package_digest" yaml:"package_digest"`
	SignatureRef     string            `json:"signature_ref" yaml:"signature_ref"`
	SchemaHash       string            `json:"schema_hash" yaml:"schema_hash"`
	Tools            []MCPToolManifest `json:"tools" yaml:"tools"`
	EffectLabels     []string          `json:"effect_labels,omitempty" yaml:"effect_labels,omitempty"`
	RequiredSecrets  []string          `json:"required_secrets,omitempty" yaml:"required_secrets,omitempty"`
	NetworkGrants    []string          `json:"network_grants,omitempty" yaml:"network_grants,omitempty"`
	FilesystemGrants []string          `json:"filesystem_grants,omitempty" yaml:"filesystem_grants,omitempty"`
}

type MCPToolManifest struct {
	Name        string   `json:"name" yaml:"name"`
	SchemaHash  string   `json:"schema_hash" yaml:"schema_hash"`
	Effect      string   `json:"effect" yaml:"effect"`
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
	Labels      []string `json:"labels,omitempty" yaml:"labels,omitempty"`
}

type HealthcheckSpec struct {
	Type    string `json:"type" yaml:"type"`
	Command string `json:"command,omitempty" yaml:"command,omitempty"`
	URL     string `json:"url,omitempty" yaml:"url,omitempty"`
}

type BudgetCeiling struct {
	USDMax      float64 `json:"usd_max" yaml:"usd_max"`
	APICallsMax int     `json:"api_calls_max" yaml:"api_calls_max"`
	TimeMSMax   int     `json:"time_ms_max" yaml:"time_ms_max"`
}

type SupplyChainEvidenceSpec struct {
	ArtifactDigest        string `json:"artifact_digest" yaml:"artifact_digest"`
	SignatureTool         string `json:"signature_tool" yaml:"signature_tool"`
	SignatureRef          string `json:"signature_ref" yaml:"signature_ref"`
	SBOMTool              string `json:"sbom_tool" yaml:"sbom_tool"`
	SBOMRef               string `json:"sbom_ref" yaml:"sbom_ref"`
	VulnerabilityScanTool string `json:"vulnerability_scan_tool" yaml:"vulnerability_scan_tool"`
	VulnerabilityScanRef  string `json:"vulnerability_scan_ref" yaml:"vulnerability_scan_ref"`
}

type PromotionEvidenceSpec struct {
	ArtifactVerificationRef string `json:"artifact_verification_ref" yaml:"artifact_verification_ref"`
	LiveE2ERunID            string `json:"live_e2e_run_id" yaml:"live_e2e_run_id"`
	EvidencePackRef         string `json:"evidence_pack_ref" yaml:"evidence_pack_ref"`
	TeardownReceiptRef      string `json:"teardown_receipt_ref" yaml:"teardown_receipt_ref"`
}

type ConformanceSpec struct {
	LicenseVerified      bool `json:"license_verified" yaml:"license_verified"`
	ArtifactVerified     bool `json:"artifact_verified" yaml:"artifact_verified"`
	PolicyPackPresent    bool `json:"policy_pack_present" yaml:"policy_pack_present"`
	SandboxVerified      bool `json:"sandbox_verified" yaml:"sandbox_verified"`
	HealthcheckPassing   bool `json:"healthcheck_passing" yaml:"healthcheck_passing"`
	E2EPassing           bool `json:"e2e_passing" yaml:"e2e_passing"`
	TeardownVerified     bool `json:"teardown_verified" yaml:"teardown_verified"`
	ReceiptVerified      bool `json:"receipt_verified" yaml:"receipt_verified"`
	EvidencePackVerified bool `json:"evidence_pack_verified" yaml:"evidence_pack_verified"`
}
