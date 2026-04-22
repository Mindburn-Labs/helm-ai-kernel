// Package skills provides skill bundle registry types, storage, lifecycle
// management, and compatibility validation for the HELM execution firewall.
//
// A SkillManifest describes a self-contained skill bundle that can be installed,
// verified, and promoted through a fail-closed lifecycle state machine.
package skills

// SkillBundleState represents the lifecycle state of a skill bundle.
type SkillBundleState string

const (
	// SkillBundleStateCandidate is the initial state after installation.
	SkillBundleStateCandidate SkillBundleState = "candidate"
	// SkillBundleStateCertified indicates the bundle has passed all verification.
	SkillBundleStateCertified SkillBundleState = "certified"
	// SkillBundleStateDeprecated indicates the bundle is slated for removal.
	SkillBundleStateDeprecated SkillBundleState = "deprecated"
	// SkillBundleStateRevoked indicates the bundle has been permanently disabled.
	SkillBundleStateRevoked SkillBundleState = "revoked"
)

// SkillCapability identifies a discrete permission that a skill may request.
type SkillCapability string

const (
	CapReadFiles       SkillCapability = "files.read"
	CapWriteFiles      SkillCapability = "files.write"
	CapExecSandbox     SkillCapability = "sandbox.exec"
	CapNetworkOutbound SkillCapability = "network.outbound"
	CapChannelSend     SkillCapability = "channel.send"
	CapMemoryReadLKS   SkillCapability = "memory.read.lks"
	CapMemoryReadCKS   SkillCapability = "memory.read.cks"
	CapMemoryPromote   SkillCapability = "memory.promote"
	CapApprovalRequest SkillCapability = "approval.request"
	CapArtifactWrite   SkillCapability = "artifact.write"
	CapConnectorInvoke SkillCapability = "connector.invoke"
)

// SkillCompatibility declares the runtime and kernel version constraints
// that a skill bundle requires to operate correctly.
type SkillCompatibility struct {
	RuntimeSpecVersion string   `json:"runtime_spec_version"`
	MinKernelVersion   string   `json:"min_kernel_version"`
	MaxKernelVersion   string   `json:"max_kernel_version,omitempty"`
	RequiredPacks      []string `json:"required_packs,omitempty"`
	RequiredConnectors []string `json:"required_connectors,omitempty"`
}

// SkillInputContract describes a single input that a skill expects.
type SkillInputContract struct {
	Name       string `json:"name"`
	SchemaRef  string `json:"schema_ref"`
	TrustClass string `json:"trust_class"`
	Required   bool   `json:"required"`
	Sensitive  bool   `json:"sensitive"`
}

// SkillOutputContract describes a single output that a skill produces.
type SkillOutputContract struct {
	Name       string `json:"name"`
	SchemaRef  string `json:"schema_ref"`
	TrustClass string `json:"trust_class"`
	Promotable bool   `json:"promotable"`
	Sensitive  bool   `json:"sensitive"`
}

// SkillManifest is the complete metadata descriptor for a skill bundle.
// It includes identity, versioning, capability declarations, input/output
// contracts, compatibility requirements, and cryptographic integrity references.
type SkillManifest struct {
	ID                  string               `json:"id"`
	Name                string               `json:"name"`
	Version             string               `json:"version"`
	Description         string               `json:"description"`
	EntryPoint          string               `json:"entry_point"`
	State               SkillBundleState     `json:"state"`
	SelfModClass        string               `json:"self_mod_class"`
	RiskClass           string               `json:"risk_class"`
	SandboxProfile      string               `json:"sandbox_profile"`
	Capabilities        []SkillCapability    `json:"capabilities"`
	Compatibility       SkillCompatibility   `json:"compatibility"`
	Inputs              []SkillInputContract `json:"inputs"`
	Outputs             []SkillOutputContract `json:"outputs"`
	PolicyProfileRef    string               `json:"policy_profile_ref"`
	ArtifactManifestRef string               `json:"artifact_manifest_ref,omitempty"`
	SBOMRef             string               `json:"sbom_ref,omitempty"`
	BundleHash          string               `json:"bundle_hash"`
	SignatureRef        string               `json:"signature_ref"`
}
