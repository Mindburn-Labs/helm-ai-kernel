// Package capability implements the governed capability registry (chunk 1:
// manifest types, validation, and a hash-pinned registry) per
// protocols/json-schemas/capability/capability_manifest.v1.json and
// docs/governance/capability-registry.md.
//
// Scope honesty: this package resolves and validates manifests. It does NOT
// mint capability tokens, execute rollback plans, or enforce permit levels;
// those are follow-up chunks documented in the governance specs.
package capability

import (
	"fmt"
	"regexp"
	"time"
)

// SchemaVersion is the only manifest schema version this registry accepts.
const SchemaVersion = "capability-manifest/v1"

// capabilityIDPattern mirrors the schema's capability_id pattern:
// helm.cap.<ns>[.<ns>...] with lowercase kebab segments.
var capabilityIDPattern = regexp.MustCompile(`^helm\.cap\.[a-z0-9][a-z0-9-]*(\.[a-z0-9][a-z0-9-]*)+$`)

// semverPattern mirrors the schema's version pattern (loose semver).
var semverPattern = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?$`)

// sourcePackHashPattern mirrors metadata.source_pack_hash when present.
var sourcePackHashPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// EffectClass is the worst-case effect a capability can produce.
type EffectClass string

const (
	EffectReadOnly         EffectClass = "read_only"
	EffectWriteLocal       EffectClass = "write_local"
	EffectWriteExternal    EffectClass = "write_external"
	EffectNetworkEgress    EffectClass = "network_egress"
	EffectCredentialAccess EffectClass = "credential_access"
	EffectCodeExecution    EffectClass = "code_execution"
	EffectFinancial        EffectClass = "financial"
	EffectIrreversible     EffectClass = "irreversible"
)

// Reversibility reuses the effect_type_definition/v2 vocabulary.
type Reversibility string

const (
	ReversibilityNone               Reversibility = "none"
	ReversibilityCompensatingAction Reversibility = "compensating_action"
	ReversibilityExactUndo          Reversibility = "exact_undo"
)

// DataBoundary is the tightest boundary a capability's data flow is confined to.
type DataBoundary string

const (
	BoundaryLocalOnly DataBoundary = "local_only"
	BoundaryDevice    DataBoundary = "device_boundary"
	BoundaryOrg       DataBoundary = "org_boundary"
	BoundaryExternal  DataBoundary = "external"
)

// PermitLevel is the minimum authorization required for dispatch.
type PermitLevel string

const (
	PermitNone       PermitLevel = "none"
	PermitSingle     PermitLevel = "single_approval"
	PermitMultiParty PermitLevel = "multi_party_permit"
)

// Protocol identifies the dispatch surface.
type Protocol string

const (
	ProtocolMCP       Protocol = "mcp"
	ProtocolA2A       Protocol = "a2a"
	ProtocolCLI       Protocol = "cli"
	ProtocolHTTPAPI   Protocol = "http-api"
	ProtocolGUIAction Protocol = "gui-action"
	ProtocolSyscall   Protocol = "syscall"
)

// Binding is the protocol-specific dispatch reference.
type Binding struct {
	Kind             string                 `json:"kind"`
	Ref              string                 `json:"ref"`
	ParametersSchema map[string]interface{} `json:"parameters_schema,omitempty"`
}

// RollbackRequirement binds a rollback plan requirement.
type RollbackRequirement struct {
	Required bool   `json:"required"`
	PlanRef  string `json:"plan_ref,omitempty"`
}

// ReceiptRequirement binds receipt production requirements.
type ReceiptRequirement struct {
	Required   bool     `json:"required"`
	SchemaRefs []string `json:"schema_refs,omitempty"`
}

// MemoryAccess declares per-domain memory grants.
type MemoryAccess struct {
	UserDomain      string `json:"user_domain"`
	AgentDomain     string `json:"agent_domain"`
	CrossDomainRead bool   `json:"cross_domain_read"`
}

// Routing declares model-tier constraints.
type Routing struct {
	MinModelTier string `json:"min_model_tier,omitempty"`
}

// Metadata carries optional provenance and certification info.
type Metadata struct {
	Homepage       string `json:"homepage,omitempty"`
	License        string `json:"license,omitempty"`
	SourcePackHash string `json:"source_pack_hash,omitempty"`
	CertifiedBy    string `json:"certified_by,omitempty"`
	CertifiedAt    string `json:"certified_at,omitempty"`
}

// Manifest is the governed capability manifest (capability-manifest/v1).
type Manifest struct {
	SchemaVersion       string              `json:"schema_version"`
	CapabilityID        string              `json:"capability_id"`
	Name                string              `json:"name"`
	Version             string              `json:"version"`
	Description         string              `json:"description,omitempty"`
	Protocol            Protocol            `json:"protocol"`
	Binding             Binding             `json:"binding"`
	EffectClass         EffectClass         `json:"effect_class"`
	Reversibility       Reversibility       `json:"reversibility"`
	DataBoundary        DataBoundary        `json:"data_boundary"`
	RiskScore           int                 `json:"risk_score"`
	RequiredPermitLevel PermitLevel         `json:"required_permit_level"`
	Rollback            RollbackRequirement `json:"rollback"`
	Receipts            ReceiptRequirement  `json:"receipts"`
	MemoryAccess        MemoryAccess        `json:"memory_access"`
	Routing             Routing             `json:"routing,omitempty"`
	Metadata            Metadata            `json:"metadata,omitempty"`
}

var validBindingKinds = map[string]bool{
	"mcp_tool": true, "mcp_server": true, "a2a_skill": true,
	"cli_command": true, "http_endpoint": true, "gui_action_primitive": true,
}

var validProtocols = map[Protocol]bool{
	ProtocolMCP: true, ProtocolA2A: true, ProtocolCLI: true,
	ProtocolHTTPAPI: true, ProtocolGUIAction: true, ProtocolSyscall: true,
}

var validEffectClasses = map[EffectClass]bool{
	EffectReadOnly: true, EffectWriteLocal: true, EffectWriteExternal: true,
	EffectNetworkEgress: true, EffectCredentialAccess: true,
	EffectCodeExecution: true, EffectFinancial: true, EffectIrreversible: true,
}

var validReversibilities = map[Reversibility]bool{
	ReversibilityNone: true, ReversibilityCompensatingAction: true, ReversibilityExactUndo: true,
}

var validBoundaries = map[DataBoundary]bool{
	BoundaryLocalOnly: true, BoundaryDevice: true, BoundaryOrg: true, BoundaryExternal: true,
}

var validPermitLevels = map[PermitLevel]bool{
	PermitNone: true, PermitSingle: true, PermitMultiParty: true,
}

var validMemoryGrants = map[string]bool{
	"none": true, "read": true, "write": true, "read_write": true,
}

var validModelTiers = map[string]bool{
	"fast_edge": true, "standard": true, "deep_reasoning": true,
}

// Validate enforces the normative rules of capability-manifest/v1.
// Any violation is an error: invalid manifests must fail closed at load time.
func (m *Manifest) Validate() error {
	if m.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version must be %q, got %q", SchemaVersion, m.SchemaVersion)
	}
	if !capabilityIDPattern.MatchString(m.CapabilityID) {
		return fmt.Errorf("capability_id %q does not match required pattern", m.CapabilityID)
	}
	if m.Name == "" {
		return fmt.Errorf("name is required")
	}
	if !semverPattern.MatchString(m.Version) {
		return fmt.Errorf("version %q is not valid semver", m.Version)
	}
	if !validProtocols[m.Protocol] {
		return fmt.Errorf("protocol %q is not a recognized dispatch surface", m.Protocol)
	}
	if !validBindingKinds[m.Binding.Kind] {
		return fmt.Errorf("binding.kind %q is not a recognized dispatch binding", m.Binding.Kind)
	}
	if m.Binding.Ref == "" {
		return fmt.Errorf("binding.ref is required")
	}
	if !validEffectClasses[m.EffectClass] {
		return fmt.Errorf("effect_class %q is not recognized", m.EffectClass)
	}
	if !validReversibilities[m.Reversibility] {
		return fmt.Errorf("reversibility %q is not recognized", m.Reversibility)
	}
	if !validBoundaries[m.DataBoundary] {
		return fmt.Errorf("data_boundary %q is not recognized", m.DataBoundary)
	}
	if m.RiskScore < 0 || m.RiskScore > 100 {
		return fmt.Errorf("risk_score %d out of range [0,100]", m.RiskScore)
	}
	if !validPermitLevels[m.RequiredPermitLevel] {
		return fmt.Errorf("required_permit_level %q is not recognized", m.RequiredPermitLevel)
	}
	// reversibility-classes.md rule 1 ("no plan, no dispatch") and the
	// schema conditional: a reversible non-read-only capability must explicitly
	// require and reference its rollback plan.
	if m.Reversibility != ReversibilityNone && m.EffectClass != EffectReadOnly {
		if !m.Rollback.Required {
			return fmt.Errorf("rollback.required must be true for reversible non-read-only capability")
		}
		if m.Rollback.PlanRef == "" {
			return fmt.Errorf("rollback.plan_ref is required for reversible non-read-only capability")
		}
	}
	if !m.Receipts.Required {
		return fmt.Errorf("receipts.required must be true: every dispatch must produce receipts")
	}
	if !validMemoryGrants[m.MemoryAccess.UserDomain] ||
		!validMemoryGrants[m.MemoryAccess.AgentDomain] {
		return fmt.Errorf("memory_access grants must be one of none/read/write/read_write")
	}
	if m.Routing.MinModelTier != "" && !validModelTiers[m.Routing.MinModelTier] {
		return fmt.Errorf("routing.min_model_tier %q is not recognized", m.Routing.MinModelTier)
	}
	if m.Metadata.SourcePackHash != "" && !sourcePackHashPattern.MatchString(m.Metadata.SourcePackHash) {
		return fmt.Errorf("metadata.source_pack_hash must be a sha256 digest")
	}
	if m.Metadata.CertifiedAt != "" {
		if _, err := time.Parse(time.RFC3339, m.Metadata.CertifiedAt); err != nil {
			return fmt.Errorf("metadata.certified_at must be RFC3339: %w", err)
		}
	}
	return nil
}
