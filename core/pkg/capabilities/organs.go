package capabilities

import ()

// MissingOrgan describes a single missing capability with resolution options.
type MissingOrgan struct {
	CapabilityID          string            `json:"capability_id"`
	RequiredEvidenceClass []string          `json:"required_evidence_class"`
	SuggestedModules      []SuggestedModule `json:"suggested_modules"`
	GenomeDeltaProposals  []GenomeDelta     `json:"genome_delta_proposals"`
	Resolvability         Resolvability     `json:"resolvability"`
	SourceRequirement     string            `json:"source_requirement"`
}

// SuggestedModule is a module that could satisfy the missing capability.
type SuggestedModule struct {
	ModuleID      string `json:"module_id"`
	Priority      int    `json:"priority"`       // Lower = higher priority
	MatchScore    int    `json:"match_score"`    // 0-100, deterministic score
	PackReference string `json:"pack_reference"` // Pack that provides this module
}

// GenomeDelta describes a minimal change to resolve the missing capability.
type GenomeDelta struct {
	DeltaID     string                 `json:"delta_id"`
	Operation   string                 `json:"operation"` // "add", "modify", "bind"
	TargetPath  string                 `json:"target_path"`
	Payload     map[string]interface{} `json:"payload"`
	ContentHash string                 `json:"content_hash"` // For determinism verification
}

// Resolvability classifies how a missing organ can be resolved.
type Resolvability string

const (
	ResolvableNow         Resolvability = "RESOLVABLE_NOW"         // Can be resolved with existing packs
	RequiresNewPack       Resolvability = "REQUIRES_NEW_PACK"      // Needs a new pack to be installed
	RequiresConfiguration Resolvability = "REQUIRES_CONFIGURATION" // Config change needed
	Unresolvable          Resolvability = "UNRESOLVABLE"           // Cannot be automatically resolved
)

// MissingOrgansReport identifies what capabilities are REQUIRED by policy
// but MISSING from the ToolCatalog, with resolution recommendations.
type MissingOrgansReport struct {
	// Legacy fields for backwards compatibility
	MissingCapabilities []string `json:"missing_capabilities"`
	Context             string   `json:"context"`

	// Enhanced fields (P0.2)
	MissingOrgans     []MissingOrgan `json:"missing_organs"`
	ReportHash        string         `json:"report_hash"` // Determinism verification
	TotalGaps         int            `json:"total_gaps"`
	ResolvableCount   int            `json:"resolvable_count"`
	UnresolvableCount int            `json:"unresolvable_count"`
}

// ModuleRegistry provides available modules for gap resolution.
type ModuleRegistry interface {
	GetModulesForCapability(capabilityID string) []SuggestedModule
	GetPackForModule(moduleID string) string
}

// DefaultModuleRegistry is a static registry for known module mappings.
type DefaultModuleRegistry struct {
	modules map[string][]SuggestedModule
}

// OrganDetector analyzes a PRG RequirementSet against the Catalog.
type OrganDetector struct {
	catalog        *ToolCatalog
	moduleRegistry ModuleRegistry
}

// NewOrganDetectorWithRegistry removed - was dead code

// Scan removed - was dead code
