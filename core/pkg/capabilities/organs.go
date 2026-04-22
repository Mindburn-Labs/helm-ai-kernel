package capabilities

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/prg"
)

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

// ComputeHash calculates a deterministic hash of the report for reproducibility.
func (r *MissingOrgansReport) ComputeHash() string {
	// Sort organs deterministically
	sortedOrgans := make([]MissingOrgan, len(r.MissingOrgans))
	copy(sortedOrgans, r.MissingOrgans)
	sort.Slice(sortedOrgans, func(i, j int) bool {
		return sortedOrgans[i].CapabilityID < sortedOrgans[j].CapabilityID
	})

	// Create canonical representation
	canonical := struct {
		Context       string         `json:"context"`
		MissingOrgans []MissingOrgan `json:"missing_organs"`
	}{
		Context:       r.Context,
		MissingOrgans: sortedOrgans,
	}

	data, err := json.Marshal(canonical)
	if err != nil {
		return ""
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
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

// NewDefaultModuleRegistry creates a registry with built-in mappings.
func NewDefaultModuleRegistry() *DefaultModuleRegistry {
	return &DefaultModuleRegistry{
		modules: map[string][]SuggestedModule{
			"email-sender": {
				{ModuleID: "smtp-adapter", Priority: 1, MatchScore: 95, PackReference: "comm-pack-v1"},
				{ModuleID: "sendgrid-adapter", Priority: 2, MatchScore: 90, PackReference: "comm-pack-v1"},
			},
			"payment-processor": {
				{ModuleID: "stripe-adapter", Priority: 1, MatchScore: 98, PackReference: "finops-pack-v1"},
				{ModuleID: "paypal-adapter", Priority: 2, MatchScore: 85, PackReference: "finops-pack-v1"},
			},
			"document-signer": {
				{ModuleID: "docusign-adapter", Priority: 1, MatchScore: 92, PackReference: "legal-pack-v1"},
			},
			"kyc-verifier": {
				{ModuleID: "plaid-adapter", Priority: 1, MatchScore: 90, PackReference: "compliance-pack-v1"},
			},
		},
	}
}

func (r *DefaultModuleRegistry) GetModulesForCapability(capabilityID string) []SuggestedModule {
	modules, ok := r.modules[capabilityID]
	if !ok {
		return nil
	}
	// Return sorted by priority for determinism
	result := make([]SuggestedModule, len(modules))
	copy(result, modules)
	sort.Slice(result, func(i, j int) bool {
		if result[i].Priority != result[j].Priority {
			return result[i].Priority < result[j].Priority
		}
		return result[i].ModuleID < result[j].ModuleID
	})
	return result
}

func (r *DefaultModuleRegistry) GetPackForModule(moduleID string) string {
	for _, modules := range r.modules {
		for _, m := range modules {
			if m.ModuleID == moduleID {
				return m.PackReference
			}
		}
	}
	return ""
}

// OrganDetector analyzes a PRG RequirementSet against the Catalog.
type OrganDetector struct {
	catalog        *ToolCatalog
	moduleRegistry ModuleRegistry
}

// NewOrganDetector creates a new detector with default module registry.
func NewOrganDetector(catalog *ToolCatalog) *OrganDetector {
	return &OrganDetector{
		catalog:        catalog,
		moduleRegistry: NewDefaultModuleRegistry(),
	}
}

// NewOrganDetectorWithRegistry removed - was dead code

// Analyze performs gap detection against a RequirementSet.
func (d *OrganDetector) Analyze(rs *prg.RequirementSet) *MissingOrgansReport {
	report := &MissingOrgansReport{
		MissingCapabilities: []string{},
		MissingOrgans:       []MissingOrgan{},
		Context:             rs.ID,
	}

	// Recursive traversal
	d.checkNode(rs, report)

	// Determinism: Sort legacy field
	sort.Strings(report.MissingCapabilities)

	// Sort enhanced organs by capability_id
	sort.Slice(report.MissingOrgans, func(i, j int) bool {
		return report.MissingOrgans[i].CapabilityID < report.MissingOrgans[j].CapabilityID
	})

	// Compute statistics
	report.TotalGaps = len(report.MissingOrgans)
	for _, organ := range report.MissingOrgans {
		if organ.Resolvability == ResolvableNow || organ.Resolvability == RequiresConfiguration {
			report.ResolvableCount++
		} else {
			report.UnresolvableCount++
		}
	}

	// Compute deterministic hash
	report.ReportHash = report.ComputeHash()

	return report
}

// Scan removed - was dead code

func (d *OrganDetector) checkNode(rs *prg.RequirementSet, report *MissingOrgansReport) {
	for _, req := range rs.Requirements {
		if strings.HasPrefix(req.Description, "REQ_CAP:") {
			capName := strings.TrimSpace(strings.TrimPrefix(req.Description, "REQ_CAP:"))
			if _, exists := d.catalog.Get(capName); !exists {
				// Check deduplication
				found := false
				for _, m := range report.MissingCapabilities {
					if m == capName {
						found = true
						break
					}
				}
				if !found {
					report.MissingCapabilities = append(report.MissingCapabilities, capName)

					// Build enhanced MissingOrgan entry
					organ := d.buildMissingOrgan(capName, req.Description)
					report.MissingOrgans = append(report.MissingOrgans, organ)
				}
			}
		}
	}

	for _, child := range rs.Children {
		d.checkNode(&child, report)
	}
}

// buildMissingOrgan creates a detailed MissingOrgan entry with resolution options.
func (d *OrganDetector) buildMissingOrgan(capabilityID, sourceReq string) MissingOrgan {
	organ := MissingOrgan{
		CapabilityID:          capabilityID,
		RequiredEvidenceClass: d.inferEvidenceClass(capabilityID),
		SourceRequirement:     sourceReq,
		SuggestedModules:      []SuggestedModule{},
		GenomeDeltaProposals:  []GenomeDelta{},
	}

	// Get suggested modules from registry
	if d.moduleRegistry != nil {
		organ.SuggestedModules = d.moduleRegistry.GetModulesForCapability(capabilityID)
	}

	// Determine resolvability
	if len(organ.SuggestedModules) > 0 {
		organ.Resolvability = ResolvableNow
	} else {
		organ.Resolvability = RequiresNewPack
	}

	// Generate delta proposals
	organ.GenomeDeltaProposals = d.generateDeltaProposals(capabilityID, organ.SuggestedModules)

	return organ
}

// inferEvidenceClass determines required evidence for a capability type.
func (d *OrganDetector) inferEvidenceClass(capabilityID string) []string {
	// Deterministic mapping based on capability patterns
	switch {
	case strings.Contains(capabilityID, "payment") || strings.Contains(capabilityID, "fund"):
		return []string{"SLSA", "attestation", "audit_log"}
	case strings.Contains(capabilityID, "sign") || strings.Contains(capabilityID, "legal"):
		return []string{"attestation", "signature_proof"}
	case strings.Contains(capabilityID, "kyc") || strings.Contains(capabilityID, "verify"):
		return []string{"attestation", "compliance_evidence"}
	case strings.Contains(capabilityID, "email") || strings.Contains(capabilityID, "notify"):
		return []string{"delivery_receipt"}
	default:
		return []string{"attestation"}
	}
}

// generateDeltaProposals creates minimal genome changes to add capability.
func (d *OrganDetector) generateDeltaProposals(capabilityID string, modules []SuggestedModule) []GenomeDelta {
	deltas := make([]GenomeDelta, 0)

	if len(modules) == 0 {
		// No modules available - propose pack installation
		delta := GenomeDelta{
			DeltaID:    "delta-" + capabilityID + "-pack-install",
			Operation:  "add",
			TargetPath: "module_lifecycle.required_packs",
			Payload: map[string]interface{}{
				"capability": capabilityID,
				"action":     "install_pack",
			},
		}
		delta.ContentHash = computeDeltaHash(delta)
		deltas = append(deltas, delta)
	} else {
		// Propose binding to first (highest priority) module
		topModule := modules[0]
		delta := GenomeDelta{
			DeltaID:    "delta-" + capabilityID + "-bind-" + topModule.ModuleID,
			Operation:  "bind",
			TargetPath: "capabilities." + capabilityID,
			Payload: map[string]interface{}{
				"module_id":      topModule.ModuleID,
				"pack_reference": topModule.PackReference,
				"priority":       topModule.Priority,
			},
		}
		delta.ContentHash = computeDeltaHash(delta)
		deltas = append(deltas, delta)
	}

	return deltas
}

// computeDeltaHash calculates a deterministic hash for a delta.
func computeDeltaHash(delta GenomeDelta) string {
	canonical := struct {
		DeltaID    string                 `json:"delta_id"`
		Operation  string                 `json:"operation"`
		TargetPath string                 `json:"target_path"`
		Payload    map[string]interface{} `json:"payload"`
	}{
		DeltaID:    delta.DeltaID,
		Operation:  delta.Operation,
		TargetPath: delta.TargetPath,
		Payload:    delta.Payload,
	}

	data, err := json.Marshal(canonical)
	if err != nil {
		return ""
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
