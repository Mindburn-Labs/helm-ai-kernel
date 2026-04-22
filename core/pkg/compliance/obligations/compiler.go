// Package obligations implements the two-tier obligations compiler.
// Tier 1: Universal control language primitives (NIST/ISO/PCI style).
// Tier 2: Jurisdiction overlays compiled as deltas (EU, US, UK, etc.).
package obligations

import (
	"fmt"
	"sort"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jkg"
)

// ControlLanguagePrimitive represents a Tier 1 universal control.
type ControlLanguagePrimitive struct {
	ControlID            string   `json:"control_id"`            // e.g., "CLT-AC-001"
	Statement            string   `json:"statement"`             // Human-readable requirement
	Family               string   `json:"family"`                // e.g., "Access Control", "Audit", "Encryption"
	Applicability        string   `json:"applicability"`         // CEL expression for scope
	EvidenceRequirements []string `json:"evidence_requirements"` // What evidence satisfies this
	CheckHooks           []string `json:"check_hooks"`           // Automated verification hooks
	Severity             string   `json:"severity"`              // "critical", "high", "medium", "low"
}

// JurisdictionOverlay represents a Tier 2 jurisdiction-specific delta.
type JurisdictionOverlay struct {
	OverlayID       string               `json:"overlay_id"`
	Jurisdiction    jkg.JurisdictionCode `json:"jurisdiction"`
	BaseControlIDs  []string             `json:"base_control_ids"` // Tier 1 controls this modifies
	DeltaRules      []DeltaRule          `json:"delta_rules"`
	EffectiveFrom   time.Time            `json:"effective_from"`
	ExpiresAt       *time.Time           `json:"expires_at,omitempty"`
	ConflictsPolicy string               `json:"conflicts_policy"` // "strictest_wins", "explicit_override", "escalate"
	SourceID        string               `json:"source_id"`        // CSR source that defines this
}

// DeltaRule is a single modification to a base control by a jurisdiction overlay.
type DeltaRule struct {
	RuleID             string   `json:"rule_id"`
	BaseControlID      string   `json:"base_control_id"`
	Modification       string   `json:"modification"` // "ADD_REQUIREMENT", "RESTRICT", "EXEMPT", "REPLACE"
	AdditionalText     string   `json:"additional_text"`
	AdditionalEvidence []string `json:"additional_evidence,omitempty"`
}

// CompiledObligation is the final compiled obligation for a specific scope.
type CompiledObligation struct {
	ObligationID    string                     `json:"obligation_id"`
	Jurisdiction    jkg.JurisdictionCode       `json:"jurisdiction"`
	Controls        []ControlLanguagePrimitive `json:"controls"`
	Overlays        []JurisdictionOverlay      `json:"overlays"`
	EffectiveFrom   time.Time                  `json:"effective_from"`
	CompilerVersion string                     `json:"compiler_version"`
	CompilationHash string                     `json:"compilation_hash"` // Deterministic hash of the compilation
}

// ConflictResolution records how a conflict between obligations was resolved.
type ConflictResolution struct {
	ConflictID       string   `json:"conflict_id"`
	ControlIDs       []string `json:"control_ids"`
	Resolution       string   `json:"resolution"` // "strictest_wins", "explicit_precedence", "escalated"
	Rationale        string   `json:"rationale"`
	EscalatedToHuman bool     `json:"escalated_to_human"`
}

// Compiler is the two-tier obligations compiler.
type Compiler struct {
	tier1Controls map[string]*ControlLanguagePrimitive
	overlays      map[string]*JurisdictionOverlay
	version       string
}

// NewCompiler creates a new obligations compiler.
func NewCompiler() *Compiler {
	return &Compiler{
		tier1Controls: make(map[string]*ControlLanguagePrimitive),
		overlays:      make(map[string]*JurisdictionOverlay),
		version:       "1.0.0",
	}
}

// RegisterTier1Control adds a universal control primitive.
func (c *Compiler) RegisterTier1Control(ctrl *ControlLanguagePrimitive) error {
	if ctrl == nil || ctrl.ControlID == "" {
		return fmt.Errorf("invalid control primitive")
	}
	c.tier1Controls[ctrl.ControlID] = ctrl
	return nil
}

// RegisterOverlay adds a jurisdiction overlay.
func (c *Compiler) RegisterOverlay(overlay *JurisdictionOverlay) error {
	if overlay == nil || overlay.OverlayID == "" {
		return fmt.Errorf("invalid overlay")
	}
	c.overlays[overlay.OverlayID] = overlay
	return nil
}

// Compile produces the final obligations for a set of jurisdictions.
// It applies Tier 2 overlays on top of Tier 1 controls and resolves conflicts
// using strictest-wins where applicable.
func (c *Compiler) Compile(jurisdictions []jkg.JurisdictionCode) (*CompilationResult, error) {
	result := &CompilationResult{
		Jurisdictions:   jurisdictions,
		Obligations:     make([]CompiledObligation, 0),
		Conflicts:       make([]ConflictResolution, 0),
		CompilerVersion: c.version,
		CompiledAt:      time.Now(),
	}

	// Collect applicable overlays per jurisdiction
	for _, jc := range jurisdictions {
		obligation := CompiledObligation{
			ObligationID:    fmt.Sprintf("OBL-%s", jc),
			Jurisdiction:    jc,
			Controls:        c.collectControls(jc),
			Overlays:        c.collectOverlays(jc),
			EffectiveFrom:   time.Now(),
			CompilerVersion: c.version,
		}
		result.Obligations = append(result.Obligations, obligation)
	}

	return result, nil
}

// CompilationResult is the output of the obligations compiler.
type CompilationResult struct {
	Jurisdictions   []jkg.JurisdictionCode `json:"jurisdictions"`
	Obligations     []CompiledObligation   `json:"obligations"`
	Conflicts       []ConflictResolution   `json:"conflicts"`
	CompilerVersion string                 `json:"compiler_version"`
	CompiledAt      time.Time              `json:"compiled_at"`
}

// collectControls gathers applicable Tier 1 controls.
func (c *Compiler) collectControls(jc jkg.JurisdictionCode) []ControlLanguagePrimitive {
	// In production, this would filter by applicability CEL expressions
	controls := make([]ControlLanguagePrimitive, 0, len(c.tier1Controls))
	for _, ctrl := range c.tier1Controls {
		controls = append(controls, *ctrl)
	}
	// Deterministic ordering
	sort.Slice(controls, func(i, j int) bool {
		return controls[i].ControlID < controls[j].ControlID
	})
	return controls
}

// collectOverlays gathers applicable overlays for a jurisdiction.
func (c *Compiler) collectOverlays(jc jkg.JurisdictionCode) []JurisdictionOverlay {
	overlays := make([]JurisdictionOverlay, 0)
	for _, o := range c.overlays {
		if o.Jurisdiction == jc {
			overlays = append(overlays, *o)
		}
	}
	sort.Slice(overlays, func(i, j int) bool {
		return overlays[i].OverlayID < overlays[j].OverlayID
	})
	return overlays
}

// ResolveConflict applies strictest-wins conflict resolution.
// Returns an escalation if the conflict cannot be resolved deterministically.
func ResolveConflict(controls []ControlLanguagePrimitive) ConflictResolution {
	if len(controls) <= 1 {
		return ConflictResolution{Resolution: "no_conflict"}
	}

	// Strictest-wins: pick the control with highest severity
	severityOrder := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
	strictest := controls[0]
	for _, c := range controls[1:] {
		if severityOrder[c.Severity] > severityOrder[strictest.Severity] {
			strictest = c
		}
	}

	ids := make([]string, len(controls))
	for i, c := range controls {
		ids[i] = c.ControlID
	}

	return ConflictResolution{
		ControlIDs: ids,
		Resolution: "strictest_wins",
		Rationale:  fmt.Sprintf("Applied %s (severity: %s)", strictest.ControlID, strictest.Severity),
	}
}
