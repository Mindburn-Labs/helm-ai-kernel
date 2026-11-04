// reversibility.go classifies effects by their reversibility level.
// This enables governance policies to gate approval requirements based on
// how difficult an action is to undo.
//
// Design invariants:
//   - Every EffectType has a default ReversibilityLevel
//   - Connectors MAY override defaults with tool-specific classifications
//   - Irreversible actions SHOULD require explicit approval
//   - Classification is deterministic: same (effectType, toolName) → same level
//   - Unknown effect types default to IRREVERSIBLE (fail-closed)
package effects

import (
	"fmt"
	"sync"
)

// ReversibilityLevel describes how reversible a side effect is.
type ReversibilityLevel string

const (
	// ReversibilityFull indicates the effect can be undone completely
	// (e.g., read, write to a versioned store).
	ReversibilityFull ReversibilityLevel = "FULLY_REVERSIBLE"

	// ReversibilityPartial indicates the effect can be partially undone
	// (e.g., send email — cannot unsend but can follow up with correction).
	ReversibilityPartial ReversibilityLevel = "PARTIALLY_REVERSIBLE"

	// ReversibilityNone indicates the effect cannot be undone
	// (e.g., delete without backup, financial transaction).
	ReversibilityNone ReversibilityLevel = "IRREVERSIBLE"
)

// defaultClassifications maps each EffectType to its default ReversibilityLevel.
// These are used when no connector-specific override exists.
var defaultClassifications = map[EffectType]ReversibilityLevel{
	EffectTypeRead:    ReversibilityFull,
	EffectTypeWrite:   ReversibilityPartial,
	EffectTypeDelete:  ReversibilityNone,
	EffectTypeExecute: ReversibilityPartial,
	EffectTypeNetwork: ReversibilityPartial,
	EffectTypeFinance: ReversibilityNone,
}

// classifierKey uniquely identifies a connector-tool pair for override lookups.
type classifierKey struct {
	ConnectorID string
	ToolName    string
}

// ReversibilityClassifier determines the reversibility level for effects.
// It combines built-in defaults per EffectType with optional connector/tool
// overrides. All methods are safe for concurrent use.
type ReversibilityClassifier struct {
	mu        sync.RWMutex
	overrides map[classifierKey]ReversibilityLevel
}

// ErrInvalidLevel is returned when an invalid ReversibilityLevel is provided.
var ErrInvalidLevel = fmt.Errorf("unknown reversibility level")

// ---------------------------------------------------------------------------
// ReversibilityPolicy — governance integration
// ---------------------------------------------------------------------------

// ReversibilityPolicy defines governance rules based on reversibility levels.
// It specifies which levels require human approval, which require evidence
// packs, and the highest level that may be auto-approved.
type ReversibilityPolicy struct {
	// RequireApprovalFor lists the reversibility levels that require
	// explicit human approval before the effect may proceed.
	RequireApprovalFor []ReversibilityLevel

	// RequireEvidenceFor lists the reversibility levels that require
	// an evidence pack to be generated for the effect execution.
	RequireEvidenceFor []ReversibilityLevel

	// MaxAutoApproveLevel is the highest reversibility level (by risk weight)
	// that may be auto-approved without human intervention.
	MaxAutoApproveLevel ReversibilityLevel
}
