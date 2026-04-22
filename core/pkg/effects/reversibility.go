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

// RequiresApproval returns true if this reversibility level should require
// explicit human approval before execution. Both IRREVERSIBLE and
// PARTIALLY_REVERSIBLE actions require approval.
func (r ReversibilityLevel) RequiresApproval() bool {
	return r == ReversibilityNone || r == ReversibilityPartial
}

// IsValid returns true if r is one of the known ReversibilityLevel values.
func (r ReversibilityLevel) IsValid() bool {
	switch r {
	case ReversibilityFull, ReversibilityPartial, ReversibilityNone:
		return true
	default:
		return false
	}
}

// RiskWeight returns a numeric risk weight for the reversibility level.
// Higher values indicate greater risk.
//   - FULLY_REVERSIBLE  → 0
//   - PARTIALLY_REVERSIBLE → 1
//   - IRREVERSIBLE → 2
func (r ReversibilityLevel) RiskWeight() int {
	switch r {
	case ReversibilityFull:
		return 0
	case ReversibilityPartial:
		return 1
	case ReversibilityNone:
		return 2
	default:
		// Unknown levels are treated as maximum risk (fail-closed).
		return 2
	}
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

// NewReversibilityClassifier creates a new classifier with no overrides.
// Built-in defaults are always available.
func NewReversibilityClassifier() *ReversibilityClassifier {
	return &ReversibilityClassifier{
		overrides: make(map[classifierKey]ReversibilityLevel),
	}
}

// Classify returns the reversibility level for the given effect.
// If a connector/tool-specific override exists, it takes precedence over
// the default classification for the effect type. Unknown effect types
// default to IRREVERSIBLE (fail-closed).
func (c *ReversibilityClassifier) Classify(effectType EffectType, connectorID, toolName string) ReversibilityLevel {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := classifierKey{ConnectorID: connectorID, ToolName: toolName}
	if level, ok := c.overrides[key]; ok {
		return level
	}

	return c.defaultForTypeLocked(effectType)
}

// SetOverride registers a tool-specific reversibility classification that
// takes precedence over the default for that tool's effect type. This is
// useful when a connector knows that a specific tool (e.g., "write" to a
// versioned S3 bucket) is fully reversible even though WRITE is normally
// only partially reversible.
func (c *ReversibilityClassifier) SetOverride(connectorID, toolName string, level ReversibilityLevel) error {
	if !level.IsValid() {
		return fmt.Errorf("effects: invalid reversibility level %q: %w", level, ErrInvalidLevel)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	key := classifierKey{ConnectorID: connectorID, ToolName: toolName}
	c.overrides[key] = level
	return nil
}

// RemoveOverride removes a previously set connector/tool override.
// After removal, Classify will return the default for the effect type.
func (c *ReversibilityClassifier) RemoveOverride(connectorID, toolName string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := classifierKey{ConnectorID: connectorID, ToolName: toolName}
	delete(c.overrides, key)
}

// DefaultForType returns the default reversibility classification for the
// given effect type. Unknown effect types return IRREVERSIBLE (fail-closed).
func (c *ReversibilityClassifier) DefaultForType(effectType EffectType) ReversibilityLevel {
	return c.defaultForTypeLocked(effectType)
}

// defaultForTypeLocked returns the default classification without acquiring
// any lock. This is safe because defaultClassifications is package-level
// and read-only after init.
func (c *ReversibilityClassifier) defaultForTypeLocked(effectType EffectType) ReversibilityLevel {
	if level, ok := defaultClassifications[effectType]; ok {
		return level
	}
	// Fail-closed: unknown effect types are treated as irreversible.
	return ReversibilityNone
}

// Overrides returns a snapshot (shallow copy) of all registered overrides.
// Mutations to the returned map do not affect the classifier.
func (c *ReversibilityClassifier) Overrides() map[classifierKey]ReversibilityLevel {
	c.mu.RLock()
	defer c.mu.RUnlock()

	snapshot := make(map[classifierKey]ReversibilityLevel, len(c.overrides))
	for k, v := range c.overrides {
		snapshot[k] = v
	}
	return snapshot
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

// DefaultReversibilityPolicy returns a sensible default policy:
//   - Auto-approve only FULLY_REVERSIBLE effects
//   - Require approval for PARTIALLY_REVERSIBLE and IRREVERSIBLE
//   - Require evidence for PARTIALLY_REVERSIBLE and IRREVERSIBLE
func DefaultReversibilityPolicy() *ReversibilityPolicy {
	return &ReversibilityPolicy{
		RequireApprovalFor: []ReversibilityLevel{
			ReversibilityPartial,
			ReversibilityNone,
		},
		RequireEvidenceFor: []ReversibilityLevel{
			ReversibilityPartial,
			ReversibilityNone,
		},
		MaxAutoApproveLevel: ReversibilityFull,
	}
}

// ShouldRequireApproval returns true if the given level is listed in
// RequireApprovalFor, or if the level's risk weight exceeds the
// MaxAutoApproveLevel's risk weight.
func (p *ReversibilityPolicy) ShouldRequireApproval(level ReversibilityLevel) bool {
	for _, l := range p.RequireApprovalFor {
		if l == level {
			return true
		}
	}
	return level.RiskWeight() > p.MaxAutoApproveLevel.RiskWeight()
}

// ShouldRequireEvidence returns true if the given level is listed in
// RequireEvidenceFor.
func (p *ReversibilityPolicy) ShouldRequireEvidence(level ReversibilityLevel) bool {
	for _, l := range p.RequireEvidenceFor {
		if l == level {
			return true
		}
	}
	return false
}
