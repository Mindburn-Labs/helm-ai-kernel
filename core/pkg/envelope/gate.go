// Package envelope provides the kernel enforcement gate for the Autonomy Envelope.
//
// EnvelopeGate is the kernel-level check that runs before any effect execution.
// It enforces the envelope's constraints at runtime, fail-closed.
package envelope

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// EffectRequest represents a request to execute an effect, to be checked against the envelope.
type EffectRequest struct {
	EffectClass   string `json:"effect_class"`   // E0..E4
	EffectType    string `json:"effect_type"`    // e.g., DATA_WRITE, FUNDS_TRANSFER
	Jurisdiction  string `json:"jurisdiction"`   // ISO code of the effect's jurisdiction
	DataClass     string `json:"data_class"`     // Data classification of data touched
	EstimatedCost int64  `json:"estimated_cost"` // Estimated cost in cents
	BlastRadius   string `json:"blast_radius"`   // Blast radius of this effect
}

// GateDecision is the result of an envelope gate check.
type GateDecision struct {
	Allowed       bool   `json:"allowed"`
	Reason        string `json:"reason"`
	Violation     string `json:"violation,omitempty"`      // Which constraint was violated
	EscalationReq string `json:"escalation_req,omitempty"` // Required escalation if not allowed
	ReceiptID     string `json:"receipt_id"`
}

// EnvelopeGate enforces the Autonomy Envelope at runtime.
// It is the kernel-level boundary that ensures every effect is within bounds.
//
// Invariants:
//   - If no valid envelope is bound, ALL effects are denied (fail-closed)
//   - Budget consumption is tracked and enforced monotonically
//   - Effect counts are tracked per class
type EnvelopeGate struct {
	mu sync.Mutex

	// The active envelope (nil if none bound)
	active *contracts.AutonomyEnvelope

	// Runtime counters (reset when a new envelope is bound)
	toolCallCount   int64
	costAccumulated int64
	effectCounts    map[string]int64 // per effect class
	startedAt       time.Time

	// Validator for structural checks
	validator *Validator

	// Clock for deterministic time
	clock func() time.Time
}

// NewEnvelopeGate creates a new enforcement gate.
func NewEnvelopeGate() *EnvelopeGate {
	return &EnvelopeGate{
		effectCounts: make(map[string]int64),
		validator:    NewValidator(),
		clock:        time.Now,
	}
}

// WithClock overrides the clock for deterministic testing.
func (g *EnvelopeGate) WithClock(clock func() time.Time) *EnvelopeGate {
	g.clock = clock
	g.validator = g.validator.WithClock(clock)
	return g
}

// Bind validates and binds an Autonomy Envelope to this gate.
// All subsequent CheckEffect calls will be enforced against this envelope.
// Returns a ValidationResult; if invalid, the gate remains unbound (fail-closed).
func (g *EnvelopeGate) Bind(ctx context.Context, env *contracts.AutonomyEnvelope) *ValidationResult {
	_ = ctx

	result := g.validator.Validate(env)
	if !result.Valid {
		return result
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	g.active = env
	g.toolCallCount = 0
	g.costAccumulated = 0
	g.effectCounts = make(map[string]int64)
	g.startedAt = g.clock()

	return result
}

// Unbind removes the active envelope, returning the gate to fail-closed state.
func (g *EnvelopeGate) Unbind() {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.active = nil
	g.toolCallCount = 0
	g.costAccumulated = 0
	g.effectCounts = make(map[string]int64)
}

// IsBound returns whether an envelope is currently active.
func (g *EnvelopeGate) IsBound() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.active != nil
}

// ActiveEnvelope returns a copy of the active envelope ID and version, or empty if unbound.
func (g *EnvelopeGate) ActiveEnvelope() (envelopeID, version string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.active == nil {
		return "", ""
	}
	return g.active.EnvelopeID, g.active.Version
}

// CheckEffect evaluates whether an effect request is allowed under the active envelope.
// This is fail-closed: if any check fails or no envelope is bound, the effect is denied.
func (g *EnvelopeGate) CheckEffect(ctx context.Context, req *EffectRequest) *GateDecision {
	_ = ctx
	g.mu.Lock()
	defer g.mu.Unlock()

	// FAIL-CLOSED: No active envelope means deny everything
	if g.active == nil {
		return &GateDecision{
			Allowed:   false,
			Reason:    "no active autonomy envelope bound",
			Violation: "NO_ENVELOPE",
		}
	}

	env := g.active
	now := g.clock()

	// 1. Check envelope expiry
	if !env.ValidUntil.IsZero() && now.After(env.ValidUntil) {
		return &GateDecision{
			Allowed:   false,
			Reason:    "autonomy envelope has expired",
			Violation: "ENVELOPE_EXPIRED",
		}
	}

	// 2. Check jurisdiction
	if req.Jurisdiction != "" {
		if !g.isJurisdictionAllowed(req.Jurisdiction) {
			return &GateDecision{
				Allowed:   false,
				Reason:    fmt.Sprintf("jurisdiction %q not allowed by envelope", req.Jurisdiction),
				Violation: "JURISDICTION_DENIED",
			}
		}
	}

	// 3. Check effect class allowlist
	allowed, maxPerRun, approvalAbove := g.isEffectAllowed(req.EffectClass, req.EffectType)
	if !allowed {
		return &GateDecision{
			Allowed:   false,
			Reason:    fmt.Sprintf("effect class %q not allowed by envelope", req.EffectClass),
			Violation: "EFFECT_CLASS_DENIED",
		}
	}

	// 4. Check per-class count limits
	currentCount := g.effectCounts[req.EffectClass]
	if maxPerRun > 0 && currentCount >= int64(maxPerRun) {
		return &GateDecision{
			Allowed:   false,
			Reason:    fmt.Sprintf("effect class %q exceeded max_per_run (%d)", req.EffectClass, maxPerRun),
			Violation: "EFFECT_COUNT_EXCEEDED",
		}
	}

	// 5. Check if escalation is needed (count above threshold)
	if approvalAbove > 0 && currentCount >= int64(approvalAbove) {
		return &GateDecision{
			Allowed:       false,
			Reason:        fmt.Sprintf("effect class %q requires approval (count %d exceeds threshold %d)", req.EffectClass, currentCount, approvalAbove),
			Violation:     "ESCALATION_REQUIRED",
			EscalationReq: "require_approval",
		}
	}

	// 6. Check data classification
	if req.DataClass != "" && !g.isDataClassAllowed(req.DataClass) {
		return &GateDecision{
			Allowed:   false,
			Reason:    fmt.Sprintf("data classification %q exceeds max %q", req.DataClass, env.DataHandling.MaxClassification),
			Violation: "DATA_CLASSIFICATION_EXCEEDED",
		}
	}

	// 7. Check budget: cost ceiling
	newCost := g.costAccumulated + req.EstimatedCost
	if req.EstimatedCost > 0 && newCost > env.Budgets.CostCeilingCents {
		return &GateDecision{
			Allowed:   false,
			Reason:    fmt.Sprintf("cost would exceed ceiling (%d > %d cents)", newCost, env.Budgets.CostCeilingCents),
			Violation: "COST_CEILING_EXCEEDED",
		}
	}

	// 8. Check budget: tool call cap
	newToolCalls := g.toolCallCount + 1
	if newToolCalls > env.Budgets.ToolCallCap {
		return &GateDecision{
			Allowed:   false,
			Reason:    fmt.Sprintf("tool call cap exceeded (%d > %d)", newToolCalls, env.Budgets.ToolCallCap),
			Violation: "TOOL_CALL_CAP_EXCEEDED",
		}
	}

	// 9. Check budget: time ceiling
	elapsed := now.Sub(g.startedAt)
	if elapsed.Seconds() > float64(env.Budgets.TimeCeilingSeconds) {
		return &GateDecision{
			Allowed:   false,
			Reason:    fmt.Sprintf("time ceiling exceeded (%.0fs > %ds)", elapsed.Seconds(), env.Budgets.TimeCeilingSeconds),
			Violation: "TIME_CEILING_EXCEEDED",
		}
	}

	// 10. Check blast radius
	if req.BlastRadius != "" && env.Budgets.BlastRadius != "" {
		if !g.isBlastRadiusAllowed(req.BlastRadius, env.Budgets.BlastRadius) {
			return &GateDecision{
				Allowed:   false,
				Reason:    fmt.Sprintf("blast radius %q exceeds max %q", req.BlastRadius, env.Budgets.BlastRadius),
				Violation: "BLAST_RADIUS_EXCEEDED",
			}
		}
	}

	// ALL CHECKS PASSED — update counters
	g.toolCallCount = newToolCalls
	g.costAccumulated = newCost
	g.effectCounts[req.EffectClass]++

	return &GateDecision{
		Allowed: true,
		Reason:  "within autonomy envelope bounds",
	}
}

// Snapshot returns the current runtime state for observability/evidence.
type GateSnapshot struct {
	EnvelopeID      string           `json:"envelope_id"`
	EnvelopeVersion string           `json:"envelope_version"`
	ToolCallCount   int64            `json:"tool_call_count"`
	CostAccumulated int64            `json:"cost_accumulated"`
	EffectCounts    map[string]int64 `json:"effect_counts"`
	ElapsedSeconds  float64          `json:"elapsed_seconds"`
}

// Snapshot returns a point-in-time snapshot of the gate's runtime state.
func (g *EnvelopeGate) Snapshot() *GateSnapshot {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.active == nil {
		return nil
	}

	counts := make(map[string]int64)
	for k, v := range g.effectCounts {
		counts[k] = v
	}

	return &GateSnapshot{
		EnvelopeID:      g.active.EnvelopeID,
		EnvelopeVersion: g.active.Version,
		ToolCallCount:   g.toolCallCount,
		CostAccumulated: g.costAccumulated,
		EffectCounts:    counts,
		ElapsedSeconds:  g.clock().Sub(g.startedAt).Seconds(),
	}
}

// --- Internal helpers ---

func (g *EnvelopeGate) isJurisdictionAllowed(jurisdiction string) bool {
	env := g.active

	// Check prohibited first
	for _, p := range env.JurisdictionScope.ProhibitedJurisdictions {
		if p == jurisdiction {
			return false
		}
	}

	// Check allowed
	for _, a := range env.JurisdictionScope.AllowedJurisdictions {
		if a == jurisdiction {
			return true
		}
	}

	return false
}

func (g *EnvelopeGate) isEffectAllowed(effectClass, effectType string) (allowed bool, maxPerRun, approvalAbove int) {
	for _, e := range g.active.AllowedEffects {
		if e.EffectClass == effectClass {
			if !e.Allowed {
				return false, 0, 0
			}

			// Check specific type allowlist if defined
			if len(e.AllowedTypes) > 0 && effectType != "" {
				found := false
				for _, t := range e.AllowedTypes {
					if t == effectType {
						found = true
						break
					}
				}
				if !found {
					return false, 0, 0
				}
			}

			return true, e.MaxPerRun, e.RequiresApprovalAbove
		}
	}

	// Effect class not mentioned in envelope → denied
	return false, 0, 0
}

var dataClassificationOrder = map[string]int{
	contracts.DataClassPublic:       0,
	contracts.DataClassInternal:     1,
	contracts.DataClassConfidential: 2,
	contracts.DataClassRestricted:   3,
}

func (g *EnvelopeGate) isDataClassAllowed(requestedClass string) bool {
	maxLevel, ok := dataClassificationOrder[g.active.DataHandling.MaxClassification]
	if !ok {
		return false // fail-closed on unknown classification
	}
	reqLevel, ok := dataClassificationOrder[requestedClass]
	if !ok {
		return false // fail-closed on unknown classification
	}
	return reqLevel <= maxLevel
}

var blastRadiusOrder = map[string]int{
	contracts.BlastRadiusSingleRecord: 0,
	contracts.BlastRadiusDataset:      1,
	contracts.BlastRadiusSystemWide:   2,
}

func (g *EnvelopeGate) isBlastRadiusAllowed(requested, max string) bool {
	maxLevel, ok := blastRadiusOrder[max]
	if !ok {
		return false
	}
	reqLevel, ok := blastRadiusOrder[requested]
	if !ok {
		return false
	}
	return reqLevel <= maxLevel
}
