package capability

import (
	"fmt"
	"time"
)

// Rollback plan schema version (rollback-plan/v1, see
// protocols/json-schemas/capability/rollback_plan.v1.json and
// docs/governance/reversibility-classes.md).
//
// Scope honesty: chunk 3 loads, validates (including cross-validation that
// every compensating step resolves to a registered capability), and binds
// plans to decisions. Executing rollback and verifying rollback outcomes
// (receipt pairing / state-digest match) are follow-up work.
const RollbackPlanSchemaVersion = "rollback-plan/v1"

// RollbackStrategy describes how an effect is reversed.
type RollbackStrategy string

const (
	StrategyExactUndo          RollbackStrategy = "exact_undo"
	StrategyCompensatingAction RollbackStrategy = "compensating_action"
	StrategySnapshotRestore    RollbackStrategy = "snapshot_restore"
)

// RollbackVerificationMethod describes how rollback success is evidenced.
type RollbackVerificationMethod string

const (
	VerifyReceiptPairing   RollbackVerificationMethod = "receipt_pairing"
	VerifyStateDigestMatch RollbackVerificationMethod = "state_digest_match"
	VerifyHumanAttestation RollbackVerificationMethod = "human_attestation"
)

var validStrategies = map[RollbackStrategy]bool{
	StrategyExactUndo: true, StrategyCompensatingAction: true, StrategySnapshotRestore: true,
}

var validVerificationMethods = map[RollbackVerificationMethod]bool{
	VerifyReceiptPairing: true, VerifyStateDigestMatch: true, VerifyHumanAttestation: true,
}

// RollbackAppliesTo binds a plan to a capability class or one executed effect.
type RollbackAppliesTo struct {
	CapabilityID     string `json:"capability_id,omitempty"`
	EffectReceiptRef string `json:"effect_receipt_ref,omitempty"`
}

// RollbackStep is one compensating/undo action.
type RollbackStep struct {
	Order              int                    `json:"order"`
	ActionRef          string                 `json:"action_ref"`
	Description        string                 `json:"description"`
	ParametersTemplate map[string]interface{} `json:"parameters_template,omitempty"`
}

// RollbackVerification declares how rollback success is proven.
type RollbackVerification struct {
	Method       RollbackVerificationMethod `json:"method"`
	EvidenceRefs []string                   `json:"evidence_refs,omitempty"`
}

// RollbackPlan is a machine-checkable rollback plan (rollback-plan/v1).
type RollbackPlan struct {
	SchemaVersion   string               `json:"schema_version"`
	PlanID          string               `json:"plan_id"`
	Strategy        RollbackStrategy     `json:"strategy"`
	AppliesTo       RollbackAppliesTo    `json:"applies_to"`
	Steps           []RollbackStep       `json:"steps"`
	Verification    RollbackVerification `json:"verification"`
	GuaranteeExpiry *time.Time           `json:"guarantee_expiry,omitempty"`
}

// Validate enforces rollback-plan/v1 rules, cross-validating step actions
// against the capability registry (reversibility-classes.md rule 2: rollback
// steps are themselves certified capabilities).
func (p *RollbackPlan) Validate(reg *Registry) error {
	if p.SchemaVersion != RollbackPlanSchemaVersion {
		return fmt.Errorf("schema_version must be %q, got %q", RollbackPlanSchemaVersion, p.SchemaVersion)
	}
	if p.PlanID == "" {
		return fmt.Errorf("plan_id is required")
	}
	if !validStrategies[p.Strategy] {
		return fmt.Errorf("strategy %q is not recognized", p.Strategy)
	}
	if p.AppliesTo.CapabilityID == "" && p.AppliesTo.EffectReceiptRef == "" {
		return fmt.Errorf("applies_to must name capability_id or effect_receipt_ref")
	}
	if p.AppliesTo.CapabilityID != "" {
		if !capabilityIDPattern.MatchString(p.AppliesTo.CapabilityID) {
			return fmt.Errorf("applies_to.capability_id %q is invalid", p.AppliesTo.CapabilityID)
		}
		if reg != nil && reg.Resolve(p.AppliesTo.CapabilityID) == nil {
			return fmt.Errorf("applies_to.capability_id %q does not resolve to a registered capability", p.AppliesTo.CapabilityID)
		}
	}
	if len(p.Steps) == 0 {
		return fmt.Errorf("steps must contain at least one step")
	}
	seenOrders := make(map[int]bool, len(p.Steps))
	for i, step := range p.Steps {
		if step.Order < 1 {
			return fmt.Errorf("step %d: order must be >= 1", i)
		}
		if seenOrders[step.Order] {
			return fmt.Errorf("step %d: duplicate order %d", i, step.Order)
		}
		seenOrders[step.Order] = true
		if step.ActionRef == "" {
			return fmt.Errorf("step %d: action_ref is required", i)
		}
		if reg != nil && reg.Resolve(step.ActionRef) == nil {
			return fmt.Errorf("step %d: action_ref %q does not resolve to a registered capability", i, step.ActionRef)
		}
	}
	if !validVerificationMethods[p.Verification.Method] {
		return fmt.Errorf("verification.method %q is not recognized", p.Verification.Method)
	}
	return nil
}

// AppliesToCapability reports whether this plan is bound to capabilityID.
// Effect-receipt-scoped plans are not substitutes for a manifest-required
// capability plan because they cannot be validated before the forward effect.
func (p *RollbackPlan) AppliesToCapability(capabilityID string) bool {
	return p != nil && p.AppliesTo.CapabilityID == capabilityID
}

// RollbackPlanEntry is a validated plan plus its content hash.
type RollbackPlanEntry struct {
	Plan       RollbackPlan `json:"plan"`
	Hash       string       `json:"hash"`
	SourcePath string       `json:"source_path"`
}

// RollbackPlanStore resolves plan references to validated plans.
type RollbackPlanStore interface {
	ResolvePlan(planRef string) *RollbackPlanEntry
	Len() int
}

// RollbackPlanRegistry is a hash-pinned, load-time-validated plan store.
type RollbackPlanRegistry struct {
	entries map[string]RollbackPlanEntry
}

// Expired reports whether the plan's rollback guarantee has lapsed. Guardian
// denies a dispatch that requires an expired plan; it does not claim to
// mutate the forward effect's class.
func (p *RollbackPlan) Expired(now time.Time) bool {
	if p.GuaranteeExpiry == nil {
		return false
	}
	return !now.Before(*p.GuaranteeExpiry)
}
