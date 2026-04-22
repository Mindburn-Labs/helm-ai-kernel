// Package contracts — reflex.go provides the Reflex Engine contracts.
//
// Reflexes are autonomous corrective actions that fire WITHOUT user input
// when specific conditions are detected. They produce deterministic
// ControlIntents and ReflexReceipts that are visible in Ops.
//
// Reflexes are projections — they evaluate the current GlobalAutonomyState
// and emit actions. They do NOT mutate state directly; the caller applies
// the returned actions.
package contracts

import "time"

// ──────────────────────────────────────────────────────────────
// ReflexKind — enumeration of reflex types
// ──────────────────────────────────────────────────────────────

// ReflexKind classifies the type of autonomous corrective action.
type ReflexKind string

const (
	// ReflexFreeze halts all new runs and pauses in-flight runs.
	ReflexFreeze ReflexKind = "FREEZE"

	// ReflexIsland disconnects from external connectors (network isolation).
	ReflexIsland ReflexKind = "ISLAND"

	// ReflexRollback reverts the last effect of a failed verification.
	ReflexRollback ReflexKind = "ROLLBACK"

	// ReflexVelocityCap limits the rate of new run creation.
	ReflexVelocityCap ReflexKind = "VELOCITY_CAP"

	// ReflexIncidentContain restricts operations to P0 incident response only.
	ReflexIncidentContain ReflexKind = "INCIDENT_CONTAIN"
)

// AllReflexKinds returns all defined reflex kinds in severity order (most severe first).
func AllReflexKinds() []ReflexKind {
	return []ReflexKind{
		ReflexIsland,
		ReflexFreeze,
		ReflexIncidentContain,
		ReflexVelocityCap,
		ReflexRollback,
	}
}

// ──────────────────────────────────────────────────────────────
// ReflexTrigger — what caused the reflex to fire
// ──────────────────────────────────────────────────────────────

// ReflexTrigger describes the condition that caused a reflex to fire.
type ReflexTrigger struct {
	// Condition is a human-readable description of what triggered the reflex.
	Condition string `json:"condition"`

	// Metric is the quantitative value that exceeded the threshold (if applicable).
	Metric float64 `json:"metric,omitempty"`

	// Threshold is the configured threshold that was breached.
	Threshold float64 `json:"threshold,omitempty"`

	// SourceRunID is the run that caused the trigger (if applicable).
	SourceRunID string `json:"source_run_id,omitempty"`
}

// ──────────────────────────────────────────────────────────────
// ReflexAction — what the reflex wants to do
// ──────────────────────────────────────────────────────────────

// ReflexAction represents a deterministic corrective action emitted by the reflex evaluator.
type ReflexAction struct {
	// Kind is the type of reflex action.
	Kind ReflexKind `json:"kind"`

	// Trigger describes why this action was emitted.
	Trigger ReflexTrigger `json:"trigger"`

	// TargetGlobalMode is the GlobalMode to transition to (for Freeze/Island).
	// Empty if the reflex does not change global mode.
	TargetGlobalMode GlobalMode `json:"target_global_mode,omitempty"`

	// TargetRunID is the specific run to act on (for Rollback/VelocityCap).
	// Empty if the reflex targets the global state.
	TargetRunID string `json:"target_run_id,omitempty"`

	// Description is a human-readable explanation of the action.
	Description string `json:"description"`
}

// ──────────────────────────────────────────────────────────────
// ReflexReceipt — proof that a reflex fired
// ──────────────────────────────────────────────────────────────

// ReflexReceipt is an immutable record that a reflex action was evaluated and (optionally) applied.
// Receipts are visible in Ops and anchor to the causal chain.
type ReflexReceipt struct {
	// ID is a stable unique identifier for this receipt.
	ID string `json:"id"`

	// Action is the reflex action that was evaluated.
	Action ReflexAction `json:"action"`

	// Applied indicates whether the action was actually applied.
	// False if the action was suppressed by policy or posture.
	Applied bool `json:"applied"`

	// SuppressedReason explains why the action was not applied (if Applied == false).
	SuppressedReason string `json:"suppressed_reason,omitempty"`

	// EvaluatedAt is when the reflex evaluation occurred.
	EvaluatedAt time.Time `json:"evaluated_at"`

	// OrgID is the organization this receipt belongs to.
	OrgID string `json:"org_id"`
}

// ──────────────────────────────────────────────────────────────
// Reflex evaluator — stateless, deterministic
// ──────────────────────────────────────────────────────────────

// ReflexThresholds configures the trigger points for each reflex type.
type ReflexThresholds struct {
	// CriticalRiskAutoFreeze: if true, CRITICAL risk auto-triggers FREEZE.
	CriticalRiskAutoFreeze bool `json:"critical_risk_auto_freeze"`

	// AnomalyCountIsland: number of anomalies that triggers ISLAND.
	// 0 = disabled.
	AnomalyCountIsland int `json:"anomaly_count_island"`

	// BlockedRunVelocityCap: number of blocked runs that triggers VELOCITY_CAP.
	// 0 = disabled.
	BlockedRunVelocityCap int `json:"blocked_run_velocity_cap"`

	// FailedVerificationRollback: if true, a run in FAILED stage triggers ROLLBACK.
	FailedVerificationRollback bool `json:"failed_verification_rollback"`

	// BudgetExhaustedFreeze: if true, exhausted budget triggers FREEZE.
	BudgetExhaustedFreeze bool `json:"budget_exhausted_freeze"`
}

// DefaultReflexThresholds returns production-grade defaults.
func DefaultReflexThresholds() ReflexThresholds {
	return ReflexThresholds{
		CriticalRiskAutoFreeze:     true,
		AnomalyCountIsland:         5,
		BlockedRunVelocityCap:      3,
		FailedVerificationRollback: true,
		BudgetExhaustedFreeze:      true,
	}
}

// EvaluateReflexes inspects the current GlobalAutonomyState and returns
// any reflex actions that should fire. This function is stateless and deterministic —
// the same state always produces the same actions.
//
// The caller is responsible for applying the actions and generating receipts.
func EvaluateReflexes(state *GlobalAutonomyState, thresholds ReflexThresholds) []ReflexAction {
	if state == nil {
		return nil
	}

	var actions []ReflexAction

	// ── CRITICAL risk → FREEZE ──
	if thresholds.CriticalRiskAutoFreeze && state.RiskLevel == RiskLevelCritical {
		actions = append(actions, ReflexAction{
			Kind: ReflexFreeze,
			Trigger: ReflexTrigger{
				Condition: "Risk level is CRITICAL",
			},
			TargetGlobalMode: GlobalModeFrozen,
			Description:      "Auto-freeze: risk level reached CRITICAL threshold",
		})
	}

	// ── Budget exhausted → FREEZE ──
	if thresholds.BudgetExhaustedFreeze && state.Budget.EnvelopeCents > 0 &&
		state.Budget.BurnCents >= state.Budget.EnvelopeCents {
		actions = append(actions, ReflexAction{
			Kind: ReflexFreeze,
			Trigger: ReflexTrigger{
				Condition: "Budget exhausted",
				Metric:    float64(state.Budget.BurnCents),
				Threshold: float64(state.Budget.EnvelopeCents),
			},
			TargetGlobalMode: GlobalModeFrozen,
			Description:      "Auto-freeze: budget envelope fully consumed",
		})
	}

	// ── Anomaly count → ISLAND ──
	if thresholds.AnomalyCountIsland > 0 && len(state.Anomalies) >= thresholds.AnomalyCountIsland {
		actions = append(actions, ReflexAction{
			Kind: ReflexIsland,
			Trigger: ReflexTrigger{
				Condition: "Anomaly count exceeded threshold",
				Metric:    float64(len(state.Anomalies)),
				Threshold: float64(thresholds.AnomalyCountIsland),
			},
			TargetGlobalMode: GlobalModeIslanded,
			Description:      "Auto-island: anomaly count exceeded safety threshold",
		})
	}

	// ── Blocked runs → VELOCITY_CAP ──
	blockedCount := 0
	for _, r := range state.ActiveRuns {
		if r.CurrentStage == RunStageBlocked {
			blockedCount++
		}
	}
	if thresholds.BlockedRunVelocityCap > 0 && blockedCount >= thresholds.BlockedRunVelocityCap {
		actions = append(actions, ReflexAction{
			Kind: ReflexVelocityCap,
			Trigger: ReflexTrigger{
				Condition: "Too many runs blocked",
				Metric:    float64(blockedCount),
				Threshold: float64(thresholds.BlockedRunVelocityCap),
			},
			Description: "Velocity cap: too many concurrent blocked runs, throttling new run creation",
		})
	}

	// ── Failed verification → ROLLBACK ──
	if thresholds.FailedVerificationRollback {
		for _, r := range state.ActiveRuns {
			if r.CurrentStage == RunStageFailed {
				actions = append(actions, ReflexAction{
					Kind: ReflexRollback,
					Trigger: ReflexTrigger{
						Condition:   "Run verification failed",
						SourceRunID: r.RunID,
					},
					TargetRunID: r.RunID,
					Description: "Auto-rollback: run " + r.RunID + " failed verification",
				})
			}
		}
	}

	return actions
}
