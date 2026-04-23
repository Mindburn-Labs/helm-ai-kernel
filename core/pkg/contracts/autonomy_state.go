// Package contracts — autonomy_state.go defines the GlobalAutonomyState projection.
//
// GlobalAutonomyState is a DERIVED projection, never a source of truth.
// It is computed from: posture config + active runs + pending decisions + budget consumption.
// It MUST be re-derivable at any point from authoritative stores (ledger, proofgraph, receipts).
package contracts

import "time"

// ──────────────────────────────────────────────────────────────
// Global Mode — org-wide operational mode
// ──────────────────────────────────────────────────────────────

// GlobalMode is the org-wide operational state.
type GlobalMode string

const (
	// GlobalModeRunning is normal operation — autonomy runs continuously.
	GlobalModeRunning GlobalMode = "RUNNING"

	// GlobalModePaused is operator-initiated temporary halt — in-flight runs complete but no new runs start.
	GlobalModePaused GlobalMode = "PAUSED"

	// GlobalModeFrozen is a hard stop — all runs halt immediately, no effects dispatched.
	GlobalModeFrozen GlobalMode = "FROZEN"

	// GlobalModeIslanded is network-isolated operation — local-only, no external effects.
	GlobalModeIslanded GlobalMode = "ISLANDED"
)

// ──────────────────────────────────────────────────────────────
// Scheduler State
// ──────────────────────────────────────────────────────────────

// SchedulerState indicates whether the autonomy scheduler is active.
type SchedulerState string

const (
	// SchedulerAwake means the scheduler is processing and dispatching.
	SchedulerAwake SchedulerState = "AWAKE"

	// SchedulerSleeping means the scheduler is idle until next scheduled action.
	SchedulerSleeping SchedulerState = "SLEEPING"
)

// ──────────────────────────────────────────────────────────────
// Risk Level
// ──────────────────────────────────────────────────────────────

// RiskLevel classifies the current operational risk.
type RiskLevel string

const (
	RiskLevelNormal   RiskLevel = "NORMAL"
	RiskLevelElevated RiskLevel = "ELEVATED"
	RiskLevelHigh     RiskLevel = "HIGH"
	RiskLevelCritical RiskLevel = "CRITICAL"
)

// ──────────────────────────────────────────────────────────────
// Run Stage (autonomy lifecycle)
// ──────────────────────────────────────────────────────────────

// AutonomyRunStage is the lifecycle stage of an autonomous run.
// This extends the existing RunStage concept with explicit sensing/planning/verifying phases.
type AutonomyRunStage string

const (
	RunStageSensing   AutonomyRunStage = "SENSING"
	RunStagePlanning  AutonomyRunStage = "PLANNING"
	RunStageGating    AutonomyRunStage = "GATING"
	RunStageExecuting AutonomyRunStage = "EXECUTING"
	RunStageVerifying AutonomyRunStage = "VERIFYING"
	RunStageDone      AutonomyRunStage = "DONE"
	RunStageFailed    AutonomyRunStage = "FAILED"
	RunStageBlocked   AutonomyRunStage = "BLOCKED"
)

// ──────────────────────────────────────────────────────────────
// NowNextNeed — derived summary triplet
// ──────────────────────────────────────────────────────────────

// NowNextNeed is a concise derived summary of the system's current state.
// "Now" = what is actively happening, "Next" = what's queued, "NeedYou" = what's blocked on human.
type NowNextNeed struct {
	// Now describes the single most important thing happening right now.
	Now string `json:"now"`

	// Next describes the next scheduled or queued action.
	Next string `json:"next"`

	// NeedYou describes what's blocked waiting for human input (empty if nothing).
	NeedYou string `json:"need_you"`
}

// ──────────────────────────────────────────────────────────────
// RunSummaryProjection — lightweight per-run summary for aggregation
// ──────────────────────────────────────────────────────────────

// RunSummaryProjection is a lightweight projection of a run's state for UI display.
// It is NOT the canonical Run — it is a computed summary.
//
//nolint:govet // fieldalignment: struct layout matches JSON display order
type RunSummaryProjection struct {
	RunID            string           `json:"run_id"`
	Status           string           `json:"status"`
	CurrentStage     AutonomyRunStage `json:"current_stage"`
	Lane             Lane             `json:"lane"`
	ProgressPct      int              `json:"progress_pct"`      // 0-100
	NextAction       string           `json:"next_action"`       // Human-readable
	LastVerification string           `json:"last_verification"` // Summary of last verification result
	StartedAt        time.Time        `json:"started_at"`
	UpdatedAt        time.Time        `json:"updated_at"`
	BlockedBy        string           `json:"blocked_by,omitempty"` // DecisionRequest ID if blocked
}

// ──────────────────────────────────────────────────────────────
// BudgetSummary — projected budget state
// ──────────────────────────────────────────────────────────────

// BudgetSummary is a projection of budget consumption vs envelope.
type BudgetSummary struct {
	EnvelopeCents int64   `json:"envelope_cents"`
	BurnCents     int64   `json:"burn_cents"`
	BurnRate      float64 `json:"burn_rate"` // Cents per hour, trailing average
	RunwayHours   float64 `json:"runway_hours,omitempty"`
}

// ──────────────────────────────────────────────────────────────
// Anomaly — detected anomaly for risk reporting
// ──────────────────────────────────────────────────────────────

// Anomaly represents a detected operational anomaly.
type Anomaly struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`        // velocity, cost, error_rate, drift
	Severity    string    `json:"severity"`    // low, medium, high, critical
	Description string    `json:"description"` // Human-readable
	DetectedAt  time.Time `json:"detected_at"`
}

// ──────────────────────────────────────────────────────────────
// Initiative — high-level work stream
// ──────────────────────────────────────────────────────────────

// Initiative is a named high-level work stream that may span multiple runs.
type Initiative struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	ProgressPct int    `json:"progress_pct"`
	ActiveRuns  int    `json:"active_runs"`
}

// ──────────────────────────────────────────────────────────────
// GlobalAutonomyState — the composite derived projection
// ──────────────────────────────────────────────────────────────

// GlobalAutonomyState is the complete derived projection of the org's autonomy state.
// It is computed on read from authoritative stores and MUST NOT be persisted as truth.
//
//nolint:govet // fieldalignment: struct layout matches JSON display order
type GlobalAutonomyState struct {
	// OrgID scopes this state to a specific organization.
	OrgID string `json:"org_id"`

	// Posture is the current execution posture for this org.
	Posture Posture `json:"posture"`

	// GlobalMode is the org-wide operational mode.
	GlobalMode GlobalMode `json:"global_mode"`

	// SchedulerState indicates scheduler status.
	SchedulerState SchedulerState `json:"scheduler_state"`

	// Summary is the derived Now/Next/NeedYou triplet.
	Summary NowNextNeed `json:"summary"`

	// ActiveInitiatives are the top N active work streams.
	ActiveInitiatives []Initiative `json:"active_initiatives"`

	// ActiveRuns are summaries of all currently active runs.
	ActiveRuns []RunSummaryProjection `json:"active_runs"`

	// BlockersQueue contains pending DecisionRequests and other blockers.
	BlockersQueue []DecisionRequest `json:"blockers_queue"`

	// Budget is the projected budget state.
	Budget BudgetSummary `json:"budget"`

	// RiskLevel is the current operational risk classification.
	RiskLevel RiskLevel `json:"risk_level"`

	// Anomalies are currently active anomalies.
	Anomalies []Anomaly `json:"anomalies"`

	// ComputedAt is when this projection was computed.
	ComputedAt time.Time `json:"computed_at"`
}
