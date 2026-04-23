// Package contracts — lane.go defines execution lanes for concurrent run organization.
//
// A Lane is a categorical grouping of autonomous runs. Each run belongs to exactly
// one lane, enabling the UI to show progress across functional domains.
package contracts

// Lane categorizes the functional domain of an autonomous run.
type Lane string

const (
	// LaneResearch covers information gathering, analysis, and learning runs.
	LaneResearch Lane = "RESEARCH"

	// LaneBuild covers engineering, development, and infrastructure runs.
	LaneBuild Lane = "BUILD"

	// LaneGTM covers go-to-market, marketing, and sales runs.
	LaneGTM Lane = "GTM"

	// LaneOps covers operational, monitoring, and maintenance runs.
	LaneOps Lane = "OPS"

	// LaneCompliance covers regulatory, audit, and governance runs.
	LaneCompliance Lane = "COMPLIANCE"
)

// AllLanes returns all defined lanes in display order.
func AllLanes() []Lane {
	return []Lane{LaneResearch, LaneBuild, LaneGTM, LaneOps, LaneCompliance}
}

// LaneState represents the current state of all runs within a single lane.
//
//nolint:govet // fieldalignment: struct layout matches JSON display order
type LaneState struct {
	// Lane identifies which lane this state describes.
	Lane Lane `json:"lane"`

	// ActiveRuns is the count of currently active runs in this lane.
	ActiveRuns int `json:"active_runs"`

	// ProgressPct is the aggregate progress across all active runs (0-100).
	ProgressPct int `json:"progress_pct"`

	// NextAction describes the next scheduled or queued action in this lane.
	NextAction string `json:"next_action"`

	// LastVerification summarizes the most recent verification result.
	LastVerification string `json:"last_verification"`

	// Status is the aggregate status: "active", "idle", "blocked".
	Status string `json:"status"`

	// BlockedCount is the number of runs blocked in this lane.
	BlockedCount int `json:"blocked_count"`
}

// IsIdle returns true if the lane has no active runs and no pending actions.
func (ls *LaneState) IsIdle() bool {
	return ls.ActiveRuns == 0 && ls.NextAction == ""
}
