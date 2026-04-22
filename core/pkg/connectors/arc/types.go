// Package arc provides the HELM connector for ARC-AGI-3 benchmark environments.
//
// Architecture:
//   - types.go:     Go types mapped 1:1 from ARC-AGI-3 observation schema
//   - client.go:    HTTP client calling the Python bridge sidecar
//   - receipts.go:  Deterministic hashing for ProofGraph receipts
//   - connector.go: High-level connector composing client + receipts + ZeroTrust
//   - policy.go:    ARC-specific policy profile and budget enforcement
//
// Per HELM Standard v1.2: every ARC action becomes an
// INTENT → EFFECT chain in the ProofGraph DAG.
package arc

import (
	"encoding/json"
)

// Frame is a single 2D grid frame from an ARC environment.
// Grids are ≤64×64, values 0-15, per ARC-AGI-3 game schema.
type Frame struct {
	Grid   [][]int `json:"grid"`
	Width  int     `json:"width"`
	Height int     `json:"height"`
}

// Observation is the full observation returned after a step or reset.
// May contain 1-N frames (multi-frame transitions).
type Observation struct {
	Frames           []Frame           `json:"frames"`
	AvailableActions []string          `json:"available_actions"`
	LevelsCompleted  int               `json:"levels_completed"`
	TotalLevels      int               `json:"total_levels"`
	Done             bool              `json:"done"`
	Reward           float64           `json:"reward"`
	Info             map[string]string `json:"info,omitempty"`
}

// StepRequest is the request to execute an action in a session.
type StepRequest struct {
	Action    string          `json:"action"`
	Reasoning json.RawMessage `json:"reasoning,omitempty"` // ≤16KB per ARC docs
}

// StepResponse is the response from executing a step.
type StepResponse struct {
	SessionID string      `json:"session_id"`
	StepCount int         `json:"step_count"`
	Obs       Observation `json:"observation"`
	Done      bool        `json:"done"`
}

// CreateSessionRequest is the request to create a new game session.
type CreateSessionRequest struct {
	GameID string `json:"game_id"`
	Mode   string `json:"mode"` // "OFFLINE" or "ONLINE"
}

// SessionInfo is session state returned on create.
type SessionInfo struct {
	SessionID string      `json:"session_id"`
	GameID    string      `json:"game_id"`
	StepCount int         `json:"step_count"`
	Obs       Observation `json:"observation"`
}

// GameInfo is summary info about an available game.
type GameInfo struct {
	GameID      string `json:"game_id"`
	Description string `json:"description,omitempty"`
}

// GameListResponse is the list of available games.
type GameListResponse struct {
	Games []GameInfo `json:"games"`
	Count int        `json:"count"`
}

// ScorecardOpenRequest is the request to open an online scorecard.
type ScorecardOpenRequest struct {
	GameIDs []string `json:"game_ids"`
}

// ScorecardInfo is scorecard metadata.
type ScorecardInfo struct {
	CardID    string            `json:"card_id"`
	Status    string            `json:"status"`
	Scores    map[string]string `json:"scores,omitempty"`
	ReplayURL string            `json:"replay_url,omitempty"`
}

// HealthResponse is the bridge health check response.
type HealthResponse struct {
	Status  string `json:"status"`
	Mode    string `json:"mode"`
	Version string `json:"version"`
}

// RunMode defines the evaluation mode for the ARC connector.
type RunMode string

const (
	// RunModeOfficialShadow is ultra-thin mode replicating frontier leaderboard conditions.
	// No domain-specific planner, no handcrafted skills, no external tools.
	// HELM only records, budgets, and reproduces.
	RunModeOfficialShadow RunMode = "OFFICIAL_SHADOW"

	// RunModeCommunityHarness is full research mode with planner stack,
	// replay mining, and skill evolution. Community leaderboard track.
	RunModeCommunityHarness RunMode = "COMMUNITY_HARNESS"
)

// EpisodeSummary captures the metadata of a completed episode.
type EpisodeSummary struct {
	SessionID   string `json:"session_id"`
	GameID      string `json:"game_id"`
	TotalSteps  int    `json:"total_steps"`
	FinalReward float64 `json:"final_reward"`
	Completed   bool   `json:"completed"`
	EpisodeHash string `json:"episode_hash"`
	ScorecardID string `json:"scorecard_id,omitempty"`
}
