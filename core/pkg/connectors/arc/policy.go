package arc

// PolicyProfile defines the ARC-specific governance constraints for HELM.
//
// This profile implements three priority tiers:
//
//   P0 — hard ceilings that cannot be overridden:
//     action/reset/session/rate budgets
//
//   P1 — action allowlist:
//     which ARC operations are permitted
//
//   P2 — mode overlays:
//     OFFICIAL_SHADOW vs COMMUNITY_HARNESS behavior switches
type PolicyProfile struct {
	// --- P0: Hard Ceilings ---

	// MaxActionsPerEpisode caps total actions before budget exhaustion.
	MaxActionsPerEpisode int `json:"max_actions_per_episode"`

	// MaxResetsPerEpisode caps resets (session recreations) per logical episode.
	MaxResetsPerEpisode int `json:"max_resets_per_episode"`

	// MaxCoordinateActionsPerEpisode caps ACTION6 (coordinate click) calls.
	MaxCoordinateActionsPerEpisode int `json:"max_coordinate_actions_per_episode"`

	// MaxParallelSessions caps concurrent sessions.
	MaxParallelSessions int `json:"max_parallel_sessions"`

	// MaxOnlineRPM caps online API requests per minute (ARC limit: 600).
	MaxOnlineRPM int `json:"max_online_rpm"`

	// MaxOnlineScorecardsPH caps scorecard opens per hour.
	MaxOnlineScorecardsPH int `json:"max_online_scorecards_per_hour"`

	// MaxOfflineSearchNodes caps search tree nodes per decision (harness mode).
	MaxOfflineSearchNodes int `json:"max_offline_search_nodes_per_decision"`

	// MaxWallclockMsPerMove caps wall-clock time per action decision.
	MaxWallclockMsPerMove int `json:"max_wallclock_ms_per_move"`

	// --- P2: Mode Overlay ---

	// Mode is the evaluation mode.
	Mode RunMode `json:"mode"`

	// BridgeMode controls whether the bridge runs OFFLINE or ONLINE.
	BridgeMode BridgeMode `json:"bridge_mode"`
}

// BridgeMode controls the Python bridge execution mode.
type BridgeMode string

const (
	BridgeModeOffline BridgeMode = "OFFLINE"
	BridgeModeOnline  BridgeMode = "ONLINE"
)

// DefaultPolicy returns sensible defaults for a given run mode.
func DefaultPolicy(mode RunMode) *PolicyProfile {
	switch mode {
	case RunModeOfficialShadow:
		return &PolicyProfile{
			MaxActionsPerEpisode:           500,
			MaxResetsPerEpisode:            10,
			MaxCoordinateActionsPerEpisode: 100,
			MaxParallelSessions:            1,
			MaxOnlineRPM:                   600, // ARC hard limit
			MaxOnlineScorecardsPH:          10,
			MaxOfflineSearchNodes:          0,   // no search in official-shadow
			MaxWallclockMsPerMove:          30000,
			Mode:                           RunModeOfficialShadow,
			BridgeMode:                     BridgeModeOffline,
		}
	case RunModeCommunityHarness:
		return &PolicyProfile{
			MaxActionsPerEpisode:           2000,
			MaxResetsPerEpisode:            50,
			MaxCoordinateActionsPerEpisode: 500,
			MaxParallelSessions:            8,
			MaxOnlineRPM:                   600,
			MaxOnlineScorecardsPH:          20,
			MaxOfflineSearchNodes:          10000,
			MaxWallclockMsPerMove:          120000,
			Mode:                           RunModeCommunityHarness,
			BridgeMode:                     BridgeModeOffline,
		}
	default:
		return DefaultPolicy(RunModeOfficialShadow)
	}
}

// AllowedDataClasses returns the P1 action allowlist for ARC connector.
func AllowedDataClasses() []string {
	return []string{
		"arc.games.list",
		"arc.scorecard.open",
		"arc.env.reset",
		"arc.env.step.simple",
		"arc.env.step.complex",
		"arc.scorecard.get",
		"arc.scorecard.close",
		"arc.replay.fetch",
	}
}

// Validate checks the policy for internal consistency.
func (p *PolicyProfile) Validate() error {
	if p.MaxActionsPerEpisode <= 0 {
		return errInvalidPolicy("max_actions_per_episode must be > 0")
	}
	if p.MaxOnlineRPM > 600 {
		return errInvalidPolicy("max_online_rpm cannot exceed ARC limit of 600")
	}
	if p.Mode == RunModeOfficialShadow && p.MaxOfflineSearchNodes > 0 {
		return errInvalidPolicy("official-shadow mode prohibits search (max_offline_search_nodes must be 0)")
	}
	return nil
}

type policyError struct {
	msg string
}

func (e *policyError) Error() string {
	return "arc policy error: " + e.msg
}

func errInvalidPolicy(msg string) error {
	return &policyError{msg: msg}
}
