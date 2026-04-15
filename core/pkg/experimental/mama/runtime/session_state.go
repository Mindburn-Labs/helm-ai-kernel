package runtime

// MissionState holds the unbendable canonical state of the exploration.
// The MAMA agent pipeline uses this typed structure instead of raw unstructured transcripts.
type MissionState struct {
	MissionID    string       `json:"mission_id"`
	Mode         ModeState    `json:"mode"`
	Agent        AgentState   `json:"agent"`
	Skill        SkillState   `json:"skill"`
	Memory       MemoryState  `json:"memory"`
	Replay       ReplayState  `json:"replay"`
	Proof        ProofState   `json:"proof"`
	Episodes     []EpisodeState `json:"episodes"`
	// ActionBudget limits the number of effects the Executor can manifest
	ActionBudget int          `json:"action_budget"`
}

// EpisodeState tracks a specific phase or attempt within a Mission.
type EpisodeState struct {
	EpisodeID string `json:"episode_id"`
	Mode      string `json:"mode"`   // Explore, Plan, Probe, Commit, etc.
	Status    string `json:"status"` // Active, Failed, Succeeded, Reverted
}

// ModeState tracks the current deterministic execution mode.
type ModeState struct {
	CurrentMode string   `json:"current_mode"`
	History     []string `json:"history"`
}

// AgentState tracks the active roster and their assignments.
type AgentState struct {
	ActiveRoles []string `json:"active_roles"`
}

// SkillState registers the currently permitted tools and constraints.
type SkillState struct {
	Active []string `json:"active"`
}

// MemoryState handles structured retrieval context.
type MemoryState struct {
	WorkingID  string `json:"working_id"`
	EpisodicID string `json:"episodic_id"`
}

// ReplayState holds timeline context for branch/rewind ops.
type ReplayState struct {
	TimelineID string `json:"timeline_id"`
}

// ProofState manages the DAG nodes demonstrating cryptographic determinism.
type ProofState struct {
	ReceiptHash string `json:"receipt_hash"`
}
