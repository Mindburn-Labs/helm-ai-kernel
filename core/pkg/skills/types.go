// Package skills implements the Forge skill evolution system with governed
// promotion ladder. The Forge is the ONLY valid path for agent-authored
// skill/workflow mutation — no virtual employee can add, modify, or remove
// skills outside of Forge.
package skills

import (
	"time"
)

// SkillClass categorizes the domain of a skill.
type SkillClass string

const (
	SkillClassActionPack    SkillClass = "ACTION_PACK"    // executive-ops, recruiting, etc.
	SkillClassChannel       SkillClass = "CHANNEL"        // email, chat, calendar composition
	SkillClassExternalComms SkillClass = "EXTERNAL_COMMS" // draft templates, response patterns
	SkillClassInternal      SkillClass = "INTERNAL"       // internal workflows, data processing
)

// PromotionLevel tracks where a skill is in the promotion ladder.
type PromotionLevel string

const (
	PromotionC0Sandbox    PromotionLevel = "C0_SANDBOX"    // Initial: runs only in sandbox
	PromotionC1Shadow     PromotionLevel = "C1_SHADOW"     // Shadow: runs alongside production, results discarded
	PromotionC2Canary     PromotionLevel = "C2_CANARY"     // Canary: handles small % of real traffic
	PromotionC3Production PromotionLevel = "C3_PRODUCTION" // Production: full deployment
)

// Skill represents a versioned, governed agent skill/workflow.
type Skill struct {
	SkillID       string         `json:"skill_id"`
	Name          string         `json:"name"`
	Description   string         `json:"description"`
	Class         SkillClass     `json:"class"`
	Version       int            `json:"version"`
	Level         PromotionLevel `json:"level"`
	AuthorID      string         `json:"author_id"`      // VirtualEmployee who proposed this
	ManagerID     string         `json:"manager_id"`     // Manager who must approve promotions
	ContentHash   string         `json:"content_hash"`   // SHA-256 of skill definition
	CapabilityIDs []string       `json:"capability_ids"` // Capabilities this skill uses
	EffectTypes   []string       `json:"effect_types"`   // Effect types this skill produces
	MaxRiskClass  string         `json:"max_risk_class"` // Highest risk class of effects
	CreatedAt     time.Time      `json:"created_at"`
	PromotedAt    *time.Time     `json:"promoted_at,omitempty"`
	Status        string         `json:"status"` // "ACTIVE", "SUSPENDED", "RETIRED"
}

// SkillProposal is a request to create or update a skill.
type SkillProposal struct {
	ProposalID   string     `json:"proposal_id"`
	SkillID      string     `json:"skill_id"` // Empty for new skills
	Name         string     `json:"name"`
	Description  string     `json:"description"`
	Class        SkillClass `json:"class"`
	AuthorID     string     `json:"author_id"`
	Definition   []byte     `json:"definition"` // Raw skill definition (JSON)
	ContentHash  string     `json:"content_hash"`
	Status       string     `json:"status"` // "PENDING", "APPROVED", "REJECTED"
	CreatedAt    time.Time  `json:"created_at"`
	ReviewedAt   *time.Time `json:"reviewed_at,omitempty"`
	ReviewedBy   string     `json:"reviewed_by,omitempty"`
	RejectReason string     `json:"reject_reason,omitempty"`
}

// PromotionRequest is a request to promote a skill from one level to the next.
type PromotionRequest struct {
	RequestID      string         `json:"request_id"`
	SkillID        string         `json:"skill_id"`
	FromLevel      PromotionLevel `json:"from_level"`
	ToLevel        PromotionLevel `json:"to_level"`
	RequestedBy    string         `json:"requested_by"`          // VirtualEmployee
	ApprovedBy     string         `json:"approved_by,omitempty"` // Manager (required for C1->C2, C2->C3)
	EvalResult     *EvalResult    `json:"eval_result,omitempty"`
	Status         string         `json:"status"` // "PENDING", "APPROVED", "REJECTED", "ROLLED_BACK"
	CreatedAt      time.Time      `json:"created_at"`
	ResolvedAt     *time.Time     `json:"resolved_at,omitempty"`
	ProofGraphNode string         `json:"proofgraph_node,omitempty"`
}

// EvalResult captures the outcome of sandbox/canary evaluation.
type EvalResult struct {
	EvalID      string         `json:"eval_id"`
	SkillID     string         `json:"skill_id"`
	Level       PromotionLevel `json:"level"`
	Passed      bool           `json:"passed"`
	Score       float64        `json:"score"` // 0.0-1.0
	ErrorCount  int            `json:"error_count"`
	SampleSize  int            `json:"sample_size"`
	Duration    time.Duration  `json:"duration"`
	Details     string         `json:"details,omitempty"`
	CompletedAt time.Time      `json:"completed_at"`
}

// SkillLineageEntry records a change in the skill's history.
type SkillLineageEntry struct {
	EntryID        string         `json:"entry_id"`
	SkillID        string         `json:"skill_id"`
	Version        int            `json:"version"`
	Action         string         `json:"action"` // "CREATED", "PROMOTED", "ROLLED_BACK", "SUSPENDED", "RETIRED"
	FromLevel      PromotionLevel `json:"from_level,omitempty"`
	ToLevel        PromotionLevel `json:"to_level,omitempty"`
	ActorID        string         `json:"actor_id"`
	ContentHash    string         `json:"content_hash"`
	ProofGraphNode string         `json:"proofgraph_node"`
	Timestamp      time.Time      `json:"timestamp"`
}
