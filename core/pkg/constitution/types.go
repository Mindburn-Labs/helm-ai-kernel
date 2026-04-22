// Package constitution provides Constitutional AI integration for HELM governance.
//
// A Constitution declares an agent's values and behavioral principles.
// The Aligner converts those principles into HELM policy constraints (CEL expressions)
// so that governance decisions are co-designed with the agent's declared values
// rather than imposed externally.
package constitution

import "time"

// Constitution represents an agent's declared values and principles.
type Constitution struct {
	ConstitutionID string      `json:"constitution_id"`
	AgentID        string      `json:"agent_id"`
	Version        string      `json:"version"`
	Principles     []Principle `json:"principles"`
	CreatedAt      time.Time   `json:"created_at"`
	ContentHash    string      `json:"content_hash"`
}

// Principle is a single value or behavioral guideline.
type Principle struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Priority    int      `json:"priority"`    // 1 = highest priority
	Category    string   `json:"category"`    // "safety", "privacy", "helpfulness", "honesty", "fairness"
	Constraints []string `json:"constraints"` // CEL expressions derived from this principle
}

// AlignmentScore measures how well a governance decision aligns with the constitution.
type AlignmentScore struct {
	ConstitutionID  string              `json:"constitution_id"`
	OverallScore    float64             `json:"overall_score"`    // 0.0-1.0
	PrincipleScores map[string]float64  `json:"principle_scores"` // principleID -> score
	Conflicts       []AlignmentConflict `json:"conflicts,omitempty"`
}

// AlignmentConflict describes a tension between governance and constitution.
type AlignmentConflict struct {
	PrincipleID string `json:"principle_id"`
	Action      string `json:"action"` // what the agent wanted to do
	Reason      string `json:"reason"` // why governance blocked/allowed it
	Resolution  string `json:"resolution"`
}

// PolicyConstraint is a governance rule derived from a constitutional principle.
type PolicyConstraint struct {
	PrincipleID string `json:"principle_id"`
	Expression  string `json:"expression"` // CEL expression
	Action      string `json:"action"`     // "deny", "require_approval", "audit"
	Priority    int    `json:"priority"`
}

// ValidCategories lists the canonical principle categories.
var ValidCategories = map[string]bool{
	"safety":      true,
	"privacy":     true,
	"helpfulness": true,
	"honesty":     true,
	"fairness":    true,
}
