// Package intent provides the Intent Studio for structured intent capture.
// Per Section 3.1 - captures user decisions via structured cards and compiles to IntentTicket.v1.
package intent

import (
	"sync"
	"time"
)

// DecisionCardType defines the category of decision being captured.
type DecisionCardType string

const (
	CardTypeBudget        DecisionCardType = "budget"
	CardTypeRiskTolerance DecisionCardType = "risk_tolerance"
	CardTypeJurisdiction  DecisionCardType = "jurisdiction"
	CardTypeIndustry      DecisionCardType = "industry"
	CardTypeTimeline      DecisionCardType = "timeline"
	CardTypeAssets        DecisionCardType = "assets"
	CardTypeProhibitions  DecisionCardType = "prohibitions"
	CardTypeCustom        DecisionCardType = "custom"
)

// DecisionCard represents a structured prompt for capturing user decisions.
type DecisionCard struct {
	CardID      string           `json:"card_id"`
	Type        DecisionCardType `json:"type"`
	Question    string           `json:"question"`
	Options     []CardOption     `json:"options,omitempty"`
	FreeForm    bool             `json:"free_form"`
	Required    bool             `json:"required"`
	Constraints []Constraint     `json:"constraints,omitempty"`
	Answer      *CardAnswer      `json:"answer,omitempty"`
}

// CardOption represents a selectable option for a decision card.
type CardOption struct {
	ID          string                 `json:"id"`
	Label       string                 `json:"label"`
	Description string                 `json:"description,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// CardAnswer holds the user's response to a decision card.
type CardAnswer struct {
	SelectedOptions []string               `json:"selected_options,omitempty"`
	FreeFormValue   string                 `json:"free_form_value,omitempty"`
	StructuredValue map[string]interface{} `json:"structured_value,omitempty"`
	Timestamp       time.Time              `json:"timestamp"`
}

// Constraint defines a validation rule for card answers.
type Constraint struct {
	Type    string      `json:"type"` // min, max, required, pattern, enum
	Field   string      `json:"field,omitempty"`
	Value   interface{} `json:"value"`
	Message string      `json:"message"`
}

// IntentSession accumulates decisions during an intent capture session.
type IntentSession struct {
	SessionID string                 `json:"session_id"`
	StartedAt time.Time              `json:"started_at"`
	UpdatedAt time.Time              `json:"updated_at"`
	Cards     []DecisionCard         `json:"cards"`
	Decisions map[string]*CardAnswer `json:"decisions"` // cardID -> answer
	Diffs     []SessionDiff          `json:"diffs"`
	Status    string                 `json:"status"` // active, completed, abandoned
	mu        sync.RWMutex
}

// SessionDiff records changes in the session for visibility.
type SessionDiff struct {
	Timestamp  time.Time   `json:"timestamp"`
	CardID     string      `json:"card_id"`
	ChangeType string      `json:"change_type"` // answered, modified, cleared
	OldValue   interface{} `json:"old_value,omitempty"`
	NewValue   interface{} `json:"new_value,omitempty"`
}

// IntentTicket is the compiled output of an intent session.
type IntentTicket struct {
	TicketID  string    `json:"ticket_id"`
	Version   string    `json:"version"`
	SessionID string    `json:"session_id"`
	CreatedAt time.Time `json:"created_at"`

	// Core intent data
	Intent      string            `json:"intent"`
	Constraints IntentConstraints `json:"constraints"`
	Context     IntentContext     `json:"context"`

	// Sovereignty checkpoints
	ApprovalRequired []ApprovalCheckpoint `json:"approval_required"`

	// Hash for determinism
	Hash string `json:"hash"`
}

// IntentConstraints captures all constraint decisions.
type IntentConstraints struct {
	Budget       *BudgetConstraint   `json:"budget,omitempty"`
	Risk         *RiskConstraint     `json:"risk,omitempty"`
	Timeline     *TimelineConstraint `json:"timeline,omitempty"`
	Prohibitions []string            `json:"prohibitions,omitempty"`
}

// BudgetConstraint defines spending limits.
type BudgetConstraint struct {
	MaxMonthly   float64 `json:"max_monthly"`
	MaxPerEffect float64 `json:"max_per_effect"`
	Currency     string  `json:"currency"`
	AlertAt      float64 `json:"alert_at_percent"`
}

// RiskConstraint defines acceptable risk levels.
type RiskConstraint struct {
	Level             string   `json:"level"` // low, medium, high
	AllowIrreversible bool     `json:"allow_irreversible"`
	RequireApproval   []string `json:"require_approval"` // effect types
}

// TimelineConstraint defines time boundaries.
type TimelineConstraint struct {
	Deadline   *time.Time `json:"deadline,omitempty"`
	Priority   string     `json:"priority"` // urgent, standard, flexible
	Milestones []string   `json:"milestones,omitempty"`
}

// IntentContext captures jurisdiction, industry, and assets.
type IntentContext struct {
	Jurisdiction string   `json:"jurisdiction"` // ISO 3166-1 alpha-2
	Industry     string   `json:"industry"`
	Assets       []string `json:"assets,omitempty"`
}

// ApprovalCheckpoint defines a sovereignty checkpoint requiring explicit approval.
type ApprovalCheckpoint struct {
	Type        string `json:"type"` // effect_type, threshold, external
	Description string `json:"description"`
	Condition   string `json:"condition"`
}

// Studio is the main Intent Studio controller.
type Studio struct {
	cardTemplates map[DecisionCardType][]DecisionCard
	validator     *IntentValidator
}

// IntentValidator validates decision card answers.
type IntentValidator struct{}
