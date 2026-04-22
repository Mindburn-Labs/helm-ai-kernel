// Package intent provides the Intent Studio for structured intent capture.
// Per Section 3.1 - captures user decisions via structured cards and compiles to IntentTicket.v1.
package intent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
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

// NewStudio creates a new Intent Studio.
func NewStudio() *Studio {
	return &Studio{
		cardTemplates: defaultCardTemplates(),
		validator:     NewIntentValidator(),
	}
}

// StartSession begins a new intent capture session.
func (s *Studio) StartSession(ctx context.Context) *IntentSession {
	session := &IntentSession{
		SessionID: uuid.New().String(),
		StartedAt: time.Now(),
		UpdatedAt: time.Now(),
		Cards:     s.generateInitialCards(),
		Decisions: make(map[string]*CardAnswer),
		Diffs:     []SessionDiff{},
		Status:    "active",
	}
	return session
}

// CaptureDecision records a user's answer to a decision card.
func (s *Studio) CaptureDecision(session *IntentSession, cardID string, answer *CardAnswer) error {
	session.mu.Lock()
	defer session.mu.Unlock()

	// Find the card
	var card *DecisionCard
	for i := range session.Cards {
		if session.Cards[i].CardID == cardID {
			card = &session.Cards[i]
			break
		}
	}
	if card == nil {
		return fmt.Errorf("card not found: %s", cardID)
	}

	// Validate answer against constraints
	if err := s.validator.ValidateAnswer(card, answer); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// Record diff
	oldAnswer := session.Decisions[cardID]
	changeType := "answered"
	if oldAnswer != nil {
		changeType = "modified"
	}
	session.Diffs = append(session.Diffs, SessionDiff{
		Timestamp:  time.Now(),
		CardID:     cardID,
		ChangeType: changeType,
		OldValue:   oldAnswer,
		NewValue:   answer,
	})

	// Store decision
	answer.Timestamp = time.Now()
	session.Decisions[cardID] = answer
	card.Answer = answer
	session.UpdatedAt = time.Now()

	return nil
}

// Compile converts the session into a validated IntentTicket.
func (s *Studio) Compile(session *IntentSession) (*IntentTicket, error) {
	session.mu.RLock()
	defer session.mu.RUnlock()

	// Validate all required cards are answered
	for _, card := range session.Cards {
		if card.Required && session.Decisions[card.CardID] == nil {
			return nil, fmt.Errorf("required card not answered: %s", card.CardID)
		}
	}

	// Build ticket from decisions
	ticket := &IntentTicket{
		TicketID:  uuid.New().String(),
		Version:   "1.0.0",
		SessionID: session.SessionID,
		CreatedAt: time.Now(),
	}

	// Extract constraints from decisions
	if err := s.extractConstraints(session, ticket); err != nil {
		return nil, fmt.Errorf("failed to extract constraints: %w", err)
	}

	// Extract context
	if err := s.extractContext(session, ticket); err != nil {
		return nil, fmt.Errorf("failed to extract context: %w", err)
	}

	// Determine required approvals based on constraints
	ticket.ApprovalRequired = s.determineApprovals(ticket)

	// Compute deterministic hash
	hash, err := s.computeHash(ticket)
	if err != nil {
		return nil, fmt.Errorf("failed to compute hash: %w", err)
	}
	ticket.Hash = hash

	session.Status = "completed"

	return ticket, nil
}

// extractConstraints builds IntentConstraints from session decisions.
func (s *Studio) extractConstraints(session *IntentSession, ticket *IntentTicket) error {
	ticket.Constraints = IntentConstraints{}

	// Budget
	if answer, ok := session.Decisions["budget"]; ok && answer != nil {
		if sv := answer.StructuredValue; sv != nil {
			ticket.Constraints.Budget = &BudgetConstraint{
				MaxMonthly:   getFloat(sv, "max_monthly", 0),
				MaxPerEffect: getFloat(sv, "max_per_effect", 0),
				Currency:     getString(sv, "currency", "USD"),
				AlertAt:      getFloat(sv, "alert_at_percent", 80),
			}
		}
	}

	// Risk
	if answer, ok := session.Decisions["risk_tolerance"]; ok && answer != nil {
		if len(answer.SelectedOptions) > 0 {
			ticket.Constraints.Risk = &RiskConstraint{
				Level: answer.SelectedOptions[0],
			}
		}
	}

	// Prohibitions
	if answer, ok := session.Decisions["prohibitions"]; ok && answer != nil {
		ticket.Constraints.Prohibitions = answer.SelectedOptions
	}

	return nil
}

// extractContext builds IntentContext from session decisions.
func (s *Studio) extractContext(session *IntentSession, ticket *IntentTicket) error {
	ticket.Context = IntentContext{}

	if answer, ok := session.Decisions["jurisdiction"]; ok && answer != nil {
		if len(answer.SelectedOptions) > 0 {
			ticket.Context.Jurisdiction = answer.SelectedOptions[0]
		}
	}

	if answer, ok := session.Decisions["industry"]; ok && answer != nil {
		if len(answer.SelectedOptions) > 0 {
			ticket.Context.Industry = answer.SelectedOptions[0]
		}
	}

	if answer, ok := session.Decisions["assets"]; ok && answer != nil {
		ticket.Context.Assets = answer.SelectedOptions
	}

	return nil
}

// determineApprovals derives required approvals from constraints.
func (s *Studio) determineApprovals(ticket *IntentTicket) []ApprovalCheckpoint {
	approvals := []ApprovalCheckpoint{}

	// High-risk effects always need approval
	if ticket.Constraints.Risk != nil && ticket.Constraints.Risk.Level == "low" {
		approvals = append(approvals, ApprovalCheckpoint{
			Type:        "effect_type",
			Description: "Approve irreversible effects",
			Condition:   "classification.reversibility == 'irreversible'",
		})
	}

	// Budget threshold approvals
	if ticket.Constraints.Budget != nil && ticket.Constraints.Budget.MaxPerEffect > 0 {
		approvals = append(approvals, ApprovalCheckpoint{
			Type: "threshold",
			Description: fmt.Sprintf("Approve effects exceeding %.2f %s",
				ticket.Constraints.Budget.MaxPerEffect,
				ticket.Constraints.Budget.Currency),
			Condition: fmt.Sprintf("effect.cost > %v", ticket.Constraints.Budget.MaxPerEffect),
		})
	}

	return approvals
}

// computeHash creates deterministic hash of the ticket using JCS canonicalization.
func (s *Studio) computeHash(ticket *IntentTicket) (string, error) {
	// Create canonical representation (excluding Hash field)
	canonical := struct {
		TicketID    string            `json:"ticket_id"`
		Version     string            `json:"version"`
		SessionID   string            `json:"session_id"`
		Constraints IntentConstraints `json:"constraints"`
		Context     IntentContext     `json:"context"`
	}{
		TicketID:    ticket.TicketID,
		Version:     ticket.Version,
		SessionID:   ticket.SessionID,
		Constraints: ticket.Constraints,
		Context:     ticket.Context,
	}

	data, err := canonicalize.JCS(canonical)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// generateInitialCards creates the default set of decision cards.
func (s *Studio) generateInitialCards() []DecisionCard {
	cards := []DecisionCard{
		{
			CardID:   "budget",
			Type:     CardTypeBudget,
			Question: "What are your budget constraints?",
			FreeForm: false,
			Required: true,
			Constraints: []Constraint{
				{Type: "min", Field: "max_monthly", Value: 0, Message: "Budget must be positive"},
			},
		},
		{
			CardID:   "risk_tolerance",
			Type:     CardTypeRiskTolerance,
			Question: "What is your risk tolerance?",
			Options: []CardOption{
				{ID: "low", Label: "Low", Description: "Conservative, require approval for most actions"},
				{ID: "medium", Label: "Medium", Description: "Balanced autonomy with oversight"},
				{ID: "high", Label: "High", Description: "Maximum autonomy, minimal intervention"},
			},
			Required: true,
		},
		{
			CardID:   "jurisdiction",
			Type:     CardTypeJurisdiction,
			Question: "What is your primary jurisdiction?",
			Options:  jurisdictionOptions(),
			Required: true,
		},
		{
			CardID:   "industry",
			Type:     CardTypeIndustry,
			Question: "What industry are you operating in?",
			Options:  industryOptions(),
			Required: true,
		},
		{
			CardID:   "prohibitions",
			Type:     CardTypeProhibitions,
			Question: "Are there any actions the system should never take?",
			FreeForm: true,
			Required: false,
		},
	}
	return cards
}

func defaultCardTemplates() map[DecisionCardType][]DecisionCard {
	return make(map[DecisionCardType][]DecisionCard)
}

func jurisdictionOptions() []CardOption {
	return []CardOption{
		{ID: "US", Label: "United States"},
		{ID: "GB", Label: "United Kingdom"},
		{ID: "DE", Label: "Germany"},
		{ID: "EU", Label: "European Union"},
		{ID: "SG", Label: "Singapore"},
		{ID: "JP", Label: "Japan"},
	}
}

func industryOptions() []CardOption {
	return []CardOption{
		{ID: "fintech", Label: "Financial Technology"},
		{ID: "ecommerce", Label: "E-Commerce"},
		{ID: "saas", Label: "Software as a Service"},
		{ID: "healthcare", Label: "Healthcare"},
		{ID: "media", Label: "Media & Entertainment"},
	}
}

// Helper functions for type-safe value extraction
func getFloat(m map[string]interface{}, key string, def float64) float64 {
	if v, ok := m[key]; ok {
		switch val := v.(type) {
		case float64:
			return val
		case int:
			return float64(val)
		}
	}
	return def
}

func getString(m map[string]interface{}, key string, def string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return def
}

// IntentValidator validates decision card answers.
type IntentValidator struct{}

// NewIntentValidator creates a new validator.
func NewIntentValidator() *IntentValidator {
	return &IntentValidator{}
}

// ValidateAnswer checks if an answer satisfies card constraints.
func (v *IntentValidator) ValidateAnswer(card *DecisionCard, answer *CardAnswer) error {
	if card.Required && answer == nil {
		return errors.New("answer is required")
	}

	for _, constraint := range card.Constraints {
		if err := v.validateConstraint(constraint, answer); err != nil {
			return err
		}
	}

	// Validate selected options exist
	if len(answer.SelectedOptions) > 0 && len(card.Options) > 0 {
		validOptions := make(map[string]bool)
		for _, opt := range card.Options {
			validOptions[opt.ID] = true
		}
		for _, selected := range answer.SelectedOptions {
			if !validOptions[selected] {
				return fmt.Errorf("invalid option: %s", selected)
			}
		}
	}

	return nil
}

func (v *IntentValidator) validateConstraint(c Constraint, answer *CardAnswer) error {
	if answer == nil || answer.StructuredValue == nil {
		return nil
	}

	switch c.Type {
	case "min":
		val := getFloat(answer.StructuredValue, c.Field, 0)
		min := toFloat(c.Value)
		if val < min {
			return errors.New(c.Message)
		}
	case "max":
		val := getFloat(answer.StructuredValue, c.Field, 0)
		max := toFloat(c.Value)
		if val > max {
			return errors.New(c.Message)
		}
	}

	return nil
}

// toFloat converts interface{} to float64 safely
func toFloat(v interface{}) float64 {
	switch val := v.(type) {
	case float64:
		return val
	case int:
		return float64(val)
	case int64:
		return float64(val)
	default:
		return 0
	}
}
