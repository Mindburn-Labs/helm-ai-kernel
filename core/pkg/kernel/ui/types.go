package ui

import "time"

// UIInteraction represents an operator action in the UI.
type UIInteraction struct {
	InteractionID string    `json:"interaction_id"`
	ComponentID   string    `json:"component_id"`
	Timestamp     time.Time `json:"timestamp"`
	Payload       string    `json:"payload"`
	UserRef       string    `json:"user_ref"`
}

// Proposal represents a state change request derived from an interaction.
type Proposal struct {
	ProposalID    string          `json:"proposal_id"`
	InteractionID string          `json:"interaction_id"`
	EffectType    string          `json:"effect_type"`
	EffectPayload interface{}     `json:"effect_payload"`
	Context       ProposalContext `json:"context"`
}

type ProposalContext struct {
	JurisdictionID string `json:"jurisdiction_id"`
	SessionID      string `json:"session_id"`
}
