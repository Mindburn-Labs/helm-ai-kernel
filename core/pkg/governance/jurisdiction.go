// Package governance — JurisdictionResolver.
//
// Per HELM 2030 Spec §1.7 — Jurisdiction-Native Operation:
//
//	Every intent/effect is bound to a deterministic jurisdiction context
//	(entity, counterparty, data subject, service region, time).
//	Conflicts are preserved and resolved as governed decisions with receipts.
package governance

import (
	"sync"
	"time"
)

// JurisdictionContext is the deterministic jurisdiction binding for an intent.
type JurisdictionContext struct {
	ContextID     string                 `json:"context_id"`
	Entity        string                 `json:"entity"`
	Counterparty  string                 `json:"counterparty,omitempty"`
	DataSubject   string                 `json:"data_subject,omitempty"`
	ServiceRegion string                 `json:"service_region"`
	LegalRegime   string                 `json:"legal_regime"` // e.g. "EU/GDPR", "US/CCPA", "UK/FCA"
	Timestamp     time.Time              `json:"timestamp"`
	Conflicts     []JurisdictionConflict `json:"conflicts,omitempty"`
	ContentHash   string                 `json:"content_hash"`
}

// JurisdictionConflict records a conflict between jurisdiction rules.
type JurisdictionConflict struct {
	ConflictID  string `json:"conflict_id"`
	RuleA       string `json:"rule_a"`
	RuleB       string `json:"rule_b"`
	Description string `json:"description"`
	Resolution  string `json:"resolution,omitempty"` // empty = unresolved
	ResolvedBy  string `json:"resolved_by,omitempty"`
}

// JurisdictionRule defines a rule for jurisdiction binding.
type JurisdictionRule struct {
	RuleID      string `json:"rule_id"`
	LegalRegime string `json:"legal_regime"`
	Region      string `json:"region"`
	DataClass   string `json:"data_class,omitempty"` // PII, financial, health, etc.
	Requirement string `json:"requirement"`
	Priority    int    `json:"priority"` // Higher priority wins (0 = default)
}

// JurisdictionResolver binds intents to jurisdiction contexts.
type JurisdictionResolver struct {
	mu    sync.Mutex
	rules []JurisdictionRule
	seq   int64
	clock func() time.Time
}
