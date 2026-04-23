// Package governance — JurisdictionResolver.
//
// Per HELM 2030 Spec §1.7 — Jurisdiction-Native Operation:
//
//	Every intent/effect is bound to a deterministic jurisdiction context
//	(entity, counterparty, data subject, service region, time).
//	Conflicts are preserved and resolved as governed decisions with receipts.
package governance

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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

// NewJurisdictionResolver creates a new resolver.
func NewJurisdictionResolver() *JurisdictionResolver {
	return &JurisdictionResolver{
		rules: make([]JurisdictionRule, 0),
		clock: time.Now,
	}
}

// WithClock overrides clock for testing.
func (r *JurisdictionResolver) WithClock(clock func() time.Time) *JurisdictionResolver {
	r.clock = clock
	return r
}

// AddRule registers a jurisdiction rule.
func (r *JurisdictionResolver) AddRule(rule JurisdictionRule) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rules = append(r.rules, rule)
}

// Resolve binds an intent to a jurisdiction context.
// Resolution uses priority-based precedence. When multiple rules match
// and the highest-priority rules have conflicting regimes at the same
// priority level, the regime is left empty — forcing escalation.
func (r *JurisdictionResolver) Resolve(entity, counterparty, dataSubject, serviceRegion string) (*JurisdictionContext, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if entity == "" || serviceRegion == "" {
		return nil, fmt.Errorf("entity and service_region required for jurisdiction binding")
	}

	r.seq++
	now := r.clock()

	// Find applicable rules
	var applicable []JurisdictionRule
	for _, rule := range r.rules {
		if rule.Region == serviceRegion || rule.Region == "*" {
			applicable = append(applicable, rule)
		}
	}

	if len(applicable) == 0 {
		return nil, fmt.Errorf("no jurisdiction rules for region %q", serviceRegion)
	}

	// Detect conflicts
	var conflicts []JurisdictionConflict
	for i := 0; i < len(applicable); i++ {
		for j := i + 1; j < len(applicable); j++ {
			if applicable[i].LegalRegime != applicable[j].LegalRegime {
				conflicts = append(conflicts, JurisdictionConflict{
					ConflictID:  fmt.Sprintf("jc-%d-%d", i, j),
					RuleA:       applicable[i].RuleID,
					RuleB:       applicable[j].RuleID,
					Description: fmt.Sprintf("regime conflict: %s vs %s", applicable[i].LegalRegime, applicable[j].LegalRegime),
				})
			}
		}
	}

	// Priority-based resolution: find the highest priority among applicable rules.
	highestPriority := applicable[0].Priority
	for _, r := range applicable[1:] {
		if r.Priority > highestPriority {
			highestPriority = r.Priority
		}
	}

	// Collect all rules at the highest priority level.
	var topRules []JurisdictionRule
	for _, r := range applicable {
		if r.Priority == highestPriority {
			topRules = append(topRules, r)
		}
	}

	// Check for conflicting regimes at the top priority level.
	regime := topRules[0].LegalRegime
	for _, r := range topRules[1:] {
		if r.LegalRegime != regime {
			// Equal-priority conflict — cannot auto-resolve. Force escalation.
			// Leave regime empty; caller MUST escalate to human review.
			regime = ""
			for i := range conflicts {
				conflicts[i].Resolution = "ESCALATE: equal-priority conflict requires human review"
			}
			break
		}
	}

	contextID := fmt.Sprintf("jctx-%d", r.seq)
	hashInput := fmt.Sprintf("%s:%s:%s:%s:%s", contextID, entity, serviceRegion, regime, now.String())
	h := sha256.Sum256([]byte(hashInput))

	return &JurisdictionContext{
		ContextID:     contextID,
		Entity:        entity,
		Counterparty:  counterparty,
		DataSubject:   dataSubject,
		ServiceRegion: serviceRegion,
		LegalRegime:   regime,
		Timestamp:     now,
		Conflicts:     conflicts,
		ContentHash:   "sha256:" + hex.EncodeToString(h[:]),
	}, nil
}
