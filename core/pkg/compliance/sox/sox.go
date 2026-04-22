// Package sox implements SOX (Sarbanes-Oxley) compliance profile.
package sox

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ── SOX Types ─────────────────────────────────────────────────

// ControlType classifies internal controls per SOX Section 302/404.
type ControlType string

const (
	ControlPreventive ControlType = "PREVENTIVE"
	ControlDetective  ControlType = "DETECTIVE"
	ControlCorrective ControlType = "CORRECTIVE"
)

// ControlEffectiveness tracks the testing outcome of a control.
type ControlEffectiveness string

const (
	EffectivenessOperating   ControlEffectiveness = "OPERATING_EFFECTIVELY"
	EffectivenessDeficiency  ControlEffectiveness = "DEFICIENCY"
	EffectivenessWeakness    ControlEffectiveness = "MATERIAL_WEAKNESS"
	EffectivenessSignificant ControlEffectiveness = "SIGNIFICANT_DEFICIENCY"
)

// InternalControl represents an ICFR (Internal Control over Financial Reporting).
type InternalControl struct {
	ID            string               `json:"id"`
	Name          string               `json:"name"`
	Type          ControlType          `json:"type"`
	Section       string               `json:"section"` // SOX section reference (302, 404, etc.)
	Process       string               `json:"process"` // Business process
	Owner         string               `json:"owner"`
	Description   string               `json:"description"`
	Effectiveness ControlEffectiveness `json:"effectiveness"`
	LastTested    time.Time            `json:"last_tested"`
	TestFrequency string               `json:"test_frequency"` // QUARTERLY, ANNUALLY
	EvidenceRefs  []string             `json:"evidence_refs"`
}

// AuditTrail represents a SOX-compliant audit trail entry.
type AuditTrail struct {
	ID            string    `json:"id"`
	Timestamp     time.Time `json:"timestamp"`
	Actor         string    `json:"actor"`
	Action        string    `json:"action"`
	Resource      string    `json:"resource"`
	OldValue      string    `json:"old_value,omitempty"`
	NewValue      string    `json:"new_value,omitempty"`
	Justification string    `json:"justification,omitempty"`
}

// DutySegregation represents a segregation of duties (SoD) rule.
type DutySegregation struct {
	ID          string `json:"id"`
	RoleA       string `json:"role_a"`
	RoleB       string `json:"role_b"`
	Description string `json:"description"`
	Enforced    bool   `json:"enforced"`
}

// ── SOX Engine ────────────────────────────────────────────────

// SOXEngine manages SOX compliance requirements.
type SOXEngine struct {
	mu         sync.RWMutex
	controls   map[string]*InternalControl
	auditTrail []AuditTrail
	sodRules   []DutySegregation
}

// NewSOXEngine creates a new SOX compliance engine.
func NewSOXEngine() *SOXEngine {
	return &SOXEngine{
		controls: make(map[string]*InternalControl),
	}
}

// RegisterControl registers an internal control.
func (e *SOXEngine) RegisterControl(_ context.Context, ctrl *InternalControl) error {
	if ctrl.Name == "" {
		return fmt.Errorf("control name is required")
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.controls[ctrl.ID] = ctrl
	return nil
}

// RecordAuditEntry records an audit trail entry.
func (e *SOXEngine) RecordAuditEntry(_ context.Context, entry AuditTrail) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.auditTrail = append(e.auditTrail, entry)
}

// CheckSoD validates that a proposed action does not violate segregation of duties.
func (e *SOXEngine) CheckSoD(roleA, roleB string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, rule := range e.sodRules {
		if rule.Enforced {
			if (rule.RoleA == roleA && rule.RoleB == roleB) ||
				(rule.RoleA == roleB && rule.RoleB == roleA) {
				return false // Conflict found
			}
		}
	}
	return true // No conflicts
}

// AddSoDRule adds a segregation of duties rule.
func (e *SOXEngine) AddSoDRule(rule DutySegregation) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sodRules = append(e.sodRules, rule)
}

// GetStatus returns SOX compliance summary.
func (e *SOXEngine) GetStatus() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	weaknesses := 0
	deficiencies := 0
	for _, c := range e.controls {
		switch c.Effectiveness {
		case EffectivenessWeakness:
			weaknesses++
		case EffectivenessDeficiency, EffectivenessSignificant:
			deficiencies++
		}
	}

	return map[string]interface{}{
		"total_controls":      len(e.controls),
		"material_weaknesses": weaknesses,
		"deficiencies":        deficiencies,
		"audit_trail_entries": len(e.auditTrail),
		"sod_rules":           len(e.sodRules),
	}
}
