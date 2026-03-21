// Package simulation — PolicySandbox.
//
// Per HELM 2030 Spec §5.8:
//
//	The policy sandbox enables simulating policy decisions against an
//	OrgTwin without affecting production state. Used for what-if analysis,
//	rollout validation, and compliance impact assessment.
package simulation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// SimulationResult is the outcome of a simulated policy evaluation.
type SimulationResult struct {
	ScenarioID  string        `json:"scenario_id"`
	Action      string        `json:"action"`
	Decision    string        `json:"decision"` // "ALLOW", "DENY", "ESCALATE"
	Reason      string        `json:"reason"`
	TriggeredBy []string      `json:"triggered_by,omitempty"` // policy IDs that fired
	RiskScore   float64       `json:"risk_score"`
	Duration    time.Duration `json:"duration_ns"`
	ContentHash string        `json:"content_hash"`
}

// WhatIfResult captures the impact of a proposed policy change.
type WhatIfResult struct {
	ProposedChange   string             `json:"proposed_change"`
	BaselineResults  []SimulationResult `json:"baseline_results"`
	ProposedResults  []SimulationResult `json:"proposed_results"`
	FlippedDecisions int                `json:"flipped_decisions"`
	NewDenials       int                `json:"new_denials"`
	RemovedDenials   int                `json:"removed_denials"`
	RiskDelta        float64            `json:"risk_delta"`
	ContentHash      string             `json:"content_hash"`
}

// CostProjection estimates economic impact of simulated actions.
type CostProjection struct {
	ScenarioID     string `json:"scenario_id"`
	ProjectedCents int64  `json:"projected_cost_cents"`
	Currency       string `json:"currency"`
	Category       string `json:"category"`
	BudgetID       string `json:"budget_id,omitempty"`
	ExceedsBudget  bool   `json:"exceeds_budget"`
}

// ComplianceImpact evaluates compliance effects of changes.
type ComplianceImpact struct {
	ChangeDescription string   `json:"change_description"`
	AffectedPolicies  []string `json:"affected_policies"`
	NewViolations     []string `json:"new_violations,omitempty"`
	ResolvedViolations []string `json:"resolved_violations,omitempty"`
	OverallStatus     string   `json:"overall_status"` // "COMPLIANT", "VIOLATION", "UNKNOWN"
}

// DriftReport captures policy drift between snapshot and current state.
type DriftReport struct {
	TwinID         string    `json:"twin_id"`
	DetectedAt     time.Time `json:"detected_at"`
	DriftedPolicies []string `json:"drifted_policies"`
	DriftedRoles    []string `json:"drifted_roles"`
	DriftedBudgets  []string `json:"drifted_budgets"`
	Severity       string    `json:"severity"` // "NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"
}

// RolloutPlan describes a phased policy rollout with simulation results.
type RolloutPlan struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Phases      []RolloutPhase `json:"phases"`
	ContentHash string         `json:"content_hash"`
}

// RolloutPhase is a single phase in a rollout.
type RolloutPhase struct {
	PhaseID     string             `json:"phase_id"`
	Name        string             `json:"name"`
	Scope       string             `json:"scope"` // percentage or group
	Changes     []PolicyRule       `json:"changes"`
	SimResults  []SimulationResult `json:"sim_results,omitempty"`
	Approved    bool               `json:"approved"`
}

// FailureScenario defines injectable failure conditions.
type FailureScenario struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	TargetSystem string `json:"target_system"`
	FailureType  string `json:"failure_type"` // "TIMEOUT", "CRASH", "PARTIAL", "CORRUPT"
	Duration     string `json:"duration"`
	Description  string `json:"description"`
}

// IncidentReplay captures an incident for replay analysis.
type IncidentReplay struct {
	ID            string    `json:"id"`
	OriginalRunID string    `json:"original_run_id"`
	IncidentTime  time.Time `json:"incident_time"`
	Actions       []string  `json:"actions"`
	PolicyState   []PolicyRule `json:"policy_state_at_time"`
	Outcome       string    `json:"outcome"`
}

// DependencyGraph maps inter-service dependencies for impact analysis.
type DependencyGraph struct {
	TenantID string           `json:"tenant_id"`
	Nodes    []DependencyNode `json:"nodes"`
	Edges    []DependencyEdge `json:"edges"`
}

// DependencyNode is a service or component in the dependency graph.
type DependencyNode struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"` // "SERVICE", "AGENT", "VENDOR", "INFRASTRUCTURE"
	Criticality string `json:"criticality"`
}

// DependencyEdge represents a dependency between nodes.
type DependencyEdge struct {
	FromID string `json:"from_id"`
	ToID   string `json:"to_id"`
	Type   string `json:"type"` // "DEPENDS_ON", "CALLS", "DELEGATES_TO"
}

// CapacityEstimate projects resource requirements.
type CapacityEstimate struct {
	ServiceID         string  `json:"service_id"`
	CurrentLoad       float64 `json:"current_load_pct"`
	ProjectedLoad     float64 `json:"projected_load_pct"`
	HeadroomPct       float64 `json:"headroom_pct"`
	ScaleNeeded       bool    `json:"scale_needed"`
	EstimatedCostDelta int64  `json:"estimated_cost_delta_cents"`
}

// SimulateDecision runs a simulated policy evaluation.
func SimulateDecision(twin *OrgTwin, action, actor string) *SimulationResult {
	start := time.Now()
	triggered := []string{}

	// Evaluate each policy in the twin against the action
	decision := "ALLOW"
	var reason string
	var riskScore float64

	for _, p := range twin.Policies {
		if !p.Enabled {
			continue
		}
		for _, et := range p.EffectTypes {
			if et == action || et == "*" {
				triggered = append(triggered, p.ID)
				// Simplified: if any policy matches and has "deny" in expression, deny
				decision = "DENY"
				reason = fmt.Sprintf("policy %s triggered", p.ID)
				riskScore += 0.3
			}
		}
	}

	if len(triggered) == 0 {
		reason = "no policy matched"
	}

	result := &SimulationResult{
		ScenarioID:  fmt.Sprintf("sim-%s-%s", action, actor),
		Action:      action,
		Decision:    decision,
		Reason:      reason,
		TriggeredBy: triggered,
		RiskScore:   riskScore,
		Duration:    time.Since(start),
	}
	result.ContentHash = computeSimHash(result)
	return result
}

func computeSimHash(r *SimulationResult) string {
	canon, _ := json.Marshal(struct {
		Action   string `json:"action"`
		Decision string `json:"decision"`
		Risk     float64 `json:"risk"`
	}{r.Action, r.Decision, r.RiskScore})
	h := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(h[:])
}
