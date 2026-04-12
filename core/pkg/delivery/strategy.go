// Package delivery implements progressive delivery strategies for HELM releases.
//
// Supports shadow (mirror traffic, compare outputs), canary (progressive traffic
// shift), and blue-green (instant cutover with rollback) deployment patterns.
// Every delivery plan is content-hashed via JCS canonicalization, and the
// controller integrates with SLO-based promotion gates and automatic rollback.
package delivery

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
)

// DeliveryStrategy defines the rollout approach.
type DeliveryStrategy string

const (
	StrategyShadow    DeliveryStrategy = "SHADOW"     // mirror traffic, compare outputs
	StrategyCanary    DeliveryStrategy = "CANARY"     // progressive traffic shift
	StrategyBlueGreen DeliveryStrategy = "BLUE_GREEN" // instant cutover with rollback
)

// DeliveryStatus tracks the lifecycle of a delivery.
type DeliveryStatus string

const (
	DeliveryPending    DeliveryStatus = "PENDING"
	DeliveryInProgress DeliveryStatus = "IN_PROGRESS"
	DeliveryPromoted   DeliveryStatus = "PROMOTED"
	DeliveryRolledBack DeliveryStatus = "ROLLED_BACK"
	DeliveryFailed     DeliveryStatus = "FAILED"
)

// DeliveryPlan defines a progressive rollout.
type DeliveryPlan struct {
	PlanID       string           `json:"plan_id"`
	Strategy     DeliveryStrategy `json:"strategy"`
	Stages       []DeliveryStage  `json:"stages"`
	Rollback     RollbackPolicy   `json:"rollback"`
	Status       DeliveryStatus   `json:"status"`
	CurrentStage int              `json:"current_stage"`
	StartedAt    time.Time        `json:"started_at,omitempty"`
	CompletedAt  time.Time        `json:"completed_at,omitempty"`
	ContentHash  string           `json:"content_hash"`
}

// DeliveryStage is one phase of a progressive rollout.
type DeliveryStage struct {
	StageID     string          `json:"stage_id"`
	Weight      int             `json:"weight"`       // traffic percentage (0-100)
	MinDuration time.Duration   `json:"min_duration"` // minimum soak time
	AutoPromote bool            `json:"auto_promote"` // auto-advance if metrics pass
	GateMetrics []PromotionGate `json:"gate_metrics"` // SLO gates for promotion
	Status      DeliveryStatus  `json:"status"`
	EnteredAt   time.Time       `json:"entered_at,omitempty"`
}

// PromotionGate defines a metric threshold for stage promotion.
type PromotionGate struct {
	MetricName string  `json:"metric_name"` // "error_rate", "p99_latency_ms", "success_rate"
	Threshold  float64 `json:"threshold"`
	Operator   string  `json:"operator"` // "lt", "gt", "lte", "gte"
}

// RollbackPolicy defines when to automatically roll back.
type RollbackPolicy struct {
	AutoRollback bool                `json:"auto_rollback"`
	Conditions   []RollbackCondition `json:"conditions"`
}

// RollbackCondition triggers automatic rollback.
type RollbackCondition struct {
	MetricName string  `json:"metric_name"`
	Threshold  float64 `json:"threshold"`
	Operator   string  `json:"operator"` // "gt", "lt", "gte", "lte"
}

// ShadowResult captures output comparison from shadow mode.
type ShadowResult struct {
	RequestID       string    `json:"request_id"`
	CurrentOutput   string    `json:"current_output_hash"`
	CandidateOutput string    `json:"candidate_output_hash"`
	Diverged        bool      `json:"diverged"`
	Timestamp       time.Time `json:"timestamp"`
}

// ComputeHash computes a JCS-canonical SHA-256 content hash of the plan.
// The content_hash field is excluded from the hash input to avoid circularity.
func (p *DeliveryPlan) ComputeHash() {
	saved := p.ContentHash
	p.ContentHash = ""
	data, err := canonicalize.JCS(p)
	p.ContentHash = saved
	if err != nil {
		return
	}
	h := sha256.Sum256(data)
	p.ContentHash = "sha256:" + hex.EncodeToString(h[:])
}
