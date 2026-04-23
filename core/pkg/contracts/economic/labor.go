// Package economic — Labor accounting.
//
// Per HELM 2030 Spec §5.7:
//
//	Every autonomous action has a cost. LaborRecord tracks the cost of
//	work performed by humans, agents, services, and robots.
package economic

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// ActorType classifies who performed the work.
type ActorType string

const (
	ActorHuman   ActorType = "HUMAN"
	ActorAgent   ActorType = "AGENT"
	ActorService ActorType = "SERVICE"
	ActorRobot   ActorType = "ROBOT"
)

// LaborRecord is the canonical record of work performed and its cost.
type LaborRecord struct {
	ID          string            `json:"id"`
	TenantID    string            `json:"tenant_id"`
	ActorType   ActorType         `json:"actor_type"`
	ActorID     string            `json:"actor_id"`
	TaskID      string            `json:"task_id"`
	Description string            `json:"description"`
	Duration    time.Duration     `json:"duration_ns"`
	CostCents   int64             `json:"cost_cents"`
	Currency    string            `json:"currency"`
	EffectID    string            `json:"effect_id,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	RecordedAt  time.Time         `json:"recorded_at"`
	ContentHash string            `json:"content_hash"`
}

// NewLaborRecord creates a labor record with deterministic hash.
func NewLaborRecord(id, tenantID string, actorType ActorType, actorID, taskID, description string, duration time.Duration, costCents int64, currency string) *LaborRecord {
	lr := &LaborRecord{
		ID:          id,
		TenantID:    tenantID,
		ActorType:   actorType,
		ActorID:     actorID,
		TaskID:      taskID,
		Description: description,
		Duration:    duration,
		CostCents:   costCents,
		Currency:    currency,
		RecordedAt:  time.Now().UTC(),
	}
	lr.ContentHash = lr.computeHash()
	return lr
}

// CostAttribution aggregates labor costs by actor type.
type CostAttribution struct {
	TenantID     string    `json:"tenant_id"`
	PeriodStart  time.Time `json:"period_start"`
	PeriodEnd    time.Time `json:"period_end"`
	HumanCents   int64     `json:"human_cost_cents"`
	AgentCents   int64     `json:"agent_cost_cents"`
	ServiceCents int64     `json:"service_cost_cents"`
	RobotCents   int64     `json:"robot_cost_cents"`
	TotalCents   int64     `json:"total_cost_cents"`
	Currency     string    `json:"currency"`
	ContentHash  string    `json:"content_hash"`
}

// NewCostAttribution creates a cost attribution from labor records.
func NewCostAttribution(tenantID, currency string, periodStart, periodEnd time.Time, records []*LaborRecord) *CostAttribution {
	ca := &CostAttribution{
		TenantID:    tenantID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
		Currency:    currency,
	}
	for _, r := range records {
		switch r.ActorType {
		case ActorHuman:
			ca.HumanCents += r.CostCents
		case ActorAgent:
			ca.AgentCents += r.CostCents
		case ActorService:
			ca.ServiceCents += r.CostCents
		case ActorRobot:
			ca.RobotCents += r.CostCents
		}
	}
	ca.TotalCents = ca.HumanCents + ca.AgentCents + ca.ServiceCents + ca.RobotCents
	ca.ContentHash = ca.computeHash()
	return ca
}

// HumanRatio returns the fraction of cost attributable to human labor.
func (ca *CostAttribution) HumanRatio() float64 {
	if ca.TotalCents == 0 {
		return 0
	}
	return float64(ca.HumanCents) / float64(ca.TotalCents)
}

// AgentRatio returns the fraction of cost attributable to agent labor.
func (ca *CostAttribution) AgentRatio() float64 {
	if ca.TotalCents == 0 {
		return 0
	}
	return float64(ca.AgentCents) / float64(ca.TotalCents)
}

// Validate ensures the labor record is well-formed.
func (lr *LaborRecord) Validate() error {
	if lr.ID == "" {
		return errors.New("labor: id is required")
	}
	if lr.TenantID == "" {
		return errors.New("labor: tenant_id is required")
	}
	if lr.ActorID == "" {
		return errors.New("labor: actor_id is required")
	}
	if lr.TaskID == "" {
		return errors.New("labor: task_id is required")
	}
	if lr.CostCents < 0 {
		return errors.New("labor: cost_cents cannot be negative")
	}
	return nil
}

func (lr *LaborRecord) computeHash() string {
	canon, _ := json.Marshal(struct {
		ID       string    `json:"id"`
		TenantID string    `json:"tenant_id"`
		Actor    ActorType `json:"actor_type"`
		ActorID  string    `json:"actor_id"`
		TaskID   string    `json:"task_id"`
		Cost     int64     `json:"cost_cents"`
	}{lr.ID, lr.TenantID, lr.ActorType, lr.ActorID, lr.TaskID, lr.CostCents})
	h := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(h[:])
}

func (ca *CostAttribution) computeHash() string {
	canon, _ := json.Marshal(struct {
		TenantID string `json:"tenant_id"`
		Human    int64  `json:"human"`
		Agent    int64  `json:"agent"`
		Service  int64  `json:"service"`
		Robot    int64  `json:"robot"`
		Total    int64  `json:"total"`
	}{ca.TenantID, ca.HumanCents, ca.AgentCents, ca.ServiceCents, ca.RobotCents, ca.TotalCents})
	h := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(h[:])
}
