package delivery

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// MetricsProvider supplies current metric values for promotion gates.
type MetricsProvider interface {
	GetMetric(ctx context.Context, metricName string) (float64, error)
}

// DeliveryController manages progressive rollout lifecycle.
type DeliveryController struct {
	mu      sync.Mutex
	plans   map[string]*DeliveryPlan
	metrics MetricsProvider
	clock   func() time.Time
}

// NewDeliveryController creates a new controller backed by the given metrics provider.
func NewDeliveryController(metrics MetricsProvider) *DeliveryController {
	return &DeliveryController{
		plans:   make(map[string]*DeliveryPlan),
		metrics: metrics,
		clock:   func() time.Time { return time.Now() },
	}
}

// WithClock injects a deterministic clock for testing.
func (c *DeliveryController) WithClock(clock func() time.Time) {
	c.clock = clock
}

// Start begins executing a delivery plan.
func (c *DeliveryController) Start(plan *DeliveryPlan) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(plan.Stages) == 0 {
		return fmt.Errorf("delivery plan has no stages")
	}

	plan.Status = DeliveryInProgress
	plan.CurrentStage = 0
	plan.StartedAt = c.clock()
	plan.Stages[0].Status = DeliveryInProgress
	plan.Stages[0].EnteredAt = c.clock()
	plan.ComputeHash()
	c.plans[plan.PlanID] = plan
	return nil
}

// CheckPromotion evaluates whether the current stage can be promoted.
// Returns (canPromote, reason, error). If canPromote is false, reason explains why.
func (c *DeliveryController) CheckPromotion(ctx context.Context, planID string) (bool, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	plan, ok := c.plans[planID]
	if !ok {
		return false, "", fmt.Errorf("plan %s not found", planID)
	}
	if plan.Status != DeliveryInProgress {
		return false, "", fmt.Errorf("plan %s is not in progress (status: %s)", planID, plan.Status)
	}

	stage := &plan.Stages[plan.CurrentStage]

	// Check minimum soak time
	elapsed := c.clock().Sub(stage.EnteredAt)
	if elapsed < stage.MinDuration {
		return false, fmt.Sprintf("soak time remaining: %s", stage.MinDuration-elapsed), nil
	}

	// Check all gate metrics
	for _, gate := range stage.GateMetrics {
		value, err := c.metrics.GetMetric(ctx, gate.MetricName)
		if err != nil {
			return false, fmt.Sprintf("failed to get metric %s: %v", gate.MetricName, err), nil
		}
		if !evaluateGate(value, gate.Threshold, gate.Operator) {
			return false, fmt.Sprintf("gate %s failed: %f %s %f", gate.MetricName, value, gate.Operator, gate.Threshold), nil
		}
	}

	return true, "all gates passed", nil
}

// Promote advances to the next stage or completes the delivery.
func (c *DeliveryController) Promote(planID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	plan, ok := c.plans[planID]
	if !ok {
		return fmt.Errorf("plan %s not found", planID)
	}
	if plan.Status != DeliveryInProgress {
		return fmt.Errorf("plan %s is not in progress (status: %s)", planID, plan.Status)
	}

	plan.Stages[plan.CurrentStage].Status = DeliveryPromoted

	if plan.CurrentStage >= len(plan.Stages)-1 {
		// Final stage promoted — delivery complete
		plan.Status = DeliveryPromoted
		plan.CompletedAt = c.clock()
		plan.ComputeHash()
		return nil
	}

	// Advance to next stage
	plan.CurrentStage++
	plan.Stages[plan.CurrentStage].Status = DeliveryInProgress
	plan.Stages[plan.CurrentStage].EnteredAt = c.clock()
	plan.ComputeHash()
	return nil
}

// Rollback aborts the delivery and marks it as rolled back.
func (c *DeliveryController) Rollback(planID, reason string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	plan, ok := c.plans[planID]
	if !ok {
		return fmt.Errorf("plan %s not found", planID)
	}

	plan.Status = DeliveryRolledBack
	plan.CompletedAt = c.clock()
	plan.ComputeHash()
	return nil
}

// CheckRollback evaluates rollback conditions against current metrics.
// Returns (shouldRollback, reason, error).
func (c *DeliveryController) CheckRollback(ctx context.Context, planID string) (bool, string, error) {
	c.mu.Lock()
	plan, ok := c.plans[planID]
	c.mu.Unlock()

	if !ok || !plan.Rollback.AutoRollback {
		return false, "", nil
	}

	for _, cond := range plan.Rollback.Conditions {
		value, err := c.metrics.GetMetric(ctx, cond.MetricName)
		if err != nil {
			continue // can't evaluate — don't rollback on metric fetch errors
		}
		if evaluateGate(value, cond.Threshold, cond.Operator) {
			return true, fmt.Sprintf("rollback condition met: %s=%f %s %f", cond.MetricName, value, cond.Operator, cond.Threshold), nil
		}
	}

	return false, "", nil
}

// GetPlan returns the current state of a delivery plan.
func (c *DeliveryController) GetPlan(planID string) (*DeliveryPlan, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	plan, ok := c.plans[planID]
	return plan, ok
}

func evaluateGate(value, threshold float64, operator string) bool {
	switch operator {
	case "lt":
		return value < threshold
	case "gt":
		return value > threshold
	case "lte":
		return value <= threshold
	case "gte":
		return value >= threshold
	default:
		return false
	}
}
