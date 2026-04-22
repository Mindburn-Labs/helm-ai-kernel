package simulation

import (
	"fmt"
	"sync"
	"time"
)

// Runner executes simulation scenarios and tracks results.
type Runner struct {
	mu   sync.RWMutex
	runs map[string]*SimRun
}

// SimRun tracks a single simulation execution.
type SimRun struct {
	RunID     string    `json:"run_id"`
	SimType   string    `json:"sim_type"` // "BUDGET", "STAFFING", "DP_REHEARSAL", "STRESS"
	Name      string    `json:"name"`
	Status    string    `json:"status"` // "PENDING", "RUNNING", "COMPLETED", "FAILED"
	StartedAt time.Time `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// NewRunner creates a simulation runner.
func NewRunner() *Runner {
	return &Runner{
		runs: make(map[string]*SimRun),
	}
}

// RunBudgetSim executes a budget simulation.
func (r *Runner) RunBudgetSim(sim BudgetSimulation) (*BudgetSimResult, error) {
	if sim.SimID == "" {
		return nil, fmt.Errorf("simulation requires sim_id")
	}

	run := &SimRun{
		RunID:     sim.SimID,
		SimType:   "BUDGET",
		Name:      sim.Scenario,
		Status:    "RUNNING",
		StartedAt: time.Now().UTC(),
	}
	r.mu.Lock()
	r.runs[sim.SimID] = run
	r.mu.Unlock()

	// Execute simulation logic
	var projected int64
	for _, adj := range sim.Adjustments {
		switch adj.ChangeType {
		case "INCREASE":
			projected += adj.AmountCents
		case "DECREASE":
			projected -= adj.AmountCents
		case "SET":
			projected = adj.AmountCents
		}
	}

	months := sim.Duration.Hours() / (24 * 30)
	if months < 1 {
		months = 1
	}
	burnRate := float64(projected) / months

	result := &BudgetSimResult{
		ProjectedSpendCents: projected,
		ProjectedRemaining:  -projected, // simplified: assume zero budget
		BurnRate:            burnRate,
		RunwayMonths:        0,
		OverBudget:          projected > 0,
		RiskLevel:           classifyBudgetRisk(projected),
	}

	now := time.Now().UTC()
	r.mu.Lock()
	run.Status = "COMPLETED"
	run.EndedAt = &now
	r.mu.Unlock()

	sim.Results = result
	return result, nil
}

// RunStaffingSim executes a staffing simulation.
func (r *Runner) RunStaffingSim(model StaffingModel) (*StaffingResult, error) {
	if model.ModelID == "" {
		return nil, fmt.Errorf("model requires model_id")
	}

	run := &SimRun{
		RunID:     model.ModelID,
		SimType:   "STAFFING",
		Name:      "Staffing " + model.ModelID,
		Status:    "RUNNING",
		StartedAt: time.Now().UTC(),
	}
	r.mu.Lock()
	r.runs[model.ModelID] = run
	r.mu.Unlock()

	var totalCost float64
	var totalCapacity float64
	for _, w := range model.Workers {
		totalCost += w.CostPerHour * w.AvailableHours * float64(w.Count)
		totalCapacity += w.Utilization * w.AvailableHours * float64(w.Count)
	}

	result := &StaffingResult{
		ModelID:           model.ModelID,
		TotalWeeklyCost:   totalCost,
		TotalCapacityHrs:  totalCapacity,
		HeadcountByType:   countByType(model.Workers),
	}

	now := time.Now().UTC()
	r.mu.Lock()
	run.Status = "COMPLETED"
	run.EndedAt = &now
	r.mu.Unlock()

	return result, nil
}

// ListRuns returns all simulation runs.
func (r *Runner) ListRuns() []SimRun {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []SimRun
	for _, run := range r.runs {
		result = append(result, *run)
	}
	return result
}

// GetRun retrieves a simulation run by ID.
func (r *Runner) GetRun(runID string) (*SimRun, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	run, ok := r.runs[runID]
	if !ok {
		return nil, fmt.Errorf("simulation run %s not found", runID)
	}
	return run, nil
}

// StaffingResult is the outcome of a staffing simulation.
type StaffingResult struct {
	ModelID          string         `json:"model_id"`
	TotalWeeklyCost  float64        `json:"total_weekly_cost"`
	TotalCapacityHrs float64       `json:"total_capacity_hours"`
	HeadcountByType  map[string]int `json:"headcount_by_type"`
}

func classifyBudgetRisk(projected int64) string {
	switch {
	case projected > 1_000_000:
		return "CRITICAL"
	case projected > 500_000:
		return "HIGH"
	case projected > 100_000:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func countByType(workers []StaffEntry) map[string]int {
	counts := make(map[string]int)
	for _, w := range workers {
		counts[w.ActorType] += w.Count
	}
	return counts
}
