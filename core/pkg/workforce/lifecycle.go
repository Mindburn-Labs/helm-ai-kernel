package workforce

import (
	"context"
	"fmt"
)

// LifecycleManager handles virtual employee state transitions.
type LifecycleManager struct {
	registry EmployeeRegistry
}

// NewLifecycleManager creates a new LifecycleManager backed by the given registry.
func NewLifecycleManager(registry EmployeeRegistry) *LifecycleManager {
	return &LifecycleManager{registry: registry}
}

// Create validates and persists a new virtual employee. A manager and
// non-zero budget envelope are required (fail-closed: no unbounded agents).
func (lm *LifecycleManager) Create(ctx context.Context, employee *VirtualEmployee) error {
	if employee == nil {
		return fmt.Errorf("workforce: employee must not be nil")
	}
	if employee.ManagerID == "" {
		return fmt.Errorf("workforce: manager_id is required")
	}
	if employee.BudgetEnvelope.DailyCentsCap <= 0 {
		return fmt.Errorf("workforce: budget_envelope.daily_cents_cap must be > 0")
	}

	employee.Status = "ACTIVE"
	return lm.registry.Create(ctx, employee)
}

// Suspend immediately halts all activity for the virtual employee.
// This is the "kill switch" — fast, reversible.
func (lm *LifecycleManager) Suspend(ctx context.Context, employeeID string) error {
	emp, err := lm.registry.Get(ctx, employeeID)
	if err != nil {
		return fmt.Errorf("workforce: suspend failed: %w", err)
	}

	if emp.Status == "TERMINATED" {
		return fmt.Errorf("workforce: cannot suspend terminated employee %q", employeeID)
	}

	emp.Status = "SUSPENDED"
	return lm.registry.Update(ctx, emp)
}

// Resume restores a suspended virtual employee to active status.
// Only employees in SUSPENDED state can be resumed.
func (lm *LifecycleManager) Resume(ctx context.Context, employeeID string) error {
	emp, err := lm.registry.Get(ctx, employeeID)
	if err != nil {
		return fmt.Errorf("workforce: resume failed: %w", err)
	}

	if emp.Status != "SUSPENDED" {
		return fmt.Errorf("workforce: can only resume from SUSPENDED (current=%s)", emp.Status)
	}

	emp.Status = "ACTIVE"
	return lm.registry.Update(ctx, emp)
}

// Terminate permanently deactivates a virtual employee. This is
// irreversible — the employee cannot be resumed.
func (lm *LifecycleManager) Terminate(ctx context.Context, employeeID string) error {
	emp, err := lm.registry.Get(ctx, employeeID)
	if err != nil {
		return fmt.Errorf("workforce: terminate failed: %w", err)
	}

	emp.Status = "TERMINATED"
	return lm.registry.Update(ctx, emp)
}
