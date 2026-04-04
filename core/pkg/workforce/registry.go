package workforce

import (
	"context"
	"fmt"
	"sync"
)

// EmployeeRegistry is the storage interface for virtual employees.
type EmployeeRegistry interface {
	// Create persists a new virtual employee.
	Create(ctx context.Context, employee *VirtualEmployee) error

	// Get retrieves a virtual employee by ID.
	Get(ctx context.Context, employeeID string) (*VirtualEmployee, error)

	// List returns all virtual employees.
	List(ctx context.Context) ([]*VirtualEmployee, error)

	// Update replaces an existing virtual employee record.
	Update(ctx context.Context, employee *VirtualEmployee) error
}

// InMemoryRegistry implements EmployeeRegistry using an in-memory map.
// Thread-safe via RWMutex.
type InMemoryRegistry struct {
	mu        sync.RWMutex
	employees map[string]*VirtualEmployee
}

// NewInMemoryRegistry creates a new in-memory employee registry.
func NewInMemoryRegistry() *InMemoryRegistry {
	return &InMemoryRegistry{
		employees: make(map[string]*VirtualEmployee),
	}
}

func (r *InMemoryRegistry) Create(ctx context.Context, employee *VirtualEmployee) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.employees[employee.EmployeeID]; exists {
		return fmt.Errorf("workforce: employee %q already exists", employee.EmployeeID)
	}

	val := *employee
	r.employees[employee.EmployeeID] = &val
	return nil
}

func (r *InMemoryRegistry) Get(ctx context.Context, employeeID string) (*VirtualEmployee, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	emp, ok := r.employees[employeeID]
	if !ok {
		return nil, fmt.Errorf("workforce: employee %q not found", employeeID)
	}

	val := *emp
	return &val, nil
}

func (r *InMemoryRegistry) List(ctx context.Context) ([]*VirtualEmployee, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*VirtualEmployee, 0, len(r.employees))
	for _, emp := range r.employees {
		val := *emp
		result = append(result, &val)
	}
	return result, nil
}

func (r *InMemoryRegistry) Update(ctx context.Context, employee *VirtualEmployee) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.employees[employee.EmployeeID]; !exists {
		return fmt.Errorf("workforce: employee %q not found", employee.EmployeeID)
	}

	val := *employee
	r.employees[employee.EmployeeID] = &val
	return nil
}
