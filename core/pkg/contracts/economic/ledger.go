package economic

import (
	"fmt"
	"sync"
	"time"
)

// Ledger tracks recurring authorities, capital allocations, and service charges.
type Ledger struct {
	mu          sync.RWMutex
	authorities map[string]*RecurringAuthority
	allocations map[string]*CapitalAllocation
	charges     []ServiceChargeRecord
}

// NewLedger creates a new in-memory economic ledger.
func NewLedger() *Ledger {
	return &Ledger{
		authorities: make(map[string]*RecurringAuthority),
		allocations: make(map[string]*CapitalAllocation),
	}
}

// RegisterAuthority adds a recurring spend authority.
func (l *Ledger) RegisterAuthority(ra RecurringAuthority) error {
	if ra.AuthorityID == "" {
		return fmt.Errorf("authority requires authority_id")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.authorities[ra.AuthorityID] = &ra
	return nil
}

// GetAuthority retrieves a recurring authority by ID.
func (l *Ledger) GetAuthority(id string) (*RecurringAuthority, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	ra, ok := l.authorities[id]
	if !ok {
		return nil, fmt.Errorf("authority %s not found", id)
	}
	return ra, nil
}

// ListAuthorities returns all recurring authorities.
func (l *Ledger) ListAuthorities() []RecurringAuthority {
	l.mu.RLock()
	defer l.mu.RUnlock()
	var result []RecurringAuthority
	for _, ra := range l.authorities {
		result = append(result, *ra)
	}
	return result
}

// Spend records a spend against a recurring authority. Fail-closed.
func (l *Ledger) Spend(authorityID string, amountCents int64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	ra, ok := l.authorities[authorityID]
	if !ok {
		return fmt.Errorf("authority %s not found", authorityID)
	}
	if !ra.CanSpend(amountCents) {
		return fmt.Errorf("spend denied: %d cents exceeds remaining %d for authority %s",
			amountCents, ra.Remaining(), authorityID)
	}
	ra.UsedThisPeriod += amountCents
	return nil
}

// RegisterAllocation stores a capital allocation.
func (l *Ledger) RegisterAllocation(ca CapitalAllocation) error {
	if ca.AllocationID == "" {
		return fmt.Errorf("allocation requires allocation_id")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.allocations[ca.AllocationID] = &ca
	return nil
}

// ListAllocations returns all capital allocations.
func (l *Ledger) ListAllocations() []CapitalAllocation {
	l.mu.RLock()
	defer l.mu.RUnlock()
	var result []CapitalAllocation
	for _, ca := range l.allocations {
		result = append(result, *ca)
	}
	return result
}

// RecordCharge records a service charge.
func (l *Ledger) RecordCharge(charge ServiceChargeRecord) error {
	if charge.ChargeID == "" {
		return fmt.Errorf("charge requires charge_id")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	charge.CreatedAt = time.Now().UTC()
	l.charges = append(l.charges, charge)
	return nil
}

// ListCharges returns all service charge records.
func (l *Ledger) ListCharges() []ServiceChargeRecord {
	l.mu.RLock()
	defer l.mu.RUnlock()
	result := make([]ServiceChargeRecord, len(l.charges))
	copy(result, l.charges)
	return result
}
