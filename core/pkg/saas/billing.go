package saas

import (
	"sync"
	"time"
)

// MeteringService tracks per-tenant usage for billing.
type MeteringService struct {
	events map[string][]BillingEvent // tenantID -> events
	mu     sync.RWMutex
	clock  func() time.Time
}

// NewMeteringService creates a new metering service with real clock.
func NewMeteringService() *MeteringService {
	return &MeteringService{
		events: make(map[string][]BillingEvent),
		clock:  func() time.Time { return time.Now().UTC() },
	}
}

// newMeteringServiceWithClock creates a metering service with injectable clock for testing.
func newMeteringServiceWithClock(clock func() time.Time) *MeteringService {
	return &MeteringService{
		events: make(map[string][]BillingEvent),
		clock:  clock,
	}
}

// RecordEvent records a billing event for a tenant.
func (m *MeteringService) RecordEvent(event BillingEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.events[event.TenantID] = append(m.events[event.TenantID], event)
}

// GetUsage aggregates billing events within [from, to) for a single tenant.
func (m *MeteringService) GetUsage(tenantID string, from, to time.Time) *UsageRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()

	usage := &UsageRecord{
		TenantID:    tenantID,
		PeriodStart: from,
		PeriodEnd:   to,
	}

	events, exists := m.events[tenantID]
	if !exists {
		return usage
	}

	for _, evt := range events {
		if evt.Timestamp.Before(from) || !evt.Timestamp.Before(to) {
			continue
		}
		aggregateEvent(usage, evt)
	}

	return usage
}

// GetAllUsage aggregates billing events within [from, to) for all tenants.
func (m *MeteringService) GetAllUsage(from, to time.Time) map[string]*UsageRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]*UsageRecord)

	for tenantID, events := range m.events {
		usage := &UsageRecord{
			TenantID:    tenantID,
			PeriodStart: from,
			PeriodEnd:   to,
		}

		for _, evt := range events {
			if evt.Timestamp.Before(from) || !evt.Timestamp.Before(to) {
				continue
			}
			aggregateEvent(usage, evt)
		}

		// Only include tenants with activity in the period.
		if usage.DecisionCount > 0 || usage.ReceiptCount > 0 || usage.EvidencePacksGB > 0 {
			result[tenantID] = usage
		}
	}

	return result
}

// aggregateEvent accumulates a single billing event into a usage record.
func aggregateEvent(usage *UsageRecord, evt BillingEvent) {
	switch evt.EventType {
	case "DECISION":
		usage.DecisionCount += evt.Quantity
		// Individual decisions are counted but we don't know allow/deny here.
		// The caller should use ALLOW or DENY event types for granularity.
	case "ALLOW":
		usage.AllowCount += evt.Quantity
		usage.DecisionCount += evt.Quantity
	case "DENY":
		usage.DenyCount += evt.Quantity
		usage.DecisionCount += evt.Quantity
	case "RECEIPT":
		usage.ReceiptCount += evt.Quantity
	case "EVIDENCE_PACK":
		// Quantity is in MB; convert to GB.
		usage.EvidencePacksGB += float64(evt.Quantity) / 1024.0
	case "ZK_PROOF":
		usage.ComputeMillis += evt.Quantity
	}
}
