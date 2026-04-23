package registry

import (
	"crypto/ed25519"
	"fmt"
	"sync"
)

// LegacyTrustEvent represents a key lifecycle event in the trust registry.
type LegacyTrustEvent struct {
	EventType string            `json:"event_type"` // KEY_ADDED, KEY_REVOKED, KEY_ROTATED
	TenantID  string            `json:"tenant_id"`
	KeyID     string            `json:"key_id"`
	PublicKey ed25519.PublicKey `json:"public_key,omitempty"`
	Lamport   uint64            `json:"lamport_height"`
}

// TrustRegistry is an event-sourced registry of authorized signing keys.
// State is derived exclusively from TRUST_EVENT ProofGraph nodes.
type TrustRegistry struct {
	mu     sync.RWMutex
	events []LegacyTrustEvent
	// Materialized view: tenant → key_id → public key (nil if revoked)
	keys map[string]map[string]ed25519.PublicKey
}

// NewTrustRegistry creates a new empty trust registry.
func NewTrustRegistry() *TrustRegistry {
	return &TrustRegistry{
		keys: make(map[string]map[string]ed25519.PublicKey),
	}
}

// Apply processes a trust event, updating the materialized view.
func (r *TrustRegistry) Apply(event LegacyTrustEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	switch event.EventType {
	case "KEY_ADDED":
		if event.PublicKey == nil {
			return fmt.Errorf("KEY_ADDED event must include public_key")
		}
		if r.keys[event.TenantID] == nil {
			r.keys[event.TenantID] = make(map[string]ed25519.PublicKey)
		}
		r.keys[event.TenantID][event.KeyID] = event.PublicKey

	case "KEY_REVOKED":
		if tenant, ok := r.keys[event.TenantID]; ok {
			delete(tenant, event.KeyID)
		}

	case "KEY_ROTATED":
		if event.PublicKey == nil {
			return fmt.Errorf("KEY_ROTATED event must include new public_key")
		}
		if r.keys[event.TenantID] == nil {
			r.keys[event.TenantID] = make(map[string]ed25519.PublicKey)
		}
		r.keys[event.TenantID][event.KeyID] = event.PublicKey

	default:
		return fmt.Errorf("unknown trust event type: %s", event.EventType)
	}

	r.events = append(r.events, event)
	return nil
}

// ResolveAuthorizedKeys returns all currently authorized keys for a tenant
// at a given Lamport height. If height is 0, returns the current state.
func (r *TrustRegistry) ResolveAuthorizedKeys(tenantID string, lamportHeight uint64) ([]ed25519.PublicKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if lamportHeight == 0 {
		// Current state
		tenant, ok := r.keys[tenantID]
		if !ok {
			return nil, nil
		}
		keys := make([]ed25519.PublicKey, 0, len(tenant))
		for _, k := range tenant {
			keys = append(keys, k)
		}
		return keys, nil
	}

	// Replay events up to lamportHeight for point-in-time resolution
	snapshot := make(map[string]ed25519.PublicKey)
	for _, ev := range r.events {
		if ev.TenantID != tenantID {
			continue
		}
		if ev.Lamport > lamportHeight {
			break
		}
		switch ev.EventType {
		case "KEY_ADDED", "KEY_ROTATED":
			snapshot[ev.KeyID] = ev.PublicKey
		case "KEY_REVOKED":
			delete(snapshot, ev.KeyID)
		}
	}

	keys := make([]ed25519.PublicKey, 0, len(snapshot))
	for _, k := range snapshot {
		keys = append(keys, k)
	}
	return keys, nil
}

// IsAuthorized checks if a specific key is currently authorized for a tenant.
func (r *TrustRegistry) IsAuthorized(tenantID, keyID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tenant, ok := r.keys[tenantID]
	if !ok {
		return false
	}
	_, exists := tenant[keyID]
	return exists
}

// EventCount returns the number of events processed.
func (r *TrustRegistry) EventCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.events)
}
