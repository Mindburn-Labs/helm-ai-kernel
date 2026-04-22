// Package credentials — Credential Rotation.
//
// Per HELM 2030 Spec §4.7:
//
//	Credential mediation: rotation, lease-based lifecycle.
package credentials

import (
	"fmt"
	"sync"
	"time"
)

// CredentialState tracks the lifecycle state of a credential.
type CredentialState string

const (
	CredentialActive  CredentialState = "ACTIVE"
	CredentialExpired CredentialState = "EXPIRED"
	CredentialRevoked CredentialState = "REVOKED"
	CredentialRotated CredentialState = "ROTATED"
)

// ManagedCredential tracks a credential with its lifecycle.
type ManagedCredential struct {
	CredentialID string          `json:"credential_id"`
	TenantID     string          `json:"tenant_id"`
	Service      string          `json:"service"`
	State        CredentialState `json:"state"`
	IssuedAt     time.Time       `json:"issued_at"`
	ExpiresAt    time.Time       `json:"expires_at"`
	RotatedAt    *time.Time      `json:"rotated_at,omitempty"`
	RotationGen  int             `json:"rotation_gen"` // generation counter
}

// RotationPolicy defines rotation rules.
type RotationPolicy struct {
	MaxAge      time.Duration `json:"max_age"`
	AutoRotate  bool          `json:"auto_rotate"`
	GracePeriod time.Duration `json:"grace_period"`
}

// RotationManager manages credential rotation.
type RotationManager struct {
	mu          sync.Mutex
	credentials map[string]*ManagedCredential
	policy      RotationPolicy
	seq         int64
	clock       func() time.Time
}

// NewRotationManager creates a new manager.
func NewRotationManager(policy RotationPolicy) *RotationManager {
	return &RotationManager{
		credentials: make(map[string]*ManagedCredential),
		policy:      policy,
		clock:       time.Now,
	}
}

// WithClock overrides clock for testing.
func (m *RotationManager) WithClock(clock func() time.Time) *RotationManager {
	m.clock = clock
	return m
}

// Issue creates a new managed credential.
func (m *RotationManager) Issue(tenantID, service string) *ManagedCredential {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.seq++
	now := m.clock()
	id := fmt.Sprintf("cred-%d", m.seq)

	cred := &ManagedCredential{
		CredentialID: id,
		TenantID:     tenantID,
		Service:      service,
		State:        CredentialActive,
		IssuedAt:     now,
		ExpiresAt:    now.Add(m.policy.MaxAge),
		RotationGen:  1,
	}

	m.credentials[id] = cred
	return cred
}

// Rotate rotates a credential, invalidating the old one.
func (m *RotationManager) Rotate(credentialID string) (*ManagedCredential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	old, ok := m.credentials[credentialID]
	if !ok {
		return nil, fmt.Errorf("credential %q not found", credentialID)
	}

	now := m.clock()

	// Mark old as rotated
	old.State = CredentialRotated
	old.RotatedAt = &now

	// Issue new
	m.seq++
	newID := fmt.Sprintf("cred-%d", m.seq)
	newCred := &ManagedCredential{
		CredentialID: newID,
		TenantID:     old.TenantID,
		Service:      old.Service,
		State:        CredentialActive,
		IssuedAt:     now,
		ExpiresAt:    now.Add(m.policy.MaxAge),
		RotationGen:  old.RotationGen + 1,
	}

	m.credentials[newID] = newCred
	return newCred, nil
}

// CheckExpiry returns all credentials that need rotation.
func (m *RotationManager) CheckExpiry() []*ManagedCredential {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.clock()
	var expiring []*ManagedCredential

	for _, cred := range m.credentials {
		if cred.State != CredentialActive {
			continue
		}
		if now.After(cred.ExpiresAt) || now.After(cred.ExpiresAt.Add(-m.policy.GracePeriod)) {
			expiring = append(expiring, cred)
		}
	}
	return expiring
}

// Revoke revokes a credential.
func (m *RotationManager) Revoke(credentialID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cred, ok := m.credentials[credentialID]
	if !ok {
		return fmt.Errorf("credential %q not found", credentialID)
	}
	cred.State = CredentialRevoked
	return nil
}

// Get retrieves a credential.
func (m *RotationManager) Get(credentialID string) (*ManagedCredential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cred, ok := m.credentials[credentialID]
	if !ok {
		return nil, fmt.Errorf("credential %q not found", credentialID)
	}
	return cred, nil
}

// IsValid checks if a credential is active and not expired.
func (m *RotationManager) IsValid(credentialID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	cred, ok := m.credentials[credentialID]
	if !ok {
		return false
	}
	if cred.State != CredentialActive {
		return false
	}
	return m.clock().Before(cred.ExpiresAt)
}
