package saas

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
)

// OnboardingService manages tenant lifecycle.
type OnboardingService struct {
	tenants map[string]*TenantRecord // tenantID -> record
	mu      sync.RWMutex
	clock   func() time.Time
}

// NewOnboardingService creates a new onboarding service with real clock.
func NewOnboardingService() *OnboardingService {
	return &OnboardingService{
		tenants: make(map[string]*TenantRecord),
		clock:   func() time.Time { return time.Now().UTC() },
	}
}

// newOnboardingServiceWithClock creates an onboarding service with injectable clock for testing.
func newOnboardingServiceWithClock(clock func() time.Time) *OnboardingService {
	return &OnboardingService{
		tenants: make(map[string]*TenantRecord),
		clock:   clock,
	}
}

// CreateTenant provisions a new tenant. Returns error if tenantID already exists.
func (s *OnboardingService) CreateTenant(tenantID, orgName, plan string) (*TenantRecord, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant_id must not be empty")
	}
	if orgName == "" {
		return nil, fmt.Errorf("org_name must not be empty")
	}
	if plan == "" {
		return nil, fmt.Errorf("plan must not be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.tenants[tenantID]; exists {
		return nil, fmt.Errorf("tenant %s already exists", tenantID)
	}

	record := &TenantRecord{
		TenantID:    tenantID,
		OrgName:     orgName,
		Status:      TenantActive,
		Plan:        plan,
		SigningKeyID: generateSigningKeyID(tenantID),
		CreatedAt:   s.clock(),
	}

	hash, err := computeContentHash(record)
	if err != nil {
		return nil, fmt.Errorf("content hash failed: %w", err)
	}
	record.ContentHash = hash

	s.tenants[tenantID] = record
	return record, nil
}

// SuspendTenant transitions a tenant to SUSPENDED status.
func (s *OnboardingService) SuspendTenant(tenantID, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, exists := s.tenants[tenantID]
	if !exists {
		return fmt.Errorf("tenant %s not found", tenantID)
	}
	if record.Status != TenantActive {
		return fmt.Errorf("tenant %s is %s, can only suspend ACTIVE tenants", tenantID, record.Status)
	}

	record.Status = TenantSuspended
	record.SuspendedAt = s.clock()

	hash, err := computeContentHash(record)
	if err != nil {
		return fmt.Errorf("content hash failed: %w", err)
	}
	record.ContentHash = hash

	return nil
}

// ActivateTenant transitions a tenant back to ACTIVE status.
func (s *OnboardingService) ActivateTenant(tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, exists := s.tenants[tenantID]
	if !exists {
		return fmt.Errorf("tenant %s not found", tenantID)
	}
	if record.Status != TenantSuspended {
		return fmt.Errorf("tenant %s is %s, can only activate SUSPENDED tenants", tenantID, record.Status)
	}

	record.Status = TenantActive
	record.SuspendedAt = time.Time{} // clear suspension time

	hash, err := computeContentHash(record)
	if err != nil {
		return fmt.Errorf("content hash failed: %w", err)
	}
	record.ContentHash = hash

	return nil
}

// DeactivateTenant permanently deactivates a tenant. Terminal state.
func (s *OnboardingService) DeactivateTenant(tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, exists := s.tenants[tenantID]
	if !exists {
		return fmt.Errorf("tenant %s not found", tenantID)
	}
	if record.Status == TenantDeactivated {
		return fmt.Errorf("tenant %s is already DEACTIVATED", tenantID)
	}

	record.Status = TenantDeactivated

	hash, err := computeContentHash(record)
	if err != nil {
		return fmt.Errorf("content hash failed: %w", err)
	}
	record.ContentHash = hash

	return nil
}

// GetTenant returns a tenant record by ID.
func (s *OnboardingService) GetTenant(tenantID string) (*TenantRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	record, exists := s.tenants[tenantID]
	return record, exists
}

// ListTenants returns all tenant records.
func (s *OnboardingService) ListTenants() []*TenantRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*TenantRecord, 0, len(s.tenants))
	for _, record := range s.tenants {
		result = append(result, record)
	}
	return result
}

// generateSigningKeyID derives a deterministic signing key ID from a tenant ID.
func generateSigningKeyID(tenantID string) string {
	h := sha256.Sum256([]byte("helm-saas-key:" + tenantID))
	return "sk-" + hex.EncodeToString(h[:8])
}

// computeContentHash computes a JCS canonical hash for a tenant record.
// The ContentHash field is excluded from the hash input by temporarily zeroing it.
func computeContentHash(record *TenantRecord) (string, error) {
	saved := record.ContentHash
	record.ContentHash = ""
	defer func() { record.ContentHash = saved }()

	hash, err := canonicalize.CanonicalHash(record)
	if err != nil {
		return "", err
	}
	return hash, nil
}
