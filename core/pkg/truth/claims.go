package truth

import (
	"fmt"
	"sync"
	"time"
)

// ClaimStatus represents the lifecycle state of a claim.
type ClaimStatus string

const (
	// ClaimStatusPending means the claim has been registered but not yet verified.
	ClaimStatusPending ClaimStatus = "PENDING"

	// ClaimStatusVerified means the claim has been verified with evidence.
	ClaimStatusVerified ClaimStatus = "VERIFIED"

	// ClaimStatusRefuted means the claim has been disproven.
	ClaimStatusRefuted ClaimStatus = "REFUTED"

	// ClaimStatusExpired means the claim's verification has expired and needs re-verification.
	ClaimStatusExpired ClaimStatus = "EXPIRED"
)

// ClaimRecord represents a strong system claim that maps to evidence.
type ClaimRecord struct {
	// ClaimID is a unique identifier for this claim.
	ClaimID string `json:"claim_id"`

	// Statement is the claim being made.
	Statement string `json:"statement"`

	// EvidenceRefs lists content-addressed hashes of supporting evidence.
	EvidenceRefs []string `json:"evidence_refs,omitempty"`

	// Confidence is a 0.0–1.0 score.
	Confidence float64 `json:"confidence,omitempty"`

	// VerificationMethod describes how the claim can be verified.
	VerificationMethod string `json:"verification_method,omitempty"`

	// Status is the current lifecycle state.
	Status ClaimStatus `json:"status"`

	// Owner identifies who is responsible for this claim.
	Owner string `json:"owner,omitempty"`

	// RegisteredAt is when the claim was first registered.
	RegisteredAt time.Time `json:"registered_at"`

	// VerifiedAt is when the claim was last verified.
	VerifiedAt time.Time `json:"verified_at,omitempty"`

	// ExpiresAt is when the claim's verification expires.
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	// RefutationReason explains why the claim was refuted (if applicable).
	RefutationReason string `json:"refutation_reason,omitempty"`
}

// ClaimRegistry tracks verified claims and their evidence.
type ClaimRegistry interface {
	// Register adds a new claim in PENDING status. Returns error if ID already exists.
	Register(claim *ClaimRecord) error

	// Verify marks a claim as verified with evidence refs.
	Verify(claimID string, evidenceRefs []string) error

	// Refute marks a claim as refuted with a reason.
	Refute(claimID string, reason string) error

	// Get returns a claim by ID. Returns nil if not found.
	Get(claimID string) (*ClaimRecord, error)

	// ListByStatus returns all claims with the given status.
	ListByStatus(status ClaimStatus) ([]*ClaimRecord, error)

	// ListAll returns all claims.
	ListAll() ([]*ClaimRecord, error)
}

// InMemoryClaimRegistry is a thread-safe in-memory implementation of ClaimRegistry.
type InMemoryClaimRegistry struct {
	mu     sync.RWMutex
	claims map[string]*ClaimRecord
	clock  func() time.Time
}

// NewInMemoryClaimRegistry creates a new in-memory claim registry.
func NewInMemoryClaimRegistry() *InMemoryClaimRegistry {
	return &InMemoryClaimRegistry{
		claims: make(map[string]*ClaimRecord),
		clock:  time.Now,
	}
}

// WithClock overrides the clock for deterministic testing.
func (r *InMemoryClaimRegistry) WithClock(clock func() time.Time) *InMemoryClaimRegistry {
	r.clock = clock
	return r
}

// Register adds a new claim in PENDING status.
func (r *InMemoryClaimRegistry) Register(claim *ClaimRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.claims[claim.ClaimID]; exists {
		return fmt.Errorf("claim already registered: %s", claim.ClaimID)
	}

	// Force initial state.
	claim.Status = ClaimStatusPending
	claim.RegisteredAt = r.clock()

	stored := *claim
	r.claims[claim.ClaimID] = &stored
	return nil
}

// Verify marks a claim as verified with evidence refs.
func (r *InMemoryClaimRegistry) Verify(claimID string, evidenceRefs []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	claim, ok := r.claims[claimID]
	if !ok {
		return fmt.Errorf("claim not found: %s", claimID)
	}
	if claim.Status == ClaimStatusRefuted {
		return fmt.Errorf("cannot verify refuted claim: %s", claimID)
	}

	claim.Status = ClaimStatusVerified
	claim.EvidenceRefs = append(claim.EvidenceRefs, evidenceRefs...)
	claim.VerifiedAt = r.clock()
	return nil
}

// Refute marks a claim as refuted.
func (r *InMemoryClaimRegistry) Refute(claimID string, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	claim, ok := r.claims[claimID]
	if !ok {
		return fmt.Errorf("claim not found: %s", claimID)
	}

	claim.Status = ClaimStatusRefuted
	claim.RefutationReason = reason
	return nil
}

// Get returns a claim by ID.
func (r *InMemoryClaimRegistry) Get(claimID string) (*ClaimRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	claim, ok := r.claims[claimID]
	if !ok {
		return nil, nil
	}
	copy := *claim
	return &copy, nil
}

// ListByStatus returns all claims with the given status.
func (r *InMemoryClaimRegistry) ListByStatus(status ClaimStatus) ([]*ClaimRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []*ClaimRecord
	for _, claim := range r.claims {
		if claim.Status == status {
			copy := *claim
			result = append(result, &copy)
		}
	}
	return result, nil
}

// ListAll returns all claims.
func (r *InMemoryClaimRegistry) ListAll() ([]*ClaimRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*ClaimRecord, 0, len(r.claims))
	for _, claim := range r.claims {
		copy := *claim
		result = append(result, &copy)
	}
	return result, nil
}
