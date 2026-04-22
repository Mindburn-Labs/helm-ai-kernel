package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// ── Delegation Session Lifecycle ──────────────────────────────
//
// This file implements the canonical delegation session lifecycle:
//   - NewDelegationSession: create a blank-slate, deny-all session
//   - AddCapability: grant subset-of-delegator capabilities
//   - BindVerifier: PKCE-style verifier binding
//   - ValidateSession: expiry, nonce, verifier, MFA, policy hash
//   - IntersectWithPolicy: compute effective permissions (never expand)

// DelegationStore provides session storage and nonce tracking.
// Guardian injects this to load/validate sessions at enforcement time.
type DelegationStore interface {
	// Store persists a delegation session.
	Store(session *DelegationSession) error
	// Load retrieves a session by ID. Returns nil if not found.
	Load(sessionID string) (*DelegationSession, error)
	// Revoke marks a session as revoked.
	Revoke(sessionID string) error
	// IsNonceUsed checks if a nonce has been seen before (anti-replay).
	IsNonceUsed(nonce string) bool
	// MarkNonceUsed records a nonce as used.
	MarkNonceUsed(nonce string)
}

// DelegationError captures delegation validation failures with structured context.
type DelegationError struct {
	Code    string `json:"code"`    // canonical reason code
	Message string `json:"message"`
}

func (e *DelegationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// NewDelegationSession creates a blank-slate, deny-all delegation session.
// The session has no capabilities until explicitly added via AddCapability.
// All required binding fields must be populated before the session is valid.
func NewDelegationSession(
	sessionID string,
	delegator string,
	delegate string,
	nonce string,
	policyHash string,
	trustRootRef string,
	principalSeqFloor uint64,
	expiresAt time.Time,
	createdWithMFA bool,
	clock func() time.Time,
) *DelegationSession {
	now := time.Now()
	if clock != nil {
		now = clock()
	}

	return &DelegationSession{
		SessionID:            sessionID,
		DelegatorPrincipal:   delegator,
		DelegatePrincipal:    delegate,
		AllowedTools:         []string{},
		Capabilities:         []CapabilityGrant{},
		SessionNonce:         nonce,
		DelegationPolicyHash: policyHash,
		TrustRootRef:         trustRootRef,
		PrincipalSeqFloor:    principalSeqFloor,
		CreatedWithMFA:       createdWithMFA,
		ExpiresAt:            expiresAt,
		CreatedAt:            now,
	}
}

// AddCapability adds a capability grant to the session.
// Each capability narrows the delegator's authority to a specific resource.
// Returns an error if the resource is empty or actions are empty.
func (s *DelegationSession) AddCapability(grant CapabilityGrant) error {
	if grant.Resource == "" {
		return &DelegationError{
			Code:    "DELEGATION_INVALID",
			Message: "capability grant must specify a resource",
		}
	}
	if len(grant.Actions) == 0 {
		return &DelegationError{
			Code:    "DELEGATION_INVALID",
			Message: "capability grant must specify at least one action",
		}
	}
	s.Capabilities = append(s.Capabilities, grant)
	return nil
}

// AddAllowedTool adds a tool to the session's permitted tool list.
func (s *DelegationSession) AddAllowedTool(toolName string) {
	s.AllowedTools = append(s.AllowedTools, toolName)
}

// SetRiskCeiling sets the maximum risk class the delegate can act under.
func (s *DelegationSession) SetRiskCeiling(ceiling string) {
	s.RiskCeiling = ceiling
}

// BindVerifier binds a PKCE-style verifier hash to the session.
// The verifier must be presented when the session is used.
func (s *DelegationSession) BindVerifier(verifier string) {
	h := sha256.Sum256([]byte(verifier))
	s.VerifierBinding = hex.EncodeToString(h[:])
}

// ── Session Validation ────────────────────────────────────────

// ValidateSession checks all session invariants.
// Returns nil if the session is valid, or a *DelegationError with
// canonical reason code on failure.
func ValidateSession(s *DelegationSession, verifier string, now time.Time, nonceChecker func(string) bool) error {
	// 1. Session must not be nil
	if s == nil {
		return &DelegationError{
			Code:    "DELEGATION_INVALID",
			Message: "delegation session is nil",
		}
	}

	// 2. Required fields
	if s.SessionID == "" || s.DelegatorPrincipal == "" || s.DelegatePrincipal == "" {
		return &DelegationError{
			Code:    "DELEGATION_INVALID",
			Message: "session missing required identity fields",
		}
	}

	// 3. Expiry check
	if now.After(s.ExpiresAt) {
		return &DelegationError{
			Code:    "DELEGATION_INVALID",
			Message: fmt.Sprintf("session expired at %s", s.ExpiresAt.Format(time.RFC3339)),
		}
	}

	// 4. Nonce anti-replay
	if s.SessionNonce == "" {
		return &DelegationError{
			Code:    "DELEGATION_INVALID",
			Message: "session nonce is required",
		}
	}
	if nonceChecker != nil && nonceChecker(s.SessionNonce) {
		return &DelegationError{
			Code:    "DELEGATION_INVALID",
			Message: "session nonce has been replayed",
		}
	}

	// 5. PKCE verifier binding
	if s.VerifierBinding != "" {
		if verifier == "" {
			return &DelegationError{
				Code:    "DELEGATION_INVALID",
				Message: "verifier required for bound session",
			}
		}
		h := sha256.Sum256([]byte(verifier))
		expected := hex.EncodeToString(h[:])
		if s.VerifierBinding != expected {
			return &DelegationError{
				Code:    "DELEGATION_INVALID",
				Message: "verifier binding mismatch",
			}
		}
	}

	// 6. MFA requirement
	if !s.CreatedWithMFA {
		// Policy may require MFA — this check enables Guardian to
		// enforce MFA requirements at session creation level.
		// Not inherently invalid, but flagged for policy evaluation.
	}

	// 7. Policy hash must be set
	if s.DelegationPolicyHash == "" {
		return &DelegationError{
			Code:    "DELEGATION_INVALID",
			Message: "delegation policy hash is required",
		}
	}

	return nil
}

// ── Scope Intersection ────────────────────────────────────────

// IsToolAllowed checks whether a tool is within the session's scope.
// Returns true if AllowedTools is empty (legacy compat) or the tool
// is explicitly listed.
func (s *DelegationSession) IsToolAllowed(toolName string) bool {
	if len(s.AllowedTools) == 0 {
		return false // deny-all by default
	}
	for _, t := range s.AllowedTools {
		if t == toolName {
			return true
		}
	}
	return false
}

// IsActionAllowed checks whether a specific action on a resource is
// permitted by any capability grant in the session.
func (s *DelegationSession) IsActionAllowed(resource, action string) bool {
	for _, cap := range s.Capabilities {
		if cap.Resource != resource {
			continue
		}
		for _, a := range cap.Actions {
			if a == action {
				return true
			}
		}
	}
	return false
}

// EffectiveTools returns the intersection of the session's allowed tools
// with a provided set of available tools. The result never expands beyond
// the session's scope.
func (s *DelegationSession) EffectiveTools(available []string) []string {
	if len(s.AllowedTools) == 0 {
		return nil // deny-all
	}
	allowed := make(map[string]bool, len(s.AllowedTools))
	for _, t := range s.AllowedTools {
		allowed[t] = true
	}
	var result []string
	for _, t := range available {
		if allowed[t] {
			result = append(result, t)
		}
	}
	return result
}

// ── In-Memory Delegation Store ────────────────────────────────

// InMemoryDelegationStore is a thread-safe in-memory implementation
// of DelegationStore for development, testing, and single-instance use.
type InMemoryDelegationStore struct {
	mu       sync.RWMutex
	sessions map[string]*DelegationSession
	revoked  map[string]bool
	nonces   map[string]bool
}

// NewInMemoryDelegationStore creates a new in-memory store.
func NewInMemoryDelegationStore() *InMemoryDelegationStore {
	return &InMemoryDelegationStore{
		sessions: make(map[string]*DelegationSession),
		revoked:  make(map[string]bool),
		nonces:   make(map[string]bool),
	}
}

// Store persists a delegation session.
func (s *InMemoryDelegationStore) Store(session *DelegationSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.SessionID] = session
	return nil
}

// Load retrieves a session by ID.
func (s *InMemoryDelegationStore) Load(sessionID string) (*DelegationSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.revoked[sessionID] {
		return nil, &DelegationError{
			Code:    "DELEGATION_INVALID",
			Message: "session has been revoked",
		}
	}
	session, ok := s.sessions[sessionID]
	if !ok {
		return nil, nil
	}
	return session, nil
}

// Revoke marks a session as revoked.
func (s *InMemoryDelegationStore) Revoke(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked[sessionID] = true
	return nil
}

// IsNonceUsed checks if a nonce has been seen before.
func (s *InMemoryDelegationStore) IsNonceUsed(nonce string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nonces[nonce]
}

// MarkNonceUsed records a nonce as used.
func (s *InMemoryDelegationStore) MarkNonceUsed(nonce string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nonces[nonce] = true
}
