// Package sandbox — Credential Broker for sandboxed execution.
//
// Per HELM 2030 Spec:
//   - Sandboxed packs never receive long-lived credentials
//   - Broker issues scoped, short-lived tokens
//   - All token issuances are logged
package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// ScopedToken is a short-lived token issued to a sandbox.
type ScopedToken struct {
	TokenID   string    `json:"token_id"`
	SandboxID string    `json:"sandbox_id"`
	Scopes    []string  `json:"scopes"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	TokenHash string    `json:"token_hash"` // Hash of actual token value
	Revoked   bool      `json:"revoked"`
}

// TokenRequest is a request for a scoped credential.
type TokenRequest struct {
	SandboxID       string   `json:"sandbox_id"`
	RequestedScopes []string `json:"requested_scopes"`
	TTLSeconds      int      `json:"ttl_seconds"`
}

// TokenIssuance records every issuance for audit.
type TokenIssuance struct {
	TokenID   string    `json:"token_id"`
	SandboxID string    `json:"sandbox_id"`
	Scopes    []string  `json:"scopes"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// CredentialBroker manages scoped credential issuance for sandboxes.
type CredentialBroker struct {
	mu            sync.Mutex
	allowedScopes map[string][]string // sandboxID → allowed scopes
	tokens        map[string]*ScopedToken
	issuances     []TokenIssuance
	maxTTLSeconds int
	clock         func() time.Time
	tokenCounter  int64
}

// NewCredentialBroker creates a new broker with a maximum token TTL.
func NewCredentialBroker(maxTTLSeconds int) *CredentialBroker {
	return &CredentialBroker{
		allowedScopes: make(map[string][]string),
		tokens:        make(map[string]*ScopedToken),
		issuances:     make([]TokenIssuance, 0),
		maxTTLSeconds: maxTTLSeconds,
		clock:         time.Now,
	}
}

// WithClock overrides clock for testing.
func (b *CredentialBroker) WithClock(clock func() time.Time) *CredentialBroker {
	b.clock = clock
	return b
}

// SetScopeAllowlist defines which scopes a sandbox may request.
func (b *CredentialBroker) SetScopeAllowlist(sandboxID string, scopes []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.allowedScopes[sandboxID] = scopes
}

// IssueToken creates a scoped, short-lived token for a sandbox.
func (b *CredentialBroker) IssueToken(req TokenRequest) (*ScopedToken, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.clock()

	// Validate sandbox has scope allowlist
	allowed, ok := b.allowedScopes[req.SandboxID]
	if !ok {
		return nil, fmt.Errorf("no scope allowlist for sandbox %q", req.SandboxID)
	}

	// Validate requested scopes
	for _, scope := range req.RequestedScopes {
		scopeAllowed := false
		for _, a := range allowed {
			if a == scope {
				scopeAllowed = true
				break
			}
		}
		if !scopeAllowed {
			return nil, fmt.Errorf("scope %q not allowed for sandbox %q", scope, req.SandboxID)
		}
	}

	// Enforce max TTL
	ttl := req.TTLSeconds
	if ttl <= 0 || ttl > b.maxTTLSeconds {
		ttl = b.maxTTLSeconds
	}

	b.tokenCounter++
	tokenID := fmt.Sprintf("tok-%s-%d", req.SandboxID, b.tokenCounter)

	// Compute token hash (in real impl, the actual token value would be different)
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%d", tokenID, now.UnixNano(), b.tokenCounter)))
	tokenHash := "sha256:" + hex.EncodeToString(h[:])

	token := &ScopedToken{
		TokenID:   tokenID,
		SandboxID: req.SandboxID,
		Scopes:    req.RequestedScopes,
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Duration(ttl) * time.Second),
		TokenHash: tokenHash,
	}

	b.tokens[tokenID] = token
	b.issuances = append(b.issuances, TokenIssuance{
		TokenID:   tokenID,
		SandboxID: req.SandboxID,
		Scopes:    req.RequestedScopes,
		IssuedAt:  now,
		ExpiresAt: token.ExpiresAt,
	})

	return token, nil
}

// ValidateToken checks if a token is valid (not expired, not revoked).
func (b *CredentialBroker) ValidateToken(tokenID string) (bool, string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	token, ok := b.tokens[tokenID]
	if !ok {
		return false, "token not found"
	}
	if token.Revoked {
		return false, "token revoked"
	}
	if b.clock().After(token.ExpiresAt) {
		return false, "token expired"
	}
	return true, "valid"
}

// RevokeToken immediately invalidates a token.
func (b *CredentialBroker) RevokeToken(tokenID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	token, ok := b.tokens[tokenID]
	if !ok {
		return fmt.Errorf("token %q not found", tokenID)
	}
	token.Revoked = true
	return nil
}

// GetIssuances returns all token issuances for audit.
func (b *CredentialBroker) GetIssuances() []TokenIssuance {
	b.mu.Lock()
	defer b.mu.Unlock()
	result := make([]TokenIssuance, len(b.issuances))
	copy(result, b.issuances)
	return result
}
