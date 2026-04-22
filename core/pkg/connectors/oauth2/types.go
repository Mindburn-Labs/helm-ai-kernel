// Package oauth2 provides shared token management for HELM connectors
// that require OAuth2 authentication.
package oauth2

import (
	"context"
	"sync"
	"time"
)

// refreshWindow is the duration before expiry at which a token needs refresh.
const refreshWindow = 5 * time.Minute

// TokenStore is the interface for persisting and retrieving OAuth2 tokens.
type TokenStore interface {
	// GetToken retrieves the stored token for a connector.
	GetToken(ctx context.Context, connectorID string) (*Token, error)
	// SaveToken persists a token for a connector.
	SaveToken(ctx context.Context, connectorID string, token *Token) error
	// DeleteToken removes the stored token for a connector.
	DeleteToken(ctx context.Context, connectorID string) error
}

// Token represents an OAuth2 token with metadata.
type Token struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type"`
	ExpiresAt    time.Time `json:"expires_at"`
	Scopes       []string  `json:"scopes,omitempty"`
}

// IsExpired returns true if the token's expiry time is before now.
func (t *Token) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// NeedsRefresh returns true if the token expires within the refresh window (5 minutes).
func (t *Token) NeedsRefresh() bool {
	return time.Now().Add(refreshWindow).After(t.ExpiresAt)
}

// InMemoryTokenStore is a thread-safe in-memory token store.
type InMemoryTokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*Token
}

// NewInMemoryTokenStore creates a new in-memory token store.
func NewInMemoryTokenStore() *InMemoryTokenStore {
	return &InMemoryTokenStore{
		tokens: make(map[string]*Token),
	}
}

// GetToken retrieves the stored token for a connector.
func (s *InMemoryTokenStore) GetToken(_ context.Context, connectorID string) (*Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tokens[connectorID]
	if !ok {
		return nil, nil
	}
	// Return a copy to prevent data races on the token fields.
	cp := *t
	if t.Scopes != nil {
		cp.Scopes = make([]string, len(t.Scopes))
		copy(cp.Scopes, t.Scopes)
	}
	return &cp, nil
}

// SaveToken persists a token for a connector.
func (s *InMemoryTokenStore) SaveToken(_ context.Context, connectorID string, token *Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *token
	if token.Scopes != nil {
		cp.Scopes = make([]string, len(token.Scopes))
		copy(cp.Scopes, token.Scopes)
	}
	s.tokens[connectorID] = &cp
	return nil
}

// DeleteToken removes the stored token for a connector.
func (s *InMemoryTokenStore) DeleteToken(_ context.Context, connectorID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, connectorID)
	return nil
}
