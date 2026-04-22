package mcp

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// DefaultSessionTTL is the default time-to-live for MCP HTTP sessions.
const DefaultSessionTTL = 30 * time.Minute

// Session represents an active MCP HTTP session.
type Session struct {
	ID              string    `json:"id"`
	CreatedAt       time.Time `json:"created_at"`
	LastAccess      time.Time `json:"last_access"`
	ProtocolVersion string    `json:"protocol_version"`
	ClientName      string    `json:"client_name,omitempty"`
}

// SessionStore manages in-memory MCP sessions with TTL-based expiry.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	ttl      time.Duration
	stopCh   chan struct{}
}

// NewSessionStore creates a new session store with the given TTL.
// A background goroutine runs every ttl/2 to evict expired sessions.
func NewSessionStore(ttl time.Duration) *SessionStore {
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	s := &SessionStore{
		sessions: make(map[string]*Session),
		ttl:      ttl,
		stopCh:   make(chan struct{}),
	}
	go s.reapLoop()
	return s
}

// Create allocates a new session and returns its ID.
func (s *SessionStore) Create(protocolVersion, clientName string) (string, error) {
	id, err := generateSessionID()
	if err != nil {
		return "", fmt.Errorf("generate session id: %w", err)
	}

	now := time.Now()
	session := &Session{
		ID:              id,
		CreatedAt:       now,
		LastAccess:      now,
		ProtocolVersion: protocolVersion,
		ClientName:      clientName,
	}

	s.mu.Lock()
	s.sessions[id] = session
	s.mu.Unlock()

	return id, nil
}

// Get retrieves a session by ID, updating LastAccess.
// Returns nil if the session does not exist or has expired.
func (s *SessionStore) Get(id string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[id]
	if !ok {
		return nil
	}

	if time.Since(session.LastAccess) > s.ttl {
		delete(s.sessions, id)
		return nil
	}

	session.LastAccess = time.Now()
	return session
}

// Delete removes a session by ID.
func (s *SessionStore) Delete(id string) {
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
}

// Len returns the number of active sessions (may include soon-to-expire ones).
func (s *SessionStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

// Stop terminates the background reaper goroutine.
func (s *SessionStore) Stop() {
	close(s.stopCh)
}

func (s *SessionStore) reapLoop() {
	interval := s.ttl / 2
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.reap()
		}
	}
}

func (s *SessionStore) reap() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for id, session := range s.sessions {
		if now.Sub(session.LastAccess) > s.ttl {
			delete(s.sessions, id)
		}
	}
}

func generateSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
