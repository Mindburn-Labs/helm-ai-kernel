// session.go — IATP session bookkeeping.
//
// The Participant in handshake.go is intentionally stateless beyond a nonce
// cache. Callers that need to look up an active capability after the
// handshake completes use the SessionStore in this file. It is in-memory,
// safe for concurrent use, and stores only the Capability returned by
// Participant.Accept.
//
// Persistence is the caller's concern: the kernel can wrap a SessionStore
// behind a Keystore interface or persist Capabilities directly into the
// proofgraph.

package iatp

import (
	"sync"
	"time"
)

// SessionStore tracks counter-signed capabilities issued by the local
// Participant. It is purely in-memory and keyed by SessionID.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Capability
	clock    func() time.Time
}

// NewSessionStore returns an empty store with time.Now as its clock.
func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*Capability),
		clock:    time.Now,
	}
}

// WithSessionClock injects a deterministic clock for tests.
func (s *SessionStore) WithSessionClock(clock func() time.Time) *SessionStore {
	s.clock = clock
	return s
}

// Put records a capability so callers can look it up by SessionID.
func (s *SessionStore) Put(cap *Capability) {
	if cap == nil || cap.SessionID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[cap.SessionID] = cap
}

// Get returns the capability for sessionID. Returns false if the session
// was never recorded or if it has expired.
func (s *SessionStore) Get(sessionID string) (*Capability, bool) {
	s.mu.RLock()
	cap, ok := s.sessions[sessionID]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if !cap.ExpiresAt.IsZero() && s.clock().After(cap.ExpiresAt) {
		s.mu.Lock()
		delete(s.sessions, sessionID)
		s.mu.Unlock()
		return nil, false
	}
	return cap, true
}

// Delete drops a session if present.
func (s *SessionStore) Delete(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
}

// Len returns the number of recorded sessions (including any that have
// silently expired but not yet been pruned).
func (s *SessionStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

// ── nonceCache ────────────────────────────────────────────────────────

// nonceCache is the per-Participant replay-protection store. Each consumed
// nonce is held until its expiry passes, then garbage-collected lazily on
// the next consume call.
type nonceCache struct {
	mu sync.Mutex
	m  map[string]time.Time
}

func newNonceCache() *nonceCache {
	return &nonceCache{m: make(map[string]time.Time)}
}

// consume atomically registers a nonce. Returns true if the nonce was
// previously unseen; false if it has already been recorded. The caller
// supplies the nonce expiry so the cache can lazily GC entries whose
// freshness window has lapsed relative to that supplied time.
func (c *nonceCache) consume(nonce string, expiresAt time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Lazy GC of entries that have lapsed relative to the new entry's
	// expiry. Using the supplied expiresAt as the reference point keeps
	// the cache deterministic under injected clocks.
	for k, exp := range c.m {
		if expiresAt.After(exp) {
			delete(c.m, k)
		}
	}

	if _, seen := c.m[nonce]; seen {
		return false
	}
	c.m[nonce] = expiresAt
	return true
}
