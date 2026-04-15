// memory_integrity.go provides tamper-evident memory protection for governed
// memory stores. Every write produces a SHA-256 hash receipt, and reads
// verify integrity before returning values.
//
// Paper basis: arXiv 2603.20357 — hash functions detect undesired memory changes
// Paper basis: arXiv 2601.05504 — MINJA achieves 95% injection success without protection
//
// Design invariants:
//   - Every write hashed and recorded
//   - Reads verify hash integrity (fail-closed: tampered = error)
//   - Thread-safe with sync.RWMutex
//   - Clock-injectable for deterministic testing
package kernel

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// MemoryEntry is a single value stored in the integrity-protected memory store.
type MemoryEntry struct {
	Key         string    `json:"key"`
	Value       []byte    `json:"value"`
	ContentHash string    `json:"content_hash"` // SHA-256 hex of Value
	WrittenAt   time.Time `json:"written_at"`
	WrittenBy   string    `json:"written_by"` // Principal ID
	Version     int       `json:"version"`    // Monotonic per key
}

// MemoryWriteEvent records a single write for the audit trail.
type MemoryWriteEvent struct {
	Key          string    `json:"key"`
	ContentHash  string    `json:"content_hash"`
	WrittenBy    string    `json:"written_by"`
	WrittenAt    time.Time `json:"written_at"`
	Version      int       `json:"version"`
	PreviousHash string   `json:"previous_hash,omitempty"`
}

// ErrMemoryTampered is returned when a read detects that the stored value
// no longer matches its recorded hash. This is a fail-closed signal —
// callers MUST NOT trust the returned data.
type ErrMemoryTampered struct {
	Key          string
	ExpectedHash string
	ActualHash   string
}

func (e *ErrMemoryTampered) Error() string {
	return fmt.Sprintf("memory tampered: key=%q expected_hash=%s actual_hash=%s", e.Key, e.ExpectedHash, e.ActualHash)
}

// MemoryIntegrityOption configures optional behavior for MemoryIntegrityStore.
type MemoryIntegrityOption func(*MemoryIntegrityStore)

// WithIntegrityClock injects a deterministic clock for testing.
func WithIntegrityClock(clock func() time.Time) MemoryIntegrityOption {
	return func(s *MemoryIntegrityStore) {
		s.clock = clock
	}
}

// MemoryIntegrityStore is a thread-safe, tamper-evident key-value store.
// Every write is hashed and recorded. Reads verify integrity before returning.
type MemoryIntegrityStore struct {
	mu      sync.RWMutex
	entries map[string]*MemoryEntry
	history []MemoryWriteEvent
	clock   func() time.Time
}

// NewMemoryIntegrityStore creates a new integrity-protected memory store.
func NewMemoryIntegrityStore(opts ...MemoryIntegrityOption) *MemoryIntegrityStore {
	s := &MemoryIntegrityStore{
		entries: make(map[string]*MemoryEntry),
		history: make([]MemoryWriteEvent, 0),
		clock:   time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// computeHash returns the SHA-256 hex digest of the given data.
func computeHash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// Write stores a value with integrity protection. It computes the SHA-256 hash,
// records the write event, and returns the resulting MemoryEntry.
func (s *MemoryIntegrityStore) Write(key string, value []byte, principalID string) (*MemoryEntry, error) {
	if key == "" {
		return nil, fmt.Errorf("memory_integrity: key must not be empty")
	}

	contentHash := computeHash(value)
	now := s.clock()

	s.mu.Lock()
	defer s.mu.Unlock()

	var previousHash string
	version := 1
	if existing, ok := s.entries[key]; ok {
		previousHash = existing.ContentHash
		version = existing.Version + 1
	}

	// Store a copy of the value to prevent external mutation
	storedValue := make([]byte, len(value))
	copy(storedValue, value)

	entry := &MemoryEntry{
		Key:         key,
		Value:       storedValue,
		ContentHash: contentHash,
		WrittenAt:   now,
		WrittenBy:   principalID,
		Version:     version,
	}
	s.entries[key] = entry

	event := MemoryWriteEvent{
		Key:          key,
		ContentHash:  contentHash,
		WrittenBy:    principalID,
		WrittenAt:    now,
		Version:      version,
		PreviousHash: previousHash,
	}
	s.history = append(s.history, event)

	// Return a copy so callers cannot mutate the stored entry
	result := *entry
	result.Value = make([]byte, len(storedValue))
	copy(result.Value, storedValue)
	return &result, nil
}

// Read retrieves a value and verifies its integrity. If the stored value's
// hash does not match the recorded hash, ErrMemoryTampered is returned.
// This is fail-closed: tampered data is never silently returned.
func (s *MemoryIntegrityStore) Read(key string) (*MemoryEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.entries[key]
	if !ok {
		return nil, fmt.Errorf("memory_integrity: key %q not found", key)
	}

	// Verify integrity
	actualHash := computeHash(entry.Value)
	if actualHash != entry.ContentHash {
		return nil, &ErrMemoryTampered{
			Key:          key,
			ExpectedHash: entry.ContentHash,
			ActualHash:   actualHash,
		}
	}

	// Return a copy
	result := *entry
	result.Value = make([]byte, len(entry.Value))
	copy(result.Value, entry.Value)
	return &result, nil
}

// Delete removes a key from the store. Returns an error if the key does not exist.
func (s *MemoryIntegrityStore) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.entries[key]; !ok {
		return fmt.Errorf("memory_integrity: key %q not found", key)
	}

	delete(s.entries, key)
	return nil
}

// History returns the write history for a specific key, in chronological order.
func (s *MemoryIntegrityStore) History(key string) []MemoryWriteEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []MemoryWriteEvent
	for _, evt := range s.history {
		if evt.Key == key {
			result = append(result, evt)
		}
	}
	return result
}

// AllHistory returns the full audit trail of all write events, in chronological order.
func (s *MemoryIntegrityStore) AllHistory() []MemoryWriteEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]MemoryWriteEvent, len(s.history))
	copy(result, s.history)
	return result
}

// Verify performs an explicit integrity check on a stored key.
// Returns nil if the value is intact, ErrMemoryTampered if corrupted,
// or a not-found error if the key does not exist.
func (s *MemoryIntegrityStore) Verify(key string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.entries[key]
	if !ok {
		return fmt.Errorf("memory_integrity: key %q not found", key)
	}

	actualHash := computeHash(entry.Value)
	if actualHash != entry.ContentHash {
		return &ErrMemoryTampered{
			Key:          key,
			ExpectedHash: entry.ContentHash,
			ActualHash:   actualHash,
		}
	}

	return nil
}
