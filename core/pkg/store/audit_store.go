// Package store implements append-only evidence storage
// with content addressing and hash chaining for audit trails.
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	ErrEntryNotFound    = errors.New("entry not found")
	ErrChainBroken      = errors.New("hash chain is broken")
	ErrMutationAttempt  = errors.New("mutation of existing entry attempted")
	ErrInvalidEntryType = errors.New("invalid entry type")
)

// EntryType categorizes audit entries.
type EntryType string

const (
	EntryTypeAttestation   EntryType = "attestation"
	EntryTypeAdmission     EntryType = "admission"
	EntryTypeAudit         EntryType = "audit"
	EntryTypeDeploy        EntryType = "deploy"
	EntryTypePolicyChange  EntryType = "policy_change"
	EntryTypeViolation     EntryType = "violation"
	EntryTypeEvidence      EntryType = "evidence"
	EntryTypeSecurityEvent EntryType = "security_event"
)

// AuditEntry is a single immutable entry in the audit store.
type AuditEntry struct {
	EntryID      string            `json:"entry_id"`
	Sequence     uint64            `json:"sequence"`
	Timestamp    time.Time         `json:"timestamp"`
	EntryType    EntryType         `json:"entry_type"`
	Subject      string            `json:"subject"`
	Action       string            `json:"action"`
	Payload      json.RawMessage   `json:"payload"`
	PayloadHash  string            `json:"payload_hash"`
	PreviousHash string            `json:"previous_hash"`
	EntryHash    string            `json:"entry_hash"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// AuditStore is an append-only audit log with hash chaining.
type AuditStore struct {
	mu          sync.RWMutex
	entries     []*AuditEntry
	entryByID   map[string]*AuditEntry
	entryByHash map[string]*AuditEntry
	sequence    uint64
	chainHead   string
	handlers    []EntryHandler
}

// EntryHandler is called when new entries are appended.
type EntryHandler func(entry *AuditEntry)

// NewAuditStore creates a new append-only audit store.
func NewAuditStore() *AuditStore {
	return &AuditStore{
		entries:     make([]*AuditEntry, 0),
		entryByID:   make(map[string]*AuditEntry),
		entryByHash: make(map[string]*AuditEntry),
		chainHead:   "genesis",
	}
}

// Append adds a new entry to the audit store.
func (s *AuditStore) Append(entryType EntryType, subject, action string, payload interface{}, metadata map[string]string) (*AuditEntry, error) {
	// Serialize payload
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize payload: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Create entry
	s.sequence++
	entry := &AuditEntry{
		EntryID:      uuid.New().String(),
		Sequence:     s.sequence,
		Timestamp:    time.Now().UTC(),
		EntryType:    entryType,
		Subject:      subject,
		Action:       action,
		Payload:      payloadBytes,
		PayloadHash:  computeHash(payloadBytes),
		PreviousHash: s.chainHead,
		Metadata:     metadata,
	}

	// Compute entry hash (includes previous hash for chaining)
	entryHash, err := s.computeEntryHash(entry)
	if err != nil {
		s.sequence-- // rollback sequence on failure
		return nil, fmt.Errorf("failed to compute entry hash: %w", err)
	}
	entry.EntryHash = entryHash
	s.chainHead = entry.EntryHash

	// Store entry
	s.entries = append(s.entries, entry)
	s.entryByID[entry.EntryID] = entry
	s.entryByHash[entry.EntryHash] = entry

	// Notify handlers
	handlers := s.handlers
	for _, h := range handlers {
		h(entry)
	}

	return entry, nil
}

// computeHash computes SHA-256 hash of data.
func computeHash(data []byte) string {
	hash := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(hash[:])
}

// computeEntryHash computes the hash of an entry for chaining.
func (s *AuditStore) computeEntryHash(entry *AuditEntry) (string, error) {
	// Create hashable representation
	hashable := struct {
		Sequence     uint64    `json:"sequence"`
		Timestamp    time.Time `json:"timestamp"`
		EntryType    EntryType `json:"entry_type"`
		Subject      string    `json:"subject"`
		Action       string    `json:"action"`
		PayloadHash  string    `json:"payload_hash"`
		PreviousHash string    `json:"previous_hash"`
	}{
		Sequence:     entry.Sequence,
		Timestamp:    entry.Timestamp,
		EntryType:    entry.EntryType,
		Subject:      subject(entry.Subject),
		Action:       entry.Action,
		PayloadHash:  entry.PayloadHash,
		PreviousHash: entry.PreviousHash,
	}

	data, err := json.Marshal(hashable)
	if err != nil {
		return "", fmt.Errorf("failed to marshal entry for hashing: %w", err)
	}
	return computeHash(data), nil
}

func subject(s string) string {
	return s
}

// Get retrieves an entry by ID.
func (s *AuditStore) Get(entryID string) (*AuditEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.entryByID[entryID]
	if !ok {
		return nil, ErrEntryNotFound
	}
	return entry, nil
}

// GetByHash retrieves an entry by its hash.
func (s *AuditStore) GetByHash(hash string) (*AuditEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.entryByHash[hash]
	if !ok {
		return nil, ErrEntryNotFound
	}
	return entry, nil
}

// GetChainHead returns the current chain head hash.
func (s *AuditStore) GetChainHead() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.chainHead
}

// GetSequence returns the current sequence number.
func (s *AuditStore) GetSequence() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sequence
}

// Query returns entries matching the filter.
func (s *AuditStore) Query(filter QueryFilter) []*AuditEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	results := make([]*AuditEntry, 0)
	for _, e := range s.entries {
		if filter.matches(e) {
			results = append(results, e)
			if filter.MaxResults > 0 && len(results) >= filter.MaxResults {
				break
			}
		}
	}
	return results
}

// QueryFilter defines filtering criteria for queries.
type QueryFilter struct {
	EntryType  EntryType
	Subject    string
	StartTime  *time.Time
	EndTime    *time.Time
	StartSeq   uint64
	EndSeq     uint64
	MaxResults int
}

func (f QueryFilter) matches(e *AuditEntry) bool {
	if f.EntryType != "" && e.EntryType != f.EntryType {
		return false
	}
	if f.Subject != "" && e.Subject != f.Subject {
		return false
	}
	if f.StartTime != nil && e.Timestamp.Before(*f.StartTime) {
		return false
	}
	if f.EndTime != nil && e.Timestamp.After(*f.EndTime) {
		return false
	}
	if f.StartSeq > 0 && e.Sequence < f.StartSeq {
		return false
	}
	if f.EndSeq > 0 && e.Sequence > f.EndSeq {
		return false
	}
	return true
}

// VerifyChain verifies the integrity of the hash chain.
func (s *AuditStore) VerifyChain() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.entries) == 0 {
		return nil
	}

	expectedPrev := "genesis"
	for i, entry := range s.entries {
		// Check previous hash
		if entry.PreviousHash != expectedPrev {
			return fmt.Errorf("%w: entry %d has previous_hash %s but expected %s",
				ErrChainBroken, i, entry.PreviousHash, expectedPrev)
		}

		// Recompute entry hash
		computed, err := s.computeEntryHash(entry)
		if err != nil {
			return fmt.Errorf("%w: entry %d hash computation failed: %w",
				ErrChainBroken, i, err)
		}
		if computed != entry.EntryHash {
			return fmt.Errorf("%w: entry %d hash mismatch (computed %s, stored %s)",
				ErrChainBroken, i, computed, entry.EntryHash)
		}

		expectedPrev = entry.EntryHash
	}

	return nil
}

// AddHandler registers a handler for new entries.
func (s *AuditStore) AddHandler(h EntryHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers = append(s.handlers, h)
}

// ExportBundle exports entries as an Audit Evidence Bundle.
func (s *AuditStore) ExportBundle(filter QueryFilter) (*AuditEvidenceBundle, error) {
	entries := s.Query(filter)
	if len(entries) == 0 {
		return nil, fmt.Errorf("no entries match filter")
	}

	bundle := &AuditEvidenceBundle{
		BundleID:   uuid.New().String(),
		Version:    "1.0.0",
		CreatedAt:  time.Now().UTC(),
		StartSeq:   entries[0].Sequence,
		EndSeq:     entries[len(entries)-1].Sequence,
		EntryCount: len(entries),
		Entries:    entries,
		ChainHead:  entries[len(entries)-1].EntryHash,
	}

	// Compute bundle hash
	bundleData, err := json.Marshal(bundle.Entries)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal bundle entries: %w", err)
	}
	bundle.BundleHash = computeHash(bundleData)

	return bundle, nil
}

// AuditEvidenceBundle is an exportable bundle of audit entries.
type AuditEvidenceBundle struct {
	BundleID   string        `json:"bundle_id"`
	Version    string        `json:"version"`
	CreatedAt  time.Time     `json:"created_at"`
	StartSeq   uint64        `json:"start_sequence"`
	EndSeq     uint64        `json:"end_sequence"`
	EntryCount int           `json:"entry_count"`
	Entries    []*AuditEntry `json:"entries"`
	ChainHead  string        `json:"chain_head"`
	BundleHash string        `json:"bundle_hash"`
}

// VerifyBundle verifies a bundle's integrity.
func VerifyBundle(bundle *AuditEvidenceBundle) error {
	if len(bundle.Entries) == 0 {
		return fmt.Errorf("bundle is empty")
	}

	// Verify bundle hash
	entriesData, _ := json.Marshal(bundle.Entries)
	computed := computeHash(entriesData)
	if computed != bundle.BundleHash {
		return fmt.Errorf("bundle hash mismatch")
	}

	// Verify internal chain consistency
	for i := 1; i < len(bundle.Entries); i++ {
		if bundle.Entries[i].PreviousHash != bundle.Entries[i-1].EntryHash {
			return fmt.Errorf("chain broken at entry %d", i)
		}
	}

	return nil
}

// Size returns the number of entries in the store.
func (s *AuditStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}
