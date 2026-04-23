// Package ledger — Typed Ledgers.
//
// Per HELM 2030 Spec §4.3:
//
//	Immutable, exportable ledgers: policy ledger, run ledger, evidence ledger.
//	All append-only, hash-chained, independently verifiable.
package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

const (
	LedgerPolicy   LedgerType = LedgerTypePolicy
	LedgerRun      LedgerType = LedgerTypeRun
	LedgerEvidence LedgerType = LedgerTypeEvidence
)

// TypedEntry is one entry in a typed ledger.
type TypedEntry struct {
	Sequence    uint64     `json:"sequence"`
	LedgerType  LedgerType `json:"ledger_type"`
	EntryType   string     `json:"entry_type"` // e.g. "policy_change", "run_start", "evidence_commit"
	Payload     string     `json:"payload"`    // JSON-encoded payload
	PrevHash    string     `json:"prev_hash"`
	ContentHash string     `json:"content_hash"`
	Timestamp   time.Time  `json:"timestamp"`
}

// TypedLedger is an append-only, hash-chained, typed ledger.
type TypedLedger struct {
	mu         sync.Mutex
	ledgerType LedgerType
	entries    []TypedEntry
	headHash   string
	clock      func() time.Time
}

// NewTypedLedger creates a new typed ledger.
func NewTypedLedger(lt LedgerType) *TypedLedger {
	return &TypedLedger{
		ledgerType: lt,
		entries:    make([]TypedEntry, 0),
		headHash:   "genesis",
		clock:      time.Now,
	}
}

// WithClock overrides clock for testing.
func (l *TypedLedger) WithClock(clock func() time.Time) *TypedLedger {
	l.clock = clock
	return l
}

// Append adds an entry to the ledger, returning the entry with its hash.
func (l *TypedLedger) Append(entryType, payload string) *TypedEntry {
	l.mu.Lock()
	defer l.mu.Unlock()

	seq := uint64(len(l.entries)) + 1
	now := l.clock()

	hashInput := fmt.Sprintf("%d:%s:%s:%s:%s", seq, l.ledgerType, entryType, payload, l.headHash)
	h := sha256.Sum256([]byte(hashInput))
	contentHash := "sha256:" + hex.EncodeToString(h[:])

	entry := TypedEntry{
		Sequence:    seq,
		LedgerType:  l.ledgerType,
		EntryType:   entryType,
		Payload:     payload,
		PrevHash:    l.headHash,
		ContentHash: contentHash,
		Timestamp:   now,
	}

	l.entries = append(l.entries, entry)
	l.headHash = contentHash
	return &entry
}

// Get retrieves an entry by sequence number.
func (l *TypedLedger) Get(seq uint64) (*TypedEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if seq < 1 || seq > uint64(len(l.entries)) {
		return nil, fmt.Errorf("sequence %d out of range [1, %d]", seq, len(l.entries))
	}
	e := l.entries[seq-1]
	return &e, nil
}

// Head returns the current head hash.
func (l *TypedLedger) Head() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.headHash
}

// Verify checks the hash chain integrity.
func (l *TypedLedger) Verify() (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	prevHash := "genesis"
	for _, entry := range l.entries {
		if entry.PrevHash != prevHash {
			return false, fmt.Errorf("chain broken at seq %d: expected prev %s, got %s", entry.Sequence, prevHash, entry.PrevHash)
		}

		hashInput := fmt.Sprintf("%d:%s:%s:%s:%s", entry.Sequence, l.ledgerType, entry.EntryType, entry.Payload, entry.PrevHash)
		h := sha256.Sum256([]byte(hashInput))
		expected := "sha256:" + hex.EncodeToString(h[:])

		if entry.ContentHash != expected {
			return false, fmt.Errorf("hash mismatch at seq %d", entry.Sequence)
		}
		prevHash = entry.ContentHash
	}
	return true, nil
}

// Length returns the number of entries.
func (l *TypedLedger) Length() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// Type returns the ledger type.
func (l *TypedLedger) Type() LedgerType {
	return l.ledgerType
}
