// Package ledger — Immutable Append-Only Ledgers.
//
// Per HELM 2030 Spec:
//   - Four ledgers: Release, Policy, Run, Evidence
//   - Each entry is hash-chained to its predecessor
//   - Append-only; no deletions or mutations
package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// LedgerType categorizes the ledger.
type LedgerType string

const (
	LedgerTypeRelease  LedgerType = "RELEASE"
	LedgerTypePolicy   LedgerType = "POLICY"
	LedgerTypeRun      LedgerType = "RUN"
	LedgerTypeEvidence LedgerType = "EVIDENCE"
)

// LedgerEntry is an immutable, hash-chained entry.
type LedgerEntry struct {
	Sequence    uint64                 `json:"sequence"`
	EntryType   string                 `json:"entry_type"`
	ContentHash string                 `json:"content_hash"`
	PrevHash    string                 `json:"prev_hash"`
	Timestamp   time.Time              `json:"timestamp"`
	Author      string                 `json:"author,omitempty"`
	Data        map[string]interface{} `json:"data"`
}

// Ledger is an append-only, hash-chained log.
type Ledger struct {
	mu         sync.RWMutex
	ledgerType LedgerType
	entries    []LedgerEntry
	headHash   string
	clock      func() time.Time
}

// NewLedger creates a new immutable ledger.
func NewLedger(lt LedgerType) *Ledger {
	return &Ledger{
		ledgerType: lt,
		entries:    make([]LedgerEntry, 0),
		headHash:   "genesis",
		clock:      time.Now,
	}
}

// WithClock overrides clock for testing.
func (l *Ledger) WithClock(clock func() time.Time) *Ledger {
	l.clock = clock
	return l
}

// Append adds an entry to the ledger. Returns the sequence number.
func (l *Ledger) Append(entryType, author string, data map[string]interface{}) (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	seq := uint64(len(l.entries)) + 1

	// Compute content hash
	hashInput := struct {
		Seq      uint64                 `json:"seq"`
		Type     string                 `json:"type"`
		Data     map[string]interface{} `json:"data"`
		PrevHash string                 `json:"prev"`
	}{seq, entryType, data, l.headHash}

	raw, err := json.Marshal(hashInput)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal entry: %w", err)
	}
	h := sha256.Sum256(raw)
	contentHash := "sha256:" + hex.EncodeToString(h[:])

	entry := LedgerEntry{
		Sequence:    seq,
		EntryType:   entryType,
		ContentHash: contentHash,
		PrevHash:    l.headHash,
		Timestamp:   l.clock(),
		Author:      author,
		Data:        data,
	}

	l.entries = append(l.entries, entry)
	l.headHash = contentHash

	return seq, nil
}

// Get retrieves an entry by sequence number.
func (l *Ledger) Get(seq uint64) (*LedgerEntry, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if seq == 0 || seq > uint64(len(l.entries)) {
		return nil, fmt.Errorf("entry %d not found", seq)
	}
	entry := l.entries[seq-1]
	return &entry, nil
}

// Head returns the current head hash.
func (l *Ledger) Head() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.headHash
}

// Length returns the number of entries.
func (l *Ledger) Length() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.entries)
}

// Verify checks the integrity of the entire ledger chain.
func (l *Ledger) Verify() (bool, string) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	prevHash := "genesis"
	for i, entry := range l.entries {
		if entry.PrevHash != prevHash {
			return false, fmt.Sprintf("chain broken at entry %d: expected prev %s, got %s", i+1, prevHash, entry.PrevHash)
		}

		// Recompute content hash
		hashInput := struct {
			Seq      uint64                 `json:"seq"`
			Type     string                 `json:"type"`
			Data     map[string]interface{} `json:"data"`
			PrevHash string                 `json:"prev"`
		}{entry.Sequence, entry.EntryType, entry.Data, entry.PrevHash}

		raw, err := json.Marshal(hashInput)
		if err != nil {
			return false, fmt.Sprintf("failed to marshal entry %d", i+1)
		}
		h := sha256.Sum256(raw)
		computed := "sha256:" + hex.EncodeToString(h[:])

		if computed != entry.ContentHash {
			return false, fmt.Sprintf("hash mismatch at entry %d", i+1)
		}
		prevHash = entry.ContentHash
	}

	return true, "chain verified"
}

// Type returns the ledger type.
func (l *Ledger) Type() LedgerType {
	return l.ledgerType
}
