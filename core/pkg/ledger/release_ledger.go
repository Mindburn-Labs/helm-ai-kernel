// Package ledger — Release Ledger.
//
// Per HELM 2030 Spec:
//   - Auditor can reproduce all guarantees from artifacts alone
//   - Links release → policy version → test evidence → supply chain attestation
package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// ReleaseRecord links a release to all its guarantees.
type ReleaseRecord struct {
	ReleaseID        string    `json:"release_id"`
	Version          string    `json:"version"`
	ReleasedAt       time.Time `json:"released_at"`
	PolicyVersion    string    `json:"policy_version"`
	TestEvidenceHash string    `json:"test_evidence_hash"`
	SupplyChainHash  string    `json:"supply_chain_hash"`
	DRDrillReceiptID string    `json:"dr_drill_receipt_id,omitempty"`
	RedTeamSuiteID   string    `json:"redteam_suite_id,omitempty"`
	ContentHash      string    `json:"content_hash"`
	PrevReleaseHash  string    `json:"prev_release_hash,omitempty"`
}

// ReleaseLedger is an append-only release log with attestation links.
type ReleaseLedger struct {
	mu       sync.Mutex
	entries  []ReleaseRecord
	headHash string
	clock    func() time.Time
}

// NewReleaseLedger creates a new release ledger.
func NewReleaseLedger() *ReleaseLedger {
	return &ReleaseLedger{
		entries:  make([]ReleaseRecord, 0),
		headHash: "genesis",
		clock:    time.Now,
	}
}

// WithClock overrides clock for testing.
func (l *ReleaseLedger) WithClock(clock func() time.Time) *ReleaseLedger {
	l.clock = clock
	return l
}

// RecordRelease appends a release to the ledger.
func (l *ReleaseLedger) RecordRelease(record ReleaseRecord) (*ReleaseRecord, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if record.ReleaseID == "" {
		record.ReleaseID = fmt.Sprintf("rel-%d", len(l.entries)+1)
	}
	if record.ReleasedAt.IsZero() {
		record.ReleasedAt = l.clock()
	}

	record.PrevReleaseHash = l.headHash

	// Compute content hash
	hashInput := struct {
		ID       string `json:"id"`
		Version  string `json:"version"`
		TestHash string `json:"test"`
		SCHash   string `json:"sc"`
		Prev     string `json:"prev"`
	}{record.ReleaseID, record.Version, record.TestEvidenceHash, record.SupplyChainHash, record.PrevReleaseHash}

	raw, err := json.Marshal(hashInput)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(raw)
	record.ContentHash = "sha256:" + hex.EncodeToString(h[:])

	l.entries = append(l.entries, record)
	l.headHash = record.ContentHash

	return &record, nil
}

// GetRelease retrieves a release by index (0-based).
func (l *ReleaseLedger) GetRelease(index int) (*ReleaseRecord, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if index < 0 || index >= len(l.entries) {
		return nil, fmt.Errorf("release index %d out of range", index)
	}
	entry := l.entries[index]
	return &entry, nil
}

// Length returns the number of releases.
func (l *ReleaseLedger) Length() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// Verify checks the integrity of the release chain.
func (l *ReleaseLedger) Verify() (bool, string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	prevHash := "genesis"
	for i, entry := range l.entries {
		if entry.PrevReleaseHash != prevHash {
			return false, fmt.Sprintf("chain broken at release %d", i)
		}

		hashInput := struct {
			ID       string `json:"id"`
			Version  string `json:"version"`
			TestHash string `json:"test"`
			SCHash   string `json:"sc"`
			Prev     string `json:"prev"`
		}{entry.ReleaseID, entry.Version, entry.TestEvidenceHash, entry.SupplyChainHash, entry.PrevReleaseHash}

		raw, err := json.Marshal(hashInput)
		if err != nil {
			return false, fmt.Sprintf("failed to marshal release %d", i)
		}
		h := sha256.Sum256(raw)
		computed := "sha256:" + hex.EncodeToString(h[:])

		if computed != entry.ContentHash {
			return false, fmt.Sprintf("hash mismatch at release %d", i)
		}
		prevHash = entry.ContentHash
	}

	return true, "release chain verified"
}
