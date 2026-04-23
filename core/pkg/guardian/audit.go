package guardian

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
)

// AuditEntry is a tamper-evident log record.
type AuditEntry struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	Details   string    `json:"details,omitempty"` // JCS canonicalized details string if possible

	// PreviousHash links this entry to the preceding one, creating a blockchain-like structure.
	PreviousHash string `json:"previous_hash"`

	// Hash is the SHA-256 digest of this entry (including PreviousHash).
	Hash string `json:"hash"`
}

// AuditLog manages a sequence of audit entries.
type AuditLog struct {
	Entries []AuditEntry
	clock   Clock
}

// NewAuditLog creates a new audit log.
// If clock is nil, a default wall-clock is used for backward compatibility.
func NewAuditLog(clock ...Clock) *AuditLog {
	var c Clock
	if len(clock) > 0 && clock[0] != nil {
		c = clock[0]
	} else {
		c = wallClock{}
	}
	return &AuditLog{
		Entries: make([]AuditEntry, 0),
		clock:   c,
	}
}

// Append adds a new entry to the log, linking it to the previous one.
func (l *AuditLog) Append(actor, action, target, details string) (*AuditEntry, error) {
	prevHash := ""
	if len(l.Entries) > 0 {
		prevHash = l.Entries[len(l.Entries)-1].Hash
	}

	now := l.clock.Now()
	entry := AuditEntry{
		ID:           fmt.Sprintf("evt_%d", now.UnixNano()),
		Timestamp:    now.UTC(),
		Actor:        actor,
		Action:       action,
		Target:       target,
		Details:      details,
		PreviousHash: prevHash,
	}

	// Compute hash of the entry
	// We need to exclude the Hash field itself from the computation, obviously.
	// But since the struct has it, we should be careful.
	// Let's create a temporary strict representation for hashing.
	hash, err := computeEntryHash(&entry)
	if err != nil {
		return nil, err
	}
	entry.Hash = hash

	l.Entries = append(l.Entries, entry)
	return &entry, nil
}

// VerifyChain checks the integrity of the audit log.
// It verifies that each entry's PreviousHash matches the actual hash of the preceding entry,
// and that each entry's Hash matches its content.
func (l *AuditLog) VerifyChain() (bool, error) {
	if len(l.Entries) == 0 {
		return true, nil
	}

	for i, entry := range l.Entries {
		// 1. Verify links
		if i > 0 {
			if entry.PreviousHash != l.Entries[i-1].Hash {
				return false, fmt.Errorf("chain broken at index %d: previous hash mismatch", i)
			}
		} else {
			if entry.PreviousHash != "" {
				return false, fmt.Errorf("genesis block (index 0) has non-empty previous hash")
			}
		}

		// 2. Verify content integrity
		computedHash, err := computeEntryHash(&entry)
		if err != nil {
			return false, fmt.Errorf("failed to recompute hash at index %d: %w", i, err)
		}

		if computedHash != entry.Hash {
			return false, fmt.Errorf("integrity failure at index %d: computed %s, stored %s", i, computedHash, entry.Hash)
		}
	}

	return true, nil
}

// computeEntryHash calculates SHA-256 hash of the entry fields.
func computeEntryHash(e *AuditEntry) (string, error) {
	// Create a stable map for canonicalization
	data := map[string]interface{}{
		"id":            e.ID,
		"timestamp":     e.Timestamp,
		"actor":         e.Actor,
		"action":        e.Action,
		"target":        e.Target,
		"details":       e.Details,
		"previous_hash": e.PreviousHash,
	}

	// Use ArtifactProtocol's JCS helper
	canonicalBytes, err := canonicalize.JCS(data)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(canonicalBytes)
	return hex.EncodeToString(hash[:]), nil
}
