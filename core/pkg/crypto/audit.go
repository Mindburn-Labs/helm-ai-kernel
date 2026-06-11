package crypto

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// AuditEvent represents a secure log entry.
type AuditEvent struct {
	Sequence     int         `json:"sequence"`
	Timestamp    string      `json:"timestamp"`
	Actor        string      `json:"actor"`
	Action       string      `json:"action"`
	Payload      interface{} `json:"payload"`
	PreviousHash string      `json:"previous_hash"`
	Hash         string      `json:"hash"` // Hash of the event content and previous link
}

// AuditLog maintains a verifiable history of events.
type AuditLog interface {
	Append(actor, action string, payload interface{}) error
	Entries() []AuditEvent
}

// FileAuditLog is a persistent implementation using append-only JSON lines.
type FileAuditLog struct {
	mu       sync.RWMutex
	filePath string
	headPath string
	hasher   Hasher
}

// NewFileAuditLog creates a new FileAuditLog at the specified path.
func NewFileAuditLog(path string) (*FileAuditLog, error) {
	// Ensure file exists
	//nolint:wrapcheck // caller provides context
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // Path is configured safe
	if err != nil {
		return nil, err
	}
	_ = f.Close() //nolint:errcheck // best-effort close during init

	return &FileAuditLog{
		filePath: path,
		headPath: path + ".head",
		hasher:   NewCanonicalHasher(),
	}, nil
}

type auditHeadState struct {
	Sequence int    `json:"sequence"`
	Hash     string `json:"hash"`
}

// Append adds a new event to the audit log.
func (l *FileAuditLog) Append(actor, action string, payload interface{}) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	existing, err := l.verifiedEntriesLocked()
	if err != nil {
		return err
	}
	sequence := len(existing)
	previousHash := ""
	if sequence > 0 {
		previousHash = existing[sequence-1].Hash
	}

	ts := time.Now().UTC().Format(time.RFC3339Nano)

	event := AuditEvent{
		Sequence:     sequence,
		Timestamp:    ts,
		Actor:        actor,
		Action:       action,
		Payload:      payload,
		PreviousHash: previousHash,
	}

	//nolint:wrapcheck // internal error handling
	h, err := hashAuditEvent(l.auditHasher(), event)
	if err != nil {
		return err
	}
	event.Hash = h

	// Serialize
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	// Append to file
	//nolint:wrapcheck // caller provides context
	f, err := os.OpenFile(l.filePath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }() //nolint:errcheck // best-effort close

	//nolint:wrapcheck // caller provides context
	if _, err := f.Write(append(data, '\n')); err != nil {
		return err
	}
	return l.writeHeadStateLocked(event)
}

// Entries retrieves all verified audit events from the log.
// It returns nil on invalid history so legacy consumers fail closed.
func (l *FileAuditLog) Entries() []AuditEvent {
	events, err := l.VerifiedEntries()
	if err != nil {
		return nil
	}
	return events
}

// VerifiedEntries retrieves all audit events after hash-chain verification.
func (l *FileAuditLog) VerifiedEntries() ([]AuditEvent, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.verifiedEntriesLocked()
}

func (l *FileAuditLog) verifiedEntriesLocked() ([]AuditEvent, error) {
	// Open file for reading
	f, err := os.Open(l.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return []AuditEvent{}, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var events []AuditEvent
	previousHash := ""
	reader := bufio.NewReader(f)
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			line = bytes.TrimSpace(line)
		}
		if len(line) > 0 {
			var event AuditEvent
			if err := json.Unmarshal(line, &event); err != nil {
				return nil, fmt.Errorf("audit log malformed entry %d: %w", len(events), err)
			}
			if err := verifyAuditEvent(l.auditHasher(), event, len(events), previousHash); err != nil {
				return nil, err
			}
			events = append(events, event)
			previousHash = event.Hash
		}
		if err != nil {
			break
		}
	}

	if err := l.verifyHeadStateLocked(events); err != nil {
		return nil, err
	}
	return events, nil
}

func (l *FileAuditLog) writeHeadStateLocked(event AuditEvent) error {
	data, err := json.Marshal(auditHeadState{Sequence: event.Sequence, Hash: event.Hash})
	if err != nil {
		return err
	}
	return os.WriteFile(l.auditHeadPath(), data, 0o600) //nolint:gosec // Path is configured safe
}

func (l *FileAuditLog) verifyHeadStateLocked(events []AuditEvent) error {
	data, err := os.ReadFile(l.auditHeadPath()) //nolint:gosec // Path is configured safe
	if err != nil {
		if os.IsNotExist(err) && len(events) == 0 {
			return nil
		}
		if os.IsNotExist(err) {
			return fmt.Errorf("audit log head checkpoint missing")
		}
		return err
	}
	var head auditHeadState
	if err := json.Unmarshal(bytes.TrimSpace(data), &head); err != nil {
		return fmt.Errorf("audit log head checkpoint malformed: %w", err)
	}
	if len(events) == 0 {
		return fmt.Errorf("audit log head checkpoint exists for empty log")
	}
	last := events[len(events)-1]
	if head.Sequence != last.Sequence || head.Hash != last.Hash {
		return fmt.Errorf("audit log head checkpoint mismatch")
	}
	return nil
}

func (l *FileAuditLog) auditHeadPath() string {
	if l.headPath != "" {
		return l.headPath
	}
	return l.filePath + ".head"
}

func (l *FileAuditLog) auditHasher() Hasher {
	if l.hasher != nil {
		return l.hasher
	}
	return NewCanonicalHasher()
}

// MemoryAuditLog is a transient implementation for Testing.
type MemoryAuditLog struct {
	mu     sync.RWMutex
	events []AuditEvent
	hasher Hasher
}

// NewMemoryAuditLog creates a new in-memory audit log for testing.
func NewMemoryAuditLog() *MemoryAuditLog {
	return &MemoryAuditLog{
		hasher: NewCanonicalHasher(),
	}
}

// Append adds a new event to the memory audit log.
func (l *MemoryAuditLog) Append(actor, action string, payload interface{}) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	ts := time.Now().UTC().Format(time.RFC3339Nano)

	event := AuditEvent{
		Sequence:  len(l.events),
		Timestamp: ts,
		Actor:     actor,
		Action:    action,
		Payload:   payload,
	}
	if len(l.events) > 0 {
		event.PreviousHash = l.events[len(l.events)-1].Hash
	}

	//nolint:wrapcheck // internal error handling
	h, err := hashAuditEvent(l.hasher, event)
	if err != nil {
		return err
	}
	event.Hash = h

	l.events = append(l.events, event)
	return nil
}

// Entries retrieves all verified audit events from the memory log.
func (l *MemoryAuditLog) Entries() []AuditEvent {
	events, err := l.VerifiedEntries()
	if err != nil {
		return nil
	}
	return events
}

// VerifiedEntries retrieves all events after hash-chain verification.
func (l *MemoryAuditLog) VerifiedEntries() ([]AuditEvent, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	out := make([]AuditEvent, len(l.events))
	copy(out, l.events)
	previousHash := ""
	for i, event := range out {
		if err := verifyAuditEvent(l.hasher, event, i, previousHash); err != nil {
			return nil, err
		}
		previousHash = event.Hash
	}
	return out, nil
}

func hashAuditEvent(hasher Hasher, event AuditEvent) (string, error) {
	if hasher == nil {
		hasher = NewCanonicalHasher()
	}
	event.Hash = ""
	return hasher.Hash(event)
}

func verifyAuditEvent(hasher Hasher, event AuditEvent, expectedSequence int, expectedPreviousHash string) error {
	if event.Sequence != expectedSequence {
		return fmt.Errorf("audit log sequence mismatch at index %d: got %d", expectedSequence, event.Sequence)
	}
	if event.PreviousHash != expectedPreviousHash {
		return fmt.Errorf("audit log previous hash mismatch at index %d", expectedSequence)
	}
	if event.Hash == "" {
		return fmt.Errorf("audit log missing hash at index %d", expectedSequence)
	}
	recomputed, err := hashAuditEvent(hasher, event)
	if err != nil {
		return fmt.Errorf("audit log hash recompute failed at index %d: %w", expectedSequence, err)
	}
	if recomputed != event.Hash {
		return fmt.Errorf("audit log hash mismatch at index %d", expectedSequence)
	}
	return nil
}
