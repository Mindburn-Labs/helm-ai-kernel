package crypto

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// AuditEvent represents a secure log entry.
type AuditEvent struct {
	Timestamp string      `json:"timestamp"`
	Actor     string      `json:"actor"`
	Action    string      `json:"action"`
	Payload   interface{} `json:"payload"`
	Hash      string      `json:"hash"` // Hash of the event content
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
	hasher   Hasher
}

// NewFileAuditLog creates a new FileAuditLog at the specified path.
func NewFileAuditLog(path string) (*FileAuditLog, error) {
	// Ensure file exists
	//nolint:wrapcheck // caller provides context
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR,0o600) //nolint:gosec // Path is configured safe
	if err != nil {
		return nil, err
	}
	_ = f.Close() //nolint:errcheck // best-effort close during init

	return &FileAuditLog{
		filePath: path,
		hasher:   NewCanonicalHasher(),
	}, nil
}

// Append adds a new event to the audit log.
func (l *FileAuditLog) Append(actor, action string, payload interface{}) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	ts := time.Now().UTC().Format(time.RFC3339Nano)

	event := AuditEvent{
		Timestamp: ts,
		Actor:     actor,
		Action:    action,
		Payload:   payload,
	}

	//nolint:wrapcheck // internal error handling
	h, err := l.hasher.Hash(event)
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
	f, err := os.OpenFile(l.filePath, os.O_APPEND|os.O_WRONLY,0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }() //nolint:errcheck // best-effort close

	//nolint:wrapcheck // caller provides context
	if _, err := f.Write(append(data, '\n')); err != nil {
		return err
	}
	return nil
}

// Entries retrieves all audit events from the log.
func (l *FileAuditLog) Entries() []AuditEvent {
	l.mu.RLock()
	defer l.mu.RUnlock()

	// Open file for reading
	f, err := os.Open(l.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return []AuditEvent{}
		}
		return nil
	}
	defer func() { _ = f.Close() }()

	var events []AuditEvent
	decoder := json.NewDecoder(f)
	for decoder.More() {
		var event AuditEvent
		if err := decoder.Decode(&event); err != nil {
			// Skip malformed lines in MVP, or log error
			continue
		}
		events = append(events, event)
	}

	return events
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
		Timestamp: ts,
		Actor:     actor,
		Action:    action,
		Payload:   payload,
	}

	//nolint:wrapcheck // internal error handling
	h, err := l.hasher.Hash(event)
	if err != nil {
		return err
	}
	event.Hash = h

	l.events = append(l.events, event)
	return nil
}

// Entries retrieves all audit events from the memory log.
func (l *MemoryAuditLog) Entries() []AuditEvent {
	l.mu.RLock()
	defer l.mu.RUnlock()

	out := make([]AuditEvent, len(l.events))
	copy(out, l.events)
	return out
}
