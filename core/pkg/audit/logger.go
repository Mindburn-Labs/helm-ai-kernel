package audit

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/auth"
)

// EventType defines the category of the audit event.
type EventType string

const (
	EventAccess   EventType = "ACCESS"
	EventMutation EventType = "MUTATION"
	EventSystem   EventType = "SYSTEM"
	EventPolicy   EventType = "POLICY"
)

// Event represents a structured audit record.
type Event struct {
	ID        string                 `json:"id"`
	TenantID  string                 `json:"tenant_id"`
	ActorID   string                 `json:"actor_id"`
	Type      EventType              `json:"type"`
	Action    string                 `json:"action"`
	Resource  string                 `json:"resource"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// Logger defines the interface for recording audit events.
type Logger interface {
	Record(ctx context.Context, eventType EventType, action, resource string, metadata map[string]interface{}) error
}

// logger implements Logger, writing structured JSON to a configurable Writer.
type logger struct {
	mu     sync.Mutex
	writer io.Writer
}

// NewLogger creates a Logger writing to os.Stdout.
func NewLogger() Logger {
	return NewLoggerWithWriter(os.Stdout)
}

// NewLoggerWithWriter creates a Logger writing to the given writer.
// This allows injection for testing and custom sinks.
func NewLoggerWithWriter(w io.Writer) Logger {
	if w == nil {
		w = os.Stdout
	}
	return &logger{writer: w}
}

func (l *logger) Record(ctx context.Context, eventType EventType, action, resource string, metadata map[string]interface{}) error {
	principal, _ := auth.GetPrincipal(ctx)
	tenantID := "system"
	actorID := "system"
	if principal != nil {
		tenantID = principal.GetTenantID()
		actorID = principal.GetID()
	}

	event := Event{
		ID:        uuid.New().String(),
		TenantID:  tenantID,
		ActorID:   actorID,
		Type:      eventType,
		Action:    action,
		Resource:  resource,
		Timestamp: time.Now(),
		Metadata:  metadata,
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	bytes, err := json.Marshal(event)
	if err != nil {
		return err
	}
	// Prefix with AUDIT: for easy filtering
	_, err = l.writer.Write(append([]byte("AUDIT: "), append(bytes, '\n')...))
	return err
}
