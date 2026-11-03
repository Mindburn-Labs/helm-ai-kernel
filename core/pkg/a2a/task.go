// Package a2a — task.go
// Task lifecycle management for A2A agent interactions.
//
// A Task represents a unit of work delegated from one agent to another.
// Tasks follow a strict state machine:
//
//	SUBMITTED → WORKING → {COMPLETED | FAILED | CANCELED}
//	           WORKING → INPUT_REQUIRED → WORKING (loop)
//
// Invariants:
//   - Only forward transitions are allowed (no going backwards).
//   - Terminal states (COMPLETED, FAILED, CANCELED) are final.
//   - Each state transition is recorded with a timestamp.
//   - Task IDs are unique within a session.
//   - Artifacts are append-only once a task is completed.

package a2a

import (
	"encoding/json"
	"sync"
	"time"
)

// ── Task Status ──────────────────────────────────────────────────

// TaskStatus represents the current phase of a task.
type TaskStatus string

const (
	TaskStatusSubmitted     TaskStatus = "SUBMITTED"
	TaskStatusWorking       TaskStatus = "WORKING"
	TaskStatusInputRequired TaskStatus = "INPUT_REQUIRED"
	TaskStatusCompleted     TaskStatus = "COMPLETED"
	TaskStatusFailed        TaskStatus = "FAILED"
	TaskStatusCanceled      TaskStatus = "CANCELED"
)

// ── Task ─────────────────────────────────────────────────────────

// Task represents a unit of work in the A2A protocol.
type Task struct {
	TaskID      string            `json:"task_id"`
	SessionID   string            `json:"session_id,omitempty"`
	Status      TaskStatus        `json:"status"`
	OriginAgent string            `json:"origin_agent"`
	TargetAgent string            `json:"target_agent"`
	Messages    []Message         `json:"messages,omitempty"`
	Artifacts   []Artifact        `json:"artifacts,omitempty"`
	History     []StatusChange    `json:"history,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// StatusChange records a task state transition.
type StatusChange struct {
	From      TaskStatus `json:"from"`
	To        TaskStatus `json:"to"`
	Reason    string     `json:"reason,omitempty"`
	Timestamp time.Time  `json:"timestamp"`
}

// ── Message ──────────────────────────────────────────────────────

// MessageRole identifies the sender role.
type MessageRole string

const (
	MessageRoleUser  MessageRole = "user"
	MessageRoleAgent MessageRole = "agent"
)

// Message is a single exchange within a task.
type Message struct {
	MessageID string      `json:"message_id"`
	Role      MessageRole `json:"role"`
	Parts     []Part      `json:"parts"`
	Timestamp time.Time   `json:"timestamp"`
}

// ── Part (message content) ───────────────────────────────────────

// PartType identifies the kind of content in a message part.
type PartType string

const (
	PartTypeText       PartType = "text"
	PartTypeFile       PartType = "file"
	PartTypeStructured PartType = "structured"
)

// Part is a content fragment within a message.
type Part struct {
	Type    PartType        `json:"type"`
	Text    string          `json:"text,omitempty"`
	FileURI string          `json:"file_uri,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"` // for structured parts
}

// ── Artifact ─────────────────────────────────────────────────────

// Artifact is an output produced by a task.
type Artifact struct {
	ArtifactID  string    `json:"artifact_id"`
	Name        string    `json:"name"`
	ContentType string    `json:"content_type"`
	Parts       []Part    `json:"parts"`
	ContentHash string    `json:"content_hash"`
	CreatedAt   time.Time `json:"created_at"`
}

// ── SSE Event ────────────────────────────────────────────────────

// SSEEventType classifies streaming events.
type SSEEventType string

const (
	SSEEventTaskStatus   SSEEventType = "task.status"
	SSEEventTaskMessage  SSEEventType = "task.message"
	SSEEventTaskArtifact SSEEventType = "task.artifact"
	SSEEventTaskError    SSEEventType = "task.error"
)

// SSEEvent represents a server-sent event for task streaming.
type SSEEvent struct {
	EventType SSEEventType    `json:"event"`
	TaskID    string          `json:"task_id"`
	Data      json.RawMessage `json:"data"`
	Sequence  int64           `json:"sequence"`
	Timestamp time.Time       `json:"timestamp"`
}

// ── Valid Transitions ────────────────────────────────────────────

// validTransitions defines the allowed state machine transitions.
var validTransitions = map[TaskStatus][]TaskStatus{
	TaskStatusSubmitted:     {TaskStatusWorking, TaskStatusCanceled},
	TaskStatusWorking:       {TaskStatusCompleted, TaskStatusFailed, TaskStatusCanceled, TaskStatusInputRequired},
	TaskStatusInputRequired: {TaskStatusWorking, TaskStatusCanceled},
	// Terminal states have no outgoing transitions.
	TaskStatusCompleted: {},
	TaskStatusFailed:    {},
	TaskStatusCanceled:  {},
}

// ── Task Manager ─────────────────────────────────────────────────

// TaskManager manages task lifecycle with fail-closed state transitions.
type TaskManager struct {
	mu    sync.RWMutex
	tasks map[string]*Task // taskID -> task
	clock func() time.Time
}

// ── SSE Stream ───────────────────────────────────────────────────

// SSEStream collects streaming events for a task.
type SSEStream struct {
	mu       sync.Mutex
	events   []SSEEvent
	sequence int64
	taskID   string
	clock    func() time.Time
}
