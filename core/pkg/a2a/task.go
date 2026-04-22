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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
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

// IsTerminal returns true for final task states.
func (s TaskStatus) IsTerminal() bool {
	return s == TaskStatusCompleted || s == TaskStatusFailed || s == TaskStatusCanceled
}

// ── Task ─────────────────────────────────────────────────────────

// Task represents a unit of work in the A2A protocol.
type Task struct {
	TaskID       string           `json:"task_id"`
	SessionID    string           `json:"session_id,omitempty"`
	Status       TaskStatus       `json:"status"`
	OriginAgent  string           `json:"origin_agent"`
	TargetAgent  string           `json:"target_agent"`
	Messages     []Message        `json:"messages,omitempty"`
	Artifacts    []Artifact       `json:"artifacts,omitempty"`
	History      []StatusChange   `json:"history,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	CreatedAt    time.Time        `json:"created_at"`
	UpdatedAt    time.Time        `json:"updated_at"`
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
	ArtifactID  string   `json:"artifact_id"`
	Name        string   `json:"name"`
	ContentType string   `json:"content_type"`
	Parts       []Part   `json:"parts"`
	ContentHash string   `json:"content_hash"`
	CreatedAt   time.Time `json:"created_at"`
}

// ComputeArtifactHash creates a deterministic hash of artifact content.
func ComputeArtifactHash(a *Artifact) string {
	hashable := struct {
		Name        string `json:"name"`
		ContentType string `json:"content_type"`
		Parts       []Part `json:"parts"`
	}{
		Name:        a.Name,
		ContentType: a.ContentType,
		Parts:       a.Parts,
	}
	data, _ := json.Marshal(hashable)
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
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

// IsValidTransition checks whether a state transition is allowed.
func IsValidTransition(from, to TaskStatus) bool {
	allowed, ok := validTransitions[from]
	if !ok {
		return false
	}
	for _, s := range allowed {
		if s == to {
			return true
		}
	}
	return false
}

// ── Task Manager ─────────────────────────────────────────────────

// TaskManager manages task lifecycle with fail-closed state transitions.
type TaskManager struct {
	mu    sync.RWMutex
	tasks map[string]*Task // taskID -> task
	clock func() time.Time
}

// NewTaskManager creates a new task manager.
func NewTaskManager() *TaskManager {
	return &TaskManager{
		tasks: make(map[string]*Task),
		clock: time.Now,
	}
}

// WithClock overrides the clock for testing.
func (m *TaskManager) WithClock(clock func() time.Time) *TaskManager {
	m.clock = clock
	return m
}

// CreateTask creates a new task in SUBMITTED state.
func (m *TaskManager) CreateTask(originAgent, targetAgent string) (*Task, error) {
	if originAgent == "" || targetAgent == "" {
		return nil, errors.New("task: origin_agent and target_agent are required")
	}

	now := m.clock()
	task := &Task{
		TaskID:      "task:" + uuid.NewString()[:8],
		Status:      TaskStatusSubmitted,
		OriginAgent: originAgent,
		TargetAgent: targetAgent,
		History: []StatusChange{{
			From:      "",
			To:        TaskStatusSubmitted,
			Reason:    "task created",
			Timestamp: now,
		}},
		Metadata:  make(map[string]string),
		CreatedAt: now,
		UpdatedAt: now,
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.tasks[task.TaskID] = task
	return task, nil
}

// TransitionTask moves a task to a new state. Fails if the transition is invalid.
func (m *TaskManager) TransitionTask(taskID string, newStatus TaskStatus, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	task, ok := m.tasks[taskID]
	if !ok {
		return fmt.Errorf("task: %s not found", taskID)
	}

	if !IsValidTransition(task.Status, newStatus) {
		return fmt.Errorf("task: invalid transition %s -> %s for task %s",
			task.Status, newStatus, taskID)
	}

	now := m.clock()
	task.History = append(task.History, StatusChange{
		From:      task.Status,
		To:        newStatus,
		Reason:    reason,
		Timestamp: now,
	})
	task.Status = newStatus
	task.UpdatedAt = now
	return nil
}

// AddMessage appends a message to a task. Only allowed for non-terminal tasks.
func (m *TaskManager) AddMessage(taskID string, role MessageRole, parts []Part) (*Message, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	task, ok := m.tasks[taskID]
	if !ok {
		return nil, fmt.Errorf("task: %s not found", taskID)
	}
	if task.Status.IsTerminal() {
		return nil, fmt.Errorf("task: cannot add message to terminal task %s (status=%s)",
			taskID, task.Status)
	}

	now := m.clock()
	msg := Message{
		MessageID: "msg:" + uuid.NewString()[:8],
		Role:      role,
		Parts:     parts,
		Timestamp: now,
	}
	task.Messages = append(task.Messages, msg)
	task.UpdatedAt = now
	return &msg, nil
}

// AddArtifact appends an artifact to a completed task.
func (m *TaskManager) AddArtifact(taskID string, name, contentType string, parts []Part) (*Artifact, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	task, ok := m.tasks[taskID]
	if !ok {
		return nil, fmt.Errorf("task: %s not found", taskID)
	}

	now := m.clock()
	artifact := Artifact{
		ArtifactID:  "art:" + uuid.NewString()[:8],
		Name:        name,
		ContentType: contentType,
		Parts:       parts,
		CreatedAt:   now,
	}
	artifact.ContentHash = ComputeArtifactHash(&artifact)
	task.Artifacts = append(task.Artifacts, artifact)
	task.UpdatedAt = now
	return &artifact, nil
}

// GetTask returns a task by ID.
func (m *TaskManager) GetTask(taskID string) (*Task, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	task, ok := m.tasks[taskID]
	return task, ok
}

// ListTasks returns all task IDs.
func (m *TaskManager) ListTasks() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ids := make([]string, 0, len(m.tasks))
	for id := range m.tasks {
		ids = append(ids, id)
	}
	return ids
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

// NewSSEStream creates a new SSE event stream for a task.
func NewSSEStream(taskID string) *SSEStream {
	return &SSEStream{
		taskID: taskID,
		clock:  time.Now,
	}
}

// WithClock overrides the clock for testing.
func (s *SSEStream) WithClock(clock func() time.Time) *SSEStream {
	s.clock = clock
	return s
}

// Emit adds an event to the stream.
func (s *SSEStream) Emit(eventType SSEEventType, data json.RawMessage) SSEEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sequence++
	event := SSEEvent{
		EventType: eventType,
		TaskID:    s.taskID,
		Data:      data,
		Sequence:  s.sequence,
		Timestamp: s.clock(),
	}
	s.events = append(s.events, event)
	return event
}

// Events returns all emitted events.
func (s *SSEStream) Events() []SSEEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]SSEEvent, len(s.events))
	copy(result, s.events)
	return result
}

// EventsSince returns events with sequence > afterSeq.
func (s *SSEStream) EventsSince(afterSeq int64) []SSEEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result []SSEEvent
	for _, e := range s.events {
		if e.Sequence > afterSeq {
			result = append(result, e)
		}
	}
	return result
}
