// Package replay provides the full Replay Engine — reconstructing
// execution from receipts, snapshots, and event log entries.
//
// Per HELM 2030 Spec — Deterministic outcomes:
//   - Any run can be fully reconstructed from its evidence trail
//   - Replay produces identical results given identical inputs + PRNG seed
//   - Divergence at any point terminates replay with a diagnostic
package replay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// Step represents a single step in a replay session.
type Step struct {
	SequenceNumber uint64        `json:"sequence_number"`
	EventID        string        `json:"event_id"`
	EventType      string        `json:"event_type"`
	InputHash      string        `json:"input_hash"`
	OutputHash     string        `json:"output_hash"`
	Duration       time.Duration `json:"duration"`
}

// Session is a replay session tracking progress through a run.
type Session struct {
	SessionID       string        `json:"session_id"`
	RunID           string        `json:"run_id"`
	Status          SessionStatus `json:"status"`
	TotalSteps      int           `json:"total_steps"`
	ReplayedSteps   int           `json:"replayed_steps"`
	DivergencePoint int           `json:"divergence_point,omitempty"`
	DivergenceInfo  string        `json:"divergence_info,omitempty"`
	OriginalHash    string        `json:"original_hash"`
	ReplayHash      string        `json:"replay_hash"`
	StartedAt       time.Time     `json:"started_at"`
	CompletedAt     time.Time     `json:"completed_at,omitempty"`
	Steps           []Step        `json:"steps"`
}

// SessionStatus is the lifecycle state of a replay session.
type SessionStatus string

const (
	SessionStatusRunning  SessionStatus = "RUNNING"
	SessionStatusComplete SessionStatus = "COMPLETE"
	SessionStatusDiverged SessionStatus = "DIVERGED"
	SessionStatusFailed   SessionStatus = "FAILED"
)

// EventSource provides events for replay.
type EventSource interface {
	// GetRunEvents returns all events for a specific run in order.
	GetRunEvents(ctx context.Context, runID string) ([]RunEvent, error)
}

// RunEvent is a recorded event from an original run.
type RunEvent struct {
	SequenceNumber uint64                 `json:"sequence_number"`
	EventID        string                 `json:"event_id"`
	EventType      string                 `json:"event_type"`
	Payload        map[string]interface{} `json:"payload"`
	PayloadHash    string                 `json:"payload_hash"`
	OutputHash     string                 `json:"output_hash"`
	PRNGSeed       string                 `json:"prng_seed,omitempty"`
	Timestamp      time.Time              `json:"timestamp"`
}

// Executor re-executes a single event during replay.
type Executor interface {
	ReplayEvent(ctx context.Context, event RunEvent) (outputHash string, err error)
}

// Engine is the full replay engine.
type Engine struct {
	mu       sync.Mutex
	source   EventSource
	executor Executor
	sessions map[string]*Session
	clock    func() time.Time
}

// NewEngine creates a new replay engine.
func NewEngine(source EventSource, executor Executor) *Engine {
	return &Engine{
		source:   source,
		executor: executor,
		sessions: make(map[string]*Session),
		clock:    time.Now,
	}
}

// WithClock overrides the clock for testing.
func (e *Engine) WithClock(clock func() time.Time) *Engine {
	e.clock = clock
	return e
}

// StartReplay begins replaying a run. Returns a session for tracking progress.
func (e *Engine) StartReplay(ctx context.Context, runID string) (*Session, error) {
	events, err := e.source.GetRunEvents(ctx, runID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch events for run %s: %w", runID, err)
	}
	if len(events) == 0 {
		return nil, fmt.Errorf("no events found for run %s", runID)
	}

	// Compute original run hash
	originalHash, err := computeRunHash(events)
	if err != nil {
		return nil, fmt.Errorf("failed to compute original hash: %w", err)
	}

	session := &Session{
		SessionID:    fmt.Sprintf("replay-%s-%d", runID, e.clock().UnixNano()),
		RunID:        runID,
		Status:       SessionStatusRunning,
		TotalSteps:   len(events),
		OriginalHash: originalHash,
		StartedAt:    e.clock(),
		Steps:        make([]Step, 0, len(events)),
	}

	e.mu.Lock()
	e.sessions[session.SessionID] = session
	e.mu.Unlock()

	// Replay each event in order
	for i, event := range events {
		start := e.clock()
		outputHash, err := e.executor.ReplayEvent(ctx, event)
		elapsed := e.clock().Sub(start)

		step := Step{
			SequenceNumber: event.SequenceNumber,
			EventID:        event.EventID,
			EventType:      event.EventType,
			InputHash:      event.PayloadHash,
			OutputHash:     outputHash,
			Duration:       elapsed,
		}

		session.Steps = append(session.Steps, step)
		session.ReplayedSteps = i + 1

		if err != nil {
			session.Status = SessionStatusFailed
			session.DivergencePoint = i
			session.DivergenceInfo = fmt.Sprintf("execution failed at step %d: %v", i, err)
			session.CompletedAt = e.clock()
			return session, nil
		}

		// Check for divergence
		if event.OutputHash != "" && outputHash != event.OutputHash {
			session.Status = SessionStatusDiverged
			session.DivergencePoint = i
			session.DivergenceInfo = fmt.Sprintf(
				"output diverged at step %d: expected %s, got %s",
				i, event.OutputHash, outputHash,
			)
			session.CompletedAt = e.clock()
			return session, nil
		}
	}

	// Compute replay hash
	replayHash, err := computeReplayHash(session.Steps)
	if err != nil {
		session.Status = SessionStatusFailed
		session.DivergenceInfo = fmt.Sprintf("failed to compute replay hash: %v", err)
	} else {
		session.ReplayHash = replayHash
		session.Status = SessionStatusComplete
	}

	session.CompletedAt = e.clock()
	return session, nil
}

// GetSession retrieves a replay session.
func (e *Engine) GetSession(sessionID string) (*Session, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	s, ok := e.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("session %q not found", sessionID)
	}
	return s, nil
}

// computeRunHash computes a deterministic hash of all events in a run.
func computeRunHash(events []RunEvent) (string, error) {
	hashable := make([]string, len(events))
	for i, e := range events {
		hashable[i] = e.PayloadHash
	}
	data, err := json.Marshal(hashable)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

// computeReplayHash computes the hash of replay outputs for comparison.
func computeReplayHash(steps []Step) (string, error) {
	hashable := make([]string, len(steps))
	for i, s := range steps {
		hashable[i] = s.OutputHash
	}
	data, err := json.Marshal(hashable)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

// VerifyReplayIntegrity verifies that a completed replay session matches the original.
func VerifyReplayIntegrity(session *Session) *contracts.EffectReceipt {
	success := session.Status == SessionStatusComplete &&
		session.ReplayedSteps == session.TotalSteps

	receipt := &contracts.EffectReceipt{
		Success:   success,
		Timestamp: session.CompletedAt,
		Duration:  session.CompletedAt.Sub(session.StartedAt),
	}

	if !success {
		receipt.Error = session.DivergenceInfo
	}

	receipt.Output = map[string]any{
		"session_id":       session.SessionID,
		"run_id":           session.RunID,
		"status":           string(session.Status),
		"total_steps":      session.TotalSteps,
		"replayed_steps":   session.ReplayedSteps,
		"original_hash":    session.OriginalHash,
		"replay_hash":      session.ReplayHash,
		"divergence_point": session.DivergencePoint,
	}

	return receipt
}
