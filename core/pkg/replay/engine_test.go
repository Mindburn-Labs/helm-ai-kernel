package replay

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// testEventSource is a mock event source for testing.
type testEventSource struct {
	runs map[string][]RunEvent
}

func (s *testEventSource) GetRunEvents(ctx context.Context, runID string) ([]RunEvent, error) {
	events, ok := s.runs[runID]
	if !ok {
		return nil, fmt.Errorf("run %q not found", runID)
	}
	return events, nil
}

// testExecutor replays events deterministically.
type testExecutor struct {
	results map[string]string // eventID -> outputHash
	failAt  string            // eventID to fail at
}

func (e *testExecutor) ReplayEvent(ctx context.Context, event RunEvent) (string, error) {
	if event.EventID == e.failAt {
		return "", fmt.Errorf("execution failed at %s", event.EventID)
	}
	if hash, ok := e.results[event.EventID]; ok {
		return hash, nil
	}
	return event.OutputHash, nil // Echo original hash by default
}

func testEvents() []RunEvent {
	return []RunEvent{
		{SequenceNumber: 1, EventID: "evt-1", EventType: "PLAN", PayloadHash: "sha256:aaa", OutputHash: "sha256:out1"},
		{SequenceNumber: 2, EventID: "evt-2", EventType: "EXECUTE", PayloadHash: "sha256:bbb", OutputHash: "sha256:out2"},
		{SequenceNumber: 3, EventID: "evt-3", EventType: "VERIFY", PayloadHash: "sha256:ccc", OutputHash: "sha256:out3"},
	}
}

func TestReplaySuccess(t *testing.T) {
	source := &testEventSource{runs: map[string][]RunEvent{"run-001": testEvents()}}
	executor := &testExecutor{results: map[string]string{}}
	engine := NewEngine(source, executor)

	session, err := engine.StartReplay(context.Background(), "run-001")
	if err != nil {
		t.Fatal(err)
	}
	if session.Status != SessionStatusComplete {
		t.Fatalf("expected COMPLETE, got %s (%s)", session.Status, session.DivergenceInfo)
	}
	if session.ReplayedSteps != 3 {
		t.Fatalf("expected 3 steps, got %d", session.ReplayedSteps)
	}
	if session.OriginalHash == "" {
		t.Fatal("expected original hash")
	}
	if session.ReplayHash == "" {
		t.Fatal("expected replay hash")
	}
}

func TestReplayDivergence(t *testing.T) {
	source := &testEventSource{runs: map[string][]RunEvent{"run-001": testEvents()}}
	executor := &testExecutor{
		results: map[string]string{
			"evt-2": "sha256:WRONG", // Divergent output
		},
	}
	engine := NewEngine(source, executor)

	session, err := engine.StartReplay(context.Background(), "run-001")
	if err != nil {
		t.Fatal(err)
	}
	if session.Status != SessionStatusDiverged {
		t.Fatalf("expected DIVERGED, got %s", session.Status)
	}
	if session.DivergencePoint != 1 {
		t.Fatalf("expected divergence at step 1, got %d", session.DivergencePoint)
	}
}

func TestReplayExecutionFailure(t *testing.T) {
	source := &testEventSource{runs: map[string][]RunEvent{"run-001": testEvents()}}
	executor := &testExecutor{failAt: "evt-3"}
	engine := NewEngine(source, executor)

	session, err := engine.StartReplay(context.Background(), "run-001")
	if err != nil {
		t.Fatal(err)
	}
	if session.Status != SessionStatusFailed {
		t.Fatalf("expected FAILED, got %s", session.Status)
	}
}

func TestReplayRunNotFound(t *testing.T) {
	source := &testEventSource{runs: map[string][]RunEvent{}}
	executor := &testExecutor{}
	engine := NewEngine(source, executor)

	_, err := engine.StartReplay(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for missing run")
	}
}

func TestReplayEmptyRun(t *testing.T) {
	source := &testEventSource{runs: map[string][]RunEvent{"run-empty": {}}}
	executor := &testExecutor{}
	engine := NewEngine(source, executor)

	_, err := engine.StartReplay(context.Background(), "run-empty")
	if err == nil {
		t.Fatal("expected error for empty run")
	}
}

func TestReplaySessionRetrieval(t *testing.T) {
	source := &testEventSource{runs: map[string][]RunEvent{"run-001": testEvents()}}
	executor := &testExecutor{}
	engine := NewEngine(source, executor)

	session, _ := engine.StartReplay(context.Background(), "run-001")
	retrieved, err := engine.GetSession(session.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if retrieved.SessionID != session.SessionID {
		t.Fatal("session mismatch")
	}
}

func TestReplayIntegrityVerification(t *testing.T) {
	source := &testEventSource{runs: map[string][]RunEvent{"run-001": testEvents()}}
	executor := &testExecutor{}
	engine := NewEngine(source, executor)

	session, _ := engine.StartReplay(context.Background(), "run-001")
	receipt := VerifyReplayIntegrity(session)
	if !receipt.Success {
		t.Fatalf("expected success, got error: %s", receipt.Error)
	}
}

func TestReplayClockOverride(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	source := &testEventSource{runs: map[string][]RunEvent{"run-001": testEvents()}}
	executor := &testExecutor{}
	engine := NewEngine(source, executor).WithClock(func() time.Time { return now })

	session, _ := engine.StartReplay(context.Background(), "run-001")
	if !session.StartedAt.Equal(now) {
		t.Fatalf("expected clock override, got %v", session.StartedAt)
	}
}
