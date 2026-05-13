package replay_test

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/replay"
)

var fixedTime = time.Date(2026, 4, 2, 12, 0, 0, 0, time.UTC)

func fixedClock() time.Time { return fixedTime }

// mockSource provides test events.
type mockSource struct {
	events []replay.RunEvent
}

func (m *mockSource) GetRunEvents(_ context.Context, _ string) ([]replay.RunEvent, error) {
	return m.events, nil
}

// mockExecutor re-executes events, returning the original output hash.
type mockExecutor struct {
	failAt int // step index to fail at (-1 = don't fail)
}

func (m *mockExecutor) ReplayEvent(_ context.Context, event replay.RunEvent) (string, error) {
	if m.failAt >= 0 && int(event.SequenceNumber) == m.failAt {
		return "", errMock("replay failed")
	}
	return event.OutputHash, nil
}

type errMock string

func (e errMock) Error() string { return string(e) }

func testEvents() []replay.RunEvent {
	return []replay.RunEvent{
		{SequenceNumber: 0, EventID: "e1", EventType: "EXECUTE", PayloadHash: "h1", OutputHash: "o1"},
		{SequenceNumber: 1, EventID: "e2", EventType: "NETWORK", PayloadHash: "h2", OutputHash: "o2"},
		{SequenceNumber: 2, EventID: "e3", EventType: "WRITE", PayloadHash: "h3", OutputHash: "o3"},
	}
}

func TestReplayManifest_DryMode(t *testing.T) {
	source := &mockSource{events: testEvents()}
	engine := replay.NewEngine(source, &mockExecutor{failAt: -1}).WithClock(fixedClock)

	session, err := engine.StartReplayWithManifest(context.Background(), &replay.ReplayManifest{
		ManifestID:            "m1",
		RunID:                 "run-1",
		Mode:                  replay.ReplayModeDry,
		ExpectedReceiptHashes: []string{"o1", "o2", "o3"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.Status != replay.SessionStatusComplete {
		t.Fatalf("expected COMPLETE, got %s (info: %s)", session.Status, session.DivergenceInfo)
	}
	if session.ReplayedSteps != 3 {
		t.Fatalf("expected 3 steps, got %d", session.ReplayedSteps)
	}
}

func TestReplayManifest_DryMode_Divergence(t *testing.T) {
	source := &mockSource{events: testEvents()}
	engine := replay.NewEngine(source, &mockExecutor{failAt: -1}).WithClock(fixedClock)

	session, err := engine.StartReplayWithManifest(context.Background(), &replay.ReplayManifest{
		ManifestID:            "m1",
		RunID:                 "run-1",
		Mode:                  replay.ReplayModeDry,
		ExpectedReceiptHashes: []string{"o1", "WRONG", "o3"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.Status != replay.SessionStatusDiverged {
		t.Fatalf("expected DIVERGED, got %s", session.Status)
	}
	if session.DivergencePoint != 1 {
		t.Fatalf("expected divergence at step 1, got %d", session.DivergencePoint)
	}
}

func TestReplayManifest_BoundedMode_SkipsNetwork(t *testing.T) {
	source := &mockSource{events: testEvents()}
	executor := &mockExecutor{failAt: -1}
	engine := replay.NewEngine(source, executor).WithClock(fixedClock)

	session, err := engine.StartReplayWithManifest(context.Background(), &replay.ReplayManifest{
		ManifestID: "m1",
		RunID:      "run-1",
		Mode:       replay.ReplayModeBounded,
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.Status != replay.SessionStatusComplete {
		t.Fatalf("expected COMPLETE, got %s (info: %s)", session.Status, session.DivergenceInfo)
	}
	if session.ReplayedSteps != 3 {
		t.Fatalf("expected 3 steps replayed, got %d", session.ReplayedSteps)
	}
	// The NETWORK step (index 1) should use the original output hash, not re-execute.
	networkStep := session.Steps[1]
	if networkStep.OutputHash != "o2" {
		t.Fatalf("expected original network output hash, got %s", networkStep.OutputHash)
	}
}

func TestReplayManifest_FullMode(t *testing.T) {
	source := &mockSource{events: testEvents()}
	engine := replay.NewEngine(source, &mockExecutor{failAt: -1}).WithClock(fixedClock)

	session, err := engine.StartReplayWithManifest(context.Background(), &replay.ReplayManifest{
		ManifestID: "m1",
		RunID:      "run-1",
		Mode:       replay.ReplayModeFull,
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.Status != replay.SessionStatusComplete {
		t.Fatalf("expected COMPLETE, got %s", session.Status)
	}
}

func TestReplayManifest_FullMode_Failure(t *testing.T) {
	source := &mockSource{events: testEvents()}
	engine := replay.NewEngine(source, &mockExecutor{failAt: 1}).WithClock(fixedClock)

	session, err := engine.StartReplayWithManifest(context.Background(), &replay.ReplayManifest{
		ManifestID: "m1",
		RunID:      "run-1",
		Mode:       replay.ReplayModeFull,
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.Status != replay.SessionStatusFailed {
		t.Fatalf("expected FAILED, got %s", session.Status)
	}
}

func TestReplayManifest_NilManifest(t *testing.T) {
	engine := replay.NewEngine(&mockSource{}, &mockExecutor{failAt: -1})
	_, err := engine.StartReplayWithManifest(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil manifest")
	}
}

func TestReplayManifest_UnknownMode(t *testing.T) {
	engine := replay.NewEngine(&mockSource{}, &mockExecutor{failAt: -1})
	_, err := engine.StartReplayWithManifest(context.Background(), &replay.ReplayManifest{
		Mode: "invalid",
	})
	if err == nil {
		t.Fatal("expected error for unknown mode")
	}
}
