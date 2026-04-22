package replay_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/replay"
)

// --- Replay Engine ---

func TestEngine_SuccessfulReplay(t *testing.T) {
	source := &mockSource{events: testEvents()}
	eng := replay.NewEngine(source, &mockExecutor{failAt: -1}).WithClock(fixedClock)
	session, err := eng.StartReplay(context.Background(), "run-1")
	if err != nil || session.Status != replay.SessionStatusComplete {
		t.Fatalf("expected complete, got status=%s err=%v", session.Status, err)
	}
}

func TestEngine_ReplayDivergence(t *testing.T) {
	divergingExec := &divergingExecutor{divergeAt: 1, wrongHash: "bad-hash"}
	source := &mockSource{events: testEvents()}
	eng := replay.NewEngine(source, divergingExec).WithClock(fixedClock)
	session, err := eng.StartReplay(context.Background(), "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if session.Status != replay.SessionStatusDiverged {
		t.Fatalf("expected DIVERGED, got %s", session.Status)
	}
	if session.DivergencePoint != 1 {
		t.Fatalf("expected divergence at 1, got %d", session.DivergencePoint)
	}
}

func TestEngine_EmptyRunFails(t *testing.T) {
	source := &mockSource{events: nil}
	eng := replay.NewEngine(source, &mockExecutor{failAt: -1})
	_, err := eng.StartReplay(context.Background(), "run-x")
	if err == nil {
		t.Fatal("empty run should error")
	}
}

func TestEngine_GetSessionAfterReplay(t *testing.T) {
	source := &mockSource{events: testEvents()}
	eng := replay.NewEngine(source, &mockExecutor{failAt: -1}).WithClock(fixedClock)
	session, _ := eng.StartReplay(context.Background(), "run-1")
	got, err := eng.GetSession(session.SessionID)
	if err != nil || got.RunID != "run-1" {
		t.Fatalf("session lookup failed: %v", err)
	}
}

func TestEngine_GetSessionNotFound(t *testing.T) {
	eng := replay.NewEngine(&mockSource{}, &mockExecutor{failAt: -1})
	_, err := eng.GetSession("nonexistent")
	if err == nil {
		t.Fatal("expected not-found error")
	}
}

func TestEngine_FailedStepSetsStatus(t *testing.T) {
	source := &mockSource{events: testEvents()}
	eng := replay.NewEngine(source, &mockExecutor{failAt: 0}).WithClock(fixedClock)
	session, err := eng.StartReplay(context.Background(), "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if session.Status != replay.SessionStatusFailed {
		t.Fatalf("expected FAILED, got %s", session.Status)
	}
}

func TestEngine_SessionHasCorrectStepCount(t *testing.T) {
	source := &mockSource{events: testEvents()}
	eng := replay.NewEngine(source, &mockExecutor{failAt: -1}).WithClock(fixedClock)
	session, _ := eng.StartReplay(context.Background(), "run-1")
	if session.TotalSteps != 3 || session.ReplayedSteps != 3 {
		t.Fatalf("expected 3/3 steps, got %d/%d", session.ReplayedSteps, session.TotalSteps)
	}
}

// --- Replay Manifest ---

func TestManifest_DryModeMatchingHashes(t *testing.T) {
	source := &mockSource{events: testEvents()}
	eng := replay.NewEngine(source, &mockExecutor{failAt: -1}).WithClock(fixedClock)
	s, err := eng.StartReplayWithManifest(context.Background(), &replay.ReplayManifest{
		RunID: "r1", Mode: replay.ReplayModeDry,
		ExpectedReceiptHashes: []string{"o1", "o2", "o3"},
	})
	if err != nil || s.Status != replay.SessionStatusComplete {
		t.Fatalf("dry mode should complete, got %s err=%v", s.Status, err)
	}
}

func TestManifest_BoundedSkipsNetwork(t *testing.T) {
	source := &mockSource{events: testEvents()}
	eng := replay.NewEngine(source, &mockExecutor{failAt: -1}).WithClock(fixedClock)
	s, _ := eng.StartReplayWithManifest(context.Background(), &replay.ReplayManifest{
		RunID: "r1", Mode: replay.ReplayModeBounded,
	})
	if s.Steps[1].OutputHash != "o2" {
		t.Fatal("bounded mode should preserve NETWORK output hash")
	}
}

func TestManifest_FullModeCompletes(t *testing.T) {
	source := &mockSource{events: testEvents()}
	eng := replay.NewEngine(source, &mockExecutor{failAt: -1}).WithClock(fixedClock)
	s, _ := eng.StartReplayWithManifest(context.Background(), &replay.ReplayManifest{
		RunID: "r1", Mode: replay.ReplayModeFull,
	})
	if s.Status != replay.SessionStatusComplete {
		t.Fatalf("expected COMPLETE, got %s", s.Status)
	}
}

// --- Replay Receipt Chain ---

func TestReplay_ValidChainTwoReceipts(t *testing.T) {
	r1 := replay.Receipt{ID: "r1", ToolName: "t", Timestamp: "2026-01-01T00:00:00Z", LamportClock: 1}
	data1, _ := json.Marshal(r1)
	h1 := sha256.Sum256(data1)
	r2 := replay.Receipt{ID: "r2", ToolName: "t", PrevHash: hex.EncodeToString(h1[:]), Timestamp: "2026-01-01T00:00:01Z", LamportClock: 2}
	result, _ := replay.Replay([]replay.Receipt{r1, r2})
	if !result.ValidChain || !result.LamportValid {
		t.Fatalf("chain should be valid: %+v", result)
	}
}

func TestReplay_EmptyChainValid(t *testing.T) {
	result, err := replay.Replay(nil)
	if err != nil || !result.ValidChain {
		t.Fatalf("empty chain should be valid, err=%v", err)
	}
}

func TestReplay_DuplicateIDsDetected(t *testing.T) {
	r1 := replay.Receipt{ID: "dup", ToolName: "t", Timestamp: "2026-01-01T00:00:00Z", LamportClock: 1}
	data1, _ := json.Marshal(r1)
	h1 := sha256.Sum256(data1)
	r2 := replay.Receipt{ID: "dup", ToolName: "t", PrevHash: hex.EncodeToString(h1[:]), Timestamp: "2026-01-01T00:00:01Z", LamportClock: 2}
	result, _ := replay.Replay([]replay.Receipt{r1, r2})
	if len(result.DuplicateIDs) == 0 {
		t.Fatal("duplicate IDs should be detected")
	}
}

func TestReplay_LamportViolationDetected(t *testing.T) {
	r1 := replay.Receipt{ID: "r1", ToolName: "t", Timestamp: "2026-01-01T00:00:00Z", LamportClock: 5}
	data1, _ := json.Marshal(r1)
	h1 := sha256.Sum256(data1)
	r2 := replay.Receipt{ID: "r2", ToolName: "t", PrevHash: hex.EncodeToString(h1[:]), Timestamp: "2026-01-01T00:00:01Z", LamportClock: 3}
	result, _ := replay.Replay([]replay.Receipt{r1, r2})
	if result.LamportValid {
		t.Fatal("Lamport violation should be detected")
	}
}

func TestReplay_TimestampOrderChecked(t *testing.T) {
	r1 := replay.Receipt{ID: "r1", ToolName: "t", Timestamp: "2026-01-01T00:00:02Z", LamportClock: 1}
	data1, _ := json.Marshal(r1)
	h1 := sha256.Sum256(data1)
	r2 := replay.Receipt{ID: "r2", ToolName: "t", PrevHash: hex.EncodeToString(h1[:]), Timestamp: "2026-01-01T00:00:01Z", LamportClock: 2}
	result, _ := replay.Replay([]replay.Receipt{r1, r2})
	if result.OrderValid {
		t.Fatal("out-of-order timestamps should be detected")
	}
}

// --- Replay Integrity ---

func TestVerifyReplayIntegrity_CompleteSession(t *testing.T) {
	session := &replay.Session{
		Status: replay.SessionStatusComplete, TotalSteps: 3, ReplayedSteps: 3,
		StartedAt: fixedTime, CompletedAt: fixedTime.Add(time.Second),
	}
	receipt := replay.VerifyReplayIntegrity(session)
	if !receipt.Success {
		t.Fatal("complete session should verify successfully")
	}
}

func TestVerifyReplayIntegrity_DivergedSession(t *testing.T) {
	session := &replay.Session{
		Status: replay.SessionStatusDiverged, TotalSteps: 3, ReplayedSteps: 2,
		DivergenceInfo: "mismatch at step 1",
		StartedAt:      fixedTime, CompletedAt: fixedTime.Add(time.Second),
	}
	receipt := replay.VerifyReplayIntegrity(session)
	if receipt.Success {
		t.Fatal("diverged session should not verify successfully")
	}
	if receipt.Error == "" {
		t.Fatal("error should contain divergence info")
	}
}

// --- Timeline / Visualizer ---

func TestBuildTimeline_ProducesEvents(t *testing.T) {
	receipts := []replay.Receipt{
		{ID: "r1", ToolName: "calc", Timestamp: "2026-01-01T00:00:00Z", Status: "ALLOW"},
		{ID: "r2", ToolName: "read", Timestamp: "2026-01-01T00:00:01Z", Status: "DENY"},
	}
	tl, err := replay.BuildTimeline("view-1", receipts)
	if err != nil || tl.Summary.TotalEvents != 2 {
		t.Fatalf("expected 2 events, err=%v", err)
	}
}

func TestBuildTimeline_EmptyReceiptsFails(t *testing.T) {
	_, err := replay.BuildTimeline("v1", nil)
	if err == nil {
		t.Fatal("empty receipts should error")
	}
}

func TestTraceLineage_SingleEvent(t *testing.T) {
	events := []replay.TimelineEvent{
		{EventID: "e1", Action: "run", Verdict: "ALLOW"},
	}
	lineage, err := replay.TraceLineage("lin-1", events, "e1")
	if err != nil || lineage.TotalDepth != 1 {
		t.Fatalf("expected depth 1, got %v err=%v", lineage, err)
	}
}

func TestTraceLineage_LeafNotFoundErrors(t *testing.T) {
	_, err := replay.TraceLineage("lin-1", nil, "missing")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatal("missing leaf should error")
	}
}

// --- helpers ---

type divergingExecutor struct {
	divergeAt int
	wrongHash string
}

func (d *divergingExecutor) ReplayEvent(_ context.Context, event replay.RunEvent) (string, error) {
	if int(event.SequenceNumber) == d.divergeAt {
		return d.wrongHash, nil
	}
	return event.OutputHash, nil
}
