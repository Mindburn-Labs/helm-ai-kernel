package replay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// ────────────────────────────────────────────────────────────────────────
// Test helpers
// ────────────────────────────────────────────────────────────────────────

type fakeEventSource struct {
	events map[string][]RunEvent
}

func (s *fakeEventSource) GetRunEvents(_ context.Context, runID string) ([]RunEvent, error) {
	evts, ok := s.events[runID]
	if !ok {
		return nil, nil
	}
	return evts, nil
}

type fakeExecutor struct {
	outputs map[string]string
	failAt  int
}

func (s *fakeExecutor) ReplayEvent(_ context.Context, event RunEvent) (string, error) {
	if s.failAt >= 0 && int(event.SequenceNumber) == s.failAt {
		return "", fmt.Errorf("intentional failure at seq %d", s.failAt)
	}
	if h, ok := s.outputs[event.EventID]; ok {
		return h, nil
	}
	return event.OutputHash, nil
}

func makeEvents(n int) []RunEvent {
	events := make([]RunEvent, n)
	for i := 0; i < n; i++ {
		events[i] = RunEvent{
			SequenceNumber: uint64(i),
			EventID:        fmt.Sprintf("evt-%d", i),
			EventType:      "EXECUTE",
			PayloadHash:    fmt.Sprintf("hash-%d", i),
			OutputHash:     fmt.Sprintf("out-%d", i),
			Timestamp:      time.Now().Add(time.Duration(i) * time.Millisecond),
		}
	}
	return events
}

// ────────────────────────────────────────────────────────────────────────
// Replay 100 receipts
// ────────────────────────────────────────────────────────────────────────

func TestStress_Replay100Receipts(t *testing.T) {
	receipts := make([]Receipt, 100)
	for i := 0; i < 100; i++ {
		receipts[i] = Receipt{
			ID:           fmt.Sprintf("r-%d", i),
			ToolName:     "tool",
			ArgsHash:     fmt.Sprintf("args-%d", i),
			Timestamp:    fmt.Sprintf("2025-01-01T00:00:%02dZ", i%60),
			Status:       "SUCCESS",
			ReasonCode:   "ok",
			LamportClock: uint64(i + 1),
		}
		if i == 0 {
			receipts[i].PrevHash = "GENESIS"
		}
	}
	// Fix the prevHash chain using crypto/sha256
	for i := 1; i < len(receipts); i++ {
		data, _ := json.Marshal(receipts[i-1])
		h := sha256.Sum256(data)
		receipts[i].PrevHash = hex.EncodeToString(h[:])
	}
	result, err := Replay(receipts)
	if err != nil {
		t.Fatal(err)
	}
	if result.TotalReceipts != 100 {
		t.Fatalf("expected 100 receipts, got %d", result.TotalReceipts)
	}
}

func TestStress_ReplayEmpty(t *testing.T) {
	result, err := Replay(nil)
	if err != nil || result.TotalReceipts != 0 || !result.ValidChain {
		t.Fatal("empty replay should succeed with valid chain")
	}
}

func TestStress_ReplayDuplicateIDs(t *testing.T) {
	receipts := []Receipt{
		{ID: "same", ToolName: "t", PrevHash: "GENESIS", LamportClock: 1, Timestamp: "2025-01-01T00:00:00Z"},
		{ID: "same", ToolName: "t", PrevHash: "x", LamportClock: 2, Timestamp: "2025-01-01T00:00:01Z"},
	}
	result, _ := Replay(receipts)
	if len(result.DuplicateIDs) != 1 {
		t.Fatal("expected 1 duplicate ID")
	}
}

func TestStress_ReplayLamportNotMonotonic(t *testing.T) {
	receipts := []Receipt{
		{ID: "r1", PrevHash: "GENESIS", LamportClock: 5, Timestamp: "2025-01-01T00:00:00Z"},
		{ID: "r2", PrevHash: "x", LamportClock: 3, Timestamp: "2025-01-01T00:00:01Z"},
	}
	result, _ := Replay(receipts)
	if result.LamportValid {
		t.Fatal("expected invalid Lamport ordering")
	}
}

func TestStress_ReplayGenesisNonStandard(t *testing.T) {
	receipts := []Receipt{
		{ID: "r1", PrevHash: "unexpected-value", LamportClock: 1, Timestamp: "2025-01-01T00:00:00Z"},
	}
	result, _ := Replay(receipts)
	if result.ValidChain {
		t.Fatal("expected invalid chain for non-standard genesis")
	}
}

func TestStress_ReplayFromReaderJSONL(t *testing.T) {
	var buf bytes.Buffer
	for i := 0; i < 10; i++ {
		r := Receipt{ID: fmt.Sprintf("r-%d", i), PrevHash: "GENESIS", LamportClock: uint64(i + 1), Timestamp: fmt.Sprintf("2025-01-01T00:00:%02dZ", i)}
		data, _ := json.Marshal(r)
		buf.Write(data)
		buf.WriteByte('\n')
	}
	result, err := ReplayFromReader(&buf)
	if err != nil || result.TotalReceipts != 10 {
		t.Fatalf("reader replay failed: err=%v total=%d", err, result.TotalReceipts)
	}
}

func TestStress_ReplayReasonCodeSummary(t *testing.T) {
	receipts := []Receipt{
		{ID: "r1", PrevHash: "GENESIS", LamportClock: 1, ReasonCode: "ok", Timestamp: "a"},
		{ID: "r2", PrevHash: "x", LamportClock: 2, ReasonCode: "ok", Timestamp: "b"},
		{ID: "r3", PrevHash: "y", LamportClock: 3, ReasonCode: "deny", Timestamp: "c"},
	}
	result, _ := Replay(receipts)
	if result.Summary["ok"] != 2 || result.Summary["deny"] != 1 {
		t.Fatalf("summary mismatch: %v", result.Summary)
	}
}

func TestStress_ReplayWithSignatureVerifier(t *testing.T) {
	receipts := []Receipt{
		{ID: "r1", PrevHash: "GENESIS", LamportClock: 1, Signature: "sig", Timestamp: "a"},
	}
	result, _ := Replay(receipts, WithSignatureVerifier(func(data []byte, sig string) error {
		return fmt.Errorf("invalid signature")
	}))
	if result.SignaturesFailed != 1 {
		t.Fatal("expected 1 signature failure")
	}
}

// ────────────────────────────────────────────────────────────────────────
// Manifest all modes
// ────────────────────────────────────────────────────────────────────────

func TestStress_ManifestModeDry(t *testing.T) {
	events := makeEvents(5)
	source := &fakeEventSource{events: map[string][]RunEvent{"run-1": events}}
	engine := NewEngine(source, &fakeExecutor{failAt: -1})
	manifest := &ReplayManifest{ManifestID: "m1", RunID: "run-1", Mode: ReplayModeDry, OrderedEffectIDs: []string{"e1"}}
	session, err := engine.StartReplayWithManifest(context.Background(), manifest)
	if err != nil || session.Status != SessionStatusComplete {
		t.Fatalf("dry replay failed: err=%v status=%s", err, session.Status)
	}
}

func TestStress_ManifestModeBounded(t *testing.T) {
	events := makeEvents(5)
	events[2].EventType = "NETWORK"
	source := &fakeEventSource{events: map[string][]RunEvent{"run-1": events}}
	engine := NewEngine(source, &fakeExecutor{failAt: -1})
	manifest := &ReplayManifest{ManifestID: "m1", RunID: "run-1", Mode: ReplayModeBounded}
	session, err := engine.StartReplayWithManifest(context.Background(), manifest)
	if err != nil || session.Status != SessionStatusComplete {
		t.Fatalf("bounded replay failed: err=%v status=%s", err, session.Status)
	}
}

func TestStress_ManifestModeFull(t *testing.T) {
	events := makeEvents(3)
	source := &fakeEventSource{events: map[string][]RunEvent{"run-1": events}}
	engine := NewEngine(source, &fakeExecutor{failAt: -1})
	manifest := &ReplayManifest{ManifestID: "m1", RunID: "run-1", Mode: ReplayModeFull}
	session, err := engine.StartReplayWithManifest(context.Background(), manifest)
	if err != nil || session.Status != SessionStatusComplete {
		t.Fatalf("full replay failed: err=%v status=%s", err, session.Status)
	}
}

func TestStress_ManifestModeUnknown(t *testing.T) {
	engine := NewEngine(&fakeEventSource{}, &fakeExecutor{failAt: -1})
	_, err := engine.StartReplayWithManifest(context.Background(), &ReplayManifest{Mode: "UNKNOWN"})
	if err == nil {
		t.Fatal("expected error for unknown mode")
	}
}

func TestStress_ManifestNil(t *testing.T) {
	engine := NewEngine(&fakeEventSource{}, &fakeExecutor{failAt: -1})
	_, err := engine.StartReplayWithManifest(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil manifest")
	}
}

// ────────────────────────────────────────────────────────────────────────
// Integrity check with tampered chain
// ────────────────────────────────────────────────────────────────────────

func TestStress_IntegrityCheckDivergedOutput(t *testing.T) {
	events := makeEvents(5)
	source := &fakeEventSource{events: map[string][]RunEvent{"run-1": events}}
	divergent := &fakeExecutor{
		failAt:  -1,
		outputs: map[string]string{"evt-3": "TAMPERED"},
	}
	engine := NewEngine(source, divergent)
	session, _ := engine.StartReplay(context.Background(), "run-1")
	if session.Status != SessionStatusDiverged {
		t.Fatalf("expected DIVERGED, got %s", session.Status)
	}
	if session.DivergencePoint != 3 {
		t.Fatalf("expected divergence at 3, got %d", session.DivergencePoint)
	}
}

func TestStress_IntegrityCheckExecutionFailed(t *testing.T) {
	events := makeEvents(5)
	source := &fakeEventSource{events: map[string][]RunEvent{"run-1": events}}
	engine := NewEngine(source, &fakeExecutor{failAt: 2})
	session, _ := engine.StartReplay(context.Background(), "run-1")
	if session.Status != SessionStatusFailed {
		t.Fatalf("expected FAILED, got %s", session.Status)
	}
}

func TestStress_VerifyReplayIntegrityComplete(t *testing.T) {
	session := &Session{
		Status:        SessionStatusComplete,
		TotalSteps:    5,
		ReplayedSteps: 5,
		CompletedAt:   time.Now(),
		StartedAt:     time.Now().Add(-time.Second),
	}
	receipt := VerifyReplayIntegrity(session)
	if !receipt.Success {
		t.Fatal("expected success for complete replay")
	}
}

func TestStress_VerifyReplayIntegrityDiverged(t *testing.T) {
	session := &Session{Status: SessionStatusDiverged, DivergenceInfo: "output mismatch"}
	receipt := VerifyReplayIntegrity(session)
	if receipt.Success {
		t.Fatal("expected failure for diverged replay")
	}
}

// ────────────────────────────────────────────────────────────────────────
// Concurrent replay sessions
// ────────────────────────────────────────────────────────────────────────

func TestStress_ConcurrentReplaySessions(t *testing.T) {
	eventsMap := make(map[string][]RunEvent)
	for i := 0; i < 20; i++ {
		eventsMap[fmt.Sprintf("run-%d", i)] = makeEvents(10)
	}
	source := &fakeEventSource{events: eventsMap}
	engine := NewEngine(source, &fakeExecutor{failAt: -1})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			session, err := engine.StartReplay(context.Background(), fmt.Sprintf("run-%d", n))
			if err != nil || session.Status != SessionStatusComplete {
				t.Errorf("run-%d: err=%v status=%s", n, err, session.Status)
			}
		}(i)
	}
	wg.Wait()
}

func TestStress_EngineGetSession(t *testing.T) {
	source := &fakeEventSource{events: map[string][]RunEvent{"r1": makeEvents(3)}}
	engine := NewEngine(source, &fakeExecutor{failAt: -1})
	session, _ := engine.StartReplay(context.Background(), "r1")
	got, err := engine.GetSession(session.SessionID)
	if err != nil || got.RunID != "r1" {
		t.Fatal("GetSession failed")
	}
}

func TestStress_EngineGetSessionNotFound(t *testing.T) {
	engine := NewEngine(&fakeEventSource{}, &fakeExecutor{failAt: -1})
	_, err := engine.GetSession("missing")
	if err == nil {
		t.Fatal("expected error for missing session")
	}
}

func TestStress_EngineNoEvents(t *testing.T) {
	source := &fakeEventSource{events: map[string][]RunEvent{"r1": {}}}
	engine := NewEngine(source, &fakeExecutor{failAt: -1})
	_, err := engine.StartReplay(context.Background(), "r1")
	if err == nil || !strings.Contains(err.Error(), "no events") {
		t.Fatalf("expected 'no events' error, got %v", err)
	}
}

func TestStress_ReplayHarnessNoScript(t *testing.T) {
	h := NewReplayHarness()
	err := h.VerifyReceipt(context.Background(), &contracts.Receipt{ReceiptID: "r1"})
	if err == nil {
		t.Fatal("expected error for no replay script")
	}
}

func TestStress_ReplayHarnessUnknownEngine(t *testing.T) {
	h := NewReplayHarness()
	err := h.VerifyReceipt(context.Background(), &contracts.Receipt{
		ReceiptID:    "r1",
		ReplayScript: &contracts.ReplayScriptRef{Engine: "unknown"},
	})
	if err == nil {
		t.Fatal("expected error for unknown engine")
	}
}

func TestStress_SessionStatusConstants(t *testing.T) {
	if SessionStatusRunning != "RUNNING" || SessionStatusComplete != "COMPLETE" || SessionStatusDiverged != "DIVERGED" || SessionStatusFailed != "FAILED" {
		t.Fatal("session status constants mismatch")
	}
}

func TestStress_ReplayModeConstants(t *testing.T) {
	if ReplayModeDry != "dry" || ReplayModeBounded != "bounded" || ReplayModeFull != "full" {
		t.Fatal("replay mode constants mismatch")
	}
}

func TestStress_ManifestDryHashMismatch(t *testing.T) {
	events := makeEvents(3)
	source := &fakeEventSource{events: map[string][]RunEvent{"r": events}}
	engine := NewEngine(source, &fakeExecutor{failAt: -1})
	manifest := &ReplayManifest{
		RunID:                 "r",
		Mode:                  ReplayModeDry,
		ExpectedReceiptHashes: []string{"wrong-hash", "", ""},
	}
	session, _ := engine.StartReplayWithManifest(context.Background(), manifest)
	if session.Status != SessionStatusDiverged {
		t.Fatalf("expected DIVERGED for hash mismatch, got %s", session.Status)
	}
}

func TestStress_ReplaySessionCompletionFields(t *testing.T) {
	source := &fakeEventSource{events: map[string][]RunEvent{"r1": makeEvents(5)}}
	engine := NewEngine(source, &fakeExecutor{failAt: -1})
	session, _ := engine.StartReplay(context.Background(), "r1")
	if session.TotalSteps != 5 || session.ReplayedSteps != 5 {
		t.Fatalf("expected 5/5 steps, got %d/%d", session.TotalSteps, session.ReplayedSteps)
	}
}

func TestStress_ReplaySessionOriginalHash(t *testing.T) {
	source := &fakeEventSource{events: map[string][]RunEvent{"r1": makeEvents(3)}}
	engine := NewEngine(source, &fakeExecutor{failAt: -1})
	session, _ := engine.StartReplay(context.Background(), "r1")
	if session.OriginalHash == "" {
		t.Fatal("original hash not computed")
	}
}

func TestStress_ReplaySessionReplayHash(t *testing.T) {
	source := &fakeEventSource{events: map[string][]RunEvent{"r1": makeEvents(3)}}
	engine := NewEngine(source, &fakeExecutor{failAt: -1})
	session, _ := engine.StartReplay(context.Background(), "r1")
	if session.ReplayHash == "" {
		t.Fatal("replay hash not computed")
	}
}

func TestStress_ReplaySessionSteps(t *testing.T) {
	source := &fakeEventSource{events: map[string][]RunEvent{"r1": makeEvents(3)}}
	engine := NewEngine(source, &fakeExecutor{failAt: -1})
	session, _ := engine.StartReplay(context.Background(), "r1")
	if len(session.Steps) != 3 {
		t.Fatalf("expected 3 steps, got %d", len(session.Steps))
	}
}

func TestStress_ReplayEngineWithClock(t *testing.T) {
	fixed := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	source := &fakeEventSource{events: map[string][]RunEvent{"r1": makeEvents(2)}}
	engine := NewEngine(source, &fakeExecutor{failAt: -1}).WithClock(func() time.Time { return fixed })
	session, _ := engine.StartReplay(context.Background(), "r1")
	if !session.StartedAt.Equal(fixed) {
		t.Fatal("clock override not applied")
	}
}

func TestStress_ReplayHarnessRegisterEngine(t *testing.T) {
	h := NewReplayHarness()
	h.RegisterEngine("test", &fakeReplayEngine{output: []byte("result")})
	err := h.VerifyReceipt(context.Background(), &contracts.Receipt{
		ReceiptID: "r1", OutputHash: "",
		ReplayScript: &contracts.ReplayScriptRef{Engine: "test"},
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

type fakeReplayEngine struct{ output []byte }

func (s *fakeReplayEngine) Replay(_ context.Context, _ *contracts.ReplayScriptRef) ([]byte, error) {
	return s.output, nil
}

func TestStress_ReplayTimestampsNotSorted(t *testing.T) {
	receipts := []Receipt{
		{ID: "r1", PrevHash: "GENESIS", LamportClock: 1, Timestamp: "2025-01-01T00:00:02Z"},
		{ID: "r2", PrevHash: "x", LamportClock: 2, Timestamp: "2025-01-01T00:00:01Z"},
	}
	result, _ := Replay(receipts)
	if result.OrderValid {
		t.Fatal("expected invalid order for unsorted timestamps")
	}
}

func TestStress_ReplayTimestampsSorted(t *testing.T) {
	receipts := []Receipt{
		{ID: "r1", PrevHash: "GENESIS", LamportClock: 1, Timestamp: "2025-01-01T00:00:00Z"},
		{ID: "r2", PrevHash: "x", LamportClock: 2, Timestamp: "2025-01-01T00:00:01Z"},
	}
	result, _ := Replay(receipts)
	if !result.OrderValid {
		t.Fatal("expected valid order for sorted timestamps")
	}
}

func TestStress_ReplaySignatureVerifierPass(t *testing.T) {
	receipts := []Receipt{
		{ID: "r1", PrevHash: "GENESIS", LamportClock: 1, Signature: "sig", Timestamp: "a"},
	}
	result, _ := Replay(receipts, WithSignatureVerifier(func(data []byte, sig string) error {
		return nil
	}))
	if result.SignaturesFailed != 0 || result.SignaturesChecked != 1 {
		t.Fatal("expected 1 checked, 0 failed")
	}
}

func TestStress_ReplayNoSignatureNoVerify(t *testing.T) {
	receipts := []Receipt{
		{ID: "r1", PrevHash: "GENESIS", LamportClock: 1, Timestamp: "a"},
	}
	result, _ := Replay(receipts, WithSignatureVerifier(func(data []byte, sig string) error {
		return fmt.Errorf("should not be called")
	}))
	if result.SignaturesChecked != 0 {
		t.Fatal("should not check empty signatures")
	}
}

func TestStress_ReplayHashesVerified(t *testing.T) {
	receipts := []Receipt{
		{ID: "r1", PrevHash: "GENESIS", LamportClock: 1, Timestamp: "a"},
		{ID: "r2", PrevHash: "x", LamportClock: 2, Timestamp: "b"},
	}
	result, _ := Replay(receipts)
	if result.HashesVerified != 2 {
		t.Fatalf("expected 2 hashes verified, got %d", result.HashesVerified)
	}
}

func TestStress_ManifestBoundedSkipsNetwork(t *testing.T) {
	events := makeEvents(5)
	events[1].EventType = "NETWORK"
	events[3].EventType = "NETWORK"
	source := &fakeEventSource{events: map[string][]RunEvent{"r": events}}
	engine := NewEngine(source, &fakeExecutor{failAt: -1})
	manifest := &ReplayManifest{RunID: "r", Mode: ReplayModeBounded}
	session, _ := engine.StartReplayWithManifest(context.Background(), manifest)
	if session.Status != SessionStatusComplete || session.ReplayedSteps != 5 {
		t.Fatalf("expected 5 replayed steps, got %d status=%s", session.ReplayedSteps, session.Status)
	}
}

func TestStress_ManifestFullExecutesAll(t *testing.T) {
	events := makeEvents(4)
	events[1].EventType = "NETWORK"
	source := &fakeEventSource{events: map[string][]RunEvent{"r": events}}
	engine := NewEngine(source, &fakeExecutor{failAt: -1})
	manifest := &ReplayManifest{RunID: "r", Mode: ReplayModeFull}
	session, _ := engine.StartReplayWithManifest(context.Background(), manifest)
	if session.Status != SessionStatusComplete {
		t.Fatalf("expected COMPLETE, got %s", session.Status)
	}
}

func TestStress_VerifyReplayIntegrityOutputFields(t *testing.T) {
	session := &Session{
		SessionID: "s1", RunID: "r1", Status: SessionStatusComplete,
		TotalSteps: 3, ReplayedSteps: 3, OriginalHash: "oh", ReplayHash: "rh",
		StartedAt: time.Now().Add(-time.Second), CompletedAt: time.Now(),
	}
	receipt := VerifyReplayIntegrity(session)
	output := receipt.Output
	if output["session_id"] != "s1" || output["run_id"] != "r1" {
		t.Fatal("output fields missing")
	}
}
