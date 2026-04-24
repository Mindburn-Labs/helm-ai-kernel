package kernel

import (
	"context"
	"strings"
	"testing"
	"time"
)

var fixedT = time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)

func fixedClk() time.Time { return fixedT }

// --- FreezeController ---

func TestCompFreezeController_InitiallyUnfrozen(t *testing.T) {
	fc := NewFreezeController()
	if fc.IsFrozen() {
		t.Fatal("new controller should not be frozen")
	}
}

func TestFreezeController_FreezeReturnReceipt(t *testing.T) {
	fc := NewFreezeController().WithClock(fixedClk)
	r, err := fc.Freeze("admin")
	if err != nil || r.Action != "freeze" || r.Principal != "admin" {
		t.Fatalf("unexpected freeze result: receipt=%+v err=%v", r, err)
	}
}

func TestFreezeController_DoubleFreezeErrors(t *testing.T) {
	fc := NewFreezeController()
	_, _ = fc.Freeze("admin")
	_, err := fc.Freeze("admin")
	if err == nil {
		t.Fatal("double freeze should return error")
	}
}

func TestFreezeController_UnfreezeWhenNotFrozenErrors(t *testing.T) {
	fc := NewFreezeController()
	_, err := fc.Unfreeze("admin")
	if err == nil {
		t.Fatal("unfreeze on unfrozen should error")
	}
}

func TestFreezeController_FreezeUnfreezeCycle(t *testing.T) {
	fc := NewFreezeController().WithClock(fixedClk)
	_, _ = fc.Freeze("admin")
	_, _ = fc.Unfreeze("admin")
	if fc.IsFrozen() {
		t.Fatal("should be unfrozen after unfreeze")
	}
	if len(fc.Receipts()) != 2 {
		t.Fatalf("expected 2 receipts, got %d", len(fc.Receipts()))
	}
}

func TestFreezeController_ReceiptContentHashNonEmpty(t *testing.T) {
	fc := NewFreezeController().WithClock(fixedClk)
	r, _ := fc.Freeze("ops")
	if r.ContentHash == "" {
		t.Fatal("content hash should be set")
	}
}

func TestFreezeState_ReturnsPrincipal(t *testing.T) {
	fc := NewFreezeController().WithClock(fixedClk)
	_, _ = fc.Freeze("root")
	frozen, principal, _ := fc.FreezeState()
	if !frozen || principal != "root" {
		t.Fatalf("expected frozen by root, got frozen=%v principal=%s", frozen, principal)
	}
}

// --- ContextGuard ---

func TestContextGuard_MatchingFingerprintPasses(t *testing.T) {
	cg := NewContextGuardWithFingerprint("abc123")
	if err := cg.Validate("abc123"); err != nil {
		t.Fatalf("matching fingerprint should pass: %v", err)
	}
}

func TestContextGuard_MismatchReturnsError(t *testing.T) {
	cg := NewContextGuardWithFingerprint("abc123def456abc123def456abc123def456abc123def456abc123def456abc1")
	err := cg.Validate("000000000000000000000000000000000000000000000000000000000000000f")
	if err == nil {
		t.Fatal("mismatched fingerprint should error")
	}
	var mismatch *ContextMismatchError
	if ok := errorAs(err, &mismatch); !ok {
		t.Fatalf("expected ContextMismatchError, got %T", err)
	}
}

func TestContextGuard_EmptyBootIsPassthrough(t *testing.T) {
	cg := NewContextGuardWithFingerprint("")
	if err := cg.Validate("anything"); err != nil {
		t.Fatalf("empty boot fingerprint should be passthrough: %v", err)
	}
}

func TestContextGuard_StatsTrackValidations(t *testing.T) {
	cg := NewContextGuardWithFingerprint("abc123def456abc123def456abc123def456abc123def456abc123def456abc1")
	_ = cg.Validate("abc123def456abc123def456abc123def456abc123def456abc123def456abc1")
	_ = cg.Validate("wrong00000000000000000000000000000000000000000000000000000000000")
	v, m := cg.Stats()
	if v != 2 || m != 1 {
		t.Fatalf("expected 2 validations 1 mismatch, got %d/%d", v, m)
	}
}

func TestContextGuard_ValidateCurrentDoesNotPanic(t *testing.T) {
	cg := NewContextGuard()
	_ = cg.ValidateCurrent()
}

// --- AgentKillSwitch ---

func TestAgentKillSwitch_InitiallyAlive(t *testing.T) {
	ks := NewAgentKillSwitch()
	if ks.IsKilled("agent-1") {
		t.Fatal("agent should not be killed initially")
	}
}

func TestCompAgentKillSwitch_KillAndCheck(t *testing.T) {
	ks := NewAgentKillSwitch().WithKillSwitchClock(fixedClk)
	_, _ = ks.Kill("agent-1", "admin", "misbehaving")
	if !ks.IsKilled("agent-1") {
		t.Fatal("agent should be killed after Kill()")
	}
}

func TestAgentKillSwitch_DoubleKillErrors(t *testing.T) {
	ks := NewAgentKillSwitch()
	_, _ = ks.Kill("a1", "admin", "reason")
	_, err := ks.Kill("a1", "admin", "reason")
	if err == nil {
		t.Fatal("double kill should error")
	}
}

func TestAgentKillSwitch_ReviveRestores(t *testing.T) {
	ks := NewAgentKillSwitch().WithKillSwitchClock(fixedClk)
	_, _ = ks.Kill("a1", "admin", "test")
	_, _ = ks.Revive("a1", "admin")
	if ks.IsKilled("a1") {
		t.Fatal("agent should be alive after revive")
	}
}

func TestCompAgentKillSwitch_ListKilled(t *testing.T) {
	ks := NewAgentKillSwitch()
	_, _ = ks.Kill("a1", "admin", "x")
	_, _ = ks.Kill("a2", "admin", "y")
	killed := ks.ListKilled()
	if len(killed) != 2 {
		t.Fatalf("expected 2 killed, got %d", len(killed))
	}
}

// --- CSNF Transform ---

func TestCSNF_StringNFCNormalization(t *testing.T) {
	tr := NewCSNFTransformer()
	out, err := tr.Transform("hello")
	if err != nil || out != "hello" {
		t.Fatalf("expected 'hello', got %v err=%v", out, err)
	}
}

func TestCSNF_IntegerPreserved(t *testing.T) {
	out, err := CSNFNormalize(float64(42))
	if err != nil {
		t.Fatal(err)
	}
	if out != int64(42) {
		t.Fatalf("expected int64(42), got %v (%T)", out, out)
	}
}

func TestCSNF_FractionalNumberRejected(t *testing.T) {
	_, err := CSNFNormalize(float64(3.14))
	if err == nil {
		t.Fatal("fractional numbers should be rejected")
	}
}

func TestCSNF_NullPreserved(t *testing.T) {
	out, err := CSNFNormalize(nil)
	if err != nil || out != nil {
		t.Fatalf("nil should be preserved, got %v err=%v", out, err)
	}
}

func TestCSNF_ObjectKeysNormalized(t *testing.T) {
	input := map[string]any{"key": "value"}
	out, err := CSNFNormalize(input)
	if err != nil {
		t.Fatal(err)
	}
	m := out.(map[string]any)
	if m["key"] != "value" {
		t.Fatalf("expected value, got %v", m["key"])
	}
}

func TestCSNF_ValidateCompliance(t *testing.T) {
	issues := ValidateCSNFCompliance(map[string]any{"x": 3.14})
	if len(issues) == 0 {
		t.Fatal("expected compliance issues for fractional number")
	}
}

func TestCSNF_NormalizeJSON(t *testing.T) {
	data, err := CSNFNormalizeJSON([]byte(`{"a":1,"b":"hello"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"a":1`) {
		t.Fatalf("unexpected output: %s", data)
	}
}

// --- DeterministicScheduler ---

func TestScheduler_ScheduleAndNext(t *testing.T) {
	s := NewInMemoryScheduler()
	defer s.Close()
	_ = s.Schedule(context.Background(), &SchedulerEvent{EventID: "e1", EventType: "test", ScheduledAt: fixedT})
	ev, err := s.Next(context.Background())
	if err != nil || ev.EventID != "e1" {
		t.Fatalf("expected e1, got %v err=%v", ev, err)
	}
}

func TestCompScheduler_PriorityOrdering(t *testing.T) {
	s := NewInMemoryScheduler()
	defer s.Close()
	_ = s.Schedule(context.Background(), &SchedulerEvent{EventID: "low", Priority: 10, ScheduledAt: fixedT})
	_ = s.Schedule(context.Background(), &SchedulerEvent{EventID: "high", Priority: 1, ScheduledAt: fixedT})
	ev, _ := s.Next(context.Background())
	if ev.EventID != "high" {
		t.Fatalf("expected high priority first, got %s", ev.EventID)
	}
}

func TestScheduler_Len(t *testing.T) {
	s := NewInMemoryScheduler()
	defer s.Close()
	_ = s.Schedule(context.Background(), &SchedulerEvent{EventID: "e1", ScheduledAt: fixedT})
	_ = s.Schedule(context.Background(), &SchedulerEvent{EventID: "e2", ScheduledAt: fixedT})
	if s.Len() != 2 {
		t.Fatalf("expected 2, got %d", s.Len())
	}
}

func TestScheduler_SnapshotHashDeterministic(t *testing.T) {
	s1 := NewInMemoryScheduler()
	defer s1.Close()
	_ = s1.Schedule(context.Background(), &SchedulerEvent{EventID: "e1", ScheduledAt: fixedT, SortKey: "k1"})
	s2 := NewInMemoryScheduler()
	defer s2.Close()
	_ = s2.Schedule(context.Background(), &SchedulerEvent{EventID: "e1", ScheduledAt: fixedT, SortKey: "k1"})
	if s1.SnapshotHash() != s2.SnapshotHash() {
		t.Fatal("snapshot hashes should be equal for identical events")
	}
}

// --- NondeterminismTracker ---

func TestNondeterminismTracker_CaptureAndReceipt(t *testing.T) {
	tr := NewNondeterminismTracker().WithClock(fixedClk)
	tr.Capture("run-1", NDSourceLLM, "llm output", "in1", "out1", "")
	tr.Capture("run-1", NDSourceRandom, "dice roll", "in2", "out2", "seed42")
	receipt, err := tr.Receipt("run-1")
	if err != nil || receipt.TotalBounds != 2 {
		t.Fatalf("expected 2 bounds, got %v err=%v", receipt, err)
	}
}

func TestNondeterminismTracker_UnknownRunErrors(t *testing.T) {
	tr := NewNondeterminismTracker()
	_, err := tr.Receipt("nonexistent")
	if err == nil {
		t.Fatal("unknown run should error")
	}
}

func TestNondeterminismTracker_BoundsForRun(t *testing.T) {
	tr := NewNondeterminismTracker().WithClock(fixedClk)
	tr.Capture("run-1", NDSourceNetwork, "http call", "in", "out", "")
	bounds := tr.BoundsForRun("run-1")
	if len(bounds) != 1 || bounds[0].Source != NDSourceNetwork {
		t.Fatalf("unexpected bounds: %+v", bounds)
	}
}

// errorAs is a simple helper matching errors.As without importing errors.
func errorAs(err error, target interface{}) bool {
	if e, ok := err.(*ContextMismatchError); ok {
		if p, ok2 := target.(**ContextMismatchError); ok2 {
			*p = e
			return true
		}
	}
	return false
}
