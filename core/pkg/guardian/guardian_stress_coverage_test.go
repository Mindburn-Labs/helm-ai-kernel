package guardian

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/firewall"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/kernel"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/prg"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/trust"
)

// fixedClock implements Clock returning a fixed time, advanceable for temporal tests.
type stressClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *stressClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *stressClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newStressClock() *stressClock { return &stressClock{t: time.Now()} }

func newTestGuardian(t *testing.T, opts ...GuardianOption) *Guardian {
	t.Helper()
	signer, err := crypto.NewEd25519Signer("stress-key")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	g := prg.NewGraph()
	return NewGuardian(signer, g, nil, opts...)
}

// ── 500 Concurrent Goroutines ───────────────────────────────────────────

func TestStress_EvaluateDecision500Concurrent(t *testing.T) {
	guardian := newTestGuardian(t)
	var wg sync.WaitGroup
	errs := make(chan error, 500)
	for range 500 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := guardian.EvaluateDecision(context.Background(), DecisionRequest{
				Principal: "agent-stress", Action: "read", Resource: "doc-1",
			})
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	if len(errs) > 0 {
		t.Fatalf("got %d errors, first: %v", len(errs), <-errs)
	}
}

// ── 1000 Sequential Decisions — no memory leak ──────────────────────────

func TestStress_1000SequentialDecisionsNoLeak(t *testing.T) {
	guardian := newTestGuardian(t)
	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)
	for range 1000 {
		_, _ = guardian.EvaluateDecision(context.Background(), DecisionRequest{
			Principal: "agent-mem", Action: "write", Resource: "res-1",
		})
	}
	runtime.GC()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)
	// Allow up to 50MB growth for 1000 decisions (generous bound).
	// Use signed comparison to handle GC reclaiming memory.
	growth := int64(m2.Alloc) - int64(m1.Alloc)
	if growth > 50*1024*1024 {
		t.Fatalf("possible leak: alloc grew by %d bytes", growth)
	}
}

// ── GuardianOption: WithBudgetTracker ───────────────────────────────────

type fakeBudget struct{}

func (fakeBudget) Check(string, BudgetCost) (bool, error) { return true, nil }
func (fakeBudget) Consume(string, BudgetCost) error       { return nil }

func TestStress_OptionWithBudgetTracker(t *testing.T) {
	g := newTestGuardian(t, WithBudgetTracker(fakeBudget{}))
	if g.tracker == nil {
		t.Fatal("budget tracker not set")
	}
}

// ── GuardianOption: WithAuditLog ────────────────────────────────────────

func TestStress_OptionWithAuditLog(t *testing.T) {
	log := NewAuditLog()
	g := newTestGuardian(t, WithAuditLog(log))
	if g.auditLog == nil {
		t.Fatal("audit log not set")
	}
}

// ── GuardianOption: WithTemporalGuardian ────────────────────────────────

func TestStress_OptionWithTemporalGuardian(t *testing.T) {
	clk := newStressClock()
	tg := NewTemporalGuardian(DefaultEscalationPolicy(), clk)
	g := newTestGuardian(t, WithTemporalGuardian(tg))
	if g.temporal == nil {
		t.Fatal("temporal not set")
	}
}

// ── GuardianOption: WithEnvFingerprint ──────────────────────────────────

func TestStress_OptionWithEnvFingerprint(t *testing.T) {
	g := newTestGuardian(t, WithEnvFingerprint("fp-test"))
	if g.envFprint != "fp-test" {
		t.Fatal("fingerprint not set")
	}
}

// ── GuardianOption: WithFreezeController ────────────────────────────────

func TestStress_OptionWithFreezeController(t *testing.T) {
	fc := kernel.NewFreezeController()
	g := newTestGuardian(t, WithFreezeController(fc))
	if g.freezeCtrl == nil {
		t.Fatal("freeze controller not set")
	}
}

// ── GuardianOption: WithAgentKillSwitch ─────────────────────────────────

func TestStress_OptionWithAgentKillSwitch(t *testing.T) {
	ks := kernel.NewAgentKillSwitch()
	g := newTestGuardian(t, WithAgentKillSwitch(ks))
	if g.agentKillSwitch == nil {
		t.Fatal("kill switch not set")
	}
}

// ── GuardianOption: WithContextGuard ────────────────────────────────────

func TestStress_OptionWithContextGuard(t *testing.T) {
	cg := kernel.NewContextGuardWithFingerprint("fp")
	g := newTestGuardian(t, WithContextGuard(cg))
	if g.contextGuard == nil {
		t.Fatal("context guard not set")
	}
}

// ── GuardianOption: WithEgressChecker ───────────────────────────────────

func TestStress_OptionWithEgressChecker(t *testing.T) {
	ec := firewall.NewEgressChecker(nil)
	g := newTestGuardian(t, WithEgressChecker(ec))
	if g.egressChecker == nil {
		t.Fatal("egress checker not set")
	}
}

// ── GuardianOption: WithClock ───────────────────────────────────────────

func TestStress_OptionWithClock(t *testing.T) {
	clk := newStressClock()
	g := newTestGuardian(t, WithClock(clk))
	if g.clock == nil {
		t.Fatal("clock not set")
	}
}

// ── GuardianOption: WithBehavioralTrustScorer ───────────────────────────

func TestStress_OptionWithBehavioralTrustScorer(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	g := newTestGuardian(t, WithBehavioralTrustScorer(scorer))
	if g.behavioralScorer == nil {
		t.Fatal("behavioral scorer not set")
	}
}

// ── Temporal Guardian: threshold boundaries ─────────────────────────────

func TestStress_TemporalThreshold9_9EffectsPerSec(t *testing.T) {
	clk := newStressClock()
	tg := NewTemporalGuardian(DefaultEscalationPolicy(), clk)
	// 594 events in 60s = 9.9/s → should remain at OBSERVE
	for range 594 {
		tg.Evaluate(context.Background())
	}
	if tg.CurrentLevel() != ResponseObserve {
		t.Fatalf("9.9/s should be OBSERVE, got %s", tg.CurrentLevel())
	}
}

func TestStress_TemporalThreshold10_0EffectsPerSec(t *testing.T) {
	clk := newStressClock()
	policy := DefaultEscalationPolicy()
	// Override SustainedFor to 0 so escalation happens immediately at rate
	policy.Thresholds[0].SustainedFor = 0
	tg := NewTemporalGuardian(policy, clk)
	for range 601 {
		tg.Evaluate(context.Background())
	}
	if tg.CurrentLevel() < ResponseThrottle {
		t.Fatalf("10.0+/s with 0 sustain should reach at least THROTTLE, got %s", tg.CurrentLevel())
	}
}

func TestStress_TemporalThreshold10_1EffectsPerSec(t *testing.T) {
	clk := newStressClock()
	policy := DefaultEscalationPolicy()
	policy.Thresholds[0].SustainedFor = 0
	tg := NewTemporalGuardian(policy, clk)
	for range 607 {
		tg.Evaluate(context.Background())
	}
	if tg.CurrentLevel() < ResponseThrottle {
		t.Fatalf("10.1/s should be THROTTLE+, got %s", tg.CurrentLevel())
	}
}

// ── Temporal: ResponseLevel String ──────────────────────────────────────

func TestStress_ResponseLevelStrings(t *testing.T) {
	levels := []ResponseLevel{ResponseObserve, ResponseThrottle, ResponseInterrupt, ResponseQuarantine, ResponseFailClosed}
	names := []string{"OBSERVE", "THROTTLE", "INTERRUPT", "QUARANTINE", "FAIL_CLOSED"}
	for i, l := range levels {
		if l.String() != names[i] {
			t.Fatalf("expected %s, got %s", names[i], l.String())
		}
	}
}

func TestStress_ResponseLevelUnknown(t *testing.T) {
	level := ResponseLevel(99)
	if level.String() == "" {
		t.Fatal("unknown level should have a string")
	}
}

// ── Audit Log: 1000 entries ─────────────────────────────────────────────

func TestStress_AuditLog1000Entries(t *testing.T) {
	log := NewAuditLog()
	for i := range 1000 {
		_, err := log.Append("actor", "action", "target", "details-"+string(rune(i)))
		if err != nil {
			t.Fatalf("append failed at %d: %v", i, err)
		}
	}
	if len(log.Entries) != 1000 {
		t.Fatalf("expected 1000, got %d", len(log.Entries))
	}
}

func TestStress_AuditLog1000VerifyChain(t *testing.T) {
	log := NewAuditLog()
	for i := range 1000 {
		_, _ = log.Append("actor", "action", "target", "d-"+string(rune('A'+i%26)))
	}
	ok, err := log.VerifyChain()
	if err != nil || !ok {
		t.Fatalf("chain verification failed: ok=%v err=%v", ok, err)
	}
}

func TestStress_AuditLogTamperDetect(t *testing.T) {
	log := NewAuditLog()
	for range 10 {
		_, _ = log.Append("actor", "action", "target", "details")
	}
	log.Entries[5].Details = "TAMPERED"
	ok, _ := log.VerifyChain()
	if ok {
		t.Fatal("tampered chain should fail verification")
	}
}

// ── Controllability Envelope ────────────────────────────────────────────

func TestStress_EnvelopeRecord1000(t *testing.T) {
	clk := newStressClock()
	env := NewControllabilityEnvelope(60*time.Second, clk)
	for range 1000 {
		env.Record()
	}
	if env.Count() != 1000 {
		t.Fatalf("expected 1000 events, got %d", env.Count())
	}
}

func TestStress_EnvelopeRateCalculation(t *testing.T) {
	clk := newStressClock()
	env := NewControllabilityEnvelope(60*time.Second, clk)
	for range 600 {
		env.Record()
	}
	rate := env.Rate()
	if rate < 9.9 || rate > 10.1 {
		t.Fatalf("expected ~10.0/s, got %.2f", rate)
	}
}

func TestStress_EnvelopePruning(t *testing.T) {
	clk := newStressClock()
	env := NewControllabilityEnvelope(10*time.Second, clk)
	for range 100 {
		env.Record()
	}
	clk.Advance(11 * time.Second)
	if env.Count() != 0 {
		t.Fatalf("events should be pruned, got %d", env.Count())
	}
}

// ── Concurrent temporal evaluations ─────────────────────────────────────

func TestStress_TemporalConcurrent100(t *testing.T) {
	clk := newStressClock()
	tg := NewTemporalGuardian(DefaultEscalationPolicy(), clk)
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tg.Evaluate(context.Background())
		}()
	}
	wg.Wait()
}

// ── Default escalation policy structure ─────────────────────────────────

func TestStress_DefaultEscalationPolicyHas4Thresholds(t *testing.T) {
	policy := DefaultEscalationPolicy()
	if len(policy.Thresholds) != 4 {
		t.Fatalf("expected 4 thresholds, got %d", len(policy.Thresholds))
	}
}

func TestStress_EscalationPolicyWindowSize(t *testing.T) {
	policy := DefaultEscalationPolicy()
	if policy.WindowSize != 60*time.Second {
		t.Fatalf("expected 60s window, got %v", policy.WindowSize)
	}
}

func TestStress_GradedResponseAllowAtObserve(t *testing.T) {
	clk := newStressClock()
	tg := NewTemporalGuardian(DefaultEscalationPolicy(), clk)
	resp := tg.Evaluate(context.Background())
	if !resp.AllowEffect {
		t.Fatal("OBSERVE level should allow effects")
	}
}

func TestStress_AuditLogEmpty(t *testing.T) {
	log := NewAuditLog()
	ok, err := log.VerifyChain()
	if err != nil || !ok {
		t.Fatal("empty log should verify")
	}
}

func TestStress_AuditLogGenesisHash(t *testing.T) {
	log := NewAuditLog()
	entry, _ := log.Append("a", "b", "c", "d")
	if entry.PreviousHash != "" {
		t.Fatal("genesis entry should have empty prev hash")
	}
	if entry.Hash == "" {
		t.Fatal("genesis entry should have a hash")
	}
}

func TestStress_EnvelopeEmptyWindow(t *testing.T) {
	clk := newStressClock()
	env := NewControllabilityEnvelope(1*time.Second, clk)
	if env.Rate() != 0.0 {
		t.Fatal("empty envelope should have 0 rate")
	}
}

func TestStress_TemporalGuardianDefaultObserve(t *testing.T) {
	clk := newStressClock()
	tg := NewTemporalGuardian(DefaultEscalationPolicy(), clk)
	if tg.CurrentLevel() != ResponseObserve {
		t.Fatal("initial level should be OBSERVE")
	}
}

func TestStress_AuditLogSingleEntry(t *testing.T) {
	log := NewAuditLog()
	_, _ = log.Append("actor", "action", "target", "details")
	ok, err := log.VerifyChain()
	if err != nil || !ok {
		t.Fatal("single entry chain should verify")
	}
}

func TestStress_AuditLogEntryHasID(t *testing.T) {
	log := NewAuditLog()
	entry, _ := log.Append("actor", "act", "tgt", "dtl")
	if entry.ID == "" {
		t.Fatal("entry should have an ID")
	}
}

func TestStress_AuditLogHashLinkage(t *testing.T) {
	log := NewAuditLog()
	e1, _ := log.Append("a", "b", "c", "d")
	e2, _ := log.Append("a", "b", "c", "d")
	if e2.PreviousHash != e1.Hash {
		t.Fatal("second entry prev hash should match first entry hash")
	}
}

func TestStress_EnvelopeCountAfterPrune(t *testing.T) {
	clk := newStressClock()
	env := NewControllabilityEnvelope(5*time.Second, clk)
	for range 50 {
		env.Record()
	}
	clk.Advance(6 * time.Second)
	for range 10 {
		env.Record()
	}
	if env.Count() != 10 {
		t.Fatalf("expected 10, got %d", env.Count())
	}
}

func TestStress_GradedResponseHasDuration(t *testing.T) {
	clk := newStressClock()
	policy := DefaultEscalationPolicy()
	policy.Thresholds[0].SustainedFor = 0
	tg := NewTemporalGuardian(policy, clk)
	for range 700 {
		tg.Evaluate(context.Background())
	}
	resp := tg.Evaluate(context.Background())
	if resp.Duration == 0 && resp.Level > ResponseObserve {
		t.Fatal("escalated level should have a duration")
	}
}

func TestStress_GuardianNilRegistry(t *testing.T) {
	g := newTestGuardian(t)
	if g == nil {
		t.Fatal("guardian should not be nil")
	}
}

func TestStress_OptionWithComplianceChecker(t *testing.T) {
	g := newTestGuardian(t) // no compliance checker
	if g.complianceChecker != nil {
		t.Fatal("compliance checker should be nil by default")
	}
}

func TestStress_WallClockReturnsTime(t *testing.T) {
	wc := wallClock{}
	now := wc.Now()
	if now.IsZero() {
		t.Fatal("wall clock should return non-zero time")
	}
}

func TestStress_NewDecisionIDUnique(t *testing.T) {
	ids := make(map[string]bool, 100)
	for range 100 {
		id := newDecisionID()
		if ids[id] {
			t.Fatalf("duplicate decision ID: %s", id)
		}
		ids[id] = true
	}
}
