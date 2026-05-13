package guardian

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/trust"
)

// ── Privilege Tier Tests ─────────────────────────────────────────

func TestDeepPrivilegeTierString(t *testing.T) {
	cases := map[PrivilegeTier]string{
		TierRestricted: "RESTRICTED", TierStandard: "STANDARD",
		TierElevated: "ELEVATED", TierSystem: "SYSTEM",
	}
	for tier, expected := range cases {
		if tier.String() != expected {
			t.Fatalf("tier %d: got %q, want %q", tier, tier.String(), expected)
		}
	}
}

func TestDeepPrivilegeTierStringUnknown(t *testing.T) {
	unknown := PrivilegeTier(99)
	s := unknown.String()
	if s != "UNKNOWN(99)" {
		t.Fatalf("expected UNKNOWN(99), got %q", s)
	}
}

func TestDeepRequiredTierForEffectKnown(t *testing.T) {
	cases := map[string]PrivilegeTier{
		"SEND_EMAIL":           TierStandard,
		"INFRA_DESTROY":        TierSystem,
		"SOFTWARE_PUBLISH":     TierElevated,
		"CI_CREDENTIAL_ACCESS": TierElevated,
	}
	for effect, want := range cases {
		if got := RequiredTierForEffect(effect); got != want {
			t.Fatalf("effect %s: got %v, want %v", effect, got, want)
		}
	}
}

func TestDeepRequiredTierForEffectUnknown(t *testing.T) {
	if RequiredTierForEffect("UNKNOWN_EFFECT") != TierStandard {
		t.Fatal("unknown effects should default to TierStandard")
	}
}

func TestDeepEffectiveTierHostile(t *testing.T) {
	if EffectiveTier(TierSystem, trust.TierHostile) != TierRestricted {
		t.Fatal("HOSTILE trust should force TierRestricted regardless of assigned tier")
	}
}

func TestDeepEffectiveTierSuspectCapsAtStandard(t *testing.T) {
	if EffectiveTier(TierElevated, trust.TierSuspect) != TierStandard {
		t.Fatal("SUSPECT trust should cap elevated to TierStandard")
	}
}

func TestDeepEffectiveTierSuspectPreservesLower(t *testing.T) {
	if EffectiveTier(TierRestricted, trust.TierSuspect) != TierRestricted {
		t.Fatal("SUSPECT trust should not elevate already-restricted tier")
	}
}

func TestDeepEffectiveTierNeutralPassThrough(t *testing.T) {
	if EffectiveTier(TierElevated, trust.TierNeutral) != TierElevated {
		t.Fatal("NEUTRAL trust should not modify assigned tier")
	}
}

func TestDeepEffectiveTierPristinePassThrough(t *testing.T) {
	if EffectiveTier(TierSystem, trust.TierPristine) != TierSystem {
		t.Fatal("PRISTINE trust should not modify assigned tier")
	}
}

// ── Static Privilege Resolver Tests ──────────────────────────────

func TestDeepStaticPrivilegeResolverDefault(t *testing.T) {
	r := NewStaticPrivilegeResolver(TierRestricted)
	tier, err := r.ResolveTier(context.Background(), "unknown-agent")
	if err != nil || tier != TierRestricted {
		t.Fatal("unknown agent should get default tier")
	}
}

func TestDeepStaticPrivilegeResolverSetTier(t *testing.T) {
	r := NewStaticPrivilegeResolver(TierRestricted)
	r.SetTier("agent-1", TierSystem)
	tier, _ := r.ResolveTier(context.Background(), "agent-1")
	if tier != TierSystem {
		t.Fatal("expected TierSystem for agent-1")
	}
}

func TestDeepStaticPrivilegeResolverOverwrite(t *testing.T) {
	r := NewStaticPrivilegeResolver(TierStandard)
	r.SetTier("a", TierElevated)
	r.SetTier("a", TierRestricted)
	tier, _ := r.ResolveTier(context.Background(), "a")
	if tier != TierRestricted {
		t.Fatal("overwrite should take effect")
	}
}

// ── Audit Log Tests ──────────────────────────────────────────────

func TestDeepAuditLogGenesisEntry(t *testing.T) {
	log := NewAuditLog()
	entry, err := log.Append("admin", "init", "system", "genesis")
	if err != nil || entry.PreviousHash != "" {
		t.Fatal("genesis entry should have empty previous hash")
	}
}

func TestDeepAuditLogChainIntegrity(t *testing.T) {
	log := NewAuditLog()
	log.Append("a", "act1", "t1", "d1")
	log.Append("b", "act2", "t2", "d2")
	log.Append("c", "act3", "t3", "d3")
	valid, err := log.VerifyChain()
	if !valid || err != nil {
		t.Fatalf("chain should be valid: %v", err)
	}
}

func TestDeepAuditLogTamperDetection(t *testing.T) {
	log := NewAuditLog()
	log.Append("a", "act1", "t1", "d1")
	log.Append("b", "act2", "t2", "d2")
	log.Entries[0].Details = "tampered"
	valid, err := log.VerifyChain()
	if valid {
		t.Fatal("tampered chain should fail verification")
	}
	if err == nil {
		t.Fatal("expected error for tampered chain")
	}
}

func TestDeepAuditLogEmptyChainValid(t *testing.T) {
	log := NewAuditLog()
	valid, err := log.VerifyChain()
	if !valid || err != nil {
		t.Fatal("empty chain should be valid")
	}
}

func TestDeepAuditLogHashDeterminism(t *testing.T) {
	clk := &deepFixedClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	log1 := NewAuditLog(clk)
	log2 := NewAuditLog(clk)
	e1, _ := log1.Append("a", "act", "tgt", "details")
	e2, _ := log2.Append("a", "act", "tgt", "details")
	if e1.Hash != e2.Hash {
		t.Fatal("same inputs and clock should produce identical hashes")
	}
}

// ── Temporal Guardian Tests ──────────────────────────────────────

func TestDeepTemporalGuardianStartsAtObserve(t *testing.T) {
	clk := &deepFixedClock{t: time.Now()}
	tg := NewTemporalGuardian(DefaultEscalationPolicy(), clk)
	if tg.CurrentLevel() != ResponseObserve {
		t.Fatal("should start at OBSERVE")
	}
}

func TestDeepTemporalGuardianAllowsAtObserve(t *testing.T) {
	clk := &deepFixedClock{t: time.Now()}
	tg := NewTemporalGuardian(DefaultEscalationPolicy(), clk)
	resp := tg.Evaluate(context.Background())
	if !resp.AllowEffect {
		t.Fatal("effects should be allowed at OBSERVE level")
	}
}

func TestDeepControllabilityEnvelopeRate(t *testing.T) {
	clk := &deepFixedClock{t: time.Now()}
	env := NewControllabilityEnvelope(60*time.Second, clk)
	for i := 0; i < 100; i++ {
		env.Record()
	}
	rate := env.Rate()
	if rate < 1.0 {
		t.Fatalf("expected positive rate, got %f", rate)
	}
}

func TestDeepControllabilityEnvelopeCount(t *testing.T) {
	clk := &deepFixedClock{t: time.Now()}
	env := NewControllabilityEnvelope(60*time.Second, clk)
	for i := 0; i < 50; i++ {
		env.Record()
	}
	if env.Count() != 50 {
		t.Fatalf("expected 50 events, got %d", env.Count())
	}
}

func TestDeepControllabilityEnvelopePruning(t *testing.T) {
	clk := &deepFixedClock{t: time.Now()}
	env := NewControllabilityEnvelope(1*time.Second, clk)
	env.Record()
	clk.t = clk.t.Add(2 * time.Second) // advance past window
	if env.Count() != 0 {
		t.Fatal("events outside window should be pruned")
	}
}

func TestDeepResponseLevelString(t *testing.T) {
	cases := map[ResponseLevel]string{
		ResponseObserve:    "OBSERVE",
		ResponseThrottle:   "THROTTLE",
		ResponseInterrupt:  "INTERRUPT",
		ResponseQuarantine: "QUARANTINE",
		ResponseFailClosed: "FAIL_CLOSED",
	}
	for level, expected := range cases {
		if level.String() != expected {
			t.Fatalf("level %d: got %q, want %q", level, level.String(), expected)
		}
	}
}

// ── Concurrent EvaluateDecision Tests ────────────────────────────

func TestDeepConcurrentPrivilegeResolve(t *testing.T) {
	r := NewStaticPrivilegeResolver(TierStandard)
	for i := 0; i < 50; i++ {
		r.SetTier(fmt.Sprintf("agent-%d", i), PrivilegeTier(i%4))
	}
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			id := fmt.Sprintf("agent-%d", idx%50)
			_, err := r.ResolveTier(context.Background(), id)
			if err != nil {
				t.Errorf("resolve failed: %v", err)
			}
		}(i)
	}
	wg.Wait()
}

func TestDeepSequentialAuditLogAppend100(t *testing.T) {
	log := NewAuditLog()
	for i := 0; i < 100; i++ {
		_, err := log.Append(fmt.Sprintf("actor-%d", i), "action", "target", "details")
		if err != nil {
			t.Fatalf("append %d failed: %v", i, err)
		}
	}
	if len(log.Entries) != 100 {
		t.Fatalf("expected 100 entries, got %d", len(log.Entries))
	}
	valid, err := log.VerifyChain()
	if !valid || err != nil {
		t.Fatalf("chain should be valid after 100 appends: %v", err)
	}
}

func TestDeepConcurrentTemporalEvaluate(t *testing.T) {
	clk := &deepFixedClock{t: time.Now()}
	tg := NewTemporalGuardian(DefaultEscalationPolicy(), clk)
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tg.Evaluate(context.Background())
		}()
	}
	wg.Wait()
	// Should not panic — concurrent safety is the assertion.
}

// ── Unique Decision IDs Test ─────────────────────────────────────

func TestDeepAuditLogUniqueIDs(t *testing.T) {
	clk := &deepAdvancingClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	log := NewAuditLog(clk)
	ids := map[string]bool{}
	for i := 0; i < 1000; i++ {
		entry, err := log.Append("actor", "action", "target", fmt.Sprintf("detail-%d", i))
		if err != nil {
			t.Fatal(err)
		}
		if ids[entry.ID] {
			t.Fatalf("duplicate ID at iteration %d: %s", i, entry.ID)
		}
		ids[entry.ID] = true
	}
}

// ── EffectTierMap Coverage ───────────────────────────────────────

func TestDeepEffectTierMapAllEntries(t *testing.T) {
	if len(EffectTierMap) == 0 {
		t.Fatal("EffectTierMap should not be empty")
	}
	for effect, tier := range EffectTierMap {
		if tier < TierRestricted || tier > TierSystem {
			t.Fatalf("invalid tier %d for effect %s", tier, effect)
		}
	}
}

// ── Helper Clocks ────────────────────────────────────────────────

type deepFixedClock struct {
	t time.Time
}

func (c *deepFixedClock) Now() time.Time { return c.t }

type deepAdvancingClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *deepAdvancingClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(1 * time.Nanosecond)
	return c.t
}
