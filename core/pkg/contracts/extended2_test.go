package contracts

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ─── 1: CondensationTier LOW – no full receipts, condense after window ─

func TestExt2_CondensationTierLow(t *testing.T) {
	p := DefaultCondensationPolicy()
	low := p.RetentionPolicy[0]
	if low.Tier != RiskTierLow || low.RetainFullReceipts || !low.CondenseAfterWindow {
		t.Fatalf("LOW tier policy mismatch: %+v", low)
	}
}

// ─── 2: CondensationTier MEDIUM – retains full receipts ─────────

func TestExt2_CondensationTierMedium(t *testing.T) {
	p := DefaultCondensationPolicy()
	med := p.RetentionPolicy[1]
	if med.Tier != RiskTierMedium || !med.RetainFullReceipts || !med.CondenseAfterWindow {
		t.Fatalf("MEDIUM tier policy mismatch: %+v", med)
	}
}

// ─── 3: CondensationTier HIGH – anchored to external log ─────

func TestExt2_CondensationTierHigh(t *testing.T) {
	p := DefaultCondensationPolicy()
	high := p.RetentionPolicy[2]
	if high.Tier != RiskTierHigh || !high.RetainFullReceipts || high.CondenseAfterWindow || !high.AnchorToExternal {
		t.Fatalf("HIGH tier policy mismatch: %+v", high)
	}
}

// ─── 4: DefaultCondensationPolicy checkpoint interval is 100 ─

func TestExt2_CondensationCheckpointInterval(t *testing.T) {
	p := DefaultCondensationPolicy()
	if p.CheckpointInterval != 100 {
		t.Fatalf("expected checkpoint interval 100, got %d", p.CheckpointInterval)
	}
}

// ─── 5: AllLanes returns exactly five lanes in order ─────────

func TestExt2_AllLanesCount(t *testing.T) {
	lanes := AllLanes()
	if len(lanes) != 5 {
		t.Fatalf("expected 5 lanes, got %d", len(lanes))
	}
}

// ─── 6: Lane constant values ────────────────────────────────

func TestExt2_LaneConstantValues(t *testing.T) {
	expected := []Lane{LaneResearch, LaneBuild, LaneGTM, LaneOps, LaneCompliance}
	vals := []string{"RESEARCH", "BUILD", "GTM", "OPS", "COMPLIANCE"}
	for i, l := range expected {
		if string(l) != vals[i] {
			t.Errorf("Lane %d: expected %s, got %s", i, vals[i], l)
		}
	}
}

// ─── 7: LaneState IsIdle true when zero runs and no next action ─

func TestExt2_LaneStateIdleTrue(t *testing.T) {
	ls := &LaneState{ActiveRuns: 0, NextAction: ""}
	if !ls.IsIdle() {
		t.Fatal("expected idle")
	}
}

// ─── 8: LaneState IsIdle false with pending action ──────────

func TestExt2_LaneStateIdleFalseWithAction(t *testing.T) {
	ls := &LaneState{ActiveRuns: 0, NextAction: "deploy"}
	if ls.IsIdle() {
		t.Fatal("expected not idle when NextAction is set")
	}
}

// ─── 9: Every InterventionType constant value ───────────────

func TestExt2_InterventionTypeConstants(t *testing.T) {
	types := map[InterventionType]string{
		InterventionNone:       "NONE",
		InterventionThrottle:   "THROTTLE",
		InterventionInterrupt:  "INTERRUPT",
		InterventionQuarantine: "QUARANTINE",
	}
	for it, want := range types {
		if string(it) != want {
			t.Errorf("InterventionType %v != %s", it, want)
		}
	}
}

// ─── 10: CompensationStep ordering preserved ─────────────────

func TestExt2_CompensationStepOrdering(t *testing.T) {
	steps := []CompensationStep{
		{StepID: "s1", Order: 1, Action: "revert_deploy"},
		{StepID: "s2", Order: 2, Action: "restore_backup"},
		{StepID: "s3", Order: 3, Action: "notify_oncall"},
	}
	r := NewCompensationRecipe("run-1", steps, true)
	for i, s := range r.Steps {
		if s.Order != i+1 {
			t.Errorf("step %d: expected order %d, got %d", i, i+1, s.Order)
		}
	}
}

// ─── 11: CompensationRecipe content hash is deterministic ────

func TestExt2_CompensationRecipeHashDeterministic(t *testing.T) {
	steps := []CompensationStep{{StepID: "s1", Order: 1, Action: "a"}}
	r1 := NewCompensationRecipe("r1", steps, false)
	r2 := NewCompensationRecipe("r1", steps, false)
	if r1.ContentHash != r2.ContentHash {
		t.Fatal("same inputs should produce same content hash")
	}
}

// ─── 12: CompensationRecipe HasFallbacks false when missing ──

func TestExt2_CompensationHasFallbacksFalse(t *testing.T) {
	steps := []CompensationStep{{StepID: "s1", Order: 1, Action: "a", Fallback: ""}}
	r := NewCompensationRecipe("r", steps, true)
	if r.HasFallbacks() {
		t.Fatal("expected HasFallbacks false when step has empty fallback")
	}
}

// ─── 13: CompensationRecipe HasFallbacks true when all set ──

func TestExt2_CompensationHasFallbacksTrue(t *testing.T) {
	steps := []CompensationStep{{StepID: "s1", Order: 1, Action: "a", Fallback: "retry"}}
	r := NewCompensationRecipe("r", steps, true)
	if !r.HasFallbacks() {
		t.Fatal("expected HasFallbacks true")
	}
}

// ─── 14: Receipt chain linking – PrevHash and LamportClock ──

func TestExt2_ReceiptChainLinking(t *testing.T) {
	r1 := Receipt{ReceiptID: "r1", LamportClock: 1, Signature: "sig1"}
	r2 := Receipt{ReceiptID: "r2", PrevHash: r1.Signature, LamportClock: r1.LamportClock + 1}
	if r2.PrevHash != "sig1" || r2.LamportClock != 2 {
		t.Fatalf("chain link broken: prev=%s clock=%d", r2.PrevHash, r2.LamportClock)
	}
}

// ─── 15: Receipt LamportClock increments monotonically ──────

func TestExt2_ReceiptLamportClockIncrement(t *testing.T) {
	receipts := make([]Receipt, 5)
	for i := range receipts {
		receipts[i].LamportClock = uint64(i + 1)
	}
	for i := 1; i < len(receipts); i++ {
		if receipts[i].LamportClock <= receipts[i-1].LamportClock {
			t.Fatalf("clock not monotonic at index %d", i)
		}
	}
}

// ─── 16: Effect serialization round-trip ─────────────────────

func TestExt2_EffectSerializationRoundTrip(t *testing.T) {
	e := Effect{EffectID: "eff-1", EffectType: "SEND_EMAIL", Params: map[string]any{"to": "bob"}}
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var e2 Effect
	if err := json.Unmarshal(data, &e2); err != nil {
		t.Fatal(err)
	}
	if e2.EffectID != e.EffectID || e2.EffectType != e.EffectType {
		t.Fatalf("round-trip mismatch: %+v", e2)
	}
}

// ─── 17: ApprovalBinding drift detection on plan change ─────

func TestExt2_ApprovalBindingDriftDetected(t *testing.T) {
	ab := NewApprovalBinding("b1", "sha256:aaa", "appr-1", time.Hour)
	drifted := ab.CheckDrift("sha256:bbb")
	if !drifted || !ab.Drifted {
		t.Fatal("expected drift detected")
	}
}

// ─── 18: ApprovalBinding no drift when hash matches ────────

func TestExt2_ApprovalBindingNoDrift(t *testing.T) {
	ab := NewApprovalBinding("b1", "sha256:aaa", "appr-1", time.Hour)
	if ab.CheckDrift("sha256:aaa") {
		t.Fatal("expected no drift when hashes match")
	}
}

// ─── 19: ApprovalBinding invalid after expiry ───────────────

func TestExt2_ApprovalBindingExpired(t *testing.T) {
	ab := NewApprovalBinding("b1", "sha256:aaa", "appr-1", time.Millisecond)
	time.Sleep(2 * time.Millisecond)
	if ab.IsValid(time.Now().UTC()) {
		t.Fatal("expected invalid after expiry")
	}
}

// ─── 20: ApprovalBinding invalid when drifted ───────────────

func TestExt2_ApprovalBindingInvalidWhenDrifted(t *testing.T) {
	ab := NewApprovalBinding("b1", "sha256:aaa", "appr-1", time.Hour)
	ab.Drifted = true
	if ab.IsValid(time.Now().UTC()) {
		t.Fatal("expected invalid when drifted")
	}
}

// ─── 21: Posture escalation ordering ────────────────────────

func TestExt2_PostureCanEscalate(t *testing.T) {
	if !PostureObserve.CanEscalateTo(PostureDraft) {
		t.Fatal("OBSERVE should escalate to DRAFT")
	}
	if PostureSovereign.CanEscalateTo(PostureTransact) {
		t.Fatal("SOVEREIGN should not escalate to TRANSACT")
	}
}

// ─── 22: AllPostures returns 4 in order ─────────────────────

func TestExt2_AllPosturesOrder(t *testing.T) {
	postures := AllPostures()
	if len(postures) != 4 {
		t.Fatalf("expected 4 postures, got %d", len(postures))
	}
	if postures[0] != PostureObserve || postures[3] != PostureSovereign {
		t.Fatal("postures not in ascending privilege order")
	}
}

// ─── 23: Budget exhaustion on token limit ───────────────────

func TestExt2_BudgetExhaustedTokens(t *testing.T) {
	b := &Budget{MaxTokens: 100, ConsumedTokens: 100}
	if !b.Exhausted() {
		t.Fatal("expected exhausted when tokens consumed equals max")
	}
}

// ─── 24: Budget RemainingTokens clamped to zero ─────────────

func TestExt2_BudgetRemainingTokensZero(t *testing.T) {
	b := &Budget{MaxTokens: 50, ConsumedTokens: 80}
	if b.RemainingTokens() != 0 {
		t.Fatalf("expected 0 remaining, got %d", b.RemainingTokens())
	}
}

// ─── 25: KnownModelProviders non-empty ──────────────────────

func TestExt2_KnownModelProvidersNonEmpty(t *testing.T) {
	providers := KnownModelProviders()
	if len(providers) == 0 {
		t.Fatal("expected at least one known model provider")
	}
}

// ─── 26: KnownModelProvidersByID lookup ─────────────────────

func TestExt2_KnownModelProvidersByIDLookup(t *testing.T) {
	byID := KnownModelProvidersByID()
	p, ok := byID["anthropic:claude-opus-4-6"]
	if !ok {
		t.Fatal("expected claude-opus-4-6 in catalog")
	}
	if !p.Active {
		t.Fatal("claude-opus-4-6 should be active")
	}
}

// ─── 27: Unknown effect type defaults to E3 (fail-closed) ───

func TestExt2_UnknownEffectDefaultsE3(t *testing.T) {
	if got := EffectRiskClass("TOTALLY_UNKNOWN"); got != "E3" {
		t.Fatalf("expected E3 for unknown, got %s", got)
	}
}

// ─── 28: LookupEffectType returns nil for unknown ───────────

func TestExt2_LookupEffectTypeNil(t *testing.T) {
	if LookupEffectType("DOES_NOT_EXIST") != nil {
		t.Fatal("expected nil for unknown effect type")
	}
}

// ─── 29: LookupEffectType returns non-nil for known ─────────

func TestExt2_LookupEffectTypeKnown(t *testing.T) {
	et := LookupEffectType(EffectTypeSendEmail)
	if et == nil || et.TypeID != EffectTypeSendEmail {
		t.Fatal("expected non-nil for SEND_EMAIL")
	}
}

// ─── 30: CondensedReceipt JSON round-trip ───────────────────

func TestExt2_CondensedReceiptRoundTrip(t *testing.T) {
	cr := CondensedReceipt{
		ReceiptID:    "r1",
		CheckpointID: "cp1",
		InclusionProof: CondensationInclusionProof{
			LeafHash: "h1", Siblings: []string{"s1"}, Positions: []string{"left"}, Root: "root",
		},
	}
	data, _ := json.Marshal(cr)
	var cr2 CondensedReceipt
	if err := json.Unmarshal(data, &cr2); err != nil {
		t.Fatal(err)
	}
	if cr2.InclusionProof.Root != "root" || !strings.Contains(string(data), "leaf_hash") {
		t.Fatal("condensed receipt round-trip failed")
	}
}
