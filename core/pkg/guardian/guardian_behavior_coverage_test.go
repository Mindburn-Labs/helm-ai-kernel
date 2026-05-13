package guardian

import (
	"context"
	"testing"
	"time"

	pkg_artifact "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/trust"
)

// ─── helpers ────────────────────────────────────────────────────

// testClock implements Clock with a fixed, advanceable time.
// (Cannot reuse fixedClock from temporal_test.go because test helper
//
//	names must be unique within the package.)
type testClock struct {
	now time.Time
}

func (c *testClock) Now() time.Time          { return c.now }
func (c *testClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

func newTestClock() *testClock {
	return &testClock{now: time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)}
}

// testSigner is a minimal mock that signs without error.
type testSigner struct{ fail bool }

func (s *testSigner) Sign([]byte) (string, error) { return "sig", nil }
func (s *testSigner) PublicKey() string           { return "pk" }
func (s *testSigner) PublicKeyBytes() []byte      { return []byte("pk") }
func (s *testSigner) SignDecision(d *contracts.DecisionRecord) error {
	if s.fail {
		return errSignerBroken
	}
	d.Signature = "test_sig"
	return nil
}
func (s *testSigner) SignIntent(i *contracts.AuthorizedExecutionIntent) error {
	if s.fail {
		return errSignerBroken
	}
	i.Signature = "test_sig"
	return nil
}
func (s *testSigner) VerifyDecision(*contracts.DecisionRecord) (bool, error) { return true, nil }
func (s *testSigner) VerifyIntent(*contracts.AuthorizedExecutionIntent) (bool, error) {
	return true, nil
}
func (s *testSigner) SignReceipt(r *contracts.Receipt) error {
	r.Signature = "test_sig"
	return nil
}
func (s *testSigner) VerifyReceipt(*contracts.Receipt) (bool, error) { return true, nil }

var errSignerBroken = errorf("signer broken")

type errString string

func errorf(s string) errString   { return errString(s) }
func (e errString) Error() string { return string(e) }

// testStore is a trivial in-memory content-addressed store.
type testStore struct{ data map[string][]byte }

func newTestStore() *testStore { return &testStore{data: map[string][]byte{}} }
func (s *testStore) Store(_ context.Context, d []byte) (string, error) {
	k := "sha256:test"
	s.data[k] = d
	return k, nil
}
func (s *testStore) Get(_ context.Context, k string) ([]byte, error) {
	if v, ok := s.data[k]; ok {
		return v, nil
	}
	return nil, errorf("not found")
}
func (s *testStore) Exists(_ context.Context, k string) (bool, error) {
	_, ok := s.data[k]
	return ok, nil
}
func (s *testStore) Delete(_ context.Context, k string) error {
	delete(s.data, k)
	return nil
}

func newMinimalGuardian(opts ...GuardianOption) *Guardian {
	signer := &testSigner{}
	graph := prg.NewGraph()
	reg := pkg_artifact.NewRegistry(newTestStore(), nil)
	return NewGuardian(signer, graph, reg, opts...)
}

// ─── 1-10: NewGuardian construction ─────────────────────────────

func TestNewGuardian_DefaultClock(t *testing.T) {
	g := newMinimalGuardian()
	if g.clock == nil {
		t.Fatal("expected non-nil default clock")
	}
}

func TestNewGuardian_NilFields(t *testing.T) {
	g := newMinimalGuardian()
	if g.tracker != nil || g.auditLog != nil || g.temporal != nil {
		t.Fatal("optional fields should be nil by default")
	}
}

func TestNewGuardian_SignerStored(t *testing.T) {
	s := &testSigner{}
	g := NewGuardian(s, prg.NewGraph(), pkg_artifact.NewRegistry(newTestStore(), nil))
	if g.signer != s {
		t.Fatal("signer not stored")
	}
}

func TestNewGuardian_PRGStored(t *testing.T) {
	graph := prg.NewGraph()
	g := NewGuardian(&testSigner{}, graph, pkg_artifact.NewRegistry(newTestStore(), nil))
	if g.prg != graph {
		t.Fatal("prg graph not stored")
	}
}

func TestNewGuardian_RegistryStored(t *testing.T) {
	reg := pkg_artifact.NewRegistry(newTestStore(), nil)
	g := NewGuardian(&testSigner{}, prg.NewGraph(), reg)
	if g.registry != reg {
		t.Fatal("registry not stored")
	}
}

func TestNewGuardian_PolicyEngineCreated(t *testing.T) {
	g := newMinimalGuardian()
	if g.pe == nil {
		t.Fatal("policy engine should be created")
	}
}

// ─── 6-15: GuardianOption functions ─────────────────────────────

func TestWithClock(t *testing.T) {
	c := newTestClock()
	g := newMinimalGuardian(WithClock(c))
	if g.clock != c {
		t.Fatal("WithClock not applied")
	}
}

func TestWithBudgetTracker(t *testing.T) {
	bt := newMockBudgetTracker(100)
	g := newMinimalGuardian(WithBudgetTracker(bt))
	if g.tracker != bt {
		t.Fatal("WithBudgetTracker not applied")
	}
}

func TestWithAuditLog(t *testing.T) {
	al := NewAuditLog()
	g := newMinimalGuardian(WithAuditLog(al))
	if g.auditLog != al {
		t.Fatal("WithAuditLog not applied")
	}
}

func TestWithTemporalGuardian(t *testing.T) {
	c := newTestClock()
	tg := NewTemporalGuardian(DefaultEscalationPolicy(), c)
	g := newMinimalGuardian(WithTemporalGuardian(tg))
	if g.temporal != tg {
		t.Fatal("WithTemporalGuardian not applied")
	}
}

func TestWithEnvFingerprint(t *testing.T) {
	g := newMinimalGuardian(WithEnvFingerprint("sha256:abc"))
	if g.envFprint != "sha256:abc" {
		t.Fatalf("expected sha256:abc, got %s", g.envFprint)
	}
}

func TestWithBehavioralTrustScorer(t *testing.T) {
	s := trust.NewBehavioralTrustScorer()
	g := newMinimalGuardian(WithBehavioralTrustScorer(s))
	if g.behavioralScorer != s {
		t.Fatal("WithBehavioralTrustScorer not applied")
	}
}

func TestWithPrivilegeResolver(t *testing.T) {
	r := NewStaticPrivilegeResolver(TierStandard)
	g := newMinimalGuardian(WithPrivilegeResolver(r))
	if g.privilegeResolver != r {
		t.Fatal("WithPrivilegeResolver not applied")
	}
}

func TestMultipleOptions(t *testing.T) {
	al := NewAuditLog()
	c := newTestClock()
	g := newMinimalGuardian(WithAuditLog(al), WithClock(c), WithEnvFingerprint("fp"))
	if g.auditLog != al || g.clock != c || g.envFprint != "fp" {
		t.Fatal("multiple options not all applied")
	}
}

// ─── 16-22: DecisionRequest fields ─────────────────────────────

func TestDecisionRequest_PrincipalField(t *testing.T) {
	req := DecisionRequest{Principal: "agent-1"}
	if req.Principal != "agent-1" {
		t.Fatalf("expected agent-1, got %s", req.Principal)
	}
}

func TestDecisionRequest_ActionField(t *testing.T) {
	req := DecisionRequest{Action: "EXECUTE_TOOL"}
	if req.Action != "EXECUTE_TOOL" {
		t.Fatalf("expected EXECUTE_TOOL, got %s", req.Action)
	}
}

func TestDecisionRequest_ResourceField(t *testing.T) {
	req := DecisionRequest{Resource: "file_read"}
	if req.Resource != "file_read" {
		t.Fatalf("expected file_read, got %s", req.Resource)
	}
}

func TestDecisionRequest_ContextField(t *testing.T) {
	ctx := map[string]interface{}{"key": "val"}
	req := DecisionRequest{Context: ctx}
	if req.Context["key"] != "val" {
		t.Fatal("context not stored correctly")
	}
}

func TestDecisionRequest_NilContext(t *testing.T) {
	req := DecisionRequest{Principal: "a", Action: "b"}
	if req.Context != nil {
		t.Fatal("expected nil context by default")
	}
}

func TestDecisionRequest_AllFields(t *testing.T) {
	req := DecisionRequest{Principal: "p", Action: "a", Resource: "r", Context: map[string]interface{}{"x": 1}}
	if req.Principal != "p" || req.Action != "a" || req.Resource != "r" {
		t.Fatal("fields mismatch")
	}
}

func TestDecisionRequest_EmptyFields(t *testing.T) {
	req := DecisionRequest{}
	if req.Principal != "" || req.Action != "" || req.Resource != "" {
		t.Fatal("zero value should be empty strings")
	}
}

// ─── 23-30: checkEnvelope ───────────────────────────────────────

func TestCheckEnvelope_Valid(t *testing.T) {
	g := newMinimalGuardian()
	e := &contracts.Effect{EffectID: "eff-1", EffectType: "EXECUTE_TOOL"}
	if err := g.checkEnvelope(e); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestCheckEnvelope_MissingEffectType(t *testing.T) {
	g := newMinimalGuardian()
	e := &contracts.Effect{EffectID: "eff-1"}
	if err := g.checkEnvelope(e); err == nil {
		t.Fatal("expected error for missing effect type")
	}
}

func TestCheckEnvelope_MissingEffectID(t *testing.T) {
	g := newMinimalGuardian()
	e := &contracts.Effect{EffectType: "EXECUTE_TOOL"}
	if err := g.checkEnvelope(e); err == nil {
		t.Fatal("expected error for missing effect ID")
	}
}

func TestCheckEnvelope_BothMissing(t *testing.T) {
	g := newMinimalGuardian()
	e := &contracts.Effect{}
	if err := g.checkEnvelope(e); err == nil {
		t.Fatal("expected error when both fields missing")
	}
}

func TestCheckEnvelope_WithParams(t *testing.T) {
	g := newMinimalGuardian()
	e := &contracts.Effect{EffectID: "e1", EffectType: "T", Params: map[string]any{"tool_name": "x"}}
	if err := g.checkEnvelope(e); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckEnvelope_WithTimestampParam(t *testing.T) {
	g := newMinimalGuardian()
	e := &contracts.Effect{EffectID: "e1", EffectType: "T", Params: map[string]any{"timestamp": time.Now().Unix()}}
	if err := g.checkEnvelope(e); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckEnvelope_EmptyEffectType(t *testing.T) {
	g := newMinimalGuardian()
	e := &contracts.Effect{EffectID: "e1", EffectType: ""}
	if err := g.checkEnvelope(e); err == nil {
		t.Fatal("empty string effect type should be rejected")
	}
}

func TestCheckEnvelope_EmptyEffectID(t *testing.T) {
	g := newMinimalGuardian()
	e := &contracts.Effect{EffectID: "", EffectType: "T"}
	if err := g.checkEnvelope(e); err == nil {
		t.Fatal("empty string effect ID should be rejected")
	}
}

// ─── 31-40: Temporal Guardian response levels ───────────────────

func TestResponseLevel_ObserveString(t *testing.T) {
	if ResponseObserve.String() != "OBSERVE" {
		t.Fatalf("expected OBSERVE, got %s", ResponseObserve.String())
	}
}

func TestResponseLevel_ThrottleString(t *testing.T) {
	if ResponseThrottle.String() != "THROTTLE" {
		t.Fatalf("expected THROTTLE, got %s", ResponseThrottle.String())
	}
}

func TestResponseLevel_InterruptString(t *testing.T) {
	if ResponseInterrupt.String() != "INTERRUPT" {
		t.Fatalf("expected INTERRUPT, got %s", ResponseInterrupt.String())
	}
}

func TestResponseLevel_QuarantineString(t *testing.T) {
	if ResponseQuarantine.String() != "QUARANTINE" {
		t.Fatalf("expected QUARANTINE, got %s", ResponseQuarantine.String())
	}
}

func TestResponseLevel_FailClosedString(t *testing.T) {
	if ResponseFailClosed.String() != "FAIL_CLOSED" {
		t.Fatalf("expected FAIL_CLOSED, got %s", ResponseFailClosed.String())
	}
}

func TestResponseLevel_UnknownString(t *testing.T) {
	unknown := ResponseLevel(99)
	s := unknown.String()
	if s != "UNKNOWN(99)" {
		t.Fatalf("expected UNKNOWN(99), got %s", s)
	}
}

func TestTemporalGuardian_InitialLevelObserve(t *testing.T) {
	c := newTestClock()
	tg := NewTemporalGuardian(DefaultEscalationPolicy(), c)
	if tg.CurrentLevel() != ResponseObserve {
		t.Fatalf("expected OBSERVE, got %s", tg.CurrentLevel())
	}
}

func TestTemporalGuardian_EvaluateAllowsAtObserve(t *testing.T) {
	c := newTestClock()
	tg := NewTemporalGuardian(DefaultEscalationPolicy(), c)
	resp := tg.Evaluate(context.Background())
	if !resp.AllowEffect {
		t.Fatal("effects should be allowed at OBSERVE level")
	}
}

func TestTemporalGuardian_HoldDurationZeroAtObserve(t *testing.T) {
	c := newTestClock()
	tg := NewTemporalGuardian(DefaultEscalationPolicy(), c)
	resp := tg.Evaluate(context.Background())
	if resp.Duration != 0 {
		t.Fatalf("expected 0 hold at OBSERVE, got %v", resp.Duration)
	}
}

func TestControllabilityEnvelope_EmptyRate(t *testing.T) {
	c := newTestClock()
	env := NewControllabilityEnvelope(60*time.Second, c)
	if env.Rate() != 0.0 {
		t.Fatalf("expected 0 rate for empty envelope, got %f", env.Rate())
	}
}

// ─── 41-50: Audit Log ───────────────────────────────────────────

func TestNewAuditLog_EmptyEntries(t *testing.T) {
	al := NewAuditLog()
	if len(al.Entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(al.Entries))
	}
}

func TestAuditLog_AppendOne(t *testing.T) {
	al := NewAuditLog()
	entry, err := al.Append("actor", "ACTION", "target", "details")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry.Actor != "actor" || entry.Action != "ACTION" {
		t.Fatal("fields not stored")
	}
}

func TestAuditLog_GenesisNoPreviousHash(t *testing.T) {
	al := NewAuditLog()
	entry, _ := al.Append("a", "b", "c", "d")
	if entry.PreviousHash != "" {
		t.Fatal("genesis entry should have empty previous hash")
	}
}

func TestAuditLog_ChainLinking(t *testing.T) {
	al := NewAuditLog()
	e1, _ := al.Append("a", "b", "c", "d")
	e2, _ := al.Append("a", "b", "c", "d")
	if e2.PreviousHash != e1.Hash {
		t.Fatal("second entry should reference first entry's hash")
	}
}

func TestAuditLog_VerifyChainEmpty(t *testing.T) {
	al := NewAuditLog()
	valid, err := al.VerifyChain()
	if err != nil || !valid {
		t.Fatal("empty chain should verify")
	}
}

func TestAuditLog_VerifyChainSingle(t *testing.T) {
	al := NewAuditLog()
	al.Append("a", "b", "c", "d")
	valid, err := al.VerifyChain()
	if err != nil || !valid {
		t.Fatal("single entry chain should verify")
	}
}

func TestAuditLog_VerifyChainMultiple(t *testing.T) {
	al := NewAuditLog()
	for i := 0; i < 5; i++ {
		al.Append("a", "b", "c", "d")
	}
	valid, err := al.VerifyChain()
	if err != nil || !valid {
		t.Fatal("multi-entry chain should verify")
	}
}

func TestAuditLog_TamperDetection(t *testing.T) {
	al := NewAuditLog()
	al.Append("a", "b", "c", "d")
	al.Append("a", "b", "c", "d")
	al.Entries[0].Details = "TAMPERED"
	valid, _ := al.VerifyChain()
	if valid {
		t.Fatal("tampered chain should not verify")
	}
}

func TestAuditLog_HashNonEmpty(t *testing.T) {
	al := NewAuditLog()
	entry, _ := al.Append("a", "b", "c", "d")
	if entry.Hash == "" {
		t.Fatal("hash should not be empty")
	}
}

func TestAuditLog_WithClock(t *testing.T) {
	c := newTestClock()
	al := NewAuditLog(c)
	entry, _ := al.Append("a", "b", "c", "d")
	if !entry.Timestamp.Equal(c.Now().UTC()) {
		t.Fatalf("expected timestamp from injected clock, got %v", entry.Timestamp)
	}
}

// ─── 51-57: Privilege tiers ─────────────────────────────────────

func TestPrivilegeTier_RestrictedString(t *testing.T) {
	if TierRestricted.String() != "RESTRICTED" {
		t.Fatalf("expected RESTRICTED, got %s", TierRestricted.String())
	}
}

func TestPrivilegeTier_StandardString(t *testing.T) {
	if TierStandard.String() != "STANDARD" {
		t.Fatalf("expected STANDARD, got %s", TierStandard.String())
	}
}

func TestPrivilegeTier_ElevatedString(t *testing.T) {
	if TierElevated.String() != "ELEVATED" {
		t.Fatalf("expected ELEVATED, got %s", TierElevated.String())
	}
}

func TestPrivilegeTier_SystemString(t *testing.T) {
	if TierSystem.String() != "SYSTEM" {
		t.Fatalf("expected SYSTEM, got %s", TierSystem.String())
	}
}

func TestPrivilegeTier_UnknownString(t *testing.T) {
	unknown := PrivilegeTier(99)
	if unknown.String() != "UNKNOWN(99)" {
		t.Fatalf("expected UNKNOWN(99), got %s", unknown.String())
	}
}

func TestRequiredTierForEffect_KnownEffect(t *testing.T) {
	tier := RequiredTierForEffect("SEND_EMAIL")
	if tier != TierStandard {
		t.Fatalf("expected STANDARD for SEND_EMAIL, got %s", tier.String())
	}
}

func TestRequiredTierForEffect_ElevatedEffect(t *testing.T) {
	tier := RequiredTierForEffect("SOFTWARE_PUBLISH")
	if tier != TierElevated {
		t.Fatalf("expected ELEVATED for SOFTWARE_PUBLISH, got %s", tier.String())
	}
}

func TestRequiredTierForEffect_SystemEffect(t *testing.T) {
	tier := RequiredTierForEffect("INFRA_DESTROY")
	if tier != TierSystem {
		t.Fatalf("expected SYSTEM for INFRA_DESTROY, got %s", tier.String())
	}
}

func TestRequiredTierForEffect_UnknownDefaultsStandard(t *testing.T) {
	tier := RequiredTierForEffect("NONEXISTENT_EFFECT")
	if tier != TierStandard {
		t.Fatalf("expected STANDARD for unknown effect, got %s", tier.String())
	}
}

func TestEffectiveTier_HostileForcesRestricted(t *testing.T) {
	result := EffectiveTier(TierSystem, trust.TierHostile)
	if result != TierRestricted {
		t.Fatalf("expected RESTRICTED under HOSTILE, got %s", result.String())
	}
}

func TestEffectiveTier_SuspectCapsAtStandard(t *testing.T) {
	result := EffectiveTier(TierElevated, trust.TierSuspect)
	if result != TierStandard {
		t.Fatalf("expected STANDARD cap under SUSPECT, got %s", result.String())
	}
}

func TestEffectiveTier_SuspectNoUpgrade(t *testing.T) {
	result := EffectiveTier(TierRestricted, trust.TierSuspect)
	if result != TierRestricted {
		t.Fatalf("expected RESTRICTED unchanged under SUSPECT, got %s", result.String())
	}
}

func TestEffectiveTier_NeutralNoChange(t *testing.T) {
	result := EffectiveTier(TierElevated, trust.TierNeutral)
	if result != TierElevated {
		t.Fatalf("expected ELEVATED unchanged under NEUTRAL, got %s", result.String())
	}
}

func TestEffectiveTier_TrustedNoChange(t *testing.T) {
	result := EffectiveTier(TierSystem, trust.TierTrusted)
	if result != TierSystem {
		t.Fatalf("expected SYSTEM unchanged under TRUSTED, got %s", result.String())
	}
}

// ─── 58-60: recordBehavioralEvent ───────────────────────────────

func TestRecordBehavioralEvent_NilScorer(t *testing.T) {
	g := newMinimalGuardian()
	// Should not panic when scorer is nil.
	g.recordBehavioralEvent("agent-1", trust.EventPolicyComply, "ok")
}

func TestRecordBehavioralEvent_EmptyPrincipal(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	g := newMinimalGuardian(WithBehavioralTrustScorer(scorer))
	g.recordBehavioralEvent("", trust.EventPolicyComply, "ok")
	// Empty principal should be a no-op; scorer should have no entries.
	score := scorer.GetScore("")
	if len(score.History) != 0 {
		t.Fatal("empty principal should not record events")
	}
}

func TestRecordBehavioralEvent_RecordsEvent(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	g := newMinimalGuardian(WithBehavioralTrustScorer(scorer))
	g.recordBehavioralEvent("agent-1", trust.EventPolicyComply, "test compliance")
	score := scorer.GetScore("agent-1")
	if len(score.History) != 1 {
		t.Fatalf("expected 1 event recorded, got %d", len(score.History))
	}
}
