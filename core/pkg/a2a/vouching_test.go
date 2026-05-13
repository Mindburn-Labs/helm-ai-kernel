package a2a

import (
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/trust"
)

func newTestScorer(clock trust.BehavioralClock) *trust.BehavioralTrustScorer {
	return trust.NewBehavioralTrustScorer(
		trust.WithBehavioralClock(clock),
		trust.WithScorerConfig(trust.ScorerConfig{
			InitialScore:     500,
			MaxHistorySize:   100,
			PositiveHalfLife: 24 * time.Hour,
			NegativeHalfLife: 72 * time.Hour,
		}),
	)
}

type fixedClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fixedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fixedClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

func TestVouchingEngine_Vouch(t *testing.T) {
	clk := &fixedClock{t: time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)}
	scorer := newTestScorer(clk)
	engine := NewVouchingEngine(scorer).WithClock(clk.Now)

	signer, err := crypto.NewEd25519Signer("voucher-key")
	if err != nil {
		t.Fatal(err)
	}

	vouch, err := engine.Vouch("agent-alpha", "agent-beta", []string{"file:read", "api:call"}, 50, 1*time.Hour, signer)
	if err != nil {
		t.Fatal(err)
	}

	if vouch.VouchID == "" {
		t.Fatal("expected non-empty vouch ID")
	}
	if vouch.Voucher != "agent-alpha" {
		t.Fatalf("expected voucher agent-alpha, got %s", vouch.Voucher)
	}
	if vouch.Vouchee != "agent-beta" {
		t.Fatalf("expected vouchee agent-beta, got %s", vouch.Vouchee)
	}
	if vouch.Stake != 50 {
		t.Fatalf("expected stake 50, got %d", vouch.Stake)
	}
	if vouch.ContentHash == "" {
		t.Fatal("expected non-empty content hash")
	}
	if vouch.Signature == "" {
		t.Fatal("expected non-empty signature")
	}

	// Verify IsVouchedFor works.
	if !engine.IsVouchedFor("agent-beta", "file:read") {
		t.Fatal("expected agent-beta to be vouched for file:read")
	}
	if !engine.IsVouchedFor("agent-beta", "api:call") {
		t.Fatal("expected agent-beta to be vouched for api:call")
	}
	if engine.IsVouchedFor("agent-beta", "file:write") {
		t.Fatal("expected agent-beta NOT to be vouched for file:write")
	}
	if engine.IsVouchedFor("agent-gamma", "file:read") {
		t.Fatal("expected agent-gamma NOT to be vouched for file:read")
	}
}

func TestVouchingEngine_SelfVouchRejected(t *testing.T) {
	clk := &fixedClock{t: time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)}
	scorer := newTestScorer(clk)
	engine := NewVouchingEngine(scorer).WithClock(clk.Now)

	signer, err := crypto.NewEd25519Signer("key")
	if err != nil {
		t.Fatal(err)
	}

	_, err = engine.Vouch("agent-alpha", "agent-alpha", []string{"x"}, 10, time.Hour, signer)
	if err == nil {
		t.Fatal("expected error for self-vouch")
	}
}

func TestVouchingEngine_RevokeVouch(t *testing.T) {
	clk := &fixedClock{t: time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)}
	scorer := newTestScorer(clk)
	engine := NewVouchingEngine(scorer).WithClock(clk.Now)

	signer, err := crypto.NewEd25519Signer("key")
	if err != nil {
		t.Fatal(err)
	}

	vouch, err := engine.Vouch("agent-alpha", "agent-beta", []string{"file:read"}, 50, 1*time.Hour, signer)
	if err != nil {
		t.Fatal(err)
	}

	// Vouch is active before revocation.
	if !engine.IsVouchedFor("agent-beta", "file:read") {
		t.Fatal("expected vouch to be active before revocation")
	}

	err = engine.RevokeVouch(vouch.VouchID, "trust withdrawn")
	if err != nil {
		t.Fatal(err)
	}

	// Vouch should no longer be active.
	if engine.IsVouchedFor("agent-beta", "file:read") {
		t.Fatal("expected vouch to be inactive after revocation")
	}

	active := engine.ActiveVouches("agent-alpha")
	if len(active) != 0 {
		t.Fatalf("expected 0 active vouches after revocation, got %d", len(active))
	}
}

func TestVouchingEngine_Slash(t *testing.T) {
	clk := &fixedClock{t: time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)}
	scorer := newTestScorer(clk)
	engine := NewVouchingEngine(scorer).WithClock(clk.Now)

	signer, err := crypto.NewEd25519Signer("key")
	if err != nil {
		t.Fatal(err)
	}

	// Boost both agents above initial so we can see penalties.
	scorer.RecordEvent("agent-alpha", trust.ScoreEvent{
		EventType: trust.EventManualBoost,
		Delta:     100,
		Reason:    "test boost",
	})
	scorer.RecordEvent("agent-beta", trust.ScoreEvent{
		EventType: trust.EventManualBoost,
		Delta:     100,
		Reason:    "test boost",
	})

	alphaScoreBefore := scorer.GetScore("agent-alpha").Score
	betaScoreBefore := scorer.GetScore("agent-beta").Score

	vouch, err := engine.Vouch("agent-alpha", "agent-beta", []string{"file:read"}, 50, 1*time.Hour, signer)
	if err != nil {
		t.Fatal(err)
	}

	result, err := engine.Slash(vouch.VouchID, "data exfiltration attempt")
	if err != nil {
		t.Fatal(err)
	}

	if result.VoucherPenalty != 50 {
		t.Fatalf("expected voucher penalty 50, got %d", result.VoucherPenalty)
	}
	if result.VoucheePenalty != 25 { // DefaultDeltas[POLICY_VIOLATE] = -25
		t.Fatalf("expected vouchee penalty 25, got %d", result.VoucheePenalty)
	}

	alphaScoreAfter := scorer.GetScore("agent-alpha").Score
	betaScoreAfter := scorer.GetScore("agent-beta").Score

	if alphaScoreAfter >= alphaScoreBefore {
		t.Fatalf("expected voucher score to decrease: before=%d, after=%d", alphaScoreBefore, alphaScoreAfter)
	}
	if betaScoreAfter >= betaScoreBefore {
		t.Fatalf("expected vouchee score to decrease: before=%d, after=%d", betaScoreBefore, betaScoreAfter)
	}

	// Vouch should be revoked after slashing.
	if engine.IsVouchedFor("agent-beta", "file:read") {
		t.Fatal("expected vouch to be revoked after slashing")
	}
}

func TestVouchingEngine_MaxExposure(t *testing.T) {
	clk := &fixedClock{t: time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)}
	scorer := newTestScorer(clk)
	engine := NewVouchingEngine(scorer).WithClock(clk.Now)

	signer, err := crypto.NewEd25519Signer("key")
	if err != nil {
		t.Fatal(err)
	}

	vouch, err := engine.Vouch("agent-alpha", "agent-beta", []string{"x"}, 100, 1*time.Hour, signer)
	if err != nil {
		t.Fatal(err)
	}

	// Manually set a lower max exposure.
	engine.mu.Lock()
	vouch.MaxExposure = 30
	engine.mu.Unlock()

	result, err := engine.Slash(vouch.VouchID, "excess exposure test")
	if err != nil {
		t.Fatal(err)
	}

	if result.VoucherPenalty != 30 {
		t.Fatalf("expected voucher penalty capped at 30 (maxExposure), got %d", result.VoucherPenalty)
	}
}

func TestVouchingEngine_ExpiredVouch(t *testing.T) {
	clk := &fixedClock{t: time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)}
	scorer := newTestScorer(clk)
	engine := NewVouchingEngine(scorer).WithClock(clk.Now)

	signer, err := crypto.NewEd25519Signer("key")
	if err != nil {
		t.Fatal(err)
	}

	_, err = engine.Vouch("agent-alpha", "agent-beta", []string{"file:read"}, 50, 1*time.Second, signer)
	if err != nil {
		t.Fatal(err)
	}

	// Vouch is active at creation time.
	if !engine.IsVouchedFor("agent-beta", "file:read") {
		t.Fatal("expected vouch to be active immediately after creation")
	}

	// Advance clock past expiration.
	clk.Set(time.Date(2026, 4, 12, 10, 0, 2, 0, time.UTC))

	if engine.IsVouchedFor("agent-beta", "file:read") {
		t.Fatal("expected expired vouch to not be active")
	}

	active := engine.ActiveVouches("agent-alpha")
	if len(active) != 0 {
		t.Fatalf("expected 0 active vouches after expiration, got %d", len(active))
	}
}
