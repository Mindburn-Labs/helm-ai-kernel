package a2a

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/trust"
)

// ── 100 concurrent envelope creations ───────────────────────────────────

func TestStress_100ConcurrentEnvelopes(t *testing.T) {
	var wg sync.WaitGroup
	hashes := make([]string, 100)
	for i := range 100 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			env := &Envelope{
				EnvelopeID:    fmt.Sprintf("env-%d", idx),
				SchemaVersion: CurrentVersion,
				OriginAgentID: fmt.Sprintf("origin-%d", idx),
				TargetAgentID: fmt.Sprintf("target-%d", idx),
				PayloadHash:   "sha256:abc",
				CreatedAt:     time.Now(),
				ExpiresAt:     time.Now().Add(time.Hour),
			}
			SignEnvelope(env, "key-1", "ed25519", env.OriginAgentID)
			hashes[idx] = ComputeEnvelopeHash(env)
		}(i)
	}
	wg.Wait()
	for i, h := range hashes {
		if h == "" {
			t.Fatalf("empty hash at index %d", i)
		}
	}
}

// ── IATP 50 concurrent handshakes ───────────────────────────────────────

func TestStress_IATP50Handshakes(t *testing.T) {
	var wg sync.WaitGroup
	errs := make(chan error, 50)
	for i := range 50 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			signer, err := crypto.NewEd25519Signer(fmt.Sprintf("iatp-key-%d", idx))
			if err != nil {
				errs <- fmt.Errorf("signer %d: %w", idx, err)
				return
			}
			auth := NewIATPAuthenticator(signer)
			challenge, err := auth.CreateChallenge(fmt.Sprintf("remote-%d", idx))
			if err != nil {
				errs <- fmt.Errorf("create challenge %d: %w", idx, err)
				return
			}
			if challenge.ChallengeID == "" {
				errs <- fmt.Errorf("empty challenge ID at %d", idx)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	if len(errs) > 0 {
		t.Fatalf("got %d errors, first: %v", len(errs), <-errs)
	}
}

// ── Vouching: 20 agents in chain ────────────────────────────────────────

func TestStress_Vouching20AgentsChain(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	for i := range 20 {
		scorer.RecordEvent(fmt.Sprintf("agent-%d", i), trust.ScoreEvent{Delta: 200})
	}
	engine := NewVouchingEngine(scorer)
	signer, _ := crypto.NewEd25519Signer("vouch-key")
	for i := range 19 {
		voucher := fmt.Sprintf("agent-%d", i)
		vouchee := fmt.Sprintf("agent-%d", i+1)
		_, err := engine.Vouch(voucher, vouchee, []string{"read"}, 50, time.Hour, signer)
		if err != nil {
			t.Fatalf("vouch %d->%d: %v", i, i+1, err)
		}
	}
	vouches := engine.AllActiveVouchesFor("agent-10")
	if len(vouches) == 0 {
		t.Fatal("agent-10 should have active vouches")
	}
}

// ── Trust propagation: 50 agents graph ──────────────────────────────────

func TestStress_TrustPropagation50Agents(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	for i := range 50 {
		scorer.RecordEvent(fmt.Sprintf("a-%d", i), trust.ScoreEvent{Delta: 200})
	}
	engine := NewVouchingEngine(scorer)
	signer, _ := crypto.NewEd25519Signer("prop-key")
	// Create a chain: a-0 → a-1 → ... → a-49
	for i := range 49 {
		_, err := engine.Vouch(fmt.Sprintf("a-%d", i), fmt.Sprintf("a-%d", i+1), []string{"all"}, 30, time.Hour, signer)
		if err != nil {
			t.Fatalf("vouch %d: %v", i, err)
		}
	}
	propagator := NewTrustPropagator(scorer, engine)
	score, _, err := propagator.PropagatedScore("a-0", "a-3")
	if err != nil {
		t.Fatalf("propagation: %v", err)
	}
	if score <= 0 {
		t.Fatalf("propagated score should be positive, got %d", score)
	}
}

func TestStress_TrustPropagationDirectScore(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	scorer.RecordEvent("a", trust.ScoreEvent{Delta: 200})
	scorer.RecordEvent("b", trust.ScoreEvent{Delta: 300})
	engine := NewVouchingEngine(scorer)
	propagator := NewTrustPropagator(scorer, engine)
	score, _, err := propagator.PropagatedScore("a", "b")
	if err != nil {
		t.Fatalf("propagation: %v", err)
	}
	if score <= 0 {
		t.Fatal("direct score should be returned")
	}
}

// ── Slash all vouches in chain ──────────────────────────────────────────

func TestStress_SlashAllVouchesInChain(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	for i := range 5 {
		scorer.RecordEvent(fmt.Sprintf("s-%d", i), trust.ScoreEvent{Delta: 200})
	}
	engine := NewVouchingEngine(scorer)
	signer, _ := crypto.NewEd25519Signer("slash-key")
	var vouchIDs []string
	for i := range 4 {
		record, _ := engine.Vouch(
			fmt.Sprintf("s-%d", i), fmt.Sprintf("s-%d", i+1),
			[]string{"all"}, 25, time.Hour, signer,
		)
		vouchIDs = append(vouchIDs, record.VouchID)
	}
	for _, id := range vouchIDs {
		result, err := engine.Slash(id, "policy violation")
		if err != nil {
			t.Fatalf("slash %s: %v", id, err)
		}
		if result.VoucherPenalty == 0 && result.VoucheePenalty == 0 {
			t.Fatalf("penalties should be non-zero for %s", id)
		}
	}
}

// ── Feature negotiation: all 8 features ─────────────────────────────────

func TestStress_AllFeatures(t *testing.T) {
	features := []Feature{
		FeatureMeteringReceipts, FeatureDisputeReplay, FeatureProofGraphSync,
		FeatureEvidenceExport, FeaturePolicyNegotiation, FeatureAgentPayments,
		FeatureIATPAuth, FeaturePeerVouching,
	}
	for _, f := range features {
		if string(f) == "" {
			t.Fatal("feature should not be empty")
		}
	}
	if len(features) != 8 {
		t.Fatalf("expected 8 features, got %d", len(features))
	}
}

func TestStress_FeatureTrustPropagation(t *testing.T) {
	if FeatureTrustPropagation != "TRUST_PROPAGATION" {
		t.Fatalf("got %s", FeatureTrustPropagation)
	}
}

// ── Every DenyReason individually ───────────────────────────────────────

func TestStress_DenyVersionIncompatible(t *testing.T) {
	if DenyVersionIncompatible != "VERSION_INCOMPATIBLE" {
		t.Fatalf("got %s", DenyVersionIncompatible)
	}
}

func TestStress_DenyFeatureMissing(t *testing.T) {
	if DenyFeatureMissing != "FEATURE_MISSING" {
		t.Fatalf("got %s", DenyFeatureMissing)
	}
}

func TestStress_DenyPolicyViolation(t *testing.T) {
	if DenyPolicyViolation != "POLICY_VIOLATION" {
		t.Fatalf("got %s", DenyPolicyViolation)
	}
}

func TestStress_DenySignatureInvalid(t *testing.T) {
	if DenySignatureInvalid != "SIGNATURE_INVALID" {
		t.Fatalf("got %s", DenySignatureInvalid)
	}
}

func TestStress_DenyAgentNotTrusted(t *testing.T) {
	if DenyAgentNotTrusted != "AGENT_NOT_TRUSTED" {
		t.Fatalf("got %s", DenyAgentNotTrusted)
	}
}

func TestStress_DenyChallengeFailure(t *testing.T) {
	if DenyChallengeFailure != "CHALLENGE_FAILURE" {
		t.Fatalf("got %s", DenyChallengeFailure)
	}
}

func TestStress_DenyVouchRevoked(t *testing.T) {
	if DenyVouchRevoked != "VOUCH_REVOKED" {
		t.Fatalf("got %s", DenyVouchRevoked)
	}
}

// ── Envelope hash determinism ───────────────────────────────────────────

func TestStress_EnvelopeHashDeterministic(t *testing.T) {
	env := &Envelope{EnvelopeID: "det", SchemaVersion: CurrentVersion, OriginAgentID: "o", TargetAgentID: "t", PayloadHash: "p"}
	h1 := ComputeEnvelopeHash(env)
	h2 := ComputeEnvelopeHash(env)
	if h1 != h2 {
		t.Fatal("envelope hash should be deterministic")
	}
}

func TestStress_SignEnvelopeSetsSignature(t *testing.T) {
	env := &Envelope{EnvelopeID: "sig", SchemaVersion: CurrentVersion, OriginAgentID: "o", TargetAgentID: "t"}
	SignEnvelope(env, "k1", "ed25519", "o")
	if env.Signature.KeyID != "k1" {
		t.Fatal("signature key ID mismatch")
	}
	if env.Signature.Value == "" {
		t.Fatal("signature value empty")
	}
}

// ── Vouch self-vouch rejected ───────────────────────────────────────────

func TestStress_SelfVouchRejected(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	engine := NewVouchingEngine(scorer)
	signer, _ := crypto.NewEd25519Signer("sv-key")
	_, err := engine.Vouch("a1", "a1", []string{"all"}, 10, time.Hour, signer)
	if err == nil {
		t.Fatal("self-vouch should be rejected")
	}
}

// ── Vouch revocation ────────────────────────────────────────────────────

func TestStress_VouchRevocation(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	scorer.RecordEvent("v1", trust.ScoreEvent{Delta: 200})
	engine := NewVouchingEngine(scorer)
	signer, _ := crypto.NewEd25519Signer("rev-key")
	record, _ := engine.Vouch("v1", "v2", []string{"read"}, 20, time.Hour, signer)
	if err := engine.RevokeVouch(record.VouchID, "test"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := engine.RevokeVouch(record.VouchID, "again"); err == nil {
		t.Fatal("double revoke should fail")
	}
}

// ── Schema version ──────────────────────────────────────────────────────

func TestStress_SchemaVersionString(t *testing.T) {
	v := SchemaVersion{Major: 1, Minor: 2, Patch: 3}
	if v.String() != "1.2.3" {
		t.Fatalf("got %s", v.String())
	}
}

func TestStress_CurrentVersionMajor(t *testing.T) {
	if CurrentVersion.Major != 1 {
		t.Fatalf("expected major 1, got %d", CurrentVersion.Major)
	}
}

// ── Vouching negative stake ─────────────────────────────────────────────

func TestStress_VouchNegativeStake(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	engine := NewVouchingEngine(scorer)
	signer, _ := crypto.NewEd25519Signer("ns-key")
	_, err := engine.Vouch("a1", "a2", nil, -1, time.Hour, signer)
	if err == nil {
		t.Fatal("negative stake should fail")
	}
}

func TestStress_VouchZeroTTL(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	engine := NewVouchingEngine(scorer)
	signer, _ := crypto.NewEd25519Signer("zt-key")
	_, err := engine.Vouch("a1", "a2", nil, 10, 0, signer)
	if err == nil {
		t.Fatal("zero TTL should fail")
	}
}

// ── Policy rules ────────────────────────────────────────────────────────

func TestStress_PolicyActionConstants(t *testing.T) {
	if PolicyAllow != "ALLOW" || PolicyDeny != "DENY" {
		t.Fatal("policy action constants mismatch")
	}
}

func TestStress_IATPSessionStatus(t *testing.T) {
	if IATPPending != "PENDING" || IATPAuthenticated != "AUTHENTICATED" || IATPFailed != "FAILED" {
		t.Fatal("IATP status mismatch")
	}
}

func TestStress_VouchEmptyVoucher(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	engine := NewVouchingEngine(scorer)
	signer, _ := crypto.NewEd25519Signer("ev-key")
	_, err := engine.Vouch("", "a2", nil, 10, time.Hour, signer)
	if err == nil {
		t.Fatal("empty voucher should fail")
	}
}

func TestStress_VouchEmptyVouchee(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	engine := NewVouchingEngine(scorer)
	signer, _ := crypto.NewEd25519Signer("ev2-key")
	_, err := engine.Vouch("a1", "", nil, 10, time.Hour, signer)
	if err == nil {
		t.Fatal("empty vouchee should fail")
	}
}

func TestStress_VouchRecordContentHash(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	scorer.RecordEvent("vh", trust.ScoreEvent{Delta: 200})
	engine := NewVouchingEngine(scorer)
	signer, _ := crypto.NewEd25519Signer("ch-key")
	record, _ := engine.Vouch("vh", "vb", []string{"r"}, 10, time.Hour, signer)
	if record.ContentHash == "" {
		t.Fatal("vouch record should have content hash")
	}
}

func TestStress_VouchRecordSignature(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	scorer.RecordEvent("vs", trust.ScoreEvent{Delta: 200})
	engine := NewVouchingEngine(scorer)
	signer, _ := crypto.NewEd25519Signer("sig-key")
	record, _ := engine.Vouch("vs", "vb", []string{"r"}, 10, time.Hour, signer)
	if record.Signature == "" {
		t.Fatal("vouch record should be signed")
	}
}

func TestStress_RevokeNonexistent(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	engine := NewVouchingEngine(scorer)
	err := engine.RevokeVouch("nonexistent", "test")
	if err == nil {
		t.Fatal("revoking nonexistent vouch should fail")
	}
}

func TestStress_PropagationConfigDefaults(t *testing.T) {
	cfg := DefaultPropagationConfig()
	if cfg.DecayPerHop != 0.7 {
		t.Fatalf("expected 0.7, got %f", cfg.DecayPerHop)
	}
	if cfg.MaxHops != 3 {
		t.Fatalf("expected 3, got %d", cfg.MaxHops)
	}
	if cfg.MinScore != 400 {
		t.Fatalf("expected 400, got %d", cfg.MinScore)
	}
}

func TestStress_PropagationCustomConfig(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	engine := NewVouchingEngine(scorer)
	cfg := PropagationConfig{DecayPerHop: 0.5, MaxHops: 2, MinScore: 300}
	prop := NewTrustPropagator(scorer, engine, cfg)
	if prop == nil {
		t.Fatal("propagator should not be nil")
	}
}

func TestStress_VouchingEngineWithClock(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	engine := NewVouchingEngine(scorer).WithClock(func() time.Time { return fixed })
	scorer.RecordEvent("vc", trust.ScoreEvent{Delta: 200})
	signer, _ := crypto.NewEd25519Signer("wc-key")
	record, _ := engine.Vouch("vc", "vb", nil, 10, time.Hour, signer)
	if !record.CreatedAt.Equal(fixed) {
		t.Fatal("clock override not applied")
	}
}

func TestStress_IATPAuthenticatorAgentID(t *testing.T) {
	signer, _ := crypto.NewEd25519Signer("agent-id-key")
	auth := NewIATPAuthenticator(signer).WithAgentID("custom-id")
	if auth == nil {
		t.Fatal("auth should not be nil")
	}
}

func TestStress_IATPAuthenticatorSessionTTL(t *testing.T) {
	signer, _ := crypto.NewEd25519Signer("ttl-key")
	auth := NewIATPAuthenticator(signer).WithSessionTTL(30 * time.Minute)
	if auth.sessionTTL != 30*time.Minute {
		t.Fatal("session TTL not set")
	}
}

func TestStress_EnvelopeHashPrefix(t *testing.T) {
	env := &Envelope{EnvelopeID: "pfx", SchemaVersion: CurrentVersion, OriginAgentID: "o", TargetAgentID: "t", PayloadHash: "p"}
	h := ComputeEnvelopeHash(env)
	if len(h) < 10 {
		t.Fatal("hash should not be short")
	}
}

func TestStress_AllActiveVouchesForEmpty(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	engine := NewVouchingEngine(scorer)
	vouches := engine.AllActiveVouchesFor("unknown-agent")
	if len(vouches) != 0 {
		t.Fatal("unknown agent should have 0 vouches")
	}
}

func TestStress_SlashNonexistent(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	engine := NewVouchingEngine(scorer)
	_, err := engine.Slash("nonexistent", "reason")
	if err == nil {
		t.Fatal("slashing nonexistent vouch should fail")
	}
}

func TestStress_EnvelopeExpiresAt(t *testing.T) {
	env := &Envelope{EnvelopeID: "exp", ExpiresAt: time.Now().Add(time.Hour)}
	if env.ExpiresAt.IsZero() {
		t.Fatal("expires_at should be set")
	}
}

func TestStress_NegotiationResultFields(t *testing.T) {
	r := NegotiationResult{Accepted: true, AgreedFeatures: []Feature{FeatureIATPAuth}}
	if !r.Accepted || len(r.AgreedFeatures) != 1 {
		t.Fatal("negotiation result field mismatch")
	}
}
