package a2a

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/trust"
)

// ── Envelope Hash Collision Resistance ──────────────────────

func TestEnvelopeHash_DiffersOnEnvelopeID(t *testing.T) {
	a := &Envelope{EnvelopeID: "id-1", PayloadHash: "same"}
	b := &Envelope{EnvelopeID: "id-2", PayloadHash: "same"}
	if ComputeEnvelopeHash(a) == ComputeEnvelopeHash(b) {
		t.Error("different envelope IDs must produce different hashes")
	}
}

func TestEnvelopeHash_DiffersOnOriginAgent(t *testing.T) {
	a := &Envelope{EnvelopeID: "e", OriginAgentID: "agent-a"}
	b := &Envelope{EnvelopeID: "e", OriginAgentID: "agent-b"}
	if ComputeEnvelopeHash(a) == ComputeEnvelopeHash(b) {
		t.Error("different origin agents must produce different hashes")
	}
}

func TestEnvelopeHash_DiffersOnTargetAgent(t *testing.T) {
	a := &Envelope{EnvelopeID: "e", TargetAgentID: "x"}
	b := &Envelope{EnvelopeID: "e", TargetAgentID: "y"}
	if ComputeEnvelopeHash(a) == ComputeEnvelopeHash(b) {
		t.Error("different target agents must produce different hashes")
	}
}

func TestEnvelopeHash_DiffersOnSchemaVersion(t *testing.T) {
	a := &Envelope{EnvelopeID: "e", SchemaVersion: SchemaVersion{1, 0, 0}}
	b := &Envelope{EnvelopeID: "e", SchemaVersion: SchemaVersion{2, 0, 0}}
	if ComputeEnvelopeHash(a) == ComputeEnvelopeHash(b) {
		t.Error("different schema versions must produce different hashes")
	}
}

// ── SchemaVersion Comparison ────────────────────────────────

func TestSchemaVersion_StringZeroValue(t *testing.T) {
	v := SchemaVersion{}
	if v.String() != "0.0.0" {
		t.Errorf("zero SchemaVersion should be 0.0.0, got %s", v.String())
	}
}

func TestSchemaVersion_PatchDifference(t *testing.T) {
	a := SchemaVersion{1, 0, 0}
	b := SchemaVersion{1, 0, 1}
	if a.String() == b.String() {
		t.Error("different patch versions should produce different strings")
	}
}

// ── Feature Negotiation with All Feature Types ──────────────

func TestNegotiate_AllFeatureTypesOffered(t *testing.T) {
	v := NewDefaultVerifier()
	all := []Feature{
		FeatureMeteringReceipts, FeatureDisputeReplay, FeatureProofGraphSync,
		FeatureEvidenceExport, FeaturePolicyNegotiation, FeatureAgentPayments,
		FeatureIATPAuth, FeaturePeerVouching, FeatureTrustPropagation,
	}
	env := &Envelope{SchemaVersion: CurrentVersion, OfferedFeatures: all}
	result, _ := v.Negotiate(context.Background(), env, all)
	if !result.Accepted || len(result.AgreedFeatures) != len(all) {
		t.Errorf("expected all %d features agreed, got %d", len(all), len(result.AgreedFeatures))
	}
}

func TestNegotiate_PolicyDenyBlocksFeature(t *testing.T) {
	v := NewDefaultVerifier()
	v.AddPolicyRule(PolicyRule{
		RuleID: "r1", OriginAgent: "*", TargetAgent: "*",
		DeniedFeatures: []Feature{FeatureAgentPayments}, Action: PolicyDeny,
	})
	env := &Envelope{SchemaVersion: CurrentVersion, OriginAgentID: "a", TargetAgentID: "b",
		RequiredFeatures: []Feature{FeatureAgentPayments}}
	result, _ := v.Negotiate(context.Background(), env, []Feature{FeatureAgentPayments})
	if result.Accepted {
		t.Error("policy deny rule should block feature")
	}
	if result.DenyReason != DenyPolicyViolation {
		t.Errorf("expected POLICY_VIOLATION, got %s", result.DenyReason)
	}
}

func TestNegotiate_PartialFeatureIntersection(t *testing.T) {
	v := NewDefaultVerifier()
	env := &Envelope{
		SchemaVersion:   CurrentVersion,
		OfferedFeatures: []Feature{FeatureEvidenceExport, FeatureIATPAuth},
	}
	result, _ := v.Negotiate(context.Background(), env, []Feature{FeatureIATPAuth, FeaturePeerVouching})
	if len(result.AgreedFeatures) != 1 || result.AgreedFeatures[0] != FeatureIATPAuth {
		t.Errorf("expected only IATP_AUTH agreed, got %v", result.AgreedFeatures)
	}
}

// ── IATP Concurrent Sessions ────────────────────────────────

func TestIATP_ConcurrentChallengeCreation(t *testing.T) {
	signer, _ := crypto.NewEd25519Signer("k1")
	auth := NewIATPAuthenticator(signer)
	var wg sync.WaitGroup
	errs := make(chan error, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ch, err := auth.CreateChallenge(fmt.Sprintf("remote-%d", idx))
			if err != nil || ch == nil {
				errs <- fmt.Errorf("challenge %d failed: %v", idx, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestIATP_NonceReplayRejected(t *testing.T) {
	signer, _ := crypto.NewEd25519Signer("k1")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	auth := NewIATPAuthenticator(signer).WithClock(func() time.Time { return now })
	ch, _ := auth.CreateChallenge("remote")
	resp, _ := auth.RespondToChallenge(ch)
	alwaysValid := func(_, _, _ string) bool { return true }
	_, _ = auth.VerifyResponse(ch, resp, alwaysValid)
	_, err := auth.VerifyResponse(ch, resp, alwaysValid)
	if err == nil {
		t.Error("nonce replay should be rejected on second verify")
	}
}

func TestIATP_GetSessionAfterAuth(t *testing.T) {
	signer, _ := crypto.NewEd25519Signer("k1")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	auth := NewIATPAuthenticator(signer).WithClock(func() time.Time { return now })
	ch, _ := auth.CreateChallenge("remote")
	resp, _ := auth.RespondToChallenge(ch)
	sess, _ := auth.VerifyResponse(ch, resp, func(_, _, _ string) bool { return true })
	retrieved, ok := auth.GetSession(sess.SessionID)
	if !ok || retrieved.Status != IATPAuthenticated {
		t.Error("authenticated session should be retrievable")
	}
}

func TestIATP_ExpiredChallengeResponse(t *testing.T) {
	signer, _ := crypto.NewEd25519Signer("k1")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	auth := NewIATPAuthenticator(signer).WithClock(func() time.Time { return now })
	ch, _ := auth.CreateChallenge("remote")
	auth.clock = func() time.Time { return now.Add(time.Second) }
	_, err := auth.RespondToChallenge(ch)
	if err == nil {
		t.Error("responding to an expired challenge should fail")
	}
}

// ── Vouching with Max Exposure Limits ───────────────────────

func TestVouch_MaxExposureCapsSlashPenalty(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	signer, _ := crypto.NewEd25519Signer("k1")
	engine := NewVouchingEngine(scorer)
	rec, _ := engine.Vouch("voucher", "vouchee", []string{"read"}, 50, time.Hour, signer)
	rec.MaxExposure = 10
	result, err := engine.Slash(rec.VouchID, "test")
	if err != nil {
		t.Fatal(err)
	}
	if result.VoucherPenalty != 10 {
		t.Errorf("voucher penalty should be capped at MaxExposure=10, got %d", result.VoucherPenalty)
	}
}

func TestVouch_ActiveVouchesExcludeExpired(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	signer, _ := crypto.NewEd25519Signer("k1")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	engine := NewVouchingEngine(scorer).WithClock(func() time.Time { return now })
	_, _ = engine.Vouch("a", "b", []string{"r"}, 5, time.Minute, signer)
	engine.clock = func() time.Time { return now.Add(2 * time.Minute) }
	actives := engine.ActiveVouches("a")
	if len(actives) != 0 {
		t.Errorf("expired vouch should not appear in active list, got %d", len(actives))
	}
}

func TestVouch_IsVouchedForCapability(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	signer, _ := crypto.NewEd25519Signer("k1")
	engine := NewVouchingEngine(scorer)
	_, _ = engine.Vouch("a", "b", []string{"read", "write"}, 5, time.Hour, signer)
	if !engine.IsVouchedFor("b", "write") {
		t.Error("vouchee should be vouched for 'write'")
	}
	if engine.IsVouchedFor("b", "delete") {
		t.Error("vouchee should not be vouched for 'delete'")
	}
}

func TestVouch_NegativeTTLRejected(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	signer, _ := crypto.NewEd25519Signer("k1")
	engine := NewVouchingEngine(scorer)
	_, err := engine.Vouch("a", "b", []string{"r"}, 5, -time.Second, signer)
	if err == nil {
		t.Error("negative TTL should be rejected")
	}
}

// ── Trust Propagation Diamond Pattern ───────────────────────

func TestPropagation_DiamondPattern(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	signer, _ := crypto.NewEd25519Signer("k1")
	engine := NewVouchingEngine(scorer)
	// Diamond: A→B, A→C, B→D, C→D
	_, _ = engine.Vouch("A", "B", []string{"r"}, 5, time.Hour, signer)
	_, _ = engine.Vouch("A", "C", []string{"r"}, 5, time.Hour, signer)
	_, _ = engine.Vouch("B", "D", []string{"r"}, 5, time.Hour, signer)
	_, _ = engine.Vouch("C", "D", []string{"r"}, 5, time.Hour, signer)
	prop := NewTrustPropagator(scorer, engine)
	score, paths, err := prop.PropagatedScore("A", "D")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 {
		t.Errorf("diamond pattern should produce 2 paths, got %d", len(paths))
	}
	if score < 1 {
		t.Error("propagated score should be positive")
	}
}

func TestVerifySignature_InactiveKeyReturnsFalse(t *testing.T) {
	v := NewDefaultVerifier()
	v.RegisterKey(TrustedKey{KeyID: "k1", AgentID: "a", Algorithm: "ed25519", Active: false})
	env := &Envelope{Signature: Signature{KeyID: "k1", Algorithm: "ed25519", Value: "val", AgentID: "a"}, OriginAgentID: "a"}
	ok, _ := v.VerifySignature(context.Background(), env)
	if ok {
		t.Error("inactive key should return false")
	}
}

func TestPropagation_MaxHopsRespected(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	signer, _ := crypto.NewEd25519Signer("k1")
	engine := NewVouchingEngine(scorer)
	// Chain: A→B→C→D→E (4 hops, MaxHops default is 3)
	_, _ = engine.Vouch("A", "B", []string{"r"}, 5, time.Hour, signer)
	_, _ = engine.Vouch("B", "C", []string{"r"}, 5, time.Hour, signer)
	_, _ = engine.Vouch("C", "D", []string{"r"}, 5, time.Hour, signer)
	_, _ = engine.Vouch("D", "E", []string{"r"}, 5, time.Hour, signer)
	prop := NewTrustPropagator(scorer, engine)
	_, paths, _ := prop.PropagatedScore("A", "E")
	if len(paths) != 0 {
		t.Errorf("4-hop chain should exceed MaxHops=3, got %d paths", len(paths))
	}
}
