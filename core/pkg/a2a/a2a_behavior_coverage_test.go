package a2a

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/trust"
)

// ── Envelope Creation ────────────────────────────────────────

func TestEnvelopeHash_Deterministic(t *testing.T) {
	env := &Envelope{EnvelopeID: "e1", SchemaVersion: CurrentVersion, OriginAgentID: "a", TargetAgentID: "b", PayloadHash: "ph1"}
	h1 := ComputeEnvelopeHash(env)
	h2 := ComputeEnvelopeHash(env)
	if h1 != h2 {
		t.Errorf("envelope hash not deterministic: %s vs %s", h1, h2)
	}
}

func TestEnvelopeHash_DiffersOnPayload(t *testing.T) {
	env1 := &Envelope{EnvelopeID: "e1", PayloadHash: "aaa"}
	env2 := &Envelope{EnvelopeID: "e1", PayloadHash: "bbb"}
	if ComputeEnvelopeHash(env1) == ComputeEnvelopeHash(env2) {
		t.Error("different payloads should produce different hashes")
	}
}

func TestSignEnvelope_SetsSignature(t *testing.T) {
	env := &Envelope{EnvelopeID: "e1", SchemaVersion: CurrentVersion, OriginAgentID: "a", TargetAgentID: "b"}
	SignEnvelope(env, "k1", "ed25519", "a")
	if env.Signature.KeyID != "k1" || env.Signature.AgentID != "a" {
		t.Errorf("SignEnvelope did not populate signature fields correctly")
	}
}

func TestSchemaVersion_String(t *testing.T) {
	v := SchemaVersion{Major: 2, Minor: 3, Patch: 4}
	if v.String() != "2.3.4" {
		t.Errorf("expected 2.3.4, got %s", v.String())
	}
}

// ── Feature Negotiation ──────────────────────────────────────

func TestNegotiate_RequiredFeatureMissing(t *testing.T) {
	v := NewDefaultVerifier()
	env := &Envelope{SchemaVersion: CurrentVersion, RequiredFeatures: []Feature{FeatureDisputeReplay}}
	result, err := v.Negotiate(context.Background(), env, []Feature{FeatureEvidenceExport})
	if err != nil || result.Accepted {
		t.Errorf("should deny when required feature missing")
	}
	if result.DenyReason != DenyFeatureMissing {
		t.Errorf("expected FEATURE_MISSING, got %s", result.DenyReason)
	}
}

func TestNegotiate_VersionMismatch(t *testing.T) {
	v := NewDefaultVerifier()
	env := &Envelope{SchemaVersion: SchemaVersion{Major: 99, Minor: 0, Patch: 0}}
	result, _ := v.Negotiate(context.Background(), env, nil)
	if result.Accepted {
		t.Error("should deny incompatible major version")
	}
}

func TestNegotiate_AllFeaturesAvailable(t *testing.T) {
	v := NewDefaultVerifier()
	env := &Envelope{
		SchemaVersion:    CurrentVersion,
		RequiredFeatures: []Feature{FeatureEvidenceExport},
		OfferedFeatures:  []Feature{FeatureEvidenceExport, FeatureProofGraphSync},
	}
	result, _ := v.Negotiate(context.Background(), env, []Feature{FeatureEvidenceExport, FeatureProofGraphSync})
	if !result.Accepted {
		t.Error("should accept when all required features available")
	}
	if len(result.AgreedFeatures) != 2 {
		t.Errorf("expected 2 agreed features, got %d", len(result.AgreedFeatures))
	}
}

func TestNegotiate_ExpiredEnvelope(t *testing.T) {
	past := time.Now().Add(-1 * time.Hour)
	v := NewDefaultVerifier()
	env := &Envelope{SchemaVersion: CurrentVersion, ExpiresAt: past}
	result, _ := v.Negotiate(context.Background(), env, nil)
	if result.Accepted {
		t.Error("should deny expired envelope")
	}
}

// ── IATP Session Management ─────────────────────────────────

func TestIATP_CreateChallengeNonceLength(t *testing.T) {
	signer, _ := crypto.NewEd25519Signer("k1")
	auth := NewIATPAuthenticator(signer)
	ch, err := auth.CreateChallenge("remote")
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Nonce) != 64 { // 32 bytes hex-encoded = 64 chars
		t.Errorf("nonce should be 64 hex chars, got %d", len(ch.Nonce))
	}
}

func TestIATP_RespondToNilChallenge(t *testing.T) {
	signer, _ := crypto.NewEd25519Signer("k1")
	auth := NewIATPAuthenticator(signer)
	_, err := auth.RespondToChallenge(nil)
	if err == nil {
		t.Error("responding to nil challenge should error")
	}
}

func TestIATP_SessionExpires(t *testing.T) {
	signer, _ := crypto.NewEd25519Signer("k1")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	auth := NewIATPAuthenticator(signer).WithClock(func() time.Time { return now }).WithSessionTTL(1 * time.Second)
	ch, _ := auth.CreateChallenge("remote")
	resp, _ := auth.RespondToChallenge(ch)
	sess, _ := auth.VerifyResponse(ch, resp, func(_, _, _ string) bool { return true })
	// Advance past session TTL
	auth.clock = func() time.Time { return now.Add(2 * time.Second) }
	_, ok := auth.GetSession(sess.SessionID)
	if ok {
		t.Error("expired session should not be returned")
	}
}

func TestIATP_FullHandshake(t *testing.T) {
	signer1, _ := crypto.NewEd25519Signer("k1")
	signer2, _ := crypto.NewEd25519Signer("k2")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	challenger := NewIATPAuthenticator(signer1).WithClock(func() time.Time { return now })
	responder := NewIATPAuthenticator(signer2).WithClock(func() time.Time { return now })
	ch, _ := challenger.CreateChallenge(responder.agentID)
	resp, _ := responder.RespondToChallenge(ch)
	verifier := func(pubKey, data, sig string) bool {
		dataBytes, _ := hex.DecodeString(data)
		ok, _ := crypto.Verify(pubKey, sig, dataBytes)
		return ok
	}
	sess, err := challenger.VerifyResponse(ch, resp, verifier)
	if err != nil || sess.Status != IATPAuthenticated {
		t.Errorf("full handshake should succeed, got status=%s err=%v", sess.Status, err)
	}
}

// ── Vouching Edge Cases ──────────────────────────────────────

func TestVouch_SelfVouchRejected(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	signer, _ := crypto.NewEd25519Signer("k1")
	engine := NewVouchingEngine(scorer)
	_, err := engine.Vouch("agent-a", "agent-a", []string{"read"}, 10, time.Hour, signer)
	if err == nil {
		t.Error("self-vouch should be rejected")
	}
}

func TestVouch_ZeroStakeRejected(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	signer, _ := crypto.NewEd25519Signer("k1")
	engine := NewVouchingEngine(scorer)
	_, err := engine.Vouch("a", "b", []string{"read"}, 0, time.Hour, signer)
	if err == nil {
		t.Error("zero stake should be rejected")
	}
}

func TestVouch_RevokeNonexistent(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	engine := NewVouchingEngine(scorer)
	err := engine.RevokeVouch("nonexistent", "test")
	if err == nil {
		t.Error("revoking nonexistent vouch should error")
	}
}

func TestVouch_SlashAppliesPenalties(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	signer, _ := crypto.NewEd25519Signer("k1")
	engine := NewVouchingEngine(scorer)
	rec, _ := engine.Vouch("voucher", "vouchee", []string{"read"}, 20, time.Hour, signer)
	result, err := engine.Slash(rec.VouchID, "misbehavior")
	if err != nil {
		t.Fatal(err)
	}
	if result.VoucherPenalty != 20 {
		t.Errorf("voucher penalty should equal stake=20, got %d", result.VoucherPenalty)
	}
}

// ── Trust Propagation Paths ──────────────────────────────────

func TestPropagation_SelfScore(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	engine := NewVouchingEngine(scorer)
	prop := NewTrustPropagator(scorer, engine)
	score, paths, _ := prop.PropagatedScore("agent-a", "agent-a")
	if score != 500 {
		t.Errorf("self-propagation should return direct score=500, got %d", score)
	}
	if len(paths) != 0 {
		t.Errorf("self-propagation should have no paths, got %d", len(paths))
	}
}

func TestPropagation_NoVouchReturnsDirectScore(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	engine := NewVouchingEngine(scorer)
	prop := NewTrustPropagator(scorer, engine)
	score, _, _ := prop.PropagatedScore("a", "b")
	if score != 500 {
		t.Errorf("without vouches, should return direct score=500, got %d", score)
	}
}

func TestPropagation_DefaultConfigValues(t *testing.T) {
	cfg := DefaultPropagationConfig()
	if cfg.DecayPerHop != 0.7 || cfg.MaxHops != 3 || cfg.MinScore != 400 {
		t.Errorf("unexpected defaults: %+v", cfg)
	}
}

func TestVerifySignature_MissingKeyReturnsFalse(t *testing.T) {
	v := NewDefaultVerifier()
	env := &Envelope{Signature: Signature{KeyID: "unknown", Value: "val"}, OriginAgentID: "a"}
	ok, _ := v.VerifySignature(context.Background(), env)
	if ok {
		t.Error("should return false for unknown key")
	}
}
