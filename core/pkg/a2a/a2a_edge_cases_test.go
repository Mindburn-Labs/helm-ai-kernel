package a2a

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/trust"
)

// ── Envelope Tests ───────────────────────────────────────────────

func TestDeepEnvelopeHashDeterministic(t *testing.T) {
	env := &Envelope{
		EnvelopeID: "e1", OriginAgentID: "a1", TargetAgentID: "a2",
		SchemaVersion: CurrentVersion, PayloadHash: "ph1",
	}
	h1 := ComputeEnvelopeHash(env)
	h2 := ComputeEnvelopeHash(env)
	if h1 != h2 || h1 == "" {
		t.Fatal("envelope hash should be deterministic")
	}
}

func TestDeepEnvelopeHashDiffersOnChange(t *testing.T) {
	env1 := &Envelope{EnvelopeID: "e1", OriginAgentID: "a1", PayloadHash: "ph1", SchemaVersion: CurrentVersion}
	env2 := &Envelope{EnvelopeID: "e1", OriginAgentID: "a2", PayloadHash: "ph1", SchemaVersion: CurrentVersion}
	if ComputeEnvelopeHash(env1) == ComputeEnvelopeHash(env2) {
		t.Fatal("different origin agent should produce different hash")
	}
}

func TestDeepSignEnvelope(t *testing.T) {
	env := &Envelope{
		EnvelopeID: "e1", OriginAgentID: "a1", TargetAgentID: "a2",
		SchemaVersion: CurrentVersion, PayloadHash: "ph1",
	}
	SignEnvelope(env, "kid1", "ed25519", "a1")
	if env.Signature.KeyID != "kid1" || env.Signature.Algorithm != "ed25519" {
		t.Fatal("signature should be populated")
	}
	if env.Signature.Value == "" {
		t.Fatal("signature value should not be empty")
	}
}

func TestDeepEnvelopeWithAllFeatures(t *testing.T) {
	allFeatures := []Feature{
		FeatureMeteringReceipts, FeatureDisputeReplay, FeatureProofGraphSync,
		FeatureEvidenceExport, FeaturePolicyNegotiation, FeatureAgentPayments,
		FeatureIATPAuth, FeaturePeerVouching,
	}
	env := &Envelope{
		EnvelopeID: "e1", SchemaVersion: CurrentVersion,
		RequiredFeatures: allFeatures, OfferedFeatures: allFeatures,
	}
	if len(env.RequiredFeatures) != 8 || len(env.OfferedFeatures) != 8 {
		t.Fatal("should support all 8 features")
	}
}

func TestDeepSchemaVersionString(t *testing.T) {
	v := SchemaVersion{Major: 1, Minor: 2, Patch: 3}
	if v.String() != "1.2.3" {
		t.Fatalf("expected 1.2.3, got %s", v.String())
	}
}

// ── IATP Tests ───────────────────────────────────────────────────

func TestDeepIATPFullHandshake(t *testing.T) {
	signerA, _ := crypto.NewEd25519Signer("key-a")
	signerB, _ := crypto.NewEd25519Signer("key-b")
	authA := NewIATPAuthenticator(signerA).WithAgentID("agent-a")
	authB := NewIATPAuthenticator(signerB).WithAgentID("agent-b")
	challenge, err := authA.CreateChallenge("agent-b")
	if err != nil {
		t.Fatal(err)
	}
	response, err := authB.RespondToChallenge(challenge)
	if err != nil {
		t.Fatal(err)
	}
	session, err := authA.VerifyResponse(challenge, response, func(pubKey, data, sig string) bool {
		valid, _ := crypto.Verify(pubKey, sig, mustHexDecode(data))
		return valid
	})
	if err != nil || session.Status != IATPAuthenticated {
		t.Fatalf("handshake should succeed: %v", err)
	}
}

func TestDeepIATPNonceReplayRejected(t *testing.T) {
	signerA, _ := crypto.NewEd25519Signer("key-a")
	signerB, _ := crypto.NewEd25519Signer("key-b")
	authA := NewIATPAuthenticator(signerA).WithAgentID("agent-a")
	authB := NewIATPAuthenticator(signerB).WithAgentID("agent-b")
	challenge, _ := authA.CreateChallenge("agent-b")
	response, _ := authB.RespondToChallenge(challenge)
	verifier := func(pubKey, data, sig string) bool {
		valid, _ := crypto.Verify(pubKey, sig, mustHexDecode(data))
		return valid
	}
	authA.VerifyResponse(challenge, response, verifier)
	// Second attempt with same nonce should fail
	response2, _ := authB.RespondToChallenge(challenge)
	_, err := authA.VerifyResponse(challenge, response2, verifier)
	if err == nil {
		t.Fatal("nonce replay should be rejected")
	}
}

func TestDeepIATPExpiredChallenge(t *testing.T) {
	signerA, _ := crypto.NewEd25519Signer("key-a")
	signerB, _ := crypto.NewEd25519Signer("key-b")
	now := time.Now()
	authA := NewIATPAuthenticator(signerA).WithClock(func() time.Time { return now })
	authB := NewIATPAuthenticator(signerB).WithClock(func() time.Time { return now.Add(1 * time.Second) })
	challenge, _ := authA.CreateChallenge("agent-b")
	_, err := authB.RespondToChallenge(challenge)
	if err == nil {
		t.Fatal("expired challenge should be rejected")
	}
}

func TestDeepIATPNilChallenge(t *testing.T) {
	signerA, _ := crypto.NewEd25519Signer("key-a")
	authA := NewIATPAuthenticator(signerA)
	_, err := authA.RespondToChallenge(nil)
	if err == nil {
		t.Fatal("nil challenge should error")
	}
}

func TestDeepIATPVerifyNilArgs(t *testing.T) {
	signerA, _ := crypto.NewEd25519Signer("key-a")
	authA := NewIATPAuthenticator(signerA)
	_, err := authA.VerifyResponse(nil, nil, nil)
	if err == nil {
		t.Fatal("nil args should error")
	}
}

func TestDeepIATPChallengeIDMismatch(t *testing.T) {
	signerA, _ := crypto.NewEd25519Signer("key-a")
	authA := NewIATPAuthenticator(signerA)
	challenge, _ := authA.CreateChallenge("agent-b")
	response := &ChallengeResponse{ChallengeID: "wrong-id"}
	_, err := authA.VerifyResponse(challenge, response, func(_, _, _ string) bool { return true })
	if err == nil {
		t.Fatal("mismatched challenge ID should error")
	}
}

func TestDeepIATPSessionExpiry(t *testing.T) {
	signerA, _ := crypto.NewEd25519Signer("key-a")
	now := time.Now()
	authA := NewIATPAuthenticator(signerA).
		WithSessionTTL(1 * time.Millisecond).
		WithClock(func() time.Time { return now })
	// Manually store a session that's already expired
	session := &IATPSession{
		SessionID: "sess-1", Status: IATPAuthenticated,
		ExpiresAt: now.Add(-1 * time.Second),
	}
	authA.sessions.Store("sess-1", session)
	_, ok := authA.GetSession("sess-1")
	if ok {
		t.Fatal("expired session should not be returned")
	}
}

func TestDeepIATPConcurrentHandshakes(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			signerA, _ := crypto.NewEd25519Signer(fmt.Sprintf("ka-%d", idx))
			signerB, _ := crypto.NewEd25519Signer(fmt.Sprintf("kb-%d", idx))
			authA := NewIATPAuthenticator(signerA)
			authB := NewIATPAuthenticator(signerB)
			ch, _ := authA.CreateChallenge("b")
			resp, _ := authB.RespondToChallenge(ch)
			authA.VerifyResponse(ch, resp, func(pubKey, data, sig string) bool {
				valid, _ := crypto.Verify(pubKey, sig, mustHexDecode(data))
				return valid
			})
		}(i)
	}
	wg.Wait()
}

// ── Vouching Tests ───────────────────────────────────────────────

func TestDeepVouchCreateAndSlash(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	engine := NewVouchingEngine(scorer)
	signer, _ := crypto.NewEd25519Signer("key-v")
	vouch, err := engine.Vouch("A", "B", []string{"read"}, 50, 1*time.Hour, signer)
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Slash(vouch.VouchID, "violation")
	if err != nil {
		t.Fatal(err)
	}
	if result.VoucherPenalty != 50 {
		t.Fatalf("voucher penalty should be 50, got %d", result.VoucherPenalty)
	}
}

func TestDeepVouchSelfVouchRejected(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	engine := NewVouchingEngine(scorer)
	signer, _ := crypto.NewEd25519Signer("key-v")
	_, err := engine.Vouch("A", "A", []string{"read"}, 10, 1*time.Hour, signer)
	if err == nil {
		t.Fatal("self-vouch should be rejected")
	}
}

func TestDeepVouchZeroStake(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	engine := NewVouchingEngine(scorer)
	signer, _ := crypto.NewEd25519Signer("key-v")
	_, err := engine.Vouch("A", "B", nil, 0, 1*time.Hour, signer)
	if err == nil {
		t.Fatal("zero stake should be rejected")
	}
}

func TestDeepVouchRevoke(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	engine := NewVouchingEngine(scorer)
	signer, _ := crypto.NewEd25519Signer("key-v")
	vouch, _ := engine.Vouch("A", "B", []string{"read"}, 10, 1*time.Hour, signer)
	if err := engine.RevokeVouch(vouch.VouchID, "test"); err != nil {
		t.Fatal(err)
	}
	if engine.IsVouchedFor("B", "read") {
		t.Fatal("revoked vouch should not count")
	}
}

func TestDeepVouchCascadingSlash(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	engine := NewVouchingEngine(scorer)
	signer, _ := crypto.NewEd25519Signer("key-v")
	vouchAB, _ := engine.Vouch("A", "B", []string{"ops"}, 30, 1*time.Hour, signer)
	vouchBC, _ := engine.Vouch("B", "C", []string{"ops"}, 20, 1*time.Hour, signer)
	// C violates → slash B-C vouch, then A-B vouch
	engine.Slash(vouchBC.VouchID, "C violated")
	engine.Slash(vouchAB.VouchID, "cascading from C violation")
	scoreA := scorer.GetScore("A")
	scoreB := scorer.GetScore("B")
	scoreC := scorer.GetScore("C")
	if scoreA.Score >= 500 || scoreB.Score >= 500 || scoreC.Score >= 500 {
		t.Fatal("all agents in vouch chain should be penalized")
	}
}

func TestDeepVouchExpiry(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	now := time.Now()
	engine := NewVouchingEngine(scorer).WithClock(func() time.Time { return now.Add(2 * time.Hour) })
	signer, _ := crypto.NewEd25519Signer("key-v")
	engine.clock = func() time.Time { return now } // back to now for vouch creation
	engine.Vouch("A", "B", []string{"read"}, 10, 1*time.Hour, signer)
	engine.clock = func() time.Time { return now.Add(2 * time.Hour) }
	if engine.IsVouchedFor("B", "read") {
		t.Fatal("expired vouch should not count")
	}
}

// ── Trust Propagation Tests ──────────────────────────────────────

func TestDeepTrustPropagationDirectScore(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	engine := NewVouchingEngine(scorer)
	prop := NewTrustPropagator(scorer, engine)
	score, _, _ := prop.PropagatedScore("A", "A")
	if score != 500 {
		t.Fatalf("self-score should be initial (500), got %d", score)
	}
}

func TestDeepTrustPropagation3HopMax(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	engine := NewVouchingEngine(scorer)
	signer, _ := crypto.NewEd25519Signer("key-v")
	// Chain: A -> B -> C -> D -> E (4 hops, exceeds max 3)
	engine.Vouch("A", "B", []string{"ops"}, 10, 1*time.Hour, signer)
	engine.Vouch("B", "C", []string{"ops"}, 10, 1*time.Hour, signer)
	engine.Vouch("C", "D", []string{"ops"}, 10, 1*time.Hour, signer)
	engine.Vouch("D", "E", []string{"ops"}, 10, 1*time.Hour, signer)
	prop := NewTrustPropagator(scorer, engine)
	_, paths, _ := prop.PropagatedScore("A", "E")
	if len(paths) != 0 {
		t.Fatal("4-hop path should not be reachable with MaxHops=3")
	}
}

func TestDeepTrustPropagation10AgentChain(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	engine := NewVouchingEngine(scorer)
	signer, _ := crypto.NewEd25519Signer("key-v")
	// Build chain: agent-0 -> agent-1 -> ... -> agent-9
	for i := 0; i < 9; i++ {
		engine.Vouch(fmt.Sprintf("agent-%d", i), fmt.Sprintf("agent-%d", i+1), []string{"ops"}, 10, 1*time.Hour, signer)
	}
	prop := NewTrustPropagator(scorer, engine)
	// 3-hop max: agent-0 can reach agent-3 but not agent-4+
	_, paths, _ := prop.PropagatedScore("agent-0", "agent-3")
	if len(paths) != 1 {
		t.Fatalf("expected 1 path to agent-3, got %d", len(paths))
	}
	_, paths, _ = prop.PropagatedScore("agent-0", "agent-4")
	if len(paths) != 0 {
		t.Fatal("agent-4 should not be reachable at max 3 hops")
	}
}

func TestDeepTrustPropagationDecay(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	engine := NewVouchingEngine(scorer)
	signer, _ := crypto.NewEd25519Signer("key-v")
	engine.Vouch("A", "B", []string{"ops"}, 10, 1*time.Hour, signer)
	engine.Vouch("B", "C", []string{"ops"}, 10, 1*time.Hour, signer)
	cfg := DefaultPropagationConfig()
	prop := NewTrustPropagator(scorer, engine, cfg)
	score, paths, _ := prop.PropagatedScore("A", "C")
	if len(paths) != 1 {
		t.Fatal("expected 1 path")
	}
	// 2 hops: 500 * 0.7^2 ≈ 245 (rounding may vary ±1)
	if paths[0].FinalScore < 243 || paths[0].FinalScore > 246 {
		t.Fatalf("expected decayed score ~245, got %d", paths[0].FinalScore)
	}
	// Direct score (500) should win over decayed (245)
	if score != 500 {
		t.Fatalf("direct score should win, got %d", score)
	}
}

func TestDeepTrustPropagationCycleDetection(t *testing.T) {
	scorer := trust.NewBehavioralTrustScorer()
	engine := NewVouchingEngine(scorer)
	signer, _ := crypto.NewEd25519Signer("key-v")
	engine.Vouch("A", "B", []string{"ops"}, 10, 1*time.Hour, signer)
	engine.Vouch("B", "A", []string{"ops"}, 10, 1*time.Hour, signer)
	prop := NewTrustPropagator(scorer, engine)
	// Should not infinite loop
	_, _, err := prop.PropagatedScore("A", "C")
	if err != nil {
		t.Fatal(err)
	}
}

// ── Helpers ──────────────────────────────────────────────────────

func mustHexDecode(s string) []byte {
	b, err := hexDecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func hexDecodeString(s string) ([]byte, error) {
	return hexDecode(s)
}

var hexDecode = func() func(string) ([]byte, error) {
	return func(s string) ([]byte, error) {
		// Import encoding/hex at function level
		b := make([]byte, len(s)/2)
		_, err := hexDecodeBytes(b, []byte(s))
		return b, err
	}
}()

var hexDecodeBytes = func(dst, src []byte) (int, error) {
	// Inline hex decode to avoid import alias collision with crypto package
	const hextable = "0123456789abcdef"
	if len(src)%2 != 0 {
		return 0, fmt.Errorf("odd length hex")
	}
	n := len(src) / 2
	for i := 0; i < n; i++ {
		a := fromHexChar(src[i*2])
		b := fromHexChar(src[i*2+1])
		if a == 0xFF || b == 0xFF {
			return i, fmt.Errorf("invalid hex char")
		}
		dst[i] = (a << 4) | b
	}
	_ = hextable
	return n, nil
}

func fromHexChar(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	}
	return 0xFF
}
