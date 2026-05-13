package a2a

import (
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

// fakeVerifier returns a verifier function that uses Ed25519 verification.
func fakeVerifier() func(pubKey, data, sig string) bool {
	return func(pubKey, data, sig string) bool {
		dataBytes, err := hex.DecodeString(data)
		if err != nil {
			return false
		}
		ok, err := crypto.Verify(pubKey, sig, dataBytes)
		if err != nil {
			return false
		}
		return ok
	}
}

func TestIATPAuthenticator_CreateChallenge(t *testing.T) {
	signer, err := crypto.NewEd25519Signer("test-key-1")
	if err != nil {
		t.Fatal(err)
	}
	auth := NewIATPAuthenticator(signer).WithAgentID("agent-alpha")

	challenge, err := auth.CreateChallenge("agent-beta")
	if err != nil {
		t.Fatal(err)
	}

	if challenge.ChallengeID == "" {
		t.Fatal("expected non-empty challenge ID")
	}
	if challenge.ChallengerAgent != "agent-alpha" {
		t.Fatalf("expected challenger agent-alpha, got %s", challenge.ChallengerAgent)
	}
	if len(challenge.Nonce) != 64 { // 32 bytes = 64 hex chars
		t.Fatalf("expected 64-char hex nonce, got %d chars", len(challenge.Nonce))
	}
	if challenge.TTL != 200*time.Millisecond {
		t.Fatalf("expected 200ms TTL, got %v", challenge.TTL)
	}
}

func TestIATPAuthenticator_ChallengeResponse(t *testing.T) {
	// Set up two agents.
	signerA, err := crypto.NewEd25519Signer("key-alpha")
	if err != nil {
		t.Fatal(err)
	}
	signerB, err := crypto.NewEd25519Signer("key-beta")
	if err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	authA := NewIATPAuthenticator(signerA).WithAgentID("agent-alpha").WithClock(clock)
	authB := NewIATPAuthenticator(signerB).WithAgentID("agent-beta").WithClock(clock)

	// Step 1: A creates challenge for B.
	challenge, err := authA.CreateChallenge("agent-beta")
	if err != nil {
		t.Fatal(err)
	}

	// Step 2: B responds to challenge.
	response, err := authB.RespondToChallenge(challenge)
	if err != nil {
		t.Fatal(err)
	}
	if response.ResponderAgent != "agent-beta" {
		t.Fatalf("expected responder agent-beta, got %s", response.ResponderAgent)
	}

	// Step 3: A verifies B's response.
	session, err := authA.VerifyResponse(challenge, response, fakeVerifier())
	if err != nil {
		t.Fatal(err)
	}
	if session.Status != IATPAuthenticated {
		t.Fatalf("expected AUTHENTICATED, got %s", session.Status)
	}
	if session.LocalAgent != "agent-alpha" {
		t.Fatalf("expected local agent-alpha, got %s", session.LocalAgent)
	}
	if session.RemoteAgent != "agent-beta" {
		t.Fatalf("expected remote agent-beta, got %s", session.RemoteAgent)
	}
}

func TestIATPAuthenticator_ExpiredChallenge(t *testing.T) {
	signer, err := crypto.NewEd25519Signer("key-1")
	if err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	auth := NewIATPAuthenticator(signer).
		WithAgentID("agent-alpha").
		WithClock(func() time.Time { return now })

	challenge, err := auth.CreateChallenge("agent-beta")
	if err != nil {
		t.Fatal(err)
	}

	// Advance clock past TTL.
	expired := now.Add(1 * time.Second)
	authResponder := NewIATPAuthenticator(signer).
		WithAgentID("agent-beta").
		WithClock(func() time.Time { return expired })

	_, err = authResponder.RespondToChallenge(challenge)
	if err == nil {
		t.Fatal("expected error for expired challenge, got nil")
	}
}

func TestIATPAuthenticator_ReplayProtection(t *testing.T) {
	signerA, err := crypto.NewEd25519Signer("key-alpha")
	if err != nil {
		t.Fatal(err)
	}
	signerB, err := crypto.NewEd25519Signer("key-beta")
	if err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	authA := NewIATPAuthenticator(signerA).WithAgentID("agent-alpha").WithClock(clock)
	authB := NewIATPAuthenticator(signerB).WithAgentID("agent-beta").WithClock(clock)

	challenge, err := authA.CreateChallenge("agent-beta")
	if err != nil {
		t.Fatal(err)
	}
	response, err := authB.RespondToChallenge(challenge)
	if err != nil {
		t.Fatal(err)
	}

	// First verification succeeds.
	_, err = authA.VerifyResponse(challenge, response, fakeVerifier())
	if err != nil {
		t.Fatal(err)
	}

	// Second verification with same nonce must fail (replay).
	_, err = authA.VerifyResponse(challenge, response, fakeVerifier())
	if err == nil {
		t.Fatal("expected replay detection error, got nil")
	}
}

func TestIATPAuthenticator_SessionLifecycle(t *testing.T) {
	signerA, err := crypto.NewEd25519Signer("key-alpha")
	if err != nil {
		t.Fatal(err)
	}
	signerB, err := crypto.NewEd25519Signer("key-beta")
	if err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	mu := sync.Mutex{}
	currentTime := now
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return currentTime
	}

	sessionTTL := 5 * time.Second
	authA := NewIATPAuthenticator(signerA).
		WithAgentID("agent-alpha").
		WithClock(clock).
		WithSessionTTL(sessionTTL)
	authB := NewIATPAuthenticator(signerB).
		WithAgentID("agent-beta").
		WithClock(clock)

	// Establish session.
	challenge, err := authA.CreateChallenge("agent-beta")
	if err != nil {
		t.Fatal(err)
	}
	response, err := authB.RespondToChallenge(challenge)
	if err != nil {
		t.Fatal(err)
	}
	session, err := authA.VerifyResponse(challenge, response, fakeVerifier())
	if err != nil {
		t.Fatal(err)
	}

	// Session should be retrievable.
	got, ok := authA.GetSession(session.SessionID)
	if !ok {
		t.Fatal("expected session to be found")
	}
	if got.Status != IATPAuthenticated {
		t.Fatalf("expected AUTHENTICATED, got %s", got.Status)
	}

	// Advance clock past session TTL.
	mu.Lock()
	currentTime = now.Add(10 * time.Second)
	mu.Unlock()

	_, ok = authA.GetSession(session.SessionID)
	if ok {
		t.Fatal("expected expired session to be purged")
	}
}

func TestIATPAuthenticator_InvalidSignature(t *testing.T) {
	signerA, err := crypto.NewEd25519Signer("key-alpha")
	if err != nil {
		t.Fatal(err)
	}
	signerB, err := crypto.NewEd25519Signer("key-beta")
	if err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	authA := NewIATPAuthenticator(signerA).WithAgentID("agent-alpha").WithClock(clock)
	authB := NewIATPAuthenticator(signerB).WithAgentID("agent-beta").WithClock(clock)

	challenge, err := authA.CreateChallenge("agent-beta")
	if err != nil {
		t.Fatal(err)
	}
	response, err := authB.RespondToChallenge(challenge)
	if err != nil {
		t.Fatal(err)
	}

	// Use a verifier that always fails.
	alwaysFail := func(pubKey, data, sig string) bool { return false }

	session, err := authA.VerifyResponse(challenge, response, alwaysFail)
	if err == nil {
		t.Fatal("expected signature verification error")
	}
	if session == nil {
		t.Fatal("expected failed session object, got nil")
	}
	if session.Status != IATPFailed {
		t.Fatalf("expected FAILED status, got %s", session.Status)
	}
}
