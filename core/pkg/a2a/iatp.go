// Package a2a — iatp.go
// Inter-Agent Trust Protocol (IATP): challenge-response mutual authentication.
//
// IATP sessions are established via a three-step handshake:
//   1. Challenger creates a ChallengeRequest with a random nonce.
//   2. Responder signs the nonce with their key and returns a ChallengeResponse.
//   3. Challenger verifies the signature, establishing an authenticated IATPSession.
//
// Invariants:
//   - Nonces are 32 cryptographically random bytes (hex-encoded).
//   - Each nonce is single-use; replay is detected and rejected.
//   - Challenge TTL defaults to 200ms per ADR-0003 overhead budget.
//   - Sessions expire after sessionTTL (default 1 hour).
//   - All operations are thread-safe.

package a2a

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/google/uuid"
)

// ── Status ────────────────────────────────────────────────────────

// IATPSessionStatus tracks the lifecycle of an IATP session.
type IATPSessionStatus string

const (
	IATPPending       IATPSessionStatus = "PENDING"
	IATPAuthenticated IATPSessionStatus = "AUTHENTICATED"
	IATPFailed        IATPSessionStatus = "FAILED"
)

// ── Challenge / Response ──────────────────────────────────────────

// ChallengeRequest is sent by the challenger to initiate mutual authentication.
type ChallengeRequest struct {
	ChallengeID     string        `json:"challenge_id"`
	ChallengerAgent string        `json:"challenger_agent"`
	Nonce           string        `json:"nonce"` // hex-encoded 32 random bytes
	Timestamp       time.Time     `json:"timestamp"`
	TTL             time.Duration `json:"ttl"` // max 200ms per ADR-0003
}

// ChallengeResponse is returned by the responder after signing the nonce.
type ChallengeResponse struct {
	ChallengeID    string    `json:"challenge_id"`
	ResponderAgent string    `json:"responder_agent"`
	SignedNonce    string    `json:"signed_nonce"` // nonce signed with responder's key
	PublicKey      string    `json:"public_key"`
	Capabilities   []string  `json:"capabilities,omitempty"`
	Timestamp      time.Time `json:"timestamp"`
}

// ── Session ───────────────────────────────────────────────────────

// IATPSession represents an authenticated peer session.
type IATPSession struct {
	SessionID     string            `json:"session_id"`
	LocalAgent    string            `json:"local_agent"`
	RemoteAgent   string            `json:"remote_agent"`
	Status        IATPSessionStatus `json:"status"`
	TrustScore    int               `json:"trust_score"` // remote agent's trust at auth time
	EstablishedAt time.Time         `json:"established_at"`
	ExpiresAt     time.Time         `json:"expires_at"`
}

// ── Constants ─────────────────────────────────────────────────────

const (
	// defaultChallengeTTL is the default challenge validity window (ADR-0003).
	defaultChallengeTTL = 200 * time.Millisecond

	// defaultSessionTTL is the default authenticated session lifetime.
	defaultSessionTTL = 1 * time.Hour

	// nonceBytes is the number of random bytes in a challenge nonce.
	nonceBytes = 32
)

// ── Authenticator ─────────────────────────────────────────────────

// IATPAuthenticator manages IATP challenge-response authentication.
type IATPAuthenticator struct {
	signer     crypto.Signer
	agentID    string
	sessions   sync.Map // sessionID -> *IATPSession
	usedNonces sync.Map // nonce -> struct{} (replay protection)
	clock      func() time.Time
	sessionTTL time.Duration
}

// NewIATPAuthenticator creates a new IATP authenticator for the given agent.
func NewIATPAuthenticator(signer crypto.Signer) *IATPAuthenticator {
	// Derive agent ID from SHA-256 of public key for better entropy distribution.
	h := sha256.Sum256([]byte(signer.PublicKey()))
	agentID := hex.EncodeToString(h[:8]) // 16 hex chars from 8 bytes of hash

	return &IATPAuthenticator{
		signer:     signer,
		agentID:    agentID,
		clock:      time.Now,
		sessionTTL: defaultSessionTTL,
	}
}

// WithAgentID overrides the default agent ID (derived from public key).
func (a *IATPAuthenticator) WithAgentID(id string) *IATPAuthenticator {
	a.agentID = id
	return a
}

// WithClock overrides the clock for testing.
func (a *IATPAuthenticator) WithClock(clock func() time.Time) *IATPAuthenticator {
	a.clock = clock
	return a
}

// WithSessionTTL overrides the default session lifetime.
func (a *IATPAuthenticator) WithSessionTTL(ttl time.Duration) *IATPAuthenticator {
	a.sessionTTL = ttl
	return a
}

// CreateChallenge generates a new challenge for a remote agent.
func (a *IATPAuthenticator) CreateChallenge(remoteAgentID string) (*ChallengeRequest, error) {
	nonce := make([]byte, nonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("iatp: nonce generation failed: %w", err)
	}

	return &ChallengeRequest{
		ChallengeID:     "iatp-ch:" + uuid.NewString()[:8],
		ChallengerAgent: a.agentID,
		Nonce:           hex.EncodeToString(nonce),
		Timestamp:       a.clock(),
		TTL:             defaultChallengeTTL,
	}, nil
}

// RespondToChallenge signs the nonce from a received challenge.
func (a *IATPAuthenticator) RespondToChallenge(challenge *ChallengeRequest) (*ChallengeResponse, error) {
	if challenge == nil {
		return nil, errors.New("iatp: nil challenge")
	}

	// Validate challenge is not expired.
	now := a.clock()
	deadline := challenge.Timestamp.Add(challenge.TTL)
	if now.After(deadline) {
		return nil, fmt.Errorf("iatp: challenge %s expired at %s", challenge.ChallengeID, deadline.Format(time.RFC3339Nano))
	}

	// Sign the raw nonce bytes.
	nonceBytes, err := hex.DecodeString(challenge.Nonce)
	if err != nil {
		return nil, fmt.Errorf("iatp: invalid nonce hex: %w", err)
	}

	sig, err := a.signer.Sign(nonceBytes)
	if err != nil {
		return nil, fmt.Errorf("iatp: signing nonce failed: %w", err)
	}

	return &ChallengeResponse{
		ChallengeID:    challenge.ChallengeID,
		ResponderAgent: a.agentID,
		SignedNonce:    sig,
		PublicKey:      a.signer.PublicKey(),
		Timestamp:      now,
	}, nil
}

// VerifyResponse verifies a challenge response and establishes an authenticated session.
// The verifier function checks: (pubKeyHex, dataHex, sigHex) -> valid.
func (a *IATPAuthenticator) VerifyResponse(
	challenge *ChallengeRequest,
	response *ChallengeResponse,
	verifier func(pubKey, data, sig string) bool,
) (*IATPSession, error) {
	if challenge == nil || response == nil {
		return nil, errors.New("iatp: nil challenge or response")
	}

	// 1. Challenge ID must match.
	if challenge.ChallengeID != response.ChallengeID {
		return nil, fmt.Errorf("iatp: challenge ID mismatch: %s vs %s",
			challenge.ChallengeID, response.ChallengeID)
	}

	// 2. Check TTL expiration.
	now := a.clock()
	deadline := challenge.Timestamp.Add(challenge.TTL)
	if now.After(deadline) {
		return nil, fmt.Errorf("iatp: challenge %s expired", challenge.ChallengeID)
	}

	// 3. Replay protection: each nonce may only be verified once.
	if _, loaded := a.usedNonces.LoadOrStore(challenge.Nonce, struct{}{}); loaded {
		return nil, fmt.Errorf("iatp: nonce replay detected for challenge %s", challenge.ChallengeID)
	}

	// 4. Verify the cryptographic signature on the nonce.
	if !verifier(response.PublicKey, challenge.Nonce, response.SignedNonce) {
		return &IATPSession{
			SessionID:   "iatp-sess:" + uuid.NewString()[:8],
			LocalAgent:  a.agentID,
			RemoteAgent: response.ResponderAgent,
			Status:      IATPFailed,
		}, fmt.Errorf("iatp: signature verification failed for agent %s", response.ResponderAgent)
	}

	// 5. Build authenticated session.
	session := &IATPSession{
		SessionID:     "iatp-sess:" + uuid.NewString()[:8],
		LocalAgent:    a.agentID,
		RemoteAgent:   response.ResponderAgent,
		Status:        IATPAuthenticated,
		EstablishedAt: now,
		ExpiresAt:     now.Add(a.sessionTTL),
	}
	a.sessions.Store(session.SessionID, session)

	return session, nil
}

// GetSession returns an active session by ID.
// Returns false if the session does not exist or has expired.
func (a *IATPAuthenticator) GetSession(sessionID string) (*IATPSession, bool) {
	val, ok := a.sessions.Load(sessionID)
	if !ok {
		return nil, false
	}
	session := val.(*IATPSession)

	// Check expiration.
	if a.clock().After(session.ExpiresAt) {
		a.sessions.Delete(sessionID)
		return nil, false
	}

	return session, true
}
