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
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
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
