// Package a2a — vouching.go
// Peer vouching with joint liability for the Inter-Agent Trust Protocol.
//
// A vouch is a signed attestation that one agent (the voucher) stakes part of
// its own trust score on the good behavior of another agent (the vouchee).
// If the vouchee violates policy, the SlashResult applies penalties to BOTH
// parties — the vouchee receives the violation severity penalty and the voucher
// loses min(stake, maxExposure) trust points.
//
// Invariants:
//   - Vouch content hashes use JCS (RFC 8785) + SHA-256 for determinism.
//   - Expired and revoked vouches are excluded from active queries.
//   - All operations are thread-safe via sync.RWMutex.

package a2a

import (
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/trust"
)

// ── Vouch Record ──────────────────────────────────────────────────

// VouchRecord is a signed attestation of one agent vouching for another.
type VouchRecord struct {
	VouchID     string    `json:"vouch_id"`
	Voucher     string    `json:"voucher_agent"` // who vouches
	Vouchee     string    `json:"vouchee_agent"` // who is vouched for
	Scope       []string  `json:"scope"`         // what capabilities are vouched
	Stake       int       `json:"stake"`         // trust score risked (joint liability)
	MaxExposure int       `json:"max_exposure"`  // max penalty per vouch
	Signature   string    `json:"signature"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Revoked     bool      `json:"revoked"`
	ContentHash string    `json:"content_hash"`
}

// ── Slash Result ──────────────────────────────────────────────────

// SlashResult records the outcome of slashing a vouch.
type SlashResult struct {
	VouchID        string `json:"vouch_id"`
	VoucherPenalty int    `json:"voucher_penalty"`
	VoucheePenalty int    `json:"vouchee_penalty"`
	Reason         string `json:"reason"`
}

// ── Vouching Engine ───────────────────────────────────────────────

// VouchingEngine manages peer vouching with joint liability.
type VouchingEngine struct {
	mu      sync.RWMutex
	vouches map[string]*VouchRecord // vouchID -> record
	byAgent map[string][]string     // agentID -> vouchIDs (as voucher)
	scorer  *trust.BehavioralTrustScorer
	clock   func() time.Time
}
