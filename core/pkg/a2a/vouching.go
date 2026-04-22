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
	"fmt"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/trust"
	"github.com/google/uuid"
)

// ── Vouch Record ──────────────────────────────────────────────────

// VouchRecord is a signed attestation of one agent vouching for another.
type VouchRecord struct {
	VouchID     string    `json:"vouch_id"`
	Voucher     string    `json:"voucher_agent"`  // who vouches
	Vouchee     string    `json:"vouchee_agent"`  // who is vouched for
	Scope       []string  `json:"scope"`          // what capabilities are vouched
	Stake       int       `json:"stake"`          // trust score risked (joint liability)
	MaxExposure int       `json:"max_exposure"`   // max penalty per vouch
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

// NewVouchingEngine creates a vouching engine backed by the given trust scorer.
func NewVouchingEngine(scorer *trust.BehavioralTrustScorer) *VouchingEngine {
	return &VouchingEngine{
		vouches: make(map[string]*VouchRecord),
		byAgent: make(map[string][]string),
		scorer:  scorer,
		clock:   time.Now,
	}
}

// WithClock overrides the clock for testing.
func (v *VouchingEngine) WithClock(clock func() time.Time) *VouchingEngine {
	v.clock = clock
	return v
}

// Vouch creates a new vouch record. The voucher stakes `stake` trust points
// on the vouchee's behavior within the given scope and TTL.
func (v *VouchingEngine) Vouch(
	voucher, vouchee string,
	scope []string,
	stake int,
	ttl time.Duration,
	signer crypto.Signer,
) (*VouchRecord, error) {
	if voucher == "" || vouchee == "" {
		return nil, fmt.Errorf("vouching: voucher and vouchee must be non-empty")
	}
	if voucher == vouchee {
		return nil, fmt.Errorf("vouching: agent cannot vouch for itself")
	}
	if stake <= 0 {
		return nil, fmt.Errorf("vouching: stake must be positive, got %d", stake)
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("vouching: TTL must be positive")
	}

	now := v.clock()
	record := &VouchRecord{
		VouchID:     "vouch:" + uuid.NewString()[:8],
		Voucher:     voucher,
		Vouchee:     vouchee,
		Scope:       scope,
		Stake:       stake,
		MaxExposure: stake, // default: max exposure equals stake
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
	}

	// Compute content hash for deterministic identification.
	hash, err := v.computeVouchHash(record)
	if err != nil {
		return nil, fmt.Errorf("vouching: hash computation failed: %w", err)
	}
	record.ContentHash = hash

	// Sign the content hash.
	sig, err := signer.Sign([]byte(record.ContentHash))
	if err != nil {
		return nil, fmt.Errorf("vouching: signing failed: %w", err)
	}
	record.Signature = sig

	v.mu.Lock()
	defer v.mu.Unlock()
	v.vouches[record.VouchID] = record
	v.byAgent[voucher] = append(v.byAgent[voucher], record.VouchID)

	return record, nil
}

// RevokeVouch revokes an existing vouch.
func (v *VouchingEngine) RevokeVouch(vouchID, reason string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	record, ok := v.vouches[vouchID]
	if !ok {
		return fmt.Errorf("vouching: vouch %s not found", vouchID)
	}
	if record.Revoked {
		return fmt.Errorf("vouching: vouch %s already revoked", vouchID)
	}

	record.Revoked = true
	return nil
}

// Slash applies joint-liability penalties to both voucher and vouchee.
//
// Slashing logic:
//   - Voucher penalty = min(stake, maxExposure)
//   - Vouchee penalty = violation severity (DefaultDeltas[POLICY_VIOLATE])
//   - Both penalties are recorded via scorer.RecordEvent
func (v *VouchingEngine) Slash(vouchID, reason string) (*SlashResult, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	record, ok := v.vouches[vouchID]
	if !ok {
		return nil, fmt.Errorf("vouching: vouch %s not found", vouchID)
	}

	// Compute penalties.
	voucherPenalty := record.Stake
	if voucherPenalty > record.MaxExposure {
		voucherPenalty = record.MaxExposure
	}

	// Vouchee penalty: use the absolute value of the default violation severity.
	voucheePenalty := trust.DefaultDeltas[trust.EventPolicyViolate] // e.g. -25
	if voucheePenalty < 0 {
		voucheePenalty = -voucheePenalty
	}

	// Apply penalties via the trust scorer.
	now := v.clock()
	v.scorer.RecordEvent(record.Voucher, trust.ScoreEvent{
		EventType: trust.EventManualPenalty,
		Delta:     -voucherPenalty,
		Reason:    fmt.Sprintf("vouch slash: %s (vouch %s)", reason, vouchID),
		Timestamp: now,
	})
	v.scorer.RecordEvent(record.Vouchee, trust.ScoreEvent{
		EventType: trust.EventPolicyViolate,
		Delta:     -voucheePenalty, // negative delta to reduce score
		Reason:    fmt.Sprintf("vouch violation: %s (vouch %s)", reason, vouchID),
		Timestamp: now,
	})

	// Mark vouch as revoked after slashing.
	record.Revoked = true

	return &SlashResult{
		VouchID:        vouchID,
		VoucherPenalty: voucherPenalty,
		VoucheePenalty: voucheePenalty, // positive magnitude
		Reason:         reason,
	}, nil
}

// ActiveVouches returns all non-revoked, non-expired vouches where agentID is the voucher.
func (v *VouchingEngine) ActiveVouches(agentID string) []*VouchRecord {
	v.mu.RLock()
	defer v.mu.RUnlock()

	now := v.clock()
	var result []*VouchRecord
	for _, vid := range v.byAgent[agentID] {
		rec := v.vouches[vid]
		if rec != nil && !rec.Revoked && now.Before(rec.ExpiresAt) {
			result = append(result, rec)
		}
	}
	return result
}

// IsVouchedFor checks whether any active vouch covers the given agent and capability.
func (v *VouchingEngine) IsVouchedFor(agentID string, capability string) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()

	now := v.clock()
	for _, rec := range v.vouches {
		if rec.Vouchee != agentID {
			continue
		}
		if rec.Revoked || now.After(rec.ExpiresAt) {
			continue
		}
		for _, s := range rec.Scope {
			if s == capability {
				return true
			}
		}
	}
	return false
}

// AllActiveVouchesFor returns all active vouches where agentID is the vouchee.
// Used by trust propagation to discover vouch chains.
func (v *VouchingEngine) AllActiveVouchesFor(agentID string) []*VouchRecord {
	v.mu.RLock()
	defer v.mu.RUnlock()

	now := v.clock()
	var result []*VouchRecord
	for _, rec := range v.vouches {
		if rec.Vouchee == agentID && !rec.Revoked && now.Before(rec.ExpiresAt) {
			result = append(result, rec)
		}
	}
	return result
}

// computeVouchHash computes a deterministic JCS + SHA-256 hash of the vouch content.
func (v *VouchingEngine) computeVouchHash(record *VouchRecord) (string, error) {
	hashable := struct {
		Voucher   string   `json:"voucher_agent"`
		Vouchee   string   `json:"vouchee_agent"`
		Scope     []string `json:"scope"`
		Stake     int      `json:"stake"`
		CreatedAt string   `json:"created_at"`
		ExpiresAt string   `json:"expires_at"`
	}{
		Voucher:   record.Voucher,
		Vouchee:   record.Vouchee,
		Scope:     record.Scope,
		Stake:     record.Stake,
		CreatedAt: record.CreatedAt.Format(time.RFC3339Nano),
		ExpiresAt: record.ExpiresAt.Format(time.RFC3339Nano),
	}
	hash, err := canonicalize.CanonicalHash(hashable)
	if err != nil {
		return "", err
	}
	return "sha256:" + hash, nil
}
