// Package trust — Pack Install Receipts + Revocation.
//
// Per HELM 2030 Spec:
//   - Every install/upgrade produces a signed, hash-chained receipt
//   - Runtime trust scoring per pack
//   - Revocation support with immediate enforcement
package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// InstallReceipt is a proof-carrying record of a pack installation.
type InstallReceipt struct {
	ReceiptID     string    `json:"receipt_id"`
	PackName      string    `json:"pack_name"`
	PackVersion   string    `json:"pack_version"`
	PackHash      string    `json:"pack_hash"`
	TenantID      string    `json:"tenant_id"`
	InstalledBy   string    `json:"installed_by"`
	InstalledAt   time.Time `json:"installed_at"`
	PrevReceiptID string    `json:"prev_receipt_id,omitempty"`
	ContentHash   string    `json:"content_hash"`
}

// PackTrustScore represents runtime trust evaluation of a pack.
type PackTrustScore struct {
	PackName   string    `json:"pack_name"`
	Score      float64   `json:"score"` // 0-100
	SignedBy   string    `json:"signed_by"`
	Certified  bool      `json:"certified"`
	Revoked    bool      `json:"revoked"`
	AssessedAt time.Time `json:"assessed_at"`
}

// InstallRegistry manages pack install receipts and trust scoring.
type InstallRegistry struct {
	mu       sync.Mutex
	receipts map[string]*InstallReceipt // receiptID → receipt
	latest   map[string]string          // packName → latest receiptID
	scores   map[string]*PackTrustScore // packName → score
	revoked  map[string]bool            // packName → revoked
	seq      int64
	clock    func() time.Time
}

// NewInstallRegistry creates a new registry.
func NewInstallRegistry() *InstallRegistry {
	return &InstallRegistry{
		receipts: make(map[string]*InstallReceipt),
		latest:   make(map[string]string),
		scores:   make(map[string]*PackTrustScore),
		revoked:  make(map[string]bool),
		clock:    time.Now,
	}
}

// WithClock overrides clock for testing.
func (r *InstallRegistry) WithClock(clock func() time.Time) *InstallRegistry {
	r.clock = clock
	return r
}

// RecordInstall creates a receipt for a pack installation.
func (r *InstallRegistry) RecordInstall(packName, packVersion, packHash, tenantID, installedBy string) (*InstallReceipt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.revoked[packName] {
		return nil, fmt.Errorf("pack %q is revoked, cannot install", packName)
	}

	r.seq++
	receiptID := fmt.Sprintf("install-%d", r.seq)

	prevReceiptID := r.latest[packName]

	hashInput := struct {
		Pack    string `json:"pack"`
		Version string `json:"version"`
		Hash    string `json:"hash"`
		Prev    string `json:"prev"`
	}{packName, packVersion, packHash, prevReceiptID}

	raw, _ := json.Marshal(hashInput)
	h := sha256.Sum256(raw)

	receipt := &InstallReceipt{
		ReceiptID:     receiptID,
		PackName:      packName,
		PackVersion:   packVersion,
		PackHash:      packHash,
		TenantID:      tenantID,
		InstalledBy:   installedBy,
		InstalledAt:   r.clock(),
		PrevReceiptID: prevReceiptID,
		ContentHash:   "sha256:" + hex.EncodeToString(h[:]),
	}

	r.receipts[receiptID] = receipt
	r.latest[packName] = receiptID

	return receipt, nil
}

// SetTrustScore sets the trust score for a pack.
func (r *InstallRegistry) SetTrustScore(score *PackTrustScore) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scores[score.PackName] = score
}

// GetTrustScore retrieves the trust score for a pack.
func (r *InstallRegistry) GetTrustScore(packName string) (*PackTrustScore, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	score, ok := r.scores[packName]
	if !ok {
		return nil, fmt.Errorf("no trust score for pack %q", packName)
	}
	return score, nil
}

// Revoke immediately revokes a pack, blocking future installations.
func (r *InstallRegistry) Revoke(packName string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revoked[packName] = true
	if score, ok := r.scores[packName]; ok {
		score.Revoked = true
		score.Score = 0
	}
}

// IsRevoked checks if a pack is revoked.
func (r *InstallRegistry) IsRevoked(packName string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.revoked[packName]
}

// GetReceipt retrieves an install receipt.
func (r *InstallRegistry) GetReceipt(receiptID string) (*InstallReceipt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	receipt, ok := r.receipts[receiptID]
	if !ok {
		return nil, fmt.Errorf("receipt %q not found", receiptID)
	}
	return receipt, nil
}
