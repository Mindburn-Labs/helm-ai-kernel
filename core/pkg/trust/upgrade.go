// Package trust — Upgrade Receipts.
//
// Per HELM 2030 Spec §1.12 — Upgradeable Without Semantic Drift:
//
//	Upgrades are proof-carrying, reversible where possible, and never
//	silently change semantics. Policy/schema/runtime compatibility is explicit.
package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// CompatibilityLevel describes semantic compatibility.
type CompatibilityLevel string

const (
	CompatFull     CompatibilityLevel = "FULL"     // No breaking changes
	CompatBackward CompatibilityLevel = "BACKWARD" // Old clients work
	CompatBreaking CompatibilityLevel = "BREAKING" // Manual migration needed
)

// UpgradeReceipt is proof that an upgrade was performed with semantic checks.
type UpgradeReceipt struct {
	ReceiptID       string             `json:"receipt_id"`
	PackName        string             `json:"pack_name"`
	FromVersion     string             `json:"from_version"`
	ToVersion       string             `json:"to_version"`
	Compatibility   CompatibilityLevel `json:"compatibility"`
	SchemaChecked   bool               `json:"schema_checked"`
	PolicyChecked   bool               `json:"policy_checked"`
	Reversible      bool               `json:"reversible"`
	RollbackVersion string             `json:"rollback_version,omitempty"`
	MigrationSteps  []string           `json:"migration_steps,omitempty"`
	UpgradedAt      time.Time          `json:"upgraded_at"`
	UpgradedBy      string             `json:"upgraded_by"`
	ContentHash     string             `json:"content_hash"`
}

// UpgradeRegistry tracks upgrade receipts.
type UpgradeRegistry struct {
	mu       sync.Mutex
	receipts map[string]*UpgradeReceipt // receiptID → receipt
	history  map[string][]string        // packName → receipt IDs
	seq      int64
	clock    func() time.Time
}

// NewUpgradeRegistry creates a new registry.
func NewUpgradeRegistry() *UpgradeRegistry {
	return &UpgradeRegistry{
		receipts: make(map[string]*UpgradeReceipt),
		history:  make(map[string][]string),
		clock:    time.Now,
	}
}

// RecordUpgrade records an upgrade with compatibility proof.
func (r *UpgradeRegistry) RecordUpgrade(packName, fromVersion, toVersion, upgradedBy string, compat CompatibilityLevel, schemaChecked, policyChecked, reversible bool) (*UpgradeReceipt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if compat == CompatBreaking && !schemaChecked {
		return nil, fmt.Errorf("breaking upgrade requires schema check")
	}

	r.seq++
	id := fmt.Sprintf("upg-%d", r.seq)
	now := r.clock()

	hashInput := fmt.Sprintf("%s:%s:%s:%s:%s", id, packName, fromVersion, toVersion, compat)
	h := sha256.Sum256([]byte(hashInput))

	receipt := &UpgradeReceipt{
		ReceiptID:     id,
		PackName:      packName,
		FromVersion:   fromVersion,
		ToVersion:     toVersion,
		Compatibility: compat,
		SchemaChecked: schemaChecked,
		PolicyChecked: policyChecked,
		Reversible:    reversible,
		UpgradedAt:    now,
		UpgradedBy:    upgradedBy,
		ContentHash:   "sha256:" + hex.EncodeToString(h[:]),
	}

	if reversible {
		receipt.RollbackVersion = fromVersion
	}

	r.receipts[id] = receipt
	r.history[packName] = append(r.history[packName], id)
	return receipt, nil
}

// GetHistory returns upgrade history for a pack.
func (r *UpgradeRegistry) GetHistory(packName string) []*UpgradeReceipt {
	r.mu.Lock()
	defer r.mu.Unlock()

	var result []*UpgradeReceipt
	for _, id := range r.history[packName] {
		result = append(result, r.receipts[id])
	}
	return result
}

// Get retrieves an upgrade receipt.
func (r *UpgradeRegistry) Get(receiptID string) (*UpgradeReceipt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	receipt, ok := r.receipts[receiptID]
	if !ok {
		return nil, fmt.Errorf("upgrade receipt %q not found", receiptID)
	}
	return receipt, nil
}
