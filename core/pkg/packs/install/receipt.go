package install

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Receipt is a proof-carrying record of a pack install lifecycle event
// (install, upgrade, uninstall, rollback). Receipts form a hash chain
// per pack via PrevReceiptID so commercial callers can replay and
// verify the complete lifecycle of any installed pack.
//
// OSS receipts are unsigned: the ContentHash authenticates the payload
// against tampering within a single trust domain (the operator's local
// store). Signed distribution is a commercial concern and is added by
// wrapping this receipt in a commercial envelope.
type Receipt struct {
	ReceiptID     string    `json:"receipt_id"`
	PackID        string    `json:"pack_id"`
	PackName      string    `json:"pack_name"`
	PackVersion   string    `json:"pack_version"`
	PackHash      string    `json:"pack_hash"`
	Action        string    `json:"action"`
	InstalledBy   string    `json:"installed_by"`
	InstalledAt   time.Time `json:"installed_at"`
	PrevReceiptID string    `json:"prev_receipt_id,omitempty"`
	ContentHash   string    `json:"content_hash"`
}

// issueReceipt produces a new receipt that chains to prevReceiptID (may
// be empty for a pack's first receipt). The ContentHash is derived from
// a stable field ordering so repeated calls with the same inputs produce
// the same hash — a property the test suite asserts.
func issueReceipt(
	packID, packName, packVersion, manifestHash string,
	action, installedBy string,
	installedAt time.Time,
	prevReceiptID string,
) (*Receipt, error) {
	if packID == "" {
		return nil, fmt.Errorf("packs/install: receipt requires pack_id")
	}
	if packVersion == "" {
		return nil, fmt.Errorf("packs/install: receipt requires pack_version")
	}
	if action == "" {
		return nil, fmt.Errorf("packs/install: receipt requires action")
	}

	hashInput := struct {
		Action  string `json:"action"`
		Pack    string `json:"pack"`
		Version string `json:"version"`
		Hash    string `json:"hash"`
		Prev    string `json:"prev"`
	}{
		Action:  action,
		Pack:    packID,
		Version: packVersion,
		Hash:    manifestHash,
		Prev:    prevReceiptID,
	}
	raw, err := json.Marshal(hashInput)
	if err != nil {
		return nil, fmt.Errorf("packs/install: marshal receipt hash input: %w", err)
	}
	sum := sha256.Sum256(raw)

	return &Receipt{
		ReceiptID:     fmt.Sprintf("%s-%d", action, installedAt.UnixNano()),
		PackID:        packID,
		PackName:      packName,
		PackVersion:   packVersion,
		PackHash:      manifestHash,
		Action:        action,
		InstalledBy:   installedBy,
		InstalledAt:   installedAt,
		PrevReceiptID: prevReceiptID,
		ContentHash:   "sha256:" + hex.EncodeToString(sum[:]),
	}, nil
}
