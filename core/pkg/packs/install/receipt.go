package install

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// Receipt is a content-addressed record of a pack lifecycle action.
// Receipts chain via PrevReceiptHash, producing a tamper-evident history per
// pack. No tenant identifier is carried in OSS — the hash input is
// (pack_id, action, manifest_hash, prev_receipt_hash, timestamp).
type Receipt struct {
	PackID          string    `json:"pack_id"`
	Action          string    `json:"action"`
	ManifestHash    string    `json:"manifest_hash"`
	PrevReceiptHash string    `json:"prev_receipt_hash,omitempty"`
	Timestamp       time.Time `json:"timestamp"`
	Hash            string    `json:"hash"`
}

// newReceipt constructs a Receipt with its content hash pre-computed.
func newReceipt(packID, action, manifestHash, prevReceiptHash string, timestamp time.Time) *Receipt {
	receipt := &Receipt{
		PackID:          packID,
		Action:          action,
		ManifestHash:    manifestHash,
		PrevReceiptHash: prevReceiptHash,
		Timestamp:       timestamp.UTC(),
	}
	receipt.Hash = computeReceiptHash(receipt)
	return receipt
}

// computeReceiptHash returns the deterministic sha256 content hash for
// receipt. The hash covers every field except Hash itself.
func computeReceiptHash(receipt *Receipt) string {
	input := struct {
		PackID          string    `json:"pack_id"`
		Action          string    `json:"action"`
		ManifestHash    string    `json:"manifest_hash"`
		PrevReceiptHash string    `json:"prev_receipt_hash"`
		Timestamp       time.Time `json:"timestamp"`
	}{
		PackID:          receipt.PackID,
		Action:          receipt.Action,
		ManifestHash:    receipt.ManifestHash,
		PrevReceiptHash: receipt.PrevReceiptHash,
		Timestamp:       receipt.Timestamp.UTC(),
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
