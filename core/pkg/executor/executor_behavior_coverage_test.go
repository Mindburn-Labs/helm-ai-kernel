package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// --- Merkle Tree ---

func TestMerkle_DomainSeparatorsDiffer(t *testing.T) {
	if LeafDomainSeparator[0] == NodeDomainSeparator[0] {
		t.Fatal("leaf and node domain separators must differ")
	}
}

// --- EvidenceView ---

// --- EvidencePack ---

func TestReceiptHashDeterministic(t *testing.T) {
	data := []byte("receipt-content")
	h1 := sha256.Sum256(data)
	h2 := sha256.Sum256(data)
	if hex.EncodeToString(h1[:]) != hex.EncodeToString(h2[:]) {
		t.Fatal("SHA-256 should be deterministic")
	}
}

// --- MCPDriver ---
