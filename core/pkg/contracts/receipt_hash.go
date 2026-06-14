package contracts

import (
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

// ReceiptChainHash returns the canonical SHA-256 digest used for receipt
// causal links. It hashes the persisted receipt envelope, including its
// signature, so any mutation to the previous receipt breaks the next link.
//
// Transparency-log anchoring metadata (Transparency, LogID, LeafIndex) is
// excluded from the digest. Those fields are assigned AFTER the leaf hash is
// computed (see anchorReceiptTransparency), and the assigned leaf hash IS this
// chain hash; if anchoring metadata entered the digest, the persisted receipt's
// recomputed chain hash would no longer match the leaf that was anchored, and
// the prev_hash of the next causal receipt would shift depending on whether the
// previous receipt was anchored. Excluding them keeps the chain hash stable.
func ReceiptChainHash(receipt *Receipt) (string, error) {
	if receipt == nil {
		return "", fmt.Errorf("receipt is nil")
	}
	chained := *receipt
	chained.Transparency = nil
	chained.LogID = ""
	chained.LeafIndex = 0
	hash, err := canonicalize.CanonicalHash(&chained)
	if err != nil {
		return "", fmt.Errorf("canonical receipt hash: %w", err)
	}
	return hash, nil
}
