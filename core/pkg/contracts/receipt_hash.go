package contracts

import (
	"fmt"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
)

// ReceiptChainHash returns the canonical SHA-256 digest used for receipt
// causal links. It hashes the persisted receipt envelope, including its
// signature, so any mutation to the previous receipt breaks the next link.
func ReceiptChainHash(receipt *Receipt) (string, error) {
	if receipt == nil {
		return "", fmt.Errorf("receipt is nil")
	}
	hash, err := canonicalize.CanonicalHash(receipt)
	if err != nil {
		return "", fmt.Errorf("canonical receipt hash: %w", err)
	}
	return hash, nil
}
