package zkgov

import (
	"fmt"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
)

// Anchor records a ZK governance proof on a transparency log.
//
// This integrates with HELM's existing Rekor transparency log infrastructure
// (see trust.RekorClient). When a proof is anchored, the log entry ID is
// recorded in the proof's RekorEntryID field, providing public auditability
// without revealing the governed policy or data.
type Anchor struct {
	// submit is the function that writes to the transparency log.
	// Injected to decouple from the specific log implementation.
	submit func(proofHash string, proofBytes []byte) (string, error)
}

// AnchorOption configures the Anchor.
type AnchorOption func(*Anchor)

// WithSubmitFunc injects a custom transparency log submission function.
// The function receives the proof's content hash and canonical bytes,
// and returns the log entry ID.
func WithSubmitFunc(fn func(proofHash string, proofBytes []byte) (string, error)) AnchorOption {
	return func(a *Anchor) { a.submit = fn }
}

// NewAnchor creates a new Anchor for transparency log integration.
// Without options, AnchorToLog returns an error indicating no log is configured.
func NewAnchor(opts ...AnchorOption) *Anchor {
	a := &Anchor{}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// AnchorToLog submits a ZK proof to a transparency log and returns the entry ID.
//
// The proof's canonical JSON representation (JCS) and content hash are submitted.
// On success, the proof's RekorEntryID field is populated with the log entry ID.
//
// This uses HELM's existing Rekor integration pattern (see trust.RekorClient).
// The transparency log records the proof's existence without revealing the
// governed policy or data — only the commitments are logged.
func (a *Anchor) AnchorToLog(proof *ZKGovernanceProof) (string, error) {
	if proof == nil {
		return "", fmt.Errorf("zkgov: nil proof")
	}

	if a.submit == nil {
		return "", fmt.Errorf("zkgov: no transparency log configured; use WithSubmitFunc")
	}

	// Canonicalize the proof for submission.
	proofBytes, err := canonicalize.JCS(proof)
	if err != nil {
		return "", fmt.Errorf("zkgov: proof canonicalization failed: %w", err)
	}

	entryID, err := a.submit(proof.ContentHash, proofBytes)
	if err != nil {
		return "", fmt.Errorf("zkgov: transparency log submission failed: %w", err)
	}

	proof.RekorEntryID = entryID
	return entryID, nil
}
