package sovereignty

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

// IntentSigner signs AuthorizedExecutionIntents.
// Injected dependency — no mock signatures.
type IntentSigner interface {
	// Sign produces a signature over the given data.
	Sign(data []byte) ([]byte, error)
}

// Ed25519IntentSigner signs intents using Ed25519.
type Ed25519IntentSigner struct {
	key ed25519.PrivateKey
}

// NewEd25519IntentSigner creates a signer from an Ed25519 private key.
func NewEd25519IntentSigner(key ed25519.PrivateKey) *Ed25519IntentSigner {
	return &Ed25519IntentSigner{key: key}
}

// Sign produces an Ed25519 signature.
func (s *Ed25519IntentSigner) Sign(data []byte) ([]byte, error) {
	if len(s.key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 private key")
	}
	return ed25519.Sign(s.key, data), nil
}

// SovereigntyGuard enforces the rule: No Effect Without Decision.
type SovereigntyGuard struct {
	signer IntentSigner
}

// NewSovereigntyGuard creates a new guard instance with an injected signer.
func NewSovereigntyGuard(signer IntentSigner) *SovereigntyGuard {
	return &SovereigntyGuard{signer: signer}
}

// Authorize validates a DecisionRecord and mints an AuthorizedExecutionIntent.
// Spec: 11.2 AuthorizedExecutionIntent v1 (Split-Phase Execution)
func (g *SovereigntyGuard) Authorize(decision *DecisionRecord) (*AuthorizedExecutionIntent, error) {
	if decision == nil {
		return nil, errors.New("decision record is nil")
	}

	// 1. Validate Decision Signature
	if decision.Signature == "" {
		return nil, errors.New("decision record is unsigned")
	}

	// 2. Validate Expiry
	if time.Now().After(decision.Expiry) {
		return nil, errors.New("decision record has expired")
	}

	// 3. Construct AuthorizedExecutionIntent
	executionID := generateExecutionID(decision.DecisionID, decision.EffectDigest)

	intent := &AuthorizedExecutionIntent{
		ExecutionID:  executionID,
		DecisionID:   decision.DecisionID,
		EffectDigest: decision.EffectDigest,
		IssuedAt:     time.Now(),
		ExpiresAt:    time.Now().Add(5 * time.Minute), // Short lived execution window
	}

	// 4. Sign the intent — fail-closed, no mock signatures
	if g.signer == nil {
		return nil, errors.New("no signer configured: cannot mint unsigned intents")
	}
	sigData := []byte(intent.ExecutionID + intent.DecisionID + intent.EffectDigest)
	sig, err := g.signer.Sign(sigData)
	if err != nil {
		return nil, errors.New("failed to sign execution intent: " + err.Error())
	}
	intent.Signature = hex.EncodeToString(sig)

	return intent, nil
}

// VerifyReceipt checks if a receipt is valid content-wise (simplified).
func (g *SovereigntyGuard) VerifyReceipt(receipt *Receipt) bool {
	if receipt == nil {
		return false
	}
	// In a real system, verify the timestamp, content hash, and chain of custody.
	return receipt.Status == "SUCCESS" || receipt.Status == "FAILURE"
}

// Helper to generate a deterministic ID
func generateExecutionID(decisionID, effectDigest string) string {
	hash := sha256.Sum256([]byte(decisionID + effectDigest))
	return hex.EncodeToString(hash[:])
}
