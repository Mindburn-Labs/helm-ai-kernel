package crypto

import (
	"encoding/hex"
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// MLDSASigner implements the Signer interface using ML-DSA-65 (FIPS 204).
// ML-DSA-65 provides NIST post-quantum digital signatures with category 3
// (128-bit classical / 128-bit quantum) security. Signatures are ~3293 bytes,
// public keys ~1952 bytes. This is the first production PQ signer in any
// AI governance framework.
type MLDSASigner struct {
	privateKey *mldsa65.PrivateKey
	publicKey  *mldsa65.PublicKey
	keyID      string
}

// NewMLDSASigner generates a new ML-DSA-65 keypair using crypto/rand.
func NewMLDSASigner(keyID string) (*MLDSASigner, error) {
	pub, priv, err := mldsa65.GenerateKey(nil) // nil uses crypto/rand
	if err != nil {
		return nil, fmt.Errorf("ml-dsa-65 key generation failed: %w", err)
	}
	return &MLDSASigner{privateKey: priv, publicKey: pub, keyID: keyID}, nil
}

// NewMLDSASignerFromKey creates a signer from an existing ML-DSA-65 private key.
func NewMLDSASignerFromKey(priv *mldsa65.PrivateKey, keyID string) *MLDSASigner {
	pub := priv.Public().(*mldsa65.PublicKey)
	return &MLDSASigner{privateKey: priv, publicKey: pub, keyID: keyID}
}

// GetKeyID returns the key identifier.
func (s *MLDSASigner) GetKeyID() string { return s.keyID }

// Sign signs data using ML-DSA-65 deterministic mode and returns hex-encoded signature.
// Uses nil context and deterministic signing (randomized=false) for reproducibility.
func (s *MLDSASigner) Sign(data []byte) (string, error) {
	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(s.privateKey, data, nil, false, sig); err != nil {
		return "", fmt.Errorf("ml-dsa-65 sign failed: %w", err)
	}
	return hex.EncodeToString(sig), nil
}

// PublicKey returns the hex-encoded public key.
// If MarshalBinary fails (corrupt key), returns empty string.
func (s *MLDSASigner) PublicKey() string {
	bytes, err := s.publicKey.MarshalBinary()
	if err != nil {
		// A marshal failure means the key is corrupt — this should never
		// happen with a properly constructed signer. Panic to fail-closed
		// rather than silently returning a value that could bypass verification.
		panic(fmt.Sprintf("ml-dsa-65: corrupt public key, MarshalBinary failed: %v", err))
	}
	return hex.EncodeToString(bytes)
}

// PublicKeyBytes returns raw public key bytes.
// Returns nil if MarshalBinary fails (corrupt key).
func (s *MLDSASigner) PublicKeyBytes() []byte {
	bytes, err := s.publicKey.MarshalBinary()
	if err != nil {
		return nil
	}
	return bytes
}

// Verify verifies a message against a raw signature using ML-DSA-65.
func (s *MLDSASigner) Verify(message []byte, signature []byte) bool {
	return mldsa65.Verify(s.publicKey, message, nil, signature)
}

// SignDecision signs a DecisionRecord using ML-DSA-65.
func (s *MLDSASigner) SignDecision(d *contracts.DecisionRecord) error {
	payload := CanonicalizeDecision(d.ID, d.Verdict, d.Reason, d.PhenotypeHash, d.PolicyContentHash, d.EffectDigest)
	sig, err := s.Sign([]byte(payload))
	if err != nil {
		return err
	}
	d.Signature = sig
	d.SignatureType = SigPrefixMLDSA65 + SigSeparator + s.keyID
	return nil
}

// SignIntent signs an AuthorizedExecutionIntent using ML-DSA-65.
func (s *MLDSASigner) SignIntent(i *contracts.AuthorizedExecutionIntent) error {
	payload := CanonicalizeIntent(i.ID, i.DecisionID, i.AllowedTool)
	sig, err := s.Sign([]byte(payload))
	if err != nil {
		return err
	}
	i.Signature = sig
	i.SignatureType = SigPrefixMLDSA65 + SigSeparator + s.keyID
	return nil
}

// SignReceipt signs a Receipt using ML-DSA-65.
func (s *MLDSASigner) SignReceipt(r *contracts.Receipt) error {
	payload := CanonicalizeReceipt(r.ReceiptID, r.DecisionID, r.EffectID, r.Status, r.OutputHash, r.PrevHash, r.LamportClock, r.ArgsHash)
	sig, err := s.Sign([]byte(payload))
	if err != nil {
		return err
	}
	r.Signature = sig
	return nil
}

// VerifyDecision verifies a DecisionRecord signature using ML-DSA-65.
func (s *MLDSASigner) VerifyDecision(d *contracts.DecisionRecord) (bool, error) {
	if d.Signature == "" {
		return false, fmt.Errorf("missing signature")
	}
	payload := CanonicalizeDecision(d.ID, d.Verdict, d.Reason, d.PhenotypeHash, d.PolicyContentHash, d.EffectDigest)
	sig, err := hex.DecodeString(d.Signature)
	if err != nil {
		return false, fmt.Errorf("invalid signature hex: %w", err)
	}
	return mldsa65.Verify(s.publicKey, []byte(payload), nil, sig), nil
}

// VerifyIntent verifies an AuthorizedExecutionIntent signature using ML-DSA-65.
func (s *MLDSASigner) VerifyIntent(i *contracts.AuthorizedExecutionIntent) (bool, error) {
	if i.Signature == "" {
		return false, fmt.Errorf("missing signature")
	}
	payload := CanonicalizeIntent(i.ID, i.DecisionID, i.AllowedTool)
	sig, err := hex.DecodeString(i.Signature)
	if err != nil {
		return false, fmt.Errorf("invalid signature hex: %w", err)
	}
	return mldsa65.Verify(s.publicKey, []byte(payload), nil, sig), nil
}

// VerifyReceipt verifies a Receipt signature using ML-DSA-65.
func (s *MLDSASigner) VerifyReceipt(r *contracts.Receipt) (bool, error) {
	if r.Signature == "" {
		return false, fmt.Errorf("missing signature")
	}
	payload := CanonicalizeReceipt(r.ReceiptID, r.DecisionID, r.EffectID, r.Status, r.OutputHash, r.PrevHash, r.LamportClock, r.ArgsHash)
	sig, err := hex.DecodeString(r.Signature)
	if err != nil {
		return false, fmt.Errorf("invalid signature hex: %w", err)
	}
	return mldsa65.Verify(s.publicKey, []byte(payload), nil, sig), nil
}
