package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// Signer defines the interface for cryptographic signing operations.
// For verification, use the separate Verifier interface.
type Signer interface {
	Sign(data []byte) (string, error)
	PublicKey() string
	PublicKeyBytes() []byte
	SignDecision(d *contracts.DecisionRecord) error
	SignIntent(i *contracts.AuthorizedExecutionIntent) error
	SignReceipt(r *contracts.Receipt) error
}

// Ed25519Signer implementation.
type Ed25519Signer struct {
	privKey ed25519.PrivateKey
	pubKey  ed25519.PublicKey
	KeyID   string
}

func NewEd25519Signer(keyID string) (*Ed25519Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("key generation failed: %w", err)
	}
	return &Ed25519Signer{
		privKey: priv,
		pubKey:  pub,
		KeyID:   keyID,
	}, nil
}

// GetKeyID returns the key identifier.
func (s *Ed25519Signer) GetKeyID() string { return s.KeyID }

func NewEd25519SignerFromKey(priv ed25519.PrivateKey, keyID string) *Ed25519Signer {
	return &Ed25519Signer{
		privKey: priv,
		pubKey:  priv.Public().(ed25519.PublicKey),
		KeyID:   keyID,
	}
}

func (s *Ed25519Signer) Sign(data []byte) (string, error) {
	sig := ed25519.Sign(s.privKey, data)
	return hex.EncodeToString(sig), nil
}

func (s *Ed25519Signer) PublicKey() string {
	return hex.EncodeToString(s.pubKey)
}

func (s *Ed25519Signer) PublicKeyBytes() []byte {
	return s.pubKey
}

// Verify verifies a signature against a public key.
func Verify(pubKeyHex, sigHex string, data []byte) (bool, error) {
	pubKey, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return false, fmt.Errorf("invalid public key hex: %w", err)
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return false, fmt.Errorf("invalid signature hex: %w", err)
	}

	if len(pubKey) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid public key size")
	}

	return ed25519.Verify(ed25519.PublicKey(pubKey), data, sig), nil
}

func (s *Ed25519Signer) Verify(message []byte, signature []byte) bool {
	return ed25519.Verify(s.pubKey, message, signature)
}

// SignDecision signs a DecisionRecord
func (s *Ed25519Signer) SignDecision(d *contracts.DecisionRecord) error {
	// Canonicalize for signing
	payload := CanonicalizeDecision(d.ID, d.Verdict, d.Reason, d.PhenotypeHash, d.PolicyContentHash, d.EffectDigest)
	sig, err := s.Sign([]byte(payload))
	if err != nil {
		return err
	}
	d.Signature = sig
	d.SignatureType = SigPrefixEd25519 + SigSeparator + s.KeyID
	return nil
}

func (s *Ed25519Signer) SignIntent(i *contracts.AuthorizedExecutionIntent) error {
	payload := CanonicalizeIntent(i.ID, i.DecisionID, i.AllowedTool)
	sig, err := s.Sign([]byte(payload))
	if err != nil {
		return err
	}
	i.Signature = sig
	return nil
}

// SignReceipt signs a Receipt
func (s *Ed25519Signer) SignReceipt(r *contracts.Receipt) error {
	// Canonicalize: ID:DecisionID:EffectID:Status:OutputHash
	payload := CanonicalizeReceipt(r.ReceiptID, r.DecisionID, r.EffectID, r.Status, r.OutputHash, r.PrevHash, r.LamportClock, r.ArgsHash)
	sig, err := s.Sign([]byte(payload))
	if err != nil {
		return err
	}
	r.Signature = sig
	return nil
}

// VerifyDecision verifies a DecisionRecord signature
func (s *Ed25519Signer) VerifyDecision(d *contracts.DecisionRecord) (bool, error) {
	if d.Signature == "" {
		return false, fmt.Errorf("missing signature")
	}
	payload := CanonicalizeDecision(d.ID, d.Verdict, d.Reason, d.PhenotypeHash, d.PolicyContentHash, d.EffectDigest)
	return Verify(s.PublicKey(), d.Signature, []byte(payload))
}

func (s *Ed25519Signer) VerifyIntent(i *contracts.AuthorizedExecutionIntent) (bool, error) {
	if i.Signature == "" {
		return false, fmt.Errorf("missing signature")
	}
	payload := CanonicalizeIntent(i.ID, i.DecisionID, i.AllowedTool)
	return Verify(s.PublicKey(), i.Signature, []byte(payload))
}

func (s *Ed25519Signer) VerifyReceipt(r *contracts.Receipt) (bool, error) {
	if r.Signature == "" {
		return false, fmt.Errorf("missing signature")
	}
	payload := CanonicalizeReceipt(r.ReceiptID, r.DecisionID, r.EffectID, r.Status, r.OutputHash, r.PrevHash, r.LamportClock, r.ArgsHash)
	return Verify(s.PublicKey(), r.Signature, []byte(payload))
}
