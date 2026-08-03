package crypto

// quantum_posture: classical receipt signing metadata for profile comparison.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
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

// NewEd25519Signer creates a signer backed by a fresh, ephemeral keypair.
//
// The argument is a key *identifier* — a label written into receipts — and NOT
// key material. Nothing about the returned signer is derived from it. Every
// process restart yields a new keypair, so receipts signed by an ephemeral
// signer cannot be verified afterwards and establish no trust root.
//
// Use NewEd25519SignerFromSeed or NewEd25519SignerFromKey for any signer whose
// signatures must outlive the process. This constructor fails closed under
// HELM_PRODUCTION so an unstable trust root cannot reach a deployment.
func NewEd25519Signer(keyID string) (*Ed25519Signer, error) {
	if productionMode() {
		return nil, fmt.Errorf(
			"refusing to create ephemeral signer %q under HELM_PRODUCTION: "+
				"ephemeral keys rotate on restart and invalidate every receipt they sign; "+
				"supply persistent key material via NewEd25519SignerFromSeed", keyID)
	}
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

// NewEd25519SignerFromSeed derives a deterministic signer from a 32-byte
// Ed25519 seed. The same seed always yields the same keypair, which is what
// makes previously issued receipts verifiable after a restart.
//
// keyID is a public label and must not contain the seed — it is published in
// every receipt's KeyID field.
func NewEd25519SignerFromSeed(seed []byte, keyID string) (*Ed25519Signer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("ed25519 seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	return NewEd25519SignerFromKey(ed25519.NewKeyFromSeed(seed), keyID), nil
}

// NewEd25519SignerFromSecret derives a deterministic signer from an
// operator-supplied secret — the shape that arrives through flags and
// environment variables such as --sign, SYSTEM_BOOT_KEY and
// EVIDENCE_SIGNING_KEY.
//
// A hex- or base64-encoded 32-byte seed (or a 64-byte private key) is used
// directly. Any other string is treated as a passphrase and hashed to a seed so
// that the trust root is still stable across restarts. Passphrase derivation is
// a single SHA-256 with no salt and no KDF: it preserves determinism, not
// entropy. derivedFromPassphrase reports which path was taken so callers can
// warn operators who supplied a low-entropy secret.
//
// The secret is never used as, or embedded in, the key identifier — keyID is
// published in every receipt.
func NewEd25519SignerFromSecret(secret, keyID string) (signer *Ed25519Signer, derivedFromPassphrase bool, err error) {
	trimmed := strings.TrimSpace(secret)
	if trimmed == "" {
		return nil, false, fmt.Errorf("empty signing secret for key %q", keyID)
	}

	if raw, decErr := hex.DecodeString(trimmed); decErr == nil {
		switch len(raw) {
		case ed25519.SeedSize:
			s, err := NewEd25519SignerFromSeed(raw, keyID)
			return s, false, err
		case ed25519.PrivateKeySize:
			s, err := NewEd25519SignerFromSeed(raw[:ed25519.SeedSize], keyID)
			return s, false, err
		}
	}
	if raw, decErr := base64.StdEncoding.DecodeString(trimmed); decErr == nil {
		switch len(raw) {
		case ed25519.SeedSize:
			s, err := NewEd25519SignerFromSeed(raw, keyID)
			return s, false, err
		case ed25519.PrivateKeySize:
			s, err := NewEd25519SignerFromSeed(raw[:ed25519.SeedSize], keyID)
			return s, false, err
		}
	}

	digest := sha256.Sum256([]byte(trimmed))
	s, err := NewEd25519SignerFromSeed(digest[:], keyID)
	return s, true, err
}

// productionMode reports whether the process is running with production
// fail-closed semantics enabled.
func productionMode() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("HELM_PRODUCTION"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
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
//
// There is deliberately no result cache here. The previous implementation keyed
// a process-global cache on sha256(pubKeyHex ‖ sigHex ‖ data) with no length
// prefixes or delimiters, and consulted it before decoding or length-checking
// its inputs. Because the concatenation is ambiguous, moving bytes across the
// signature/message boundary produced an identical key, letting a forged pair
// inherit a genuine pair's cached `true` without ed25519.Verify ever running.
// ed25519.Verify costs tens of microseconds; correctness is worth more.
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
		return false, fmt.Errorf("invalid public key size: got %d, want %d", len(pubKey), ed25519.PublicKeySize)
	}
	if len(sig) != ed25519.SignatureSize {
		return false, fmt.Errorf("invalid signature size: got %d, want %d", len(sig), ed25519.SignatureSize)
	}

	return ed25519.Verify(ed25519.PublicKey(pubKey), data, sig), nil
}

func (s *Ed25519Signer) Verify(message []byte, signature []byte) bool {
	return ed25519.Verify(s.pubKey, message, signature)
}

// SignDecision signs a DecisionRecord
func (s *Ed25519Signer) SignDecision(d *contracts.DecisionRecord) error {
	payload, err := prepareDecisionForSigning(d, SigPrefixEd25519+SigSeparator+s.KeyID)
	if err != nil {
		return err
	}
	sig, err := s.Sign(payload)
	if err != nil {
		return err
	}
	d.Signature = sig
	return nil
}

func (s *Ed25519Signer) SignIntent(i *contracts.AuthorizedExecutionIntent) error {
	payload, err := prepareAuthorizedExecutionIntent(i, SigPrefixEd25519+SigSeparator+s.KeyID)
	if err != nil {
		return err
	}
	sig, err := s.Sign(payload)
	if err != nil {
		return err
	}
	i.Signature = sig
	return nil
}

// SignReceipt signs a Receipt
func (s *Ed25519Signer) SignReceipt(r *contracts.Receipt) error {
	// ReceiptSigningPayload selects the active versioned receipt preimage.
	payload, err := ReceiptSigningPayload(r)
	if err != nil {
		return err
	}
	sig, err := s.Sign(payload)
	if err != nil {
		return err
	}
	r.Signature = sig
	r.SignatureProfile = ReceiptProfileClassical
	r.SignatureAlgorithm = SigPrefixEd25519
	r.KeyID = s.KeyID
	r.PublicKeySet = map[string]string{SigPrefixEd25519: s.PublicKey()}
	return nil
}

// VerifyDecision verifies a DecisionRecord signature
func (s *Ed25519Signer) VerifyDecision(d *contracts.DecisionRecord) (bool, error) {
	if d.Signature == "" {
		return false, fmt.Errorf("missing signature")
	}
	payload, perr := DecisionVerifyPayload(d)
	if perr != nil {
		return false, perr
	}
	return Verify(s.PublicKey(), d.Signature, payload)
}

func (s *Ed25519Signer) VerifyIntent(i *contracts.AuthorizedExecutionIntent) (bool, error) {
	if i.Signature == "" {
		return false, fmt.Errorf("missing signature")
	}
	payload, err := CanonicalizeAuthorizedExecutionIntent(i)
	if err != nil {
		return false, err
	}
	return Verify(s.PublicKey(), i.Signature, payload)
}

func (s *Ed25519Signer) VerifyReceipt(r *contracts.Receipt) (bool, error) {
	if r.Signature == "" {
		return false, fmt.Errorf("missing signature")
	}
	payload, perr := ReceiptVerifyPayload(r)
	if perr != nil {
		return false, perr
	}
	return Verify(s.PublicKey(), r.Signature, payload)
}

// SignCounterfactualReceipt seals (if needed) and signs a counterfactual
// receipt. The signature covers the enforcement-prefixed receipt hash, so it can
// never be lifted onto an enforced receipt. Validation runs first: a receipt that
// is not labeled counterfactual will not seal and will not be signed.
func (s *Ed25519Signer) SignCounterfactualReceipt(r *contracts.CounterfactualReceipt) error {
	sealed, err := r.Seal()
	if err != nil {
		return err
	}
	sig, err := s.Sign([]byte(sealed.SigningPayload()))
	if err != nil {
		return err
	}
	sealed.SignerKeyID = s.PublicKey()
	sealed.Signature = sig
	*r = sealed
	return nil
}

// VerifyCounterfactualReceipt verifies the signature over a counterfactual
// receipt. It re-seals the receipt to recompute the content hash, so a tampered
// would-have verdict, reason code, or grant id breaks verification. A receipt
// that does not validate as counterfactual is rejected before any signature math.
func (s *Ed25519Signer) VerifyCounterfactualReceipt(r *contracts.CounterfactualReceipt) (bool, error) {
	if r.Signature == "" {
		return false, fmt.Errorf("missing signature")
	}
	sealed, err := r.Seal()
	if err != nil {
		return false, err
	}
	return Verify(s.PublicKey(), r.Signature, []byte(sealed.SigningPayload()))
}
