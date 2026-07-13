package crypto

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// KeyIDer is implemented by signers that expose their key identifier.
// This enables algorithm-agnostic key registration in the KeyRing.
type KeyIDer interface {
	GetKeyID() string
}

// KeyRing implements Signer/Verifier for multiple keys (Rotation support).
type KeyRing struct {
	mu      sync.RWMutex
	signers map[string]Signer // map keyID -> Signer
}

// hybridKeyRingSigner adapts a HybridSigner to the byte-oriented Verifier
// interface used by KeyRing. HybridSigner intentionally exposes a richer
// string-envelope Verify API for callers; storing this adapter means a keyring
// can still select the hybrid key for signing and deterministically verify the
// resulting v2 decision, intent, and receipt envelopes by KeyID.
type hybridKeyRingSigner struct {
	*HybridSigner
}

// signerIdentity is the signer-owned metadata that a versioned envelope must
// carry. Key IDs alone are not sufficient: a keyring may rotate several
// algorithms, and accepting an Ed25519 signature labelled as hybrid (or vice
// versa) would let callers misrepresent the cryptographic posture of a
// governed decision or receipt.
type signerIdentity struct {
	algorithm    string
	profile      string
	publicKeySet map[string]string
}

func (h *hybridKeyRingSigner) Verify(message []byte, signature []byte) bool {
	verified, err := h.HybridSigner.Verify(message, string(signature))
	return err == nil && verified
}

func (h *hybridKeyRingSigner) VerifyDecision(d *contracts.DecisionRecord) (bool, error) {
	if d == nil || d.Signature == "" {
		return false, fmt.Errorf("missing signature")
	}
	payload, err := CanonicalDecisionPayload(d)
	if err != nil {
		return false, err
	}
	return h.HybridSigner.Verify(payload, d.Signature)
}

func (h *hybridKeyRingSigner) VerifyIntent(i *contracts.AuthorizedExecutionIntent) (bool, error) {
	if i == nil || i.Signature == "" {
		return false, fmt.Errorf("missing signature")
	}
	payload, err := CanonicalIntentPayload(i)
	if err != nil {
		return false, err
	}
	return h.HybridSigner.Verify(payload, i.Signature)
}

func (h *hybridKeyRingSigner) VerifyReceipt(r *contracts.Receipt) (bool, error) {
	if r == nil || r.Signature == "" {
		return false, fmt.Errorf("missing signature")
	}
	payload, err := CanonicalReceiptPayload(r)
	if err != nil {
		return false, err
	}
	return h.HybridSigner.Verify(payload, r.Signature)
}

func identityForSigner(s Signer) (signerIdentity, error) {
	switch signer := s.(type) {
	case *Ed25519Signer:
		return signerIdentity{
			algorithm: SigPrefixEd25519,
			profile:   ReceiptProfileClassical,
			publicKeySet: map[string]string{
				SigPrefixEd25519: signer.PublicKey(),
			},
		}, nil
	case *MLDSASigner:
		return signerIdentity{
			algorithm: SigPrefixMLDSA65,
			profile:   ReceiptProfilePQC,
			publicKeySet: map[string]string{
				SigPrefixMLDSA65: signer.PublicKey(),
			},
		}, nil
	case *HybridSigner:
		return signerIdentity{
			algorithm: SigPrefixHybrid,
			profile:   ReceiptProfileHybrid,
			publicKeySet: map[string]string{
				SigPrefixEd25519: signer.Ed25519Signer().PublicKey(),
				SigPrefixMLDSA65: signer.MLDSASigner().PublicKey(),
			},
		}, nil
	case *hybridKeyRingSigner:
		return identityForSigner(signer.HybridSigner)
	default:
		return signerIdentity{}, fmt.Errorf("unsupported keyring signer type %T", s)
	}
}

func parseBoundSignatureType(signatureType string) (algorithm, keyID string, err error) {
	parts := strings.Split(signatureType, SigSeparator)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid signature type format: %s", signatureType)
	}
	algorithm = strings.TrimSpace(parts[0])
	keyID = strings.TrimSpace(parts[1])
	if algorithm == "" || keyID == "" {
		return "", "", fmt.Errorf("invalid signature type format: %s", signatureType)
	}
	return algorithm, keyID, nil
}

func requireSignatureTypeMatchesSigner(s Signer, signatureType string) (string, error) {
	algorithm, keyID, err := parseBoundSignatureType(signatureType)
	if err != nil {
		return "", err
	}
	identity, err := identityForSigner(s)
	if err != nil {
		return "", err
	}
	if algorithm != identity.algorithm {
		return "", fmt.Errorf("signature algorithm %q does not match registered signer algorithm %q", algorithm, identity.algorithm)
	}
	return keyID, nil
}

func samePublicKeySet(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for algorithm, publicKey := range left {
		if right[algorithm] != publicKey {
			return false
		}
	}
	return true
}

var _ Signer = (*hybridKeyRingSigner)(nil)
var _ Verifier = (*hybridKeyRingSigner)(nil)

// NewKeyRing creates a new empty KeyRing.
func NewKeyRing() *KeyRing {
	return &KeyRing{
		signers: make(map[string]Signer),
	}
}

// AddKey adds a signer to the keyring. The signer must implement KeyIDer
// (Ed25519Signer, MLDSASigner) or be an *Ed25519Signer (legacy path).
func (k *KeyRing) AddKey(s Signer) {
	k.mu.Lock()
	defer k.mu.Unlock()
	// HybridSigner has a string-envelope Verify method for its public API and
	// cannot itself satisfy Verifier's byte-envelope method. Store the local
	// adapter so selection and verification stay symmetric in a rotated ring.
	if hybrid, ok := s.(*HybridSigner); ok {
		k.signers[hybrid.GetKeyID()] = &hybridKeyRingSigner{HybridSigner: hybrid}
		return
	}
	if kid, ok := s.(KeyIDer); ok {
		k.signers[kid.GetKeyID()] = s
		return
	}
	// Legacy fallback for Ed25519Signer (uses exported KeyID field)
	if ed, ok := s.(*Ed25519Signer); ok {
		k.signers[ed.KeyID] = s
	}
}

// RevokeKey removes a key from the keyring by ID.
func (k *KeyRing) RevokeKey(keyID string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.signers, keyID)
}

// SignDecision signs with the active key, selected deterministically.
func (k *KeyRing) SignDecision(d *contracts.DecisionRecord) error {
	k.mu.RLock()
	defer k.mu.RUnlock()
	var keys []string
	for k := range k.signers {
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return fmt.Errorf("no keyring keys available")
	}
	sort.Strings(keys)
	selectedKey := keys[len(keys)-1]

	return k.signers[selectedKey].SignDecision(d)
}

// VerifyKey verifies signature for a specific key.
// Supports Ed25519 and ML-DSA-65 signers.
func (k *KeyRing) VerifyKey(keyID string, message []byte, signature []byte) (bool, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	signer, exists := k.signers[keyID]
	if !exists {
		return false, fmt.Errorf("unknown key: %s", keyID)
	}

	if v, ok := signer.(Verifier); ok {
		return v.Verify(message, signature), nil
	}

	return false, fmt.Errorf("signer %s does not support raw verification", keyID)
}

// VerifyDecision verifies a decision against the keyring.
func (k *KeyRing) VerifyDecision(d *contracts.DecisionRecord) (bool, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if d == nil {
		return false, fmt.Errorf("decision is required")
	}

	// The signature type is part of the v2 preimage and must select exactly one
	// registered signer. Do not treat a malformed or algorithm-confused label as
	// an all-key lookup: that would erase the key/algorithm binding on rotation.
	_, keyID, err := parseBoundSignatureType(d.SignatureType)
	if err != nil {
		return false, err
	}

	signer, exists := k.signers[keyID]
	if !exists {
		return false, fmt.Errorf("unknown or revoked key: %s", keyID)
	}
	if _, err := requireSignatureTypeMatchesSigner(signer, d.SignatureType); err != nil {
		return false, err
	}

	//nolint:wrapcheck // internal delegation
	if v, ok := signer.(Verifier); ok {
		return v.VerifyDecision(d)
	}
	return false, fmt.Errorf("key %s does not implement Verifier", keyID)
}

// Sign signs data with the first available key.
func (k *KeyRing) Sign(data []byte) (string, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	// Deterministic selection
	var keys []string
	for k := range k.signers {
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return "", fmt.Errorf("no keyring keys available")
	}
	sort.Strings(keys)
	selectedKey := keys[len(keys)-1]

	return k.signers[selectedKey].Sign(data)
}

func (k *KeyRing) VerifyIntent(i *contracts.AuthorizedExecutionIntent) (bool, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if i == nil {
		return false, fmt.Errorf("execution intent is required")
	}

	// A non-empty signature type is an explicit signer claim and must be fully
	// well-formed and match the registered signer. Only a truly legacy intent
	// with no signature type may use the audit-only all-key fallback.
	if i.SignatureType != "" {
		_, keyID, err := parseBoundSignatureType(i.SignatureType)
		if err != nil {
			return false, err
		}
		signer, exists := k.signers[keyID]
		if !exists {
			return false, fmt.Errorf("unknown or revoked key: %s", keyID)
		}
		if _, err := requireSignatureTypeMatchesSigner(signer, i.SignatureType); err != nil {
			return false, err
		}
		if v, ok := signer.(Verifier); ok {
			return v.VerifyIntent(i)
		}
		return false, fmt.Errorf("key %s does not implement Verifier", keyID)
	}

	// Fallback: try all keys for backward compatibility with intents that lack SignatureType.
	for _, s := range k.signers {
		if v, ok := s.(Verifier); ok {
			if verified, err := v.VerifyIntent(i); verified && err == nil {
				return true, nil
			}
		}
	}
	return false, fmt.Errorf("no key verified the intent")
}

func (k *KeyRing) Verify(message []byte, signature []byte) bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	// Try all keys
	for _, s := range k.signers {
		if v, ok := s.(Verifier); ok {
			if v.Verify(message, signature) {
				return true
			}
		}
		// Or if Signer is not Verifier? Signer extends Verifier usually.
	}
	return false
}

func (k *KeyRing) PublicKey() string {
	// KeyRing doesn't have a single public key.
	// We returns a marker to indicate this is a keyring.
	return "keyring-aggregate"
}

// PublicKeyBytes returns nil for a KeyRing since it is an aggregate of multiple keys.
func (k *KeyRing) PublicKeyBytes() []byte {
	return nil
}

// SignIntent signs an intent with the first available key.
func (k *KeyRing) SignIntent(i *contracts.AuthorizedExecutionIntent) error {
	k.mu.RLock()
	defer k.mu.RUnlock()

	// Deterministic selection
	var keys []string
	for k := range k.signers {
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return fmt.Errorf("no keyring keys available")
	}
	sort.Strings(keys)
	selectedKey := keys[len(keys)-1]

	return k.signers[selectedKey].SignIntent(i)
}

// SignReceipt signs a receipt with the first available key.
func (k *KeyRing) SignReceipt(r *contracts.Receipt) error {
	k.mu.RLock()
	defer k.mu.RUnlock()

	// Deterministic selection
	var keys []string
	for k := range k.signers {
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return fmt.Errorf("no keyring keys available")
	}
	sort.Strings(keys)
	selectedKey := keys[len(keys)-1]

	return k.signers[selectedKey].SignReceipt(r)
}

// VerifyReceipt verifies a receipt against the keyring. A v2 receipt carries a
// signed KeyID, so it must be verified by exactly that registered key. Trying
// every key for a v2 envelope would reintroduce signer-identity ambiguity after
// key rotation. Historic v1 receipts have no key identifier and retain the
// audit-only all-key fallback.
func (k *KeyRing) VerifyReceipt(r *contracts.Receipt) (bool, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if r == nil {
		return false, fmt.Errorf("receipt is required")
	}

	switch r.SignatureSchema {
	case ReceiptSignatureSchemaV2:
		if r.KeyID == "" {
			return false, fmt.Errorf("receipt signature schema %q requires key_id", ReceiptSignatureSchemaV2)
		}
		signer, exists := k.signers[r.KeyID]
		if !exists {
			return false, fmt.Errorf("unknown or revoked key: %s", r.KeyID)
		}
		identity, err := identityForSigner(signer)
		if err != nil {
			return false, err
		}
		if r.SignatureAlgorithm != identity.algorithm {
			return false, fmt.Errorf("receipt signature algorithm %q does not match registered signer algorithm %q", r.SignatureAlgorithm, identity.algorithm)
		}
		if r.SignatureProfile != identity.profile {
			return false, fmt.Errorf("receipt signature profile %q does not match registered signer profile %q", r.SignatureProfile, identity.profile)
		}
		if !samePublicKeySet(r.PublicKeySet, identity.publicKeySet) {
			return false, fmt.Errorf("receipt public_key_set does not match registered signer %q", r.KeyID)
		}
		if v, ok := signer.(Verifier); ok {
			return v.VerifyReceipt(r)
		}
		return false, fmt.Errorf("key %s does not implement Verifier", r.KeyID)
	case "":
		for _, s := range k.signers {
			if v, ok := s.(Verifier); ok {
				if verified, err := v.VerifyReceipt(r); verified && err == nil {
					return true, nil
				}
			}
		}
		return false, fmt.Errorf("no key verified the legacy receipt")
	default:
		return false, fmt.Errorf("unsupported receipt signature schema %q", r.SignatureSchema)
	}
}
