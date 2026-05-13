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

	// Parse 'ed25519:key-id'
	parts := strings.Split(d.SignatureType, SigSeparator)
	if len(parts) != 2 {
		return false, fmt.Errorf("invalid signature type format: %s", d.SignatureType)
	}
	keyID := parts[1]

	signer, exists := k.signers[keyID]
	if !exists {
		return false, fmt.Errorf("unknown or revoked key: %s", keyID)
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

	// If the intent has a SignatureType with key ID (e.g. "ed25519:key-id"), verify against that specific key.
	if i.SignatureType != "" {
		parts := strings.Split(i.SignatureType, SigSeparator)
		if len(parts) == 2 {
			keyID := parts[1]
			signer, exists := k.signers[keyID]
			if !exists {
				return false, fmt.Errorf("unknown or revoked key: %s", keyID)
			}
			if v, ok := signer.(Verifier); ok {
				return v.VerifyIntent(i)
			}
			return false, fmt.Errorf("key %s does not implement Verifier", keyID)
		}
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

// VerifyReceipt verifies a receipt against the keyring.
// If the receipt's signature contains a key ID prefix (e.g. "ed25519:key-id:sig"),
// verification targets that specific key. Otherwise falls back to trying all keys.
func (k *KeyRing) VerifyReceipt(r *contracts.Receipt) (bool, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	// Try all keys since receipt doesn't have a separate key ID field yet.
	// Future: add SignatureType to Receipt for targeted verification.
	for _, s := range k.signers {
		if v, ok := s.(Verifier); ok {
			if verified, err := v.VerifyReceipt(r); verified && err == nil {
				return true, nil
			}
		}
	}
	return false, fmt.Errorf("no key verified the receipt")
}
