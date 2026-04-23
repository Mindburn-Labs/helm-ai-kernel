package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// AlgorithmEd25519 is the algorithm identifier for Ed25519 keys.
const AlgorithmEd25519 = "ed25519"

// AlgorithmMLDSA65 is the algorithm identifier for ML-DSA-65 (FIPS 204) keys.
const AlgorithmMLDSA65 = "ml-dsa-65"

// SoftHSM provides file-backed key management for Ed25519 and ML-DSA-65.
// This is a software implementation suitable for development and testing.
// For production deployments requiring hardware-grade key protection,
// use the PKCS#11 provider in crypto/hsm.
type SoftHSM struct {
	keyDir string
	mu     sync.RWMutex
	keys   map[string]ed25519.PrivateKey
	pqKeys map[string]*mldsa65.PrivateKey
}

func NewSoftHSM(keyDir string) (*SoftHSM, error) {
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create key dir: %w", err)
	}
	return &SoftHSM{
		keyDir: keyDir,
		keys:   make(map[string]ed25519.PrivateKey),
		pqKeys: make(map[string]*mldsa65.PrivateKey),
	}, nil
}

// GetSigner returns an Ed25519 signer for the given key label.
// If no key exists at the label path, a new Ed25519 key pair is generated
// and persisted to disk.
func (h *SoftHSM) GetSigner(keyLabel string) (Signer, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Check in-memory cache first
	if key, ok := h.keys[keyLabel]; ok {
		return NewEd25519SignerFromKey(key, keyLabel), nil
	}

	keyPath := filepath.Join(h.keyDir, keyLabel+".key")

	// Load existing key
	if _, err := os.Stat(keyPath); err == nil {
		keyBytes, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read key %s: %w", keyLabel, err)
		}

		// Handle both seed (32 bytes) and full private key (64 bytes)
		var privKey ed25519.PrivateKey
		switch len(keyBytes) {
		case ed25519.SeedSize:
			privKey = ed25519.NewKeyFromSeed(keyBytes)
		case ed25519.PrivateKeySize:
			privKey = keyBytes
		default:
			return nil, fmt.Errorf("invalid key size for %s: %d", keyLabel, len(keyBytes))
		}

		h.keys[keyLabel] = privKey
		return NewEd25519SignerFromKey(privKey, keyLabel), nil
	}

	// Generate new Ed25519 key pair
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}

	// Persist seed (32 bytes) for compact storage
	if err := os.WriteFile(keyPath, privKey.Seed(), 0o600); err != nil {
		return nil, fmt.Errorf("failed to save key %s: %w", keyLabel, err)
	}

	h.keys[keyLabel] = privKey
	return NewEd25519SignerFromKey(privKey, keyLabel), nil
}

// GetSignerWithAlgorithm returns a signer for the given key label and algorithm.
// Supported algorithms: "ed25519" (default), "ml-dsa-65" (post-quantum).
// If no key exists at the label path, a new key pair is generated and persisted.
func (h *SoftHSM) GetSignerWithAlgorithm(keyLabel, algorithm string) (Signer, error) {
	switch algorithm {
	case AlgorithmEd25519, "":
		return h.GetSigner(keyLabel)
	case AlgorithmMLDSA65:
		return h.getMLDSASigner(keyLabel)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// getMLDSASigner returns an ML-DSA-65 signer for the given key label.
// If no key exists at the label path, a new ML-DSA-65 key pair is generated
// and persisted to disk using the seed (32 bytes) for compact storage.
func (h *SoftHSM) getMLDSASigner(keyLabel string) (Signer, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Check in-memory cache first
	if key, ok := h.pqKeys[keyLabel]; ok {
		return NewMLDSASignerFromKey(key, keyLabel), nil
	}

	keyPath := filepath.Join(h.keyDir, keyLabel+".mldsa65.key")

	// Load existing key from seed
	if _, err := os.Stat(keyPath); err == nil {
		seedBytes, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read ml-dsa-65 key %s: %w", keyLabel, err)
		}

		if len(seedBytes) != mldsa65.SeedSize {
			return nil, fmt.Errorf("invalid ml-dsa-65 seed size for %s: %d, expected %d", keyLabel, len(seedBytes), mldsa65.SeedSize)
		}

		var seed [mldsa65.SeedSize]byte
		copy(seed[:], seedBytes)
		_, priv := mldsa65.NewKeyFromSeed(&seed)

		h.pqKeys[keyLabel] = priv
		return NewMLDSASignerFromKey(priv, keyLabel), nil
	}

	// Generate new ML-DSA-65 key pair
	_, priv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ml-dsa-65 key: %w", err)
	}

	// Persist seed for compact storage
	seed := priv.Seed()
	if err := os.WriteFile(keyPath, seed, 0o600); err != nil {
		return nil, fmt.Errorf("failed to save ml-dsa-65 key %s: %w", keyLabel, err)
	}

	h.pqKeys[keyLabel] = priv
	return NewMLDSASignerFromKey(priv, keyLabel), nil
}
