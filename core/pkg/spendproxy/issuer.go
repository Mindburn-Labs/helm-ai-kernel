// quantum_posture: offline savings manifests use classical Ed25519 signatures
// and SHA-256 hashes. Historical registries contain public keys only.

package spendproxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Issuer signs offline savings manifests. It grants no spending authority.
type Issuer struct {
	keyID string
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
}

// NewIssuer builds an issuer from an operator-supplied secret. A hex- or
// base64-encoded 32-byte seed (or 64-byte private key) is used directly; any
// other non-empty string is treated as a passphrase and hashed to a seed
// (deterministic but low-entropy — derivedFromPassphrase reports it so callers
// can warn). An empty secret generates a fresh key that lives in memory only.
// The offline CLI requires an explicit key when producing a signed manifest.
func NewIssuer(secret string) (issuer *Issuer, derivedFromPassphrase bool, err error) {
	var priv ed25519.PrivateKey
	trimmed := strings.TrimSpace(secret)
	switch {
	case trimmed == "":
		_, generated, genErr := ed25519.GenerateKey(rand.Reader)
		if genErr != nil {
			return nil, false, fmt.Errorf("spendproxy: generate signing key: %w", genErr)
		}
		priv = generated
	default:
		seed, fromPassphrase, decErr := decodeSigningSeed(trimmed)
		if decErr != nil {
			return nil, false, decErr
		}
		derivedFromPassphrase = fromPassphrase
		priv = ed25519.NewKeyFromSeed(seed)
	}
	pub := priv.Public().(ed25519.PublicKey)
	return &Issuer{
		keyID: IssuerKeyID(pub),
		priv:  priv,
		pub:   pub,
	}, derivedFromPassphrase, nil
}

func decodeSigningSeed(secret string) (seed []byte, derivedFromPassphrase bool, err error) {
	if raw, decErr := hex.DecodeString(secret); decErr == nil {
		switch len(raw) {
		case ed25519.SeedSize:
			return raw, false, nil
		case ed25519.PrivateKeySize:
			return raw[:ed25519.SeedSize], false, nil
		}
	}
	if raw, decErr := base64.StdEncoding.DecodeString(secret); decErr == nil {
		switch len(raw) {
		case ed25519.SeedSize:
			return raw, false, nil
		case ed25519.PrivateKeySize:
			return raw[:ed25519.SeedSize], false, nil
		}
	}
	digest := sha256.Sum256([]byte(secret))
	return digest[:], true, nil
}

// KeyID returns the public key identifier written into receipts.
func (i *Issuer) KeyID() string { return i.keyID }

// PublicKey returns the verifying key.
func (i *Issuer) PublicKey() ed25519.PublicKey { return i.pub }

// SignRaw signs arbitrary bytes with the issuer key (used for the savings
// pack manifest-hash signature), returning the key id and raw signature.
func (i *Issuer) SignRaw(payload []byte) (keyID string, signature []byte, err error) {
	return i.keyID, ed25519.Sign(i.priv, payload), nil
}

// TrustedKeyFileName is the trusted-key registry file inside a receipts dir.
const TrustedKeyFileName = "trusted_keys.json"

// RegisteredKey is one trusted verdict-signing public key.
type RegisteredKey struct {
	Algorithm    string    `json:"algorithm"`
	PublicKey    string    `json:"public_key"` // "ed25519:<hex>"
	RegisteredAt time.Time `json:"registered_at"`
}

type trustedKeyFile struct {
	Version string                   `json:"version"`
	Keys    map[string]RegisteredKey `json:"keys"`
}

// TrustedKeys is the durable registry of verdict-signing public keys. Receipts
// reference keys by SignatureKeyID; verification resolves the public key here,
// so receipts signed by past process runs stay verifiable.
type TrustedKeys struct {
	mu   sync.Mutex
	keys map[string]RegisteredKey
}

// OpenTrustedKeys reads a historical registry without creating or changing it.
func OpenTrustedKeys(dir string) (*TrustedKeys, error) {
	path := filepath.Join(dir, TrustedKeyFileName)
	t := &TrustedKeys{keys: make(map[string]RegisteredKey)}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return t, nil
		}
		return nil, fmt.Errorf("spendproxy: read trusted keys: %w", err)
	}
	var file trustedKeyFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("spendproxy: parse trusted keys %s: %w", path, err)
	}
	if file.Keys != nil {
		t.keys = file.Keys
	}
	return t, nil
}

// PublicKeyFor resolves a registered public key by id.
func (t *TrustedKeys) PublicKeyFor(keyID string) (ed25519.PublicKey, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	entry, ok := t.keys[keyID]
	if !ok {
		return nil, false
	}
	raw := strings.TrimPrefix(entry.PublicKey, "ed25519:")
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, false
	}
	return ed25519.PublicKey(decoded), true
}
