// quantum_posture: the spend proxy signs BudgetVerdict receipts with a
// classical Ed25519 key and hashes canonical payloads with SHA-256; the
// trusted-key registry file stores public keys only. No post-quantum
// primitives are used in this file.

package spendproxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

// Issuer is the in-process BudgetVerdict signer. The engine creates verdict
// receipts unsigned; the proxy seals them with this key before they are
// persisted, and the matching public key is registered in the trusted-key
// registry so receipts stay verifiable after the process exits.
type Issuer struct {
	keyID string
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
}

// NewIssuer builds an issuer from an operator-supplied secret. A hex- or
// base64-encoded 32-byte seed (or 64-byte private key) is used directly; any
// other non-empty string is treated as a passphrase and hashed to a seed
// (deterministic but low-entropy — derivedFromPassphrase reports it so callers
// can warn). An empty secret generates a fresh key: past receipts remain
// verifiable through the registry's stored public key, but a restarted proxy
// signs under a new key id.
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
	sum := sha256.Sum256(pub)
	return &Issuer{
		keyID: "spend-proxy-" + hex.EncodeToString(sum[:6]),
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

// Sign seals a BudgetVerdict receipt with the issuer key. Only ALLOW receipts
// exist (the engine issues no receipt on DENY/ESCALATE), and a receipt that is
// already sealed by this issuer is left untouched.
func (i *Issuer) Sign(r *economic.BudgetVerdictReceipt) error {
	if r == nil {
		return errors.New("spendproxy: nil budget verdict receipt")
	}
	if r.Signature != "" && r.SignatureKeyID == i.keyID {
		return nil
	}
	return r.Seal(i.keyID, i.priv)
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
	path string
	keys map[string]RegisteredKey
}

// OpenTrustedKeys loads (or initializes) the registry file inside dir.
func OpenTrustedKeys(dir string) (*TrustedKeys, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("spendproxy: create receipts dir: %w", err)
	}
	path := filepath.Join(dir, TrustedKeyFileName)
	t := &TrustedKeys{path: path, keys: make(map[string]RegisteredKey)}
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

// Register adds a public key under a key id and persists the registry.
// Re-registering the identical key is a no-op; registering a DIFFERENT key
// under an existing id fails closed (a key id must never be re-bound).
func (t *TrustedKeys) Register(keyID string, pub ed25519.PublicKey) error {
	if keyID == "" {
		return errors.New("spendproxy: trusted key id is required")
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("spendproxy: trusted key must be %d bytes", ed25519.PublicKeySize)
	}
	encoded := "ed25519:" + hex.EncodeToString(pub)
	t.mu.Lock()
	defer t.mu.Unlock()
	if existing, ok := t.keys[keyID]; ok {
		if existing.PublicKey != encoded {
			return fmt.Errorf("spendproxy: trusted key id %q is already bound to a different key", keyID)
		}
		return nil
	}
	t.keys[keyID] = RegisteredKey{
		Algorithm:    "ed25519",
		PublicKey:    encoded,
		RegisteredAt: time.Now().UTC(),
	}
	return t.persistLocked()
}

func (t *TrustedKeys) persistLocked() error {
	data, err := json.MarshalIndent(trustedKeyFile{Version: "spend-proxy-trusted-keys.v1", Keys: t.keys}, "", "  ")
	if err != nil {
		return fmt.Errorf("spendproxy: marshal trusted keys: %w", err)
	}
	tmp := t.path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("spendproxy: write trusted keys: %w", err)
	}
	if err := os.Rename(tmp, t.path); err != nil {
		return fmt.Errorf("spendproxy: replace trusted keys: %w", err)
	}
	return nil
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

// Verify checks a receipt's Ed25519 signature against the registered key for
// its SignatureKeyID. Unknown key ids fail closed.
func (t *TrustedKeys) Verify(r *economic.BudgetVerdictReceipt) error {
	if r == nil {
		return errors.New("spendproxy: nil budget verdict receipt")
	}
	pub, ok := t.PublicKeyFor(r.SignatureKeyID)
	if !ok {
		return fmt.Errorf("spendproxy: signature key %q is not in the trusted-key registry", r.SignatureKeyID)
	}
	return r.VerifySignature(pub)
}
