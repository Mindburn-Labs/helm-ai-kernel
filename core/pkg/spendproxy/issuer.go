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
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
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
// can warn). An empty secret generates a fresh key that lives in memory only.
// The proxy and reconcile never pass an empty secret: without one they sign
// with the seed generated in the receipts directory (SigningSeedFileName).
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

// SignDetached signs the RFC 8785 (JCS) canonicalization of an arbitrary
// receipt payload with the issuer key, returning the key id and the base64
// signature. Detached signatures cover EVERY field of the payload — including
// post-dispatch fields (token counts, timestamps, substitution flags) that the
// receipt types' sealed content-hash preimages deliberately omit — so a pack
// carrying them cannot have those fields rewritten without the signing key.
func (i *Issuer) SignDetached(payload any) (keyID, signature string, err error) {
	canonical, err := canonicalize.JCS(payload)
	if err != nil {
		return "", "", fmt.Errorf("spendproxy: canonicalize payload for detached signature: %w", err)
	}
	sig := ed25519.Sign(i.priv, canonical)
	return i.keyID, base64.StdEncoding.EncodeToString(sig), nil
}

// SignRaw signs arbitrary bytes with the issuer key (used for the savings
// pack manifest-hash signature), returning the key id and raw signature.
func (i *Issuer) SignRaw(payload []byte) (keyID string, signature []byte, err error) {
	return i.keyID, ed25519.Sign(i.priv, payload), nil
}

// SigningSeedFileName is the file inside a receipts directory that holds the
// signing seed a proxy generated because it was started without one, as 64
// hex digits, mode 0600 (helm-tracker#313 r2, finding 5). A restart and
// `spend-proxy reconcile` without a seed sign with it, so one key signs the
// whole log. Whoever can read the file can sign receipt lines; pass a seed
// (--sign or HELM_SPEND_PROXY_SIGNING_SEED) to keep it elsewhere.
const SigningSeedFileName = "signing-seed"

// signingSeed resolves the secret a proxy signs with: secret when given, else
// the seed generated in dir, which create generates when there is none. It
// returns the seed file's path when the seed came from it. The seed file must
// be a regular file, not a link to one elsewhere (helm-tracker#313 r3, note
// 6), and on unix readable by its owner only.
func signingSeed(dir, secret string, create bool) (string, string, error) {
	if strings.TrimSpace(secret) != "" {
		return secret, "", nil
	}
	path := filepath.Join(dir, SigningSeedFileName)
	info, err := os.Lstat(path)
	switch {
	case err == nil:
		if !info.Mode().IsRegular() {
			return "", "", fmt.Errorf("spendproxy: the signing seed %s is not a regular file (mode %v): replace it with the seed itself", path, info.Mode())
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			return "", "", fmt.Errorf("spendproxy: the signing seed %s is readable by others (mode %v): chmod 600 it", path, info.Mode().Perm())
		}
		raw, readErr := os.ReadFile(path) //nolint:gosec // G304: fixed seed filename in the operator-owned receipts directory; no request input.
		if readErr != nil {
			return "", "", fmt.Errorf("spendproxy: read the signing seed: %w", readErr)
		}
		seed, decErr := hex.DecodeString(strings.TrimSpace(string(raw)))
		if decErr != nil || len(seed) != ed25519.SeedSize {
			return "", "", fmt.Errorf("spendproxy: the signing seed %s is not %d bytes of hex", path, ed25519.SeedSize)
		}
		return hex.EncodeToString(seed), path, nil
	case !os.IsNotExist(err):
		return "", "", fmt.Errorf("spendproxy: read the signing seed: %w", err)
	case !create:
		return "", "", fmt.Errorf("spendproxy: no signing seed: pass the proxy's --sign seed, or run against a receipts directory whose proxy generated %s", SigningSeedFileName)
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return "", "", fmt.Errorf("spendproxy: generate a signing seed: %w", err)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", "", fmt.Errorf("spendproxy: create receipts dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: fixed seed filename in the operator-owned directory; exclusive creation cannot overwrite an existing path.
	if err != nil {
		return "", "", fmt.Errorf("spendproxy: create the signing seed: %w", err)
	}
	encoded := hex.EncodeToString(seed)
	_, werr := f.WriteString(encoded + "\n")
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		return "", "", fmt.Errorf("spendproxy: write the signing seed: %w", err)
	}
	return encoded, path, nil
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
