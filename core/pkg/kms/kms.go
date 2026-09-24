// Package kms provides key management for credential encryption.
//
// CRED-001: Replaces bare os.Getenv("CREDENTIALS_ENCRYPTION_KEY") with a
// persistent, file-backed key store that supports versioned keys.
//
// CRED-002: Supports key rotation — new keys can be generated while old
// keys remain available for decryption of previously encrypted data, and a
// retired version can be revoked for good.
//
// quantum_posture: AES-256-GCM only. It is symmetric, and a 256-bit key keeps
// about 128-bit strength against Grover search; no asymmetric primitive here.
package kms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// ErrKeyRevoked reports a key version that was revoked. Its ciphertexts no
// longer open and the version can never be imported again.
var ErrKeyRevoked = errors.New("kms: key version revoked")

// Binding names the record a ciphertext belongs to. Encrypt authenticates it,
// together with the key version, as AES-GCM additional data, so a ciphertext
// copied into another tenant's or connection's record does not decrypt.
type Binding struct {
	Tenant     string
	Connection string
}

// Manager defines the key management interface.
type Manager interface {
	// Encrypt seals plaintext under the active key, bound to b.
	Encrypt(plaintext string, b Binding) (string, error)

	// Decrypt opens a ciphertext produced by Encrypt for the same binding.
	// Legacy unbound "v<N>:" ciphertexts still open; see NeedsRewrap.
	Decrypt(ciphertext string, b Binding) (string, error)

	// NeedsRewrap reports whether a ciphertext is legacy unbound data or
	// sealed under a key other than the active one, and should be re-sealed.
	NeedsRewrap(ciphertext string) bool
}

// Keystore is the on-disk JSON format for persisted keys.
type Keystore struct {
	ActiveVersion int               `json:"active_version"`
	Keys          map[string]string `json:"keys"` // version -> base64-encoded 32-byte key
	Revoked       []int             `json:"revoked,omitempty"`
}

// LocalKMS is a file-backed KMS using AES-256-GCM with versioned keys.
//
// ponytail: one serving process per keystore. A running server holds the
// keystore it loaded at start, so rotate/revoke take effect on restart. Several
// replicas sharing a key need a cloud KMS backend behind Manager.
type LocalKMS struct {
	mu    sync.RWMutex
	store Keystore
	path  string
	keys  map[int][]byte // decoded keys cache
}

const (
	// boundPrefix marks ciphertexts sealed with Binding as additional data.
	// Plain "v<N>:" ciphertexts predate it and are decrypt-only.
	boundPrefix = "aad1:"
	aadDomain   = "helm.kms.credential.aad.v1\x00"
)

// NewLocalKMS loads or creates a local keystore at the given path.
// If the file does not exist, a new key (version 1) is generated.
func NewLocalKMS(keystorePath string) (*LocalKMS, error) {
	return openLocalKMS(keystorePath, nil)
}

// NewLocalKMSWithLegacyKey is NewLocalKMS for a deployment that still sets the
// legacy CREDENTIALS_ENCRYPTION_KEY. A keystore created now starts with that
// key as its active version 0, so a deployment whose data directory does not
// persist keeps opening its rows. An existing keystore receives it through
// ImportKey: decryption only, never re-pinned, never overwriting a version.
func NewLocalKMSWithLegacyKey(keystorePath string, legacyKey []byte) (*LocalKMS, error) {
	if len(legacyKey) != 32 {
		return nil, fmt.Errorf("kms: legacy key must be 32 bytes, got %d", len(legacyKey))
	}
	k, err := openLocalKMS(keystorePath, legacyKey)
	if err != nil {
		return nil, err
	}
	if err := k.ImportKey(legacyKey, 0); err != nil {
		return nil, fmt.Errorf("kms: legacy CREDENTIALS_ENCRYPTION_KEY: %w", err)
	}
	return k, nil
}

func openLocalKMS(keystorePath string, legacyKey []byte) (*LocalKMS, error) {
	kms := &LocalKMS{
		path: keystorePath,
		keys: make(map[int][]byte),
	}

	info, err := os.Stat(keystorePath)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(keystorePath), 0700); err != nil {
			return nil, fmt.Errorf("kms: create dir: %w", err)
		}

		version, key := 0, slices.Clone(legacyKey)
		if key == nil {
			version, key = 1, make([]byte, 32)
			if _, err := io.ReadFull(rand.Reader, key); err != nil {
				return nil, fmt.Errorf("kms: generate key: %w", err)
			}
		}

		store := Keystore{
			ActiveVersion: version,
			Keys:          map[string]string{strconv.Itoa(version): base64.StdEncoding.EncodeToString(key)},
		}
		if err := writeKeystore(keystorePath, store); err != nil {
			return nil, err
		}
		kms.store = store
		kms.keys[version] = key
		return kms, nil
	}
	if err != nil {
		return nil, fmt.Errorf("kms: stat keystore: %w", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o007 != 0 {
		return nil, fmt.Errorf("kms: keystore %s is accessible to other users (mode %o); expected 600", keystorePath, info.Mode().Perm())
	}

	data, err := os.ReadFile(keystorePath)
	if err != nil {
		return nil, fmt.Errorf("kms: read keystore: %w", err)
	}

	if err := json.Unmarshal(data, &kms.store); err != nil {
		return nil, fmt.Errorf("kms: parse keystore: %w", err)
	}

	// Decode all keys into cache
	for vStr, encoded := range kms.store.Keys {
		v, err := strconv.Atoi(vStr)
		if err != nil || v < 0 {
			return nil, fmt.Errorf("kms: invalid version %q", vStr)
		}
		if slices.Contains(kms.store.Revoked, v) {
			return nil, fmt.Errorf("kms: version %d is both present and revoked", v)
		}
		key, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("kms: decode key v%d: %w", v, err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("kms: key v%d invalid length %d (need 32)", v, len(key))
		}
		kms.keys[v] = key
	}

	if _, ok := kms.keys[kms.store.ActiveVersion]; !ok {
		return nil, fmt.Errorf("kms: active version %d not in keystore", kms.store.ActiveVersion)
	}

	return kms, nil
}

// ImportKey adds an existing raw key (the legacy env key) so that ciphertexts
// under that version stay readable. It never changes the active version and
// never replaces a stored key: importing the same key again is a no-op, a
// different key under a taken version is refused, and so is a revoked version.
func (k *LocalKMS) ImportKey(rawKey []byte, version int) error {
	if len(rawKey) != 32 {
		return fmt.Errorf("kms: import key must be 32 bytes, got %d", len(rawKey))
	}
	if version < 0 {
		return fmt.Errorf("kms: invalid import version %d", version)
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	if slices.Contains(k.store.Revoked, version) {
		return fmt.Errorf("%w: v%d", ErrKeyRevoked, version)
	}
	if existing, ok := k.keys[version]; ok {
		if subtle.ConstantTimeCompare(existing, rawKey) == 1 {
			return nil
		}
		return fmt.Errorf("kms: version %d already holds a different key; refusing to overwrite it", version)
	}

	next := k.cloneStore()
	next.Keys[strconv.Itoa(version)] = base64.StdEncoding.EncodeToString(rawKey)
	if err := writeKeystore(k.path, next); err != nil {
		return err
	}
	k.store = next
	k.keys[version] = slices.Clone(rawKey)
	return nil
}

// Encrypt encrypts plaintext with the active key, returning
// "aad1:v<N>:<base64(nonce+ciphertext)>". Binding and version are the AAD.
func (k *LocalKMS) Encrypt(plaintext string, b Binding) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	if err := b.validate(); err != nil {
		return "", err
	}

	k.mu.RLock()
	activeVersion := k.store.ActiveVersion
	key := k.keys[activeVersion]
	k.mu.RUnlock()

	ct, err := aesGCMEncrypt(key, []byte(plaintext), additionalData(b, activeVersion))
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%sv%d:%s", boundPrefix, activeVersion, base64.StdEncoding.EncodeToString(ct)), nil
}

// Decrypt decrypts versioned ciphertext for binding b. Supports any key
// version still in the store; a revoked version fails with ErrKeyRevoked.
func (k *LocalKMS) Decrypt(ciphertext string, b Binding) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	if err := b.validate(); err != nil {
		return "", err
	}

	body, bound := strings.CutPrefix(ciphertext, boundPrefix)
	version, payload, err := parseVersioned(body)
	if err != nil {
		return "", err
	}

	k.mu.RLock()
	key, ok := k.keys[version]
	revoked := slices.Contains(k.store.Revoked, version)
	k.mu.RUnlock()

	if revoked {
		return "", fmt.Errorf("%w: v%d", ErrKeyRevoked, version)
	}
	if !ok {
		return "", fmt.Errorf("kms: unknown key version %d", version)
	}

	ct, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", fmt.Errorf("kms: decode ciphertext: %w", err)
	}

	var aad []byte
	if bound {
		aad = additionalData(b, version)
	}
	pt, err := aesGCMDecrypt(key, ct, aad)
	if err != nil {
		return "", err
	}

	return string(pt), nil
}

// NeedsRewrap reports whether ciphertext is legacy unbound data or sealed
// under a version other than the active one.
func (k *LocalKMS) NeedsRewrap(ciphertext string) bool {
	if ciphertext == "" {
		return false
	}
	body, bound := strings.CutPrefix(ciphertext, boundPrefix)
	version, _, err := parseVersioned(body)
	if err != nil {
		return false
	}
	return !bound || version != k.ActiveVersion()
}

// Rotate generates a new active key and persists the updated keystore. The
// new version is above every version ever used, including imported and
// revoked ones, so no existing key is overwritten and no number is reused.
func (k *LocalKMS) Rotate() (int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	newVersion := slices.Max(append(slices.Collect(maps.Keys(k.keys)), k.store.Revoked...)) + 1

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return 0, fmt.Errorf("kms: generate key: %w", err)
	}

	next := k.cloneStore()
	next.Keys[strconv.Itoa(newVersion)] = base64.StdEncoding.EncodeToString(key)
	next.ActiveVersion = newVersion
	if err := writeKeystore(k.path, next); err != nil {
		return 0, err
	}
	k.store = next
	k.keys[newVersion] = key

	return newVersion, nil
}

// Revoke deletes a retired key version for good. Its ciphertexts stop
// opening, and ImportKey refuses it afterwards. The active version cannot be
// revoked; rotate first.
func (k *LocalKMS) Revoke(version int) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if slices.Contains(k.store.Revoked, version) {
		return nil
	}
	if version == k.store.ActiveVersion {
		return fmt.Errorf("kms: version %d is active; rotate before revoking it", version)
	}
	if _, ok := k.keys[version]; !ok {
		return fmt.Errorf("kms: unknown key version %d", version)
	}

	next := k.cloneStore()
	delete(next.Keys, strconv.Itoa(version))
	next.Revoked = append(next.Revoked, version)
	slices.Sort(next.Revoked)
	if err := writeKeystore(k.path, next); err != nil {
		return err
	}
	k.store = next
	delete(k.keys, version)
	return nil
}

// ActiveVersion returns the current active key version.
func (k *LocalKMS) ActiveVersion() int {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.store.ActiveVersion
}

// KeyVersions reports the active version, every version that can still
// decrypt, and the revoked ones. It never exposes key material.
func (k *LocalKMS) KeyVersions() (active int, usable, revoked []int) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.store.ActiveVersion, slices.Sorted(maps.Keys(k.keys)), slices.Clone(k.store.Revoked)
}

func (k *LocalKMS) cloneStore() Keystore {
	return Keystore{
		ActiveVersion: k.store.ActiveVersion,
		Keys:          maps.Clone(k.store.Keys),
		Revoked:       slices.Clone(k.store.Revoked),
	}
}

// writeKeystore replaces the keystore file atomically: a 0600 temp file in the
// same directory is written and fsynced, then renamed over the old one, so a
// crash or full disk leaves either the old or the new keystore, never a
// truncated one.
func writeKeystore(path string, store Keystore) (err error) {
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("kms: marshal keystore: %w", err)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("kms: write keystore: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if err = tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("kms: write keystore: %w", err)
	}
	if _, err = tmp.Write(data); err != nil {
		return fmt.Errorf("kms: write keystore: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("kms: sync keystore: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("kms: write keystore: %w", err)
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("kms: replace keystore: %w", err)
	}
	// Make the rename itself durable. Some platforms cannot fsync a
	// directory; the rename is still atomic there.
	if d, dirErr := os.Open(dir); dirErr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func (b Binding) validate() error {
	if b.Tenant == "" || b.Connection == "" {
		return errors.New("kms: binding requires a tenant and a connection")
	}
	return nil
}

// additionalData encodes (tenant, connection, version) without ambiguity:
// a domain tag, then each string length-prefixed, then the version.
func additionalData(b Binding, version int) []byte {
	aad := []byte(aadDomain)
	for _, field := range []string{b.Tenant, b.Connection} {
		aad = binary.BigEndian.AppendUint32(aad, uint32(len(field)))
		aad = append(aad, field...)
	}
	return binary.BigEndian.AppendUint64(aad, uint64(version))
}

// --- AES-256-GCM helpers ---

func aesGCMEncrypt(key, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("kms: aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("kms: gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("kms: nonce: %w", err)
	}

	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

func aesGCMDecrypt(key, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("kms: aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("kms: gcm: %w", err)
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("kms: ciphertext too short")
	}

	nonce, ct := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, aad)
}

// parseVersioned splits "v<N>:<payload>" into (N, payload).
func parseVersioned(s string) (int, string, error) {
	if !strings.HasPrefix(s, "v") {
		return 0, "", errors.New("kms: missing version prefix")
	}

	idx := strings.Index(s, ":")
	if idx < 2 {
		return 0, "", errors.New("kms: malformed versioned ciphertext")
	}

	v, err := strconv.Atoi(s[1:idx])
	if err != nil || v < 0 {
		return 0, "", errors.New("kms: malformed key version")
	}

	return v, s[idx+1:], nil
}
