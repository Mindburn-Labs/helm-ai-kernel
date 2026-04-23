// Package kms provides key management for credential encryption.
//
// CRED-001: Replaces bare os.Getenv("CREDENTIALS_ENCRYPTION_KEY") with a
// persistent, file-backed key store that supports versioned keys.
//
// CRED-002: Supports key rotation — new keys can be generated while old
// keys remain available for decryption of previously encrypted data.
package kms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// Manager defines the key management interface.
type Manager interface {
	// Encrypt encrypts plaintext, returning versioned ciphertext ("v<N>:<base64>").
	Encrypt(plaintext string) (string, error)

	// Decrypt decrypts versioned ciphertext produced by Encrypt.
	Decrypt(ciphertext string) (string, error)

	// Rotate generates a new active key. Old keys remain for decryption.
	Rotate() (version int, err error)

	// ActiveVersion returns the current active key version.
	ActiveVersion() int
}

// Keystore is the on-disk JSON format for persisted keys.
type Keystore struct {
	ActiveVersion int               `json:"active_version"`
	Keys          map[string]string `json:"keys"` // version -> base64-encoded 32-byte key
}

// LocalKMS is a file-backed KMS using AES-256-GCM with versioned keys.
type LocalKMS struct {
	mu    sync.RWMutex
	store Keystore
	path  string
	keys  map[int][]byte // decoded keys cache
}

// NewLocalKMS loads or creates a local keystore at the given path.
// If the file does not exist, a new key (version 1) is generated.
func NewLocalKMS(keystorePath string) (*LocalKMS, error) {
	kms := &LocalKMS{
		path: keystorePath,
		keys: make(map[int][]byte),
	}

	if _, err := os.Stat(keystorePath); errors.Is(err, os.ErrNotExist) {
		// Create directory
		if err := os.MkdirAll(filepath.Dir(keystorePath), 0700); err != nil {
			return nil, fmt.Errorf("kms: create dir: %w", err)
		}

		// Generate initial key
		key := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, fmt.Errorf("kms: generate key: %w", err)
		}

		kms.store = Keystore{
			ActiveVersion: 1,
			Keys:          map[string]string{"1": base64.StdEncoding.EncodeToString(key)},
		}
		kms.keys[1] = key

		if err := kms.persist(); err != nil {
			return nil, err
		}
		return kms, nil
	}

	// Load existing
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
		if err != nil {
			return nil, fmt.Errorf("kms: invalid version %q: %w", vStr, err)
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

// ImportKey imports an existing raw key as the initial version.
// This enables migration from the old env-var approach.
func (k *LocalKMS) ImportKey(rawKey []byte, version int) error {
	if len(rawKey) != 32 {
		return fmt.Errorf("kms: import key must be 32 bytes, got %d", len(rawKey))
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	vStr := strconv.Itoa(version)
	k.store.Keys[vStr] = base64.StdEncoding.EncodeToString(rawKey)
	k.store.ActiveVersion = version
	k.keys[version] = rawKey

	return k.persist()
}

// Encrypt encrypts plaintext with the active key, returning "v<N>:<base64(nonce+ciphertext)>".
func (k *LocalKMS) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	k.mu.RLock()
	activeVersion := k.store.ActiveVersion
	key := k.keys[activeVersion]
	k.mu.RUnlock()

	ct, err := aesGCMEncrypt(key, []byte(plaintext))
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("v%d:%s", activeVersion, base64.StdEncoding.EncodeToString(ct)), nil
}

// Decrypt decrypts versioned ciphertext. Supports any key version in the store.
func (k *LocalKMS) Decrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}

	// Parse version prefix
	version, payload, err := parseVersioned(ciphertext)
	if err != nil {
		return "", err
	}

	k.mu.RLock()
	key, ok := k.keys[version]
	k.mu.RUnlock()

	if !ok {
		return "", fmt.Errorf("kms: unknown key version %d", version)
	}

	ct, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", fmt.Errorf("kms: decode ciphertext: %w", err)
	}

	pt, err := aesGCMDecrypt(key, ct)
	if err != nil {
		return "", err
	}

	return string(pt), nil
}

// Rotate generates a new key version and persists the updated keystore.
func (k *LocalKMS) Rotate() (int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	newVersion := k.store.ActiveVersion + 1

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return 0, fmt.Errorf("kms: generate key: %w", err)
	}

	vStr := strconv.Itoa(newVersion)
	k.store.Keys[vStr] = base64.StdEncoding.EncodeToString(key)
	k.store.ActiveVersion = newVersion
	k.keys[newVersion] = key

	if err := k.persist(); err != nil {
		return 0, err
	}

	return newVersion, nil
}

// ActiveVersion returns the current active key version.
func (k *LocalKMS) ActiveVersion() int {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.store.ActiveVersion
}

// ActiveKey returns the raw active encryption key.
// Useful for passing to subsystems that need a raw key (e.g., legacy Store).
func (k *LocalKMS) ActiveKey() []byte {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.keys[k.store.ActiveVersion]
}

// persist writes the keystore to disk with restricted permissions.
func (k *LocalKMS) persist() error {
	data, err := json.MarshalIndent(k.store, "", "  ")
	if err != nil {
		return fmt.Errorf("kms: marshal keystore: %w", err)
	}
	if err := os.WriteFile(k.path, data, 0600); err != nil {
		return fmt.Errorf("kms: write keystore: %w", err)
	}
	return nil
}

// --- AES-256-GCM helpers ---

func aesGCMEncrypt(key, plaintext []byte) ([]byte, error) {
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

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func aesGCMDecrypt(key, ciphertext []byte) ([]byte, error) {
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
	return gcm.Open(nil, nonce, ct, nil)
}

// parseVersioned splits "v<N>:<payload>" into (N, payload).
func parseVersioned(s string) (int, string, error) {
	if !strings.HasPrefix(s, "v") {
		return 0, "", fmt.Errorf("kms: missing version prefix in %q", s)
	}

	idx := strings.Index(s, ":")
	if idx < 2 {
		return 0, "", fmt.Errorf("kms: malformed versioned string %q", s)
	}

	v, err := strconv.Atoi(s[1:idx])
	if err != nil {
		return 0, "", fmt.Errorf("kms: parse version: %w", err)
	}

	return v, s[idx+1:], nil
}
