// Package shredding provides GDPR crypto-shredding for HELM.
//
// Crypto-shredding enables compliant data deletion by encrypting personal
// data with per-subject keys, then destroying the key when deletion is
// requested — making the data permanently irrecoverable without modifying
// the ProofGraph's hash chain.
package shredding

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
	"time"
)

// SubjectKey tracks the encryption key for a data subject's personal data.
type SubjectKey struct {
	SubjectID  string     `json:"subject_id"`
	KeyID      string     `json:"key_id"`
	Key        []byte     `json:"-"` // Never serialized
	CreatedAt  time.Time  `json:"created_at"`
	ShreddedAt *time.Time `json:"shredded_at,omitempty"`
	Active     bool       `json:"active"`
}

// ShreddingRecord documents a crypto-shredding operation.
type ShreddingRecord struct {
	SubjectID     string    `json:"subject_id"`
	RequestedAt   time.Time `json:"requested_at"`
	CompletedAt   time.Time `json:"completed_at"`
	KeyID         string    `json:"key_id"`
	AffectedNodes int       `json:"affected_nodes"`
	LegalBasis    string    `json:"legal_basis"` // e.g., "GDPR Art. 17 - Right to Erasure"
}

// KeyStore manages per-subject encryption keys.
type KeyStore struct {
	mu   sync.RWMutex
	keys map[string]*SubjectKey
	log  []ShreddingRecord
}

// NewKeyStore creates a new subject key store.
func NewKeyStore() *KeyStore {
	return &KeyStore{keys: make(map[string]*SubjectKey)}
}

// GenerateKey creates a new AES-256 key for a data subject.
func (ks *KeyStore) GenerateKey(_ context.Context, subjectID string) (*SubjectKey, error) {
	key := make([]byte, 32) // AES-256
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("shredding: generate key: %w", err)
	}

	sk := &SubjectKey{
		SubjectID: subjectID,
		KeyID:     fmt.Sprintf("sk-%s-%d", subjectID, time.Now().UnixNano()),
		Key:       key,
		CreatedAt: time.Now(),
		Active:    true,
	}

	ks.mu.Lock()
	ks.keys[subjectID] = sk
	ks.mu.Unlock()

	return sk, nil
}

// Encrypt encrypts personal data with the subject's key.
func (ks *KeyStore) Encrypt(_ context.Context, subjectID string, plaintext []byte) ([]byte, error) {
	ks.mu.RLock()
	sk, ok := ks.keys[subjectID]
	ks.mu.RUnlock()

	if !ok || !sk.Active {
		return nil, fmt.Errorf("shredding: no active key for subject %s", subjectID)
	}

	block, err := aes.NewCipher(sk.Key)
	if err != nil {
		return nil, fmt.Errorf("shredding: cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("shredding: gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("shredding: nonce: %w", err)
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts personal data with the subject's key.
func (ks *KeyStore) Decrypt(_ context.Context, subjectID string, ciphertext []byte) ([]byte, error) {
	ks.mu.RLock()
	sk, ok := ks.keys[subjectID]
	ks.mu.RUnlock()

	if !ok || !sk.Active {
		return nil, fmt.Errorf("shredding: no active key for subject %s (data may have been shredded)", subjectID)
	}

	block, err := aes.NewCipher(sk.Key)
	if err != nil {
		return nil, fmt.Errorf("shredding: cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("shredding: gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("shredding: ciphertext too short")
	}

	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ct, nil)
}

// Shred destroys the subject's encryption key, making all encrypted data irrecoverable.
func (ks *KeyStore) Shred(_ context.Context, subjectID, legalBasis string) (*ShreddingRecord, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	sk, ok := ks.keys[subjectID]
	if !ok {
		return nil, fmt.Errorf("shredding: subject %s not found", subjectID)
	}

	now := time.Now()

	// Zero out key material
	for i := range sk.Key {
		sk.Key[i] = 0
	}
	sk.Key = nil
	sk.Active = false
	sk.ShreddedAt = &now

	record := ShreddingRecord{
		SubjectID:   subjectID,
		RequestedAt: now,
		CompletedAt: now,
		KeyID:       sk.KeyID,
		LegalBasis:  legalBasis,
	}
	ks.log = append(ks.log, record)

	return &record, nil
}

// GetShreddingLog returns the audit log of all shredding operations.
func (ks *KeyStore) GetShreddingLog() []ShreddingRecord {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	log := make([]ShreddingRecord, len(ks.log))
	copy(log, ks.log)
	return log
}

// IsShredded checks if a subject's data has been crypto-shredded.
func (ks *KeyStore) IsShredded(subjectID string) bool {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	sk, ok := ks.keys[subjectID]
	return ok && !sk.Active
}

// SubjectKeyID returns the encryption key ID for a subject (for audit reference).
func (ks *KeyStore) SubjectKeyID(subjectID string) string {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	sk, ok := ks.keys[subjectID]
	if !ok {
		return ""
	}
	return sk.KeyID
}

// ensure hex import is used
var _ = hex.EncodeToString
