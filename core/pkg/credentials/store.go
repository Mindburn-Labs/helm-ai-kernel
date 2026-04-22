// Package credentials provides secure, encrypted storage for AI provider credentials.
// AES-256-GCM encryption, vault pattern, automatic refresh.
package credentials

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/kms"
)

// ProviderType represents supported credential providers.
type ProviderType string

const (
	ProviderGoogle    ProviderType = "google"
	ProviderOpenAI    ProviderType = "openai"
	ProviderAnthropic ProviderType = "anthropic"
)

// TokenType indicates the credential mechanism.
type TokenType string

const (
	TokenTypeBearer TokenType = "bearer"
	TokenTypeApiKey TokenType = "apikey"
)

// Credential represents a stored credential.
type Credential struct {
	ID           string       `json:"id" db:"id"`
	OperatorID   string       `json:"operator_id" db:"operator_id"`
	Provider     ProviderType `json:"provider" db:"provider"`
	TokenType    TokenType    `json:"token_type" db:"token_type"`
	AccessToken  string       `json:"-" db:"access_token"`  // Encrypted at rest
	RefreshToken string       `json:"-" db:"refresh_token"` // Encrypted at rest
	Scopes       []string     `json:"scopes" db:"-"`
	ScopesJSON   string       `json:"-" db:"scopes"`
	Email        string       `json:"email,omitempty" db:"email"`
	ExpiresAt    *time.Time   `json:"expires_at,omitempty" db:"expires_at"`
	CreatedAt    time.Time    `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at" db:"updated_at"`
	LastUsedAt   *time.Time   `json:"last_used_at,omitempty" db:"last_used_at"`
}

// CredentialStatus is the public-facing status without sensitive data.
type CredentialStatus struct {
	Provider   ProviderType `json:"provider"`
	Connected  bool         `json:"connected"`
	Email      string       `json:"email,omitempty"`
	ExpiresAt  *time.Time   `json:"expires_at,omitempty"`
	Scopes     []string     `json:"scopes,omitempty"`
	LastUsedAt *time.Time   `json:"last_used_at,omitempty"`
}

// Store manages encrypted credential storage.
type Store struct {
	db          *sql.DB
	encKey      []byte      // legacy raw key (used when kmsManager is nil)
	kmsManager  kms.Manager // CRED-001: KMS-backed encryption
	mu          sync.RWMutex
	envFallback bool // Allow fallback to env vars
}

// StoreOption configures the credential store.
type StoreOption func(*Store)

// WithEnvFallback enables fallback to environment variables.
func WithEnvFallback(enabled bool) StoreOption {
	return func(s *Store) {
		s.envFallback = enabled
	}
}

// NewStore creates a new credential store with a raw encryption key (legacy).
// encryptionKey must be exactly 32 bytes for AES-256.
func NewStore(db *sql.DB, encryptionKey []byte, opts ...StoreOption) (*Store, error) {
	if len(encryptionKey) != 32 {
		return nil, errors.New("encryption key must be 32 bytes for AES-256")
	}

	s := &Store{
		db:          db,
		encKey:      encryptionKey,
		envFallback: true, // Default: allow env fallback for CI/automation
	}

	for _, opt := range opts {
		opt(s)
	}

	return s, nil
}

// NewStoreWithKMS creates a credential store backed by a KMS Manager (CRED-001).
func NewStoreWithKMS(db *sql.DB, km kms.Manager, opts ...StoreOption) *Store {
	s := &Store{
		db:          db,
		kmsManager:  km,
		envFallback: true,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// encrypt encrypts plaintext using KMS (preferred) or legacy AES-256-GCM.
func (s *Store) encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	// CRED-001: Use KMS if available
	if s.kmsManager != nil {
		return s.kmsManager.Encrypt(plaintext)
	}

	// Legacy path: raw key
	block, err := aes.NewCipher(s.encKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decrypt decrypts ciphertext using KMS (preferred) or legacy AES-256-GCM.
func (s *Store) decrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}

	// CRED-001: Use KMS if available
	if s.kmsManager != nil {
		return s.kmsManager.Decrypt(ciphertext)
	}

	// Legacy path: raw key
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	block, err := aes.NewCipher(s.encKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	if len(data) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}

	nonce, cipherBytes := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, cipherBytes, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

// SaveCredential stores or updates a credential with encryption.
func (s *Store) SaveCredential(ctx context.Context, cred *Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Encrypt sensitive fields
	encAccess, err := s.encrypt(cred.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to encrypt access token: %w", err)
	}

	encRefresh, err := s.encrypt(cred.RefreshToken)
	if err != nil {
		return fmt.Errorf("failed to encrypt refresh token: %w", err)
	}

	// Serialize scopes
	scopesJSON, _ := json.Marshal(cred.Scopes)

	now := time.Now().UTC()

	query := `
		INSERT INTO credentials (id, operator_id, provider, token_type, access_token, refresh_token, scopes, email, expires_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10)
		ON CONFLICT (operator_id, provider) DO UPDATE SET
			access_token = EXCLUDED.access_token,
			refresh_token = EXCLUDED.refresh_token,
			scopes = EXCLUDED.scopes,
			email = EXCLUDED.email,
			expires_at = EXCLUDED.expires_at,
			updated_at = EXCLUDED.updated_at
	`

	_, err = s.db.ExecContext(ctx, query,
		cred.ID,
		cred.OperatorID,
		cred.Provider,
		cred.TokenType,
		encAccess,
		encRefresh,
		string(scopesJSON),
		cred.Email,
		cred.ExpiresAt,
		now,
	)

	return err
}

// GetCredential retrieves a credential by operator and provider.
func (s *Store) GetCredential(ctx context.Context, operatorID string, provider ProviderType) (*Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var cred Credential
	var encAccess, encRefresh sql.NullString
	var scopesJSON sql.NullString
	var email sql.NullString
	var expiresAt, lastUsedAt sql.NullTime

	query := `
		SELECT id, operator_id, provider, token_type, access_token, refresh_token, scopes, email, expires_at, created_at, updated_at, last_used_at
		FROM credentials
		WHERE operator_id = $1 AND provider = $2
	`

	err := s.db.QueryRowContext(ctx, query, operatorID, provider).Scan(
		&cred.ID,
		&cred.OperatorID,
		&cred.Provider,
		&cred.TokenType,
		&encAccess,
		&encRefresh,
		&scopesJSON,
		&email,
		&expiresAt,
		&cred.CreatedAt,
		&cred.UpdatedAt,
		&lastUsedAt,
	)

	if errors.Is(err, sql.ErrNoRows) {
		// Fallback to environment variables if enabled
		if s.envFallback {
			return s.getFromEnv(provider)
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// Decrypt sensitive fields
	if encAccess.Valid {
		cred.AccessToken, err = s.decrypt(encAccess.String)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt access token: %w", err)
		}
	}

	if encRefresh.Valid {
		cred.RefreshToken, err = s.decrypt(encRefresh.String)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt refresh token: %w", err)
		}
	}

	if scopesJSON.Valid {
		_ = json.Unmarshal([]byte(scopesJSON.String), &cred.Scopes)
	}

	if email.Valid {
		cred.Email = email.String
	}

	if expiresAt.Valid {
		cred.ExpiresAt = &expiresAt.Time
	}

	if lastUsedAt.Valid {
		cred.LastUsedAt = &lastUsedAt.Time
	}

	return &cred, nil
}

// getFromEnv returns a credential from environment variables (fallback).
func (s *Store) getFromEnv(provider ProviderType) (*Credential, error) {
	var envVar string
	switch provider {
	case ProviderGoogle:
		envVar = "GEMINI_API_KEY"
	case ProviderOpenAI:
		envVar = "OPENAI_API_KEY"
	case ProviderAnthropic:
		envVar = "ANTHROPIC_API_KEY"
	default:
		return nil, nil
	}

	value := os.Getenv(envVar)
	if value == "" {
		return nil, nil
	}

	return &Credential{
		Provider:    provider,
		TokenType:   TokenTypeApiKey,
		AccessToken: value,
	}, nil
}

// GetStatus returns the public credential status for all providers.
func (s *Store) GetStatus(ctx context.Context, operatorID string) ([]CredentialStatus, error) {
	providers := []ProviderType{ProviderGoogle, ProviderOpenAI, ProviderAnthropic}
	statuses := make([]CredentialStatus, 0, len(providers))

	for _, p := range providers {
		cred, err := s.GetCredential(ctx, operatorID, p)
		if err != nil {
			return nil, err
		}

		status := CredentialStatus{
			Provider:  p,
			Connected: cred != nil && cred.AccessToken != "",
		}

		if cred != nil {
			status.Email = cred.Email
			status.ExpiresAt = cred.ExpiresAt
			status.Scopes = cred.Scopes
			status.LastUsedAt = cred.LastUsedAt
		}

		statuses = append(statuses, status)
	}

	return statuses, nil
}

// DeleteCredential removes a credential.
func (s *Store) DeleteCredential(ctx context.Context, operatorID string, provider ProviderType) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `DELETE FROM credentials WHERE operator_id = $1 AND provider = $2`
	_, err := s.db.ExecContext(ctx, query, operatorID, provider)
	return err
}

// UpdateLastUsed updates the last_used_at timestamp.
func (s *Store) UpdateLastUsed(ctx context.Context, operatorID string, provider ProviderType) error {
	query := `UPDATE credentials SET last_used_at = $1 WHERE operator_id = $2 AND provider = $3`
	_, err := s.db.ExecContext(ctx, query, time.Now().UTC(), operatorID, provider)
	return err
}

// NeedsRefresh checks if a credential needs token refresh.
func (c *Credential) NeedsRefresh() bool {
	if c == nil || c.ExpiresAt == nil {
		return false
	}
	// Refresh if expiring within 5 minutes
	return time.Until(*c.ExpiresAt) < 5*time.Minute
}
