// Package credentials provides secure, encrypted storage for AI provider credentials.
// AES-256-GCM through pkg/kms, each ciphertext bound to its operator, provider
// and field; vault pattern, automatic refresh.
package credentials

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kms"
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
	db  *sql.DB
	kms kms.Manager // CRED-001: KMS-backed encryption
	mu  sync.RWMutex
}

// NewStoreWithKMS creates a credential store backed by a KMS Manager (CRED-001).
func NewStoreWithKMS(db *sql.DB, km kms.Manager) *Store {
	return &Store{db: db, kms: km}
}

const (
	fieldAccessToken  = "access_token"
	fieldRefreshToken = "refresh_token"
)

// binding is the AAD for one stored secret. The credentials table is scoped
// by operator_id, so the operator is the tenant; provider plus column is the
// connection. A ciphertext therefore opens only in the field it was written to.
func binding(operatorID string, provider ProviderType, field string) kms.Binding {
	return kms.Binding{Tenant: operatorID, Connection: string(provider) + "/" + field}
}

// SaveCredential stores or updates a credential with encryption.
func (s *Store) SaveCredential(ctx context.Context, cred *Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Encrypt sensitive fields
	encAccess, err := s.kms.Encrypt(cred.AccessToken, binding(cred.OperatorID, cred.Provider, fieldAccessToken))
	if err != nil {
		return fmt.Errorf("failed to encrypt access token: %w", err)
	}

	encRefresh, err := s.kms.Encrypt(cred.RefreshToken, binding(cred.OperatorID, cred.Provider, fieldRefreshToken))
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

	// 12-07: no row means no credential. The server's own provider keys are
	// never handed to an operator who has not connected one.
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// Decrypt sensitive fields
	if encAccess.Valid {
		cred.AccessToken, err = s.kms.Decrypt(encAccess.String, binding(operatorID, provider, fieldAccessToken))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt access token: %w", err)
		}
	}

	if encRefresh.Valid {
		cred.RefreshToken, err = s.kms.Decrypt(encRefresh.String, binding(operatorID, provider, fieldRefreshToken))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt refresh token: %w", err)
		}
	}

	if s.kms.NeedsRewrap(encAccess.String) || s.kms.NeedsRewrap(encRefresh.String) {
		s.rewrap(ctx, &cred, encAccess, encRefresh)
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

// rewrap re-seals a row that was read under a legacy unbound format or a
// rotated-out key version, so rotation reaches stored rows and the old version
// can later be revoked. The update is compare-and-swap on the ciphertexts that
// were read: a concurrent save wins, and a failure leaves the readable row as
// it was.
func (s *Store) rewrap(ctx context.Context, cred *Credential, oldAccess, oldRefresh sql.NullString) {
	newAccess, err := s.kms.Encrypt(cred.AccessToken, binding(cred.OperatorID, cred.Provider, fieldAccessToken))
	newRefresh := oldRefresh
	if err == nil && oldRefresh.Valid {
		newRefresh.String, err = s.kms.Encrypt(cred.RefreshToken, binding(cred.OperatorID, cred.Provider, fieldRefreshToken))
	}
	if err == nil {
		_, err = s.db.ExecContext(ctx, `
			UPDATE credentials SET access_token = $1, refresh_token = $2
			WHERE operator_id = $3 AND provider = $4
			  AND access_token = $5 AND refresh_token IS NOT DISTINCT FROM $6`,
			newAccess, newRefresh, cred.OperatorID, cred.Provider, oldAccess.String, oldRefresh)
	}
	if err != nil {
		slog.WarnContext(ctx, "credentials: re-seal under the active key failed", "provider", cred.Provider, "error", err)
	}
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
