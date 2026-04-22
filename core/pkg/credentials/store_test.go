package credentials

import (
	"bytes"
	"context"
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func setupTestDB(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}

	// Create schema
	_, err = db.Exec(`
		CREATE TABLE credentials (
			id TEXT PRIMARY KEY,
			operator_id TEXT NOT NULL,
			provider TEXT NOT NULL,
			token_type TEXT NOT NULL,
			access_token TEXT NOT NULL,
			refresh_token TEXT,
			scopes TEXT,
			email TEXT,
			expires_at DATETIME,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_used_at DATETIME,
			UNIQUE (operator_id, provider)
		)
	`)
	if err != nil {
		t.Fatalf("failed to create schema: %v", err)
	}

	return db
}

func TestStore_EncryptDecrypt(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	key := bytes.Repeat([]byte("a"), 32) // 32-byte key for AES-256
	store, err := NewStore(db, key)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	// Test encryption/decryption
	original := "super-secret-api-key-12345"
	encrypted, err := store.encrypt(original)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	if encrypted == original {
		t.Error("encrypted should not equal original")
	}

	decrypted, err := store.decrypt(encrypted)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	if decrypted != original {
		t.Errorf("decrypted = %q, want %q", decrypted, original)
	}
}

func TestStore_SaveAndGetCredential(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	key := bytes.Repeat([]byte("b"), 32)
	store, err := NewStore(db, key, WithEnvFallback(false))
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ctx := context.Background()
	expiresAt := time.Now().Add(1 * time.Hour)

	// Save credential
	cred := &Credential{
		ID:           "test-id-1",
		OperatorID:   "operator-123",
		Provider:     ProviderGoogle,
		TokenType:    TokenTypeBearer,
		AccessToken:  "access-token-xyz",
		RefreshToken: "refresh-token-abc",
		Scopes:       []string{"email", "profile"},
		Email:        "test@example.com",
		ExpiresAt:    &expiresAt,
	}

	if err := store.SaveCredential(ctx, cred); err != nil {
		t.Fatalf("SaveCredential failed: %v", err)
	}

	// Retrieve credential
	retrieved, err := store.GetCredential(ctx, "operator-123", ProviderGoogle)
	if err != nil {
		t.Fatalf("GetCredential failed: %v", err)
	}

	if retrieved == nil {
		t.Fatal("GetCredential returned nil")
	}

	if retrieved.AccessToken != cred.AccessToken {
		t.Errorf("AccessToken = %q, want %q", retrieved.AccessToken, cred.AccessToken)
	}

	if retrieved.RefreshToken != cred.RefreshToken {
		t.Errorf("RefreshToken = %q, want %q", retrieved.RefreshToken, cred.RefreshToken)
	}

	if retrieved.Email != cred.Email {
		t.Errorf("Email = %q, want %q", retrieved.Email, cred.Email)
	}
}

func TestStore_DeleteCredential(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	key := bytes.Repeat([]byte("c"), 32)
	store, err := NewStore(db, key, WithEnvFallback(false))
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ctx := context.Background()

	// Save credential
	cred := &Credential{
		ID:          "test-id-2",
		OperatorID:  "operator-456",
		Provider:    ProviderOpenAI,
		TokenType:   TokenTypeApiKey,
		AccessToken: "sk-test-key",
	}

	if err := store.SaveCredential(ctx, cred); err != nil {
		t.Fatalf("SaveCredential failed: %v", err)
	}

	// Delete credential
	if err := store.DeleteCredential(ctx, "operator-456", ProviderOpenAI); err != nil {
		t.Fatalf("DeleteCredential failed: %v", err)
	}

	// Verify deleted
	retrieved, err := store.GetCredential(ctx, "operator-456", ProviderOpenAI)
	if err != nil {
		t.Fatalf("GetCredential failed: %v", err)
	}

	if retrieved != nil {
		t.Error("expected nil after delete")
	}
}

func TestStore_GetStatus(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	key := bytes.Repeat([]byte("d"), 32)
	store, err := NewStore(db, key, WithEnvFallback(false))
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ctx := context.Background()

	// Save one credential
	cred := &Credential{
		ID:          "test-id-3",
		OperatorID:  "operator-789",
		Provider:    ProviderGoogle,
		TokenType:   TokenTypeBearer,
		AccessToken: "access-token",
		Email:       "user@gmail.com",
	}

	if err := store.SaveCredential(ctx, cred); err != nil {
		t.Fatalf("SaveCredential failed: %v", err)
	}

	// Get status
	statuses, err := store.GetStatus(ctx, "operator-789")
	if err != nil {
		t.Fatalf("GetStatus failed: %v", err)
	}

	if len(statuses) != 3 {
		t.Errorf("expected 3 statuses, got %d", len(statuses))
	}

	// Find Google status
	var googleStatus *CredentialStatus
	for i := range statuses {
		if statuses[i].Provider == ProviderGoogle {
			googleStatus = &statuses[i]
			break
		}
	}

	if googleStatus == nil {
		t.Fatal("Google status not found")
	}

	if !googleStatus.Connected {
		t.Error("Google should be connected")
	}

	if googleStatus.Email != "user@gmail.com" {
		t.Errorf("Email = %q, want %q", googleStatus.Email, "user@gmail.com")
	}
}

func TestCredential_NeedsRefresh(t *testing.T) {
	tests := []struct {
		name      string
		expiresIn time.Duration
		want      bool
	}{
		{"expires in 1 hour", 1 * time.Hour, false},
		{"expires in 10 minutes", 10 * time.Minute, false},
		{"expires in 4 minutes", 4 * time.Minute, true},
		{"expires in 1 minute", 1 * time.Minute, true},
		{"already expired", -1 * time.Minute, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expiresAt := time.Now().Add(tt.expiresIn)
			cred := &Credential{ExpiresAt: &expiresAt}

			if got := cred.NeedsRefresh(); got != tt.want {
				t.Errorf("NeedsRefresh() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStore_InvalidKeyLength(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Try with 16-byte key (should fail)
	_, err := NewStore(db, []byte("16-byte-key-xxx!"))
	if err == nil {
		t.Error("expected error for 16-byte key")
	}

	// Try with 32-byte key (should work)
	_, err = NewStore(db, bytes.Repeat([]byte("a"), 32))
	if err != nil {
		t.Errorf("unexpected error for 32-byte key: %v", err)
	}
}
