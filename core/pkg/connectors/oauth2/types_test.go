package oauth2

import (
	"context"
	"testing"
	"time"
)

func TestToken_IsExpired(t *testing.T) {
	expired := &Token{
		AccessToken: "abc",
		ExpiresAt:   time.Now().Add(-1 * time.Hour),
	}
	if !expired.IsExpired() {
		t.Error("expected token to be expired")
	}

	valid := &Token{
		AccessToken: "abc",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}
	if valid.IsExpired() {
		t.Error("expected token to not be expired")
	}
}

func TestToken_NeedsRefresh(t *testing.T) {
	// Token expiring in 3 minutes should need refresh (within 5-minute window)
	needsRefresh := &Token{
		AccessToken: "abc",
		ExpiresAt:   time.Now().Add(3 * time.Minute),
	}
	if !needsRefresh.NeedsRefresh() {
		t.Error("expected token to need refresh (expires in 3 min)")
	}

	// Token expiring in 10 minutes should NOT need refresh
	ok := &Token{
		AccessToken: "abc",
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	}
	if ok.NeedsRefresh() {
		t.Error("expected token to not need refresh (expires in 10 min)")
	}
}

func TestInMemoryTokenStore_CRUD(t *testing.T) {
	store := NewInMemoryTokenStore()
	ctx := context.Background()

	// Get non-existent token returns nil
	token, err := store.GetToken(ctx, "test-connector")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != nil {
		t.Fatal("expected nil token for non-existent connector")
	}

	// Save and retrieve
	saved := &Token{
		AccessToken:  "access-123",
		RefreshToken: "refresh-456",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		Scopes:       []string{"read", "write"},
	}
	if err := store.SaveToken(ctx, "test-connector", saved); err != nil {
		t.Fatalf("unexpected error saving token: %v", err)
	}

	retrieved, err := store.GetToken(ctx, "test-connector")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if retrieved == nil {
		t.Fatal("expected token, got nil")
	}
	if retrieved.AccessToken != "access-123" {
		t.Errorf("AccessToken = %q, want %q", retrieved.AccessToken, "access-123")
	}
	if retrieved.RefreshToken != "refresh-456" {
		t.Errorf("RefreshToken = %q, want %q", retrieved.RefreshToken, "refresh-456")
	}
	if len(retrieved.Scopes) != 2 {
		t.Errorf("Scopes length = %d, want 2", len(retrieved.Scopes))
	}

	// Delete
	if err := store.DeleteToken(ctx, "test-connector"); err != nil {
		t.Fatalf("unexpected error deleting token: %v", err)
	}
	afterDelete, err := store.GetToken(ctx, "test-connector")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if afterDelete != nil {
		t.Fatal("expected nil token after delete")
	}
}

func TestInMemoryTokenStore_Isolation(t *testing.T) {
	// Ensure stored tokens are copies (mutations don't affect store)
	store := NewInMemoryTokenStore()
	ctx := context.Background()

	original := &Token{
		AccessToken: "original",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		Scopes:      []string{"read"},
	}
	if err := store.SaveToken(ctx, "connector-1", original); err != nil {
		t.Fatal(err)
	}

	// Mutate the original
	original.AccessToken = "mutated"
	original.Scopes[0] = "mutated-scope"

	// Retrieved token should be unchanged
	retrieved, _ := store.GetToken(ctx, "connector-1")
	if retrieved.AccessToken != "original" {
		t.Errorf("store was mutated: AccessToken = %q, want %q", retrieved.AccessToken, "original")
	}
	if retrieved.Scopes[0] != "read" {
		t.Errorf("store was mutated: Scopes[0] = %q, want %q", retrieved.Scopes[0], "read")
	}
}

func TestTokenRefresher_EnsureValid_ValidToken(t *testing.T) {
	store := NewInMemoryTokenStore()
	ctx := context.Background()

	token := &Token{
		AccessToken: "valid-token",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}
	_ = store.SaveToken(ctx, "test-connector", token)

	refresher := &TokenRefresher{
		Store: store,
	}

	result, err := refresher.EnsureValid(ctx, "test-connector")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.AccessToken != "valid-token" {
		t.Errorf("AccessToken = %q, want %q", result.AccessToken, "valid-token")
	}
}

func TestTokenRefresher_EnsureValid_NoToken(t *testing.T) {
	store := NewInMemoryTokenStore()
	ctx := context.Background()

	refresher := &TokenRefresher{
		Store: store,
	}

	_, err := refresher.EnsureValid(ctx, "missing")
	if err == nil {
		t.Fatal("expected error for missing token")
	}
}

func TestTokenRefresher_EnsureValid_ExpiredNoRefreshToken(t *testing.T) {
	store := NewInMemoryTokenStore()
	ctx := context.Background()

	token := &Token{
		AccessToken: "expired-token",
		ExpiresAt:   time.Now().Add(-1 * time.Hour),
	}
	_ = store.SaveToken(ctx, "test-connector", token)

	refresher := &TokenRefresher{
		Store: store,
	}

	_, err := refresher.EnsureValid(ctx, "test-connector")
	if err == nil {
		t.Fatal("expected error for expired token without refresh token")
	}
}

func TestTokenRefresher_EnsureValid_NeedsRefreshStub(t *testing.T) {
	store := NewInMemoryTokenStore()
	ctx := context.Background()

	token := &Token{
		AccessToken:  "needs-refresh",
		RefreshToken: "refresh-token",
		ExpiresAt:    time.Now().Add(2 * time.Minute), // within 5-min refresh window
	}
	_ = store.SaveToken(ctx, "test-connector", token)

	refresher := &TokenRefresher{
		ClientID:      "client-id",
		ClientSecret:  "client-secret",
		TokenEndpoint: "https://oauth.example.com/token",
		Store:         store,
	}

	// Should return error since HTTP refresh is stubbed
	_, err := refresher.EnsureValid(ctx, "test-connector")
	if err == nil {
		t.Fatal("expected error from stubbed refresh")
	}
}
