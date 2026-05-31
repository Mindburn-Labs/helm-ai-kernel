package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveLoadSession_Roundtrip(t *testing.T) {
	// Use a temp directory as the home dir so we don't touch real config.
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	session := Session{
		Token:     "eyJhbGciOiJIUzI1NiJ9.test-payload.test-sig",
		Email:     "operator@helm.mindburn.org",
		TenantID:  "tenant_abc123",
		ExpiresAt: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
	}

	if err := SaveSession(session); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	// Verify file permissions.
	dir, _ := ConfigDir()
	path := filepath.Join(dir, SessionFile)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat session file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("session file permissions = %o, want 0600", perm)
	}

	loaded, err := LoadSession()
	if err != nil {
		t.Fatalf("LoadSession: %v", err)
	}
	if loaded.Token != session.Token {
		t.Errorf("token = %q, want %q", loaded.Token, session.Token)
	}
	if loaded.Email != session.Email {
		t.Errorf("email = %q, want %q", loaded.Email, session.Email)
	}
	if loaded.TenantID != session.TenantID {
		t.Errorf("tenant_id = %q, want %q", loaded.TenantID, session.TenantID)
	}
}

func TestLoadSession_NotExists(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	_, err := LoadSession()
	if err == nil {
		t.Fatal("LoadSession should fail when no session exists")
	}
}

func TestIsTokenExpired(t *testing.T) {
	tests := []struct {
		name    string
		session Session
		want    bool
	}{
		{
			name:    "no expiry set",
			session: Session{Token: "tok", ExpiresAt: ""},
			want:    false,
		},
		{
			name: "future expiry",
			session: Session{
				Token:     "tok",
				ExpiresAt: time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339),
			},
			want: false,
		},
		{
			name: "past expiry",
			session: Session{
				Token:     "tok",
				ExpiresAt: time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339),
			},
			want: true,
		},
		{
			name:    "unparseable expiry (fail-closed)",
			session: Session{Token: "tok", ExpiresAt: "not-a-date"},
			want:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsTokenExpired(tt.session)
			if got != tt.want {
				t.Errorf("IsTokenExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRunLogin_InvalidCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid credentials"}`))
	}))
	defer srv.Close()

	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	err := RunLogin(LoginOptions{
		Email:    "bad@example.com",
		Password: "wrong",
		APIURL:   srv.URL,
	})
	if err == nil {
		t.Fatal("RunLogin should fail with invalid credentials")
	}
	if got := err.Error(); !contains(got, "401") {
		t.Errorf("error should mention 401, got: %s", got)
	}
}

func TestRunLogin_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/auth/login" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		resp := loginResponse{
			Token:     "test-jwt-token",
			Email:     body["email"],
			TenantID:  "tenant_test",
			ExpiresAt: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		}
		resp.Workspace.ID = "ws_123"
		resp.Workspace.Name = "Test Workspace"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	err := RunLogin(LoginOptions{
		Email:    "test@example.com",
		Password: "correct",
		APIURL:   srv.URL,
	})
	if err != nil {
		t.Fatalf("RunLogin: %v", err)
	}

	// Verify session was persisted.
	loaded, err := LoadSession()
	if err != nil {
		t.Fatalf("LoadSession after login: %v", err)
	}
	if loaded.Token != "test-jwt-token" {
		t.Errorf("token = %q, want 'test-jwt-token'", loaded.Token)
	}
}

func TestRunLogin_MissingFields(t *testing.T) {
	if err := RunLogin(LoginOptions{Email: "", Password: "x"}); err == nil {
		t.Error("expected error for missing email")
	}
	if err := RunLogin(LoginOptions{Email: "x@y.com", Password: ""}); err == nil {
		t.Error("expected error for missing password")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsImpl(s, substr))
}

func containsImpl(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
