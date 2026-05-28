// Package cmd implements CLI commands for authenticating with the HELM Console
// and pairing a local helm-ai-kernel instance with a remote workspace.
package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Default API endpoint for the HELM Console backend.
const defaultConsoleURL = "https://console.helm.mindburn.org"

// SessionFile is the canonical filename for stored JWT sessions.
const SessionFile = "session.json"

// Session represents a persisted authentication session.
type Session struct {
	Token    string `json:"token"`
	Email    string `json:"email"`
	TenantID string `json:"tenant_id"`
	ExpiresAt string `json:"expires_at"`
}

// LoginOptions configures the login command behaviour.
type LoginOptions struct {
	Email    string
	Password string
	APIURL   string
	Stdout   io.Writer
	Stderr   io.Writer
}

// loginResponse is the expected shape of POST /api/auth/login.
type loginResponse struct {
	Token    string `json:"token"`
	Email    string `json:"email"`
	TenantID string `json:"tenant_id"`
	ExpiresAt string `json:"expires_at"`
	Workspace struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"workspace"`
}

// RunLogin performs the login flow: POST credentials, persist JWT.
func RunLogin(opts LoginOptions) error {
	if opts.Email == "" {
		return errors.New("email is required (--email or prompt)")
	}
	if opts.Password == "" {
		return errors.New("password is required (--password or prompt)")
	}
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}

	apiURL := resolveConsoleURL(opts.APIURL)
	slog.Info("authenticating with HELM Console", "api_url", apiURL)

	// Build request body.
	body, err := json.Marshal(map[string]string{
		"email":    opts.Email,
		"password": opts.Password,
	})
	if err != nil {
		return fmt.Errorf("marshal login body: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, apiURL+"/api/auth/login", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "helm-ai-kernel/cli")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read login response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		slog.Error("login failed", "status", resp.StatusCode, "body", string(respBody))
		return fmt.Errorf("login failed: HTTP %d — %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var lr loginResponse
	if err := json.Unmarshal(respBody, &lr); err != nil {
		return fmt.Errorf("parse login response: %w", err)
	}
	if lr.Token == "" {
		return errors.New("login response did not contain a token")
	}

	session := Session{
		Token:     lr.Token,
		Email:     lr.Email,
		TenantID:  lr.TenantID,
		ExpiresAt: lr.ExpiresAt,
	}
	if err := SaveSession(session); err != nil {
		return fmt.Errorf("persist session: %w", err)
	}

	fmt.Fprintf(opts.Stdout, "✅ Logged in as %s (tenant: %s)\n", lr.Email, lr.TenantID)
	if lr.Workspace.ID != "" {
		fmt.Fprintf(opts.Stdout, "   Workspace: %s (%s)\n", lr.Workspace.Name, lr.Workspace.ID)
	}
	return nil
}

// --- Session persistence ---

// ConfigDir returns the canonical config directory for helm-ai-kernel sessions.
func ConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".config", "helm-ai-kernel"), nil
}

// SessionPath returns the full path to the session file.
func SessionPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, SessionFile), nil
}

// SaveSession writes the session to disk with restrictive permissions.
func SaveSession(s Session) error {
	dir, err := ConfigDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}
	path := filepath.Join(dir, SessionFile)
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

// LoadSession reads the persisted session from disk.
func LoadSession() (Session, error) {
	path, err := SessionPath()
	if err != nil {
		return Session{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Session{}, fmt.Errorf("no session found; run 'helm-ai-kernel login' first")
		}
		return Session{}, fmt.Errorf("read session: %w", err)
	}
	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return Session{}, fmt.Errorf("parse session: %w", err)
	}
	return s, nil
}

// IsTokenExpired returns true if the session token has passed its expiry time.
func IsTokenExpired(s Session) bool {
	if s.ExpiresAt == "" {
		return false // no expiry set; assume valid
	}
	expiry, err := time.Parse(time.RFC3339, s.ExpiresAt)
	if err != nil {
		slog.Warn("could not parse token expiry", "expires_at", s.ExpiresAt, "error", err)
		return true // fail-closed: treat unparseable expiry as expired
	}
	return time.Now().After(expiry)
}

// resolveConsoleURL picks the console backend URL from explicit flag, env, or default.
func resolveConsoleURL(explicit string) string {
	if explicit != "" {
		return strings.TrimRight(explicit, "/")
	}
	if envURL := os.Getenv("HELM_CONSOLE_URL"); envURL != "" {
		return strings.TrimRight(envURL, "/")
	}
	return defaultConsoleURL
}
