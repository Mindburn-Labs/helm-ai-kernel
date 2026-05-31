package cmd

import (
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

// PairingFile is the canonical filename for stored workspace pairings.
const PairingFile = "pairing.json"

// Pairing represents a persisted workspace pairing.
type Pairing struct {
	WorkspaceID string `json:"workspace_id"`
	PairedAt    string `json:"paired_at"`
	APIURL      string `json:"api_url"`
}

// PairOptions configures the console pair command behaviour.
type PairOptions struct {
	WorkspaceID string
	APIURL      string
	Stdout      io.Writer
	Stderr      io.Writer
}

// entitlementsResponse is the expected shape of GET /api/v1/me/entitlements.
type entitlementsResponse struct {
	Workspaces []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"workspaces"`
}

// RunPair pairs the local kernel with a HELM Console workspace.
func RunPair(opts PairOptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}

	// Load and validate session.
	session, err := LoadSession()
	if err != nil {
		return err
	}
	if session.Token == "" {
		return errors.New("no valid token found; run 'helm-ai-kernel login' first")
	}
	if IsTokenExpired(session) {
		return errors.New("session token has expired; run 'helm-ai-kernel login' to re-authenticate")
	}

	apiURL := resolveConsoleURL(opts.APIURL)
	workspaceID := opts.WorkspaceID

	// Auto-discover workspace if not specified.
	if workspaceID == "" {
		slog.Info("no workspace specified, discovering from entitlements", "api_url", apiURL)
		discovered, err := discoverWorkspace(apiURL, session.Token)
		if err != nil {
			return fmt.Errorf("workspace discovery failed: %w", err)
		}
		workspaceID = discovered
	}

	if workspaceID == "" {
		return errors.New("could not determine workspace; use --workspace <id>")
	}

	pairing := Pairing{
		WorkspaceID: workspaceID,
		PairedAt:    time.Now().UTC().Format(time.RFC3339),
		APIURL:      apiURL,
	}
	if err := SavePairing(pairing); err != nil {
		return fmt.Errorf("persist pairing: %w", err)
	}

	fmt.Fprintf(opts.Stdout, "✅ Paired with workspace %s\n", workspaceID)
	fmt.Fprintf(opts.Stdout, "   API: %s\n", apiURL)
	fmt.Fprintf(opts.Stdout, "   Paired at: %s\n", pairing.PairedAt)
	return nil
}

// discoverWorkspace calls the entitlements endpoint and returns the first
// workspace ID, or an error if none are found.
func discoverWorkspace(apiURL, token string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, apiURL+"/api/v1/me/entitlements", nil)
	if err != nil {
		return "", fmt.Errorf("build entitlements request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "helm-ai-kernel/cli")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("entitlements request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return "", fmt.Errorf("read entitlements response: %w", readErr)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return "", errors.New("unauthorized — token may be invalid or expired; run 'helm-ai-kernel login'")
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("entitlements HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var er entitlementsResponse
	if err := json.Unmarshal(respBody, &er); err != nil {
		return "", fmt.Errorf("parse entitlements: %w", err)
	}
	if len(er.Workspaces) == 0 {
		return "", errors.New("no workspaces found for this account")
	}

	slog.Info("discovered workspace", "workspace_id", er.Workspaces[0].ID, "workspace_name", er.Workspaces[0].Name)
	return er.Workspaces[0].ID, nil
}

// --- Pairing persistence ---

// PairingPath returns the full path to the pairing file.
func PairingPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, PairingFile), nil
}

// SavePairing writes the pairing to disk with restrictive permissions.
func SavePairing(p Pairing) error {
	dir, err := ConfigDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal pairing: %w", err)
	}
	path := filepath.Join(dir, PairingFile)
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

// LoadPairing reads the persisted pairing from disk.
func LoadPairing() (Pairing, error) {
	path, err := PairingPath()
	if err != nil {
		return Pairing{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Pairing{}, fmt.Errorf("no pairing found; run 'helm-ai-kernel console pair' first")
		}
		return Pairing{}, fmt.Errorf("read pairing: %w", err)
	}
	var p Pairing
	if err := json.Unmarshal(data, &p); err != nil {
		return Pairing{}, fmt.Errorf("parse pairing: %w", err)
	}
	return p, nil
}
