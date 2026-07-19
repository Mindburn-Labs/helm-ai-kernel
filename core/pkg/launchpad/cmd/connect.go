package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// MachineCredentialFile is the canonical filename for a persisted cloud machine
// credential obtained via `helm-ai-kernel connect`.
const MachineCredentialFile = "machine.json"

// MachineTokenEnvVar is the environment variable a generated agent client config
// references for the short-lived bearer. The literal token is never written into
// a client config file; only this reference is.
const MachineTokenEnvVar = "HELM_MACHINE_TOKEN"

// defaultDeviceInterval is the fallback poll interval when the control plane does
// not return one within the allowed range.
const defaultDeviceInterval = 5 * time.Second

// MachineCredential is a persisted, workspace-scoped machine credential. The
// access token is short-lived; the refresh token is longer-lived but is stored
// only in this 0600 file and is never printed or written to a client config.
type MachineCredential struct {
	TokenType        string `json:"token_type"`
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	Scope            string `json:"scope"`
	CredentialID     string `json:"credential_id"`
	Subject          string `json:"subject"`
	WorkspaceID      string `json:"workspace_id"`
	APIURL           string `json:"api_url"`
	AccessExpiresAt  string `json:"access_expires_at"`
	RefreshExpiresAt string `json:"refresh_expires_at"`
	ConnectedAt      string `json:"connected_at"`
}

// deviceCodeResponse mirrors DeviceCodeResponse in the control-plane OpenAPI.
type deviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// machineTokenResponse mirrors MachineTokenResponse in the control-plane OpenAPI.
type machineTokenResponse struct {
	TokenType        string `json:"token_type"`
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	Scope            string `json:"scope"`
	CredentialID     string `json:"credential_id"`
	Subject          string `json:"subject"`
	WorkspaceID      string `json:"workspace_id"`
}

// machinePrincipal mirrors MachinePrincipal in the control-plane OpenAPI.
type machinePrincipal struct {
	CredentialID        string `json:"credential_id"`
	Subject             string `json:"subject"`
	WorkspaceID         string `json:"workspace_id"`
	ApprovedByPrincipal string `json:"approved_by_principal"`
	ClientName          string `json:"client_name"`
	ClientType          string `json:"client_type"`
}

// oauthError mirrors the OAuth device-flow error body {error, error_description}.
type oauthError struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

// ConnectOptions configures the one-click cloud connect device flow.
type ConnectOptions struct {
	// CloudBaseURL is the control-plane base (default: production cloud).
	CloudBaseURL string
	// ClientName is the self-reported client label sent to the control plane.
	ClientName string
	// ClientType is one of cli, desktop, framework, other.
	ClientType string
	Stdout     io.Writer
	Stderr     io.Writer

	// Injectable seams for testing; all default to real implementations.
	HTTPClient  *http.Client
	Now         func() time.Time
	Sleep       func(time.Duration)
	OpenBrowser func(string) error
}

// ConnectResult is the outcome of a successful connect device flow.
type ConnectResult struct {
	Credential  MachineCredential
	WorkspaceID string
	APIURL      string
	Principal   string
}

// RunConnect drives the browser-approved device authorization flow: it requests
// a device code, prints the user code and verification URL (opening the browser
// best-effort), polls for the token honoring authorization_pending / slow_down /
// expired_token, and on success persists a short-lived machine credential.
//
// It never writes an agent client config and never prints token material; the
// caller is responsible for writing the (token-free) client config after this
// returns successfully.
func RunConnect(opts ConnectOptions) (ConnectResult, error) {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Sleep == nil {
		opts.Sleep = time.Sleep
	}
	if opts.OpenBrowser == nil {
		opts.OpenBrowser = openBrowserBestEffort
	}
	if strings.TrimSpace(opts.ClientName) == "" {
		opts.ClientName = "HELM AI Kernel CLI"
	}
	if strings.TrimSpace(opts.ClientType) == "" {
		opts.ClientType = "cli"
	}

	base := resolveControlPlaneURL(opts.CloudBaseURL)

	code, err := requestDeviceCode(opts.HTTPClient, base, opts.ClientName, opts.ClientType)
	if err != nil {
		return ConnectResult{}, err
	}

	fmt.Fprintf(opts.Stdout, "\nTo connect this machine, approve it in the HELM Console:\n\n")
	fmt.Fprintf(opts.Stdout, "  1. Open: %s\n", code.VerificationURI)
	fmt.Fprintf(opts.Stdout, "  2. Enter code: %s\n\n", code.UserCode)
	if err := opts.OpenBrowser(verificationTarget(code)); err == nil {
		fmt.Fprintf(opts.Stdout, "Opened your browser to the approval page. Waiting for approval...\n")
	} else {
		fmt.Fprintf(opts.Stdout, "Open the URL above in your browser. Waiting for approval...\n")
	}

	token, err := pollDeviceToken(opts, base, code)
	if err != nil {
		return ConnectResult{}, err
	}

	now := opts.Now().UTC()
	cred := MachineCredential{
		TokenType:        token.TokenType,
		AccessToken:      token.AccessToken,
		RefreshToken:     token.RefreshToken,
		Scope:            token.Scope,
		CredentialID:     token.CredentialID,
		Subject:          token.Subject,
		WorkspaceID:      token.WorkspaceID,
		APIURL:           base,
		AccessExpiresAt:  now.Add(time.Duration(token.ExpiresIn) * time.Second).Format(time.RFC3339),
		RefreshExpiresAt: now.Add(time.Duration(token.RefreshExpiresIn) * time.Second).Format(time.RFC3339),
		ConnectedAt:      now.Format(time.RFC3339),
	}
	if err := SaveMachineCredential(cred); err != nil {
		return ConnectResult{}, fmt.Errorf("persist machine credential: %w", err)
	}

	result := ConnectResult{
		Credential:  cred,
		WorkspaceID: cred.WorkspaceID,
		APIURL:      base,
		Principal:   cred.Subject,
	}
	// Best-effort session verification for a friendlier principal display; the
	// authoritative credential is the token exchange above.
	if principal, err := resolveMachineSession(opts.HTTPClient, base, token.AccessToken); err == nil {
		if principal.ApprovedByPrincipal != "" {
			result.Principal = principal.ApprovedByPrincipal
		}
	}
	return result, nil
}

func requestDeviceCode(client *http.Client, base, clientName, clientType string) (deviceCodeResponse, error) {
	body, err := json.Marshal(map[string]string{
		"client_name": clientName,
		"client_type": clientType,
	})
	if err != nil {
		return deviceCodeResponse{}, fmt.Errorf("marshal device code request: %w", err)
	}
	resp, err := postJSON(client, base+"/api/v1/auth/device/code", body)
	if err != nil {
		return deviceCodeResponse{}, fmt.Errorf("start device authorization: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return deviceCodeResponse{}, fmt.Errorf("device authorization request rejected (HTTP %d): %s", resp.StatusCode, oauthMessage(raw))
	}
	var code deviceCodeResponse
	if err := json.Unmarshal(raw, &code); err != nil {
		return deviceCodeResponse{}, fmt.Errorf("parse device code response: %w", err)
	}
	if code.DeviceCode == "" || code.UserCode == "" || code.VerificationURI == "" {
		return deviceCodeResponse{}, errors.New("device code response was incomplete")
	}
	return code, nil
}

func pollDeviceToken(opts ConnectOptions, base string, code deviceCodeResponse) (machineTokenResponse, error) {
	interval := time.Duration(code.Interval) * time.Second
	if interval <= 0 || interval > 60*time.Second {
		interval = defaultDeviceInterval
	}
	expiresIn := code.ExpiresIn
	if expiresIn < 60 {
		expiresIn = 60
	}
	deadline := opts.Now().Add(time.Duration(expiresIn) * time.Second)

	reqBody, err := json.Marshal(map[string]string{
		"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
		"device_code": code.DeviceCode,
	})
	if err != nil {
		return machineTokenResponse{}, fmt.Errorf("marshal token request: %w", err)
	}

	for {
		if !opts.Now().Before(deadline) {
			return machineTokenResponse{}, errors.New("device authorization expired before it was approved; run connect again")
		}
		opts.Sleep(interval)

		resp, err := postJSON(opts.HTTPClient, base+"/api/v1/auth/device/token", reqBody)
		if err != nil {
			return machineTokenResponse{}, fmt.Errorf("poll for device token: %w", err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			var token machineTokenResponse
			if err := json.Unmarshal(raw, &token); err != nil {
				return machineTokenResponse{}, fmt.Errorf("parse token response: %w", err)
			}
			if token.AccessToken == "" || token.RefreshToken == "" || token.WorkspaceID == "" {
				return machineTokenResponse{}, errors.New("token response was incomplete")
			}
			return token, nil
		}

		var oe oauthError
		_ = json.Unmarshal(raw, &oe)
		switch oe.Code {
		case "authorization_pending":
			continue
		case "slow_down":
			interval += defaultDeviceInterval
			continue
		case "expired_token":
			return machineTokenResponse{}, errors.New("device authorization expired before it was approved; run connect again")
		case "access_denied":
			return machineTokenResponse{}, errors.New("device authorization was denied in the Console")
		case "invalid_grant":
			return machineTokenResponse{}, errors.New("device authorization is invalid or was already used; run connect again")
		default:
			return machineTokenResponse{}, fmt.Errorf("device token exchange failed (HTTP %d): %s", resp.StatusCode, oauthMessage(raw))
		}
	}
}

func resolveMachineSession(client *http.Client, base, accessToken string) (machinePrincipal, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, base+"/api/v1/auth/machine/session", nil)
	if err != nil {
		return machinePrincipal{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("User-Agent", "helm-ai-kernel/cli")
	resp, err := client.Do(req)
	if err != nil {
		return machinePrincipal{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return machinePrincipal{}, fmt.Errorf("machine session HTTP %d", resp.StatusCode)
	}
	var principal machinePrincipal
	if err := json.Unmarshal(raw, &principal); err != nil {
		return machinePrincipal{}, err
	}
	return principal, nil
}

func postJSON(client *http.Client, url string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "helm-ai-kernel/cli")
	return client.Do(req)
}

func oauthMessage(raw []byte) string {
	var oe oauthError
	if err := json.Unmarshal(raw, &oe); err == nil && oe.Code != "" {
		if oe.Description != "" {
			return oe.Code + ": " + oe.Description
		}
		return oe.Code
	}
	return strings.TrimSpace(string(raw))
}

func verificationTarget(code deviceCodeResponse) string {
	if code.VerificationURIComplete != "" {
		return code.VerificationURIComplete
	}
	return code.VerificationURI
}

// openBrowserBestEffort attempts to open a URL in the default browser. Any
// failure is returned so the caller can fall back to printing the URL; it never
// blocks the flow.
func openBrowserBestEffort(url string) error {
	if strings.TrimSpace(url) == "" {
		return errors.New("empty url")
	}
	var name string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		name, args = "open", []string{url}
	case "windows":
		name, args = "rundll32", []string{"url.dll,FileProtocolHandler", url}
	default:
		name, args = "xdg-open", []string{url}
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return err
	}
	return exec.Command(path, args...).Start()
}

// --- Machine credential persistence ---

// MachineCredentialPath returns the full path to the machine credential file.
func MachineCredentialPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, MachineCredentialFile), nil
}

// SaveMachineCredential writes the credential to disk with 0600 permissions.
func SaveMachineCredential(mc MachineCredential) error {
	dir, err := ConfigDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := json.MarshalIndent(mc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal machine credential: %w", err)
	}
	path := filepath.Join(dir, MachineCredentialFile)
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

// LoadMachineCredential reads the persisted machine credential from disk.
func LoadMachineCredential() (MachineCredential, error) {
	path, err := MachineCredentialPath()
	if err != nil {
		return MachineCredential{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return MachineCredential{}, fmt.Errorf("no cloud connection found; run 'helm-ai-kernel connect' first")
		}
		return MachineCredential{}, fmt.Errorf("read machine credential: %w", err)
	}
	var mc MachineCredential
	if err := json.Unmarshal(data, &mc); err != nil {
		return MachineCredential{}, fmt.Errorf("parse machine credential: %w", err)
	}
	return mc, nil
}
