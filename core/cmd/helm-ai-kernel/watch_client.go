package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// approvalClient is the narrow approval API surface required by watch. The
// command never creates or consumes approvals: it only reads server state and
// records an explicitly confirmed approval or denial.
type approvalClient interface {
	ListApprovals(ctx context.Context) ([]contracts.ApprovalCeremony, error)
	TransitionApproval(ctx context.Context, approvalID, action, actor, reason string) (contracts.ApprovalCeremony, error)
}

const approvalAPIBasePath = "/api/v1/approvals"

var errApprovalAPIKeyMissing = errors.New("admin API key is required (set HELM_ADMIN_API_KEY or use --api-key-file)")

// approvalHTTPClient talks to the kernel's admin-protected approval routes.
// It deliberately owns the bearer token and never exposes it through command
// output or request errors.
type approvalHTTPClient struct {
	baseURL    *url.URL
	apiKey     string
	httpClient *http.Client
}

func newApprovalHTTPClient(rawURL, apiKey string) (*approvalHTTPClient, error) {
	base := strings.TrimSpace(rawURL)
	if base == "" {
		return nil, errors.New("server URL is required")
	}
	parsed, err := url.Parse(base)
	if err != nil {
		return nil, errors.New("server URL could not be parsed")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("server URL must be http or https")
	}
	if parsed.Host == "" {
		return nil, errors.New("server URL must include a host")
	}
	// The endpoint does not accept credentials or query parameters. Rejecting
	// both prevents a secret from being smuggled through the argv URL.
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("server URL must not contain credentials, a query, or a fragment")
	}
	// The client sends an admin bearer key on every request. Plain HTTP is only
	// safe for the explicit loopback identifiers; do not resolve hostnames or
	// broaden this allowlist.
	if parsed.Scheme == "http" && !isLoopbackHost(parsed.Hostname()) {
		return nil, errors.New("server URL must use https: plain http is only allowed for loopback hosts (127.0.0.1, ::1, localhost)")
	}
	key := strings.TrimSpace(apiKey)
	// Construction remains side-effect free so callers can build a client
	// before credentials are available; do rejects a missing key before any
	// network request. Non-empty malformed keys fail here.
	if key != "" && strings.IndexFunc(key, unicode.IsControl) >= 0 {
		return nil, errors.New("admin API key must not contain control characters")
	}
	return &approvalHTTPClient{
		baseURL: parsed,
		apiKey:  key,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			// Never follow a redirect after attaching an admin bearer token.
			// Returning the first response makes redirects explicit failures and
			// ensures the key cannot be forwarded to another endpoint.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// isLoopbackHost reports only the loopback identifiers that are safe for an
// HTTP bearer-token connection. Broader 127/8, wildcard, and resolver-based
// interpretations are deliberately rejected.
func isLoopbackHost(host string) bool {
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "127.0.0.1", "::1", "localhost":
		return true
	default:
		return false
	}
}

func validateApprovalAPIKey(key string) error {
	if key == "" {
		return errApprovalAPIKeyMissing
	}
	if strings.IndexFunc(key, unicode.IsControl) >= 0 {
		return errors.New("admin API key must not contain control characters")
	}
	return nil
}

func (c *approvalHTTPClient) ListApprovals(ctx context.Context) ([]contracts.ApprovalCeremony, error) {
	var ceremonies []contracts.ApprovalCeremony
	if err := c.do(ctx, http.MethodGet, approvalAPIBasePath, nil, &ceremonies); err != nil {
		return nil, err
	}
	return ceremonies, nil
}

func (c *approvalHTTPClient) TransitionApproval(ctx context.Context, approvalID, action, actor, reason string) (contracts.ApprovalCeremony, error) {
	switch action {
	case "approve", "deny":
	default:
		return contracts.ApprovalCeremony{}, fmt.Errorf("unsupported approval transition action %q", action)
	}
	if strings.TrimSpace(approvalID) == "" {
		return contracts.ApprovalCeremony{}, errors.New("approval id is required")
	}
	if strings.TrimSpace(actor) == "" {
		return contracts.ApprovalCeremony{}, errors.New("approval transition actor is required")
	}
	body := struct {
		Actor  string `json:"actor"`
		Reason string `json:"reason,omitempty"`
	}{Actor: actor, Reason: reason}
	var ceremony contracts.ApprovalCeremony
	path := approvalAPIBasePath + "/" + url.PathEscape(approvalID) + "/" + action
	if err := c.do(ctx, http.MethodPost, path, body, &ceremony); err != nil {
		return contracts.ApprovalCeremony{}, err
	}
	return ceremony, nil
}

func (c *approvalHTTPClient) do(ctx context.Context, method, path string, body, out any) error {
	if c == nil {
		return errors.New("approval client is required")
	}
	if err := validateApprovalAPIKey(c.apiKey); err != nil {
		return err
	}
	if c.baseURL == nil {
		return errors.New("approval API base URL is required")
	}
	if c.httpClient == nil {
		return errors.New("approval HTTP client is required")
	}

	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode approval request: %w", err)
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL.JoinPath(path).String(), reader)
	if err != nil {
		return fmt.Errorf("build approval request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("approval API %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read approval API response: %w", err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("approval API %s %s: HTTP %d: %s", method, path, resp.StatusCode, terminalSafe(strings.TrimSpace(string(payload))))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("decode approval API response: %w", err)
	}
	return nil
}
