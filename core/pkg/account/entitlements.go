package account

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var ErrUnavailable = errors.New("account entitlements unavailable")

type Client struct {
	DecisionsURL string
	Issuer       string
	Audience     string
	JWKSURL      string
	Required     bool
	HTTPClient   *http.Client
}

type UsageCounters struct {
	MonthlyLaunches int64 `json:"monthly_launches,omitempty"`
	ConcurrentRuns  int64 `json:"concurrent_runs,omitempty"`
	CloudTargets    int64 `json:"cloud_targets,omitempty"`
}

type DecisionRequest struct {
	PrincipalID   string        `json:"principal_id,omitempty"`
	TenantID      string        `json:"tenant_id,omitempty"`
	WorkspaceID   string        `json:"workspace_id,omitempty"`
	Action        string        `json:"action"`
	AppID         string        `json:"app_id,omitempty"`
	SubstrateID   string        `json:"substrate_id,omitempty"`
	Target        string        `json:"target,omitempty"`
	CurrentUsage  UsageCounters `json:"current_usage,omitempty"`
	RunID         string        `json:"run_id,omitempty"`
	RequestedAt   time.Time     `json:"requested_at,omitempty"`
	DecisionNonce string        `json:"decision_nonce,omitempty"`
}

type Decision struct {
	Allowed            bool      `json:"allowed"`
	UserState          string    `json:"user_state"`
	RequiredCapability string    `json:"required_capability,omitempty"`
	ReasonCode         string    `json:"reason_code"`
	Reason             string    `json:"reason"`
	UpgradeReason      string    `json:"upgrade_reason,omitempty"`
	Limit              int64     `json:"limit,omitempty"`
	Used               int64     `json:"used,omitempty"`
	Remaining          int64     `json:"remaining,omitempty"`
	DecisionRef        string    `json:"decision_ref"`
	Source             string    `json:"source"`
	ExpiresAt          time.Time `json:"expires_at"`
}

func NewClientFromEnv() *Client {
	return &Client{
		DecisionsURL: decisionsURL(os.Getenv("HELM_ACCOUNT_ENTITLEMENTS_URL")),
		JWKSURL:      strings.TrimSpace(os.Getenv("HELM_ACCOUNT_JWKS_URL")),
		Issuer:       strings.TrimSpace(os.Getenv("HELM_ACCOUNT_ISSUER")),
		Audience:     strings.TrimSpace(os.Getenv("HELM_ACCOUNT_AUDIENCE")),
		Required:     strings.EqualFold(strings.TrimSpace(os.Getenv("HELM_ACCOUNT_REQUIRED")), "true"),
		HTTPClient:   &http.Client{Timeout: 5 * time.Second},
	}
}

func (c *Client) Enabled() bool {
	return c != nil && strings.TrimSpace(c.DecisionsURL) != ""
}

func (c *Client) Decide(ctx context.Context, inbound *http.Request, req DecisionRequest) (*Decision, error) {
	if !c.Enabled() {
		return nil, nil
	}
	if req.RequestedAt.IsZero() {
		req.RequestedAt = time.Now().UTC()
	}
	if c.Required && !hasSessionCredential(inbound) {
		return nil, fmt.Errorf("%w: hosted session credential required", ErrUnavailable)
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.DecisionsURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	for _, key := range []string{"Authorization", "Cookie", "X-Request-ID", "X-HELM-Workspace-ID"} {
		for _, value := range inbound.Header.Values(key) {
			if strings.TrimSpace(value) != "" {
				httpReq.Header.Add(key, value)
			}
		}
	}
	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: decision endpoint returned %d", ErrUnavailable, resp.StatusCode)
	}
	var decision Decision
	if err := json.NewDecoder(resp.Body).Decode(&decision); err != nil {
		return nil, err
	}
	return &decision, nil
}

func decisionsURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return raw
	}
	if strings.HasSuffix(strings.TrimRight(parsed.Path, "/"), "/api/v1/account/decisions") {
		return strings.TrimRight(raw, "/")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/api/v1/account/decisions"
	return parsed.String()
}

func hasSessionCredential(r *http.Request) bool {
	if r == nil {
		return false
	}
	if strings.TrimSpace(r.Header.Get("Authorization")) != "" {
		return true
	}
	cookie, err := r.Cookie("helm_session")
	return err == nil && strings.TrimSpace(cookie.Value) != ""
}
