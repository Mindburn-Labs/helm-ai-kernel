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

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// approvalClient is the client surface of the kernel approval API consumed by
// `watch` and `workstation gate --request-approval`. Pending items always
// derive from server state; implementations must fail closed on transport and
// status errors.
type approvalClient interface {
	ListApprovals(ctx context.Context) ([]contracts.ApprovalCeremony, error)
	TransitionApproval(ctx context.Context, approvalID, action, actor, reason string) (contracts.ApprovalCeremony, error)
	CreateApproval(ctx context.Context, req createApprovalRequest) (contracts.ApprovalCeremony, error)
}

// createApprovalRequest mirrors the POST /api/v1/approvals payload in
// contract_routes.go.
type createApprovalRequest struct {
	ApprovalID  string   `json:"approval_id,omitempty"`
	Subject     string   `json:"subject"`
	Action      string   `json:"action"`
	RequestedBy string   `json:"requested_by"`
	Approvers   []string `json:"approvers,omitempty"`
	Quorum      int      `json:"quorum,omitempty"`
	Reason      string   `json:"reason,omitempty"`
	ReceiptID   string   `json:"receipt_id,omitempty"`
}

const approvalAPIBasePath = "/api/v1/approvals"

var errApprovalAPIKeyMissing = errors.New("admin API key is required (set HELM_ADMIN_API_KEY or --api-key-file)")

// approvalHTTPClient talks to the kernel server approval routes with the
// standalone admin API key (Authorization: Bearer).
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
		return nil, fmt.Errorf("parse server URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("server URL must be http or https: %q", base)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("server URL must include a host: %q", base)
	}
	return &approvalHTTPClient{
		baseURL:    parsed,
		apiKey:     strings.TrimSpace(apiKey),
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}, nil
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

func (c *approvalHTTPClient) CreateApproval(ctx context.Context, req createApprovalRequest) (contracts.ApprovalCeremony, error) {
	if strings.TrimSpace(req.Subject) == "" || strings.TrimSpace(req.Action) == "" || strings.TrimSpace(req.RequestedBy) == "" {
		return contracts.ApprovalCeremony{}, errors.New("approval subject, action, and requested_by are required")
	}
	var ceremony contracts.ApprovalCeremony
	if err := c.do(ctx, http.MethodPost, approvalAPIBasePath, req, &ceremony); err != nil {
		return contracts.ApprovalCeremony{}, err
	}
	return ceremony, nil
}

func (c *approvalHTTPClient) do(ctx context.Context, method, path string, body, out any) error {
	if c.apiKey == "" {
		return errApprovalAPIKeyMissing
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
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("approval API %s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(payload)))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("decode approval API response: %w", err)
	}
	return nil
}
