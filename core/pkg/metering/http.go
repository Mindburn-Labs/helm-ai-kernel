package metering

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	ControlPlaneURLEnv = "HELM_METERING_URL"
	ServiceTokenEnv    = "HELM_METERING_SERVICE_TOKEN"
	ActivationEnv      = "HELM_METERING_ACTIVATE"

	authorizePath = "/api/v1/metering/authorize"
	settlePath    = "/api/v1/metering/settle"
)

// Config is server-owned configuration for the control-plane client. It is
// intentionally separate from customer request headers and payloads.
type Config struct {
	BaseURL      string
	ServiceToken string
	HTTPClient   *http.Client
}

func ConfigFromEnvironment() (Config, bool, error) {
	baseURL := strings.TrimSpace(os.Getenv(ControlPlaneURLEnv))
	if baseURL == "" {
		return Config{}, false, nil
	}
	return Config{
		BaseURL:      baseURL,
		ServiceToken: strings.TrimSpace(os.Getenv(ServiceTokenEnv)),
	}, true, nil
}

// FromEnvironment returns a disabled client unless an operator explicitly sets
// HELM_METERING_ACTIVATE=1. This keeps the OSS/local default network-free and
// prevents a configured URL from silently changing dispatch behavior. Once
// activated, any unavailable or incompatible service-auth route fails closed at
// authorization; the kernel never falls back to session-scoped control-plane
// APIs or caller credentials.
func FromEnvironment() (Client, error) {
	cfg, enabled, err := ConfigFromEnvironment()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return Disabled{}, nil
	}
	activation := strings.TrimSpace(os.Getenv(ActivationEnv))
	if activation == "" || activation == "0" {
		return Disabled{}, nil
	}
	if activation != "1" {
		return nil, fmt.Errorf("%s must be 1 when configured", ActivationEnv)
	}
	if strings.TrimSpace(cfg.ServiceToken) == "" {
		return nil, fmt.Errorf("%s is required when %s is configured", ServiceTokenEnv, ControlPlaneURLEnv)
	}
	return NewHTTPClient(cfg)
}

type httpClient struct {
	baseURL      *url.URL
	serviceToken string
	client       *http.Client
}

func NewHTTPClient(cfg Config) (Client, error) {
	if strings.TrimSpace(cfg.ServiceToken) == "" {
		return nil, fmt.Errorf("%s is required when %s is configured", ServiceTokenEnv, ControlPlaneURLEnv)
	}
	baseURL, err := url.Parse(strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/"))
	if err != nil || baseURL.Scheme == "" || baseURL.Host == "" {
		return nil, fmt.Errorf("%s must be an absolute HTTP URL", ControlPlaneURLEnv)
	}
	if baseURL.Scheme != "https" && baseURL.Scheme != "http" {
		return nil, fmt.Errorf("%s must use http or https", ControlPlaneURLEnv)
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &httpClient{
		baseURL:      baseURL,
		serviceToken: cfg.ServiceToken,
		client:       client,
	}, nil
}

func (c *httpClient) Enabled() bool { return true }

func (c *httpClient) Authorize(ctx context.Context, request AuthorizationRequest) (Authorization, error) {
	if err := request.Validate(); err != nil {
		return Authorization{}, err
	}
	var result Authorization
	if err := c.post(ctx, authorizePath, request, "authorize:"+request.DecisionReceiptID, &result); err != nil {
		return Authorization{}, fmt.Errorf("metering authorization: %w", err)
	}
	if !result.Approved || strings.TrimSpace(result.AuthorizationID) == "" {
		return Authorization{}, fmt.Errorf("metering authorization was not approved")
	}
	return result, nil
}

func (c *httpClient) Settle(ctx context.Context, request SettlementRequest) (Settlement, error) {
	if err := request.Validate(); err != nil {
		return Settlement{}, err
	}
	var result Settlement
	if err := c.post(ctx, settlePath, request, "settle:"+request.SettlementReceiptID, &result); err != nil {
		return Settlement{}, fmt.Errorf("metering settlement: %w", err)
	}
	if !result.Settled {
		return Settlement{}, fmt.Errorf("metering settlement was not confirmed")
	}
	return result, nil
}

func (c *httpClient) post(ctx context.Context, path string, payload any, idempotencyKey string, destination any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	endpoint := c.baseURL.ResolveReference(&url.URL{Path: path})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.serviceToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", idempotencyKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return fmt.Errorf("control plane returned %s: %s", resp.Status, strings.TrimSpace(string(detail)))
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(destination); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}
