// Package client provides a typed Go client for the HELM kernel API.
// Zero external dependencies — uses net/http and encoding/json only.
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// HelmApiError is returned when the API responds with a non-2xx status.
type HelmApiError struct {
	Status     int
	Message    string
	ReasonCode ReasonCode
}

func (e *HelmApiError) Error() string {
	return fmt.Sprintf("helm api %d: %s (%s)", e.Status, e.Message, e.ReasonCode)
}

// HelmClient is a typed client for the HELM kernel API.
type HelmClient struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
}

// New creates a new HelmClient.
func New(baseURL string, opts ...Option) *HelmClient {
	c := &HelmClient{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Option configures the client.
type Option func(*HelmClient)

// WithAPIKey sets the bearer token.
func WithAPIKey(key string) Option {
	return func(c *HelmClient) { c.APIKey = key }
}

// WithTimeout sets the HTTP timeout.
func WithTimeout(d time.Duration) Option {
	return func(c *HelmClient) { c.HTTPClient.Timeout = d }
}

func (c *HelmClient) do(method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, c.BaseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var helmErr HelmError
		if err := json.NewDecoder(resp.Body).Decode(&helmErr); err == nil {
			return &HelmApiError{
				Status:     resp.StatusCode,
				Message:    helmErr.Error.Message,
				ReasonCode: helmErr.Error.ReasonCode,
			}
		}
		return &HelmApiError{Status: resp.StatusCode, Message: "unknown error", ReasonCode: ReasonErrorInternal}
	}

	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// ChatCompletions calls POST /v1/chat/completions.
func (c *HelmClient) ChatCompletions(req ChatCompletionRequest) (*ChatCompletionResponse, error) {
	var out ChatCompletionResponse
	err := c.do("POST", "/v1/chat/completions", req, &out)
	return &out, err
}

// ApproveIntent calls POST /api/v1/kernel/approve.
func (c *HelmClient) ApproveIntent(req ApprovalRequest) (*Receipt, error) {
	var out Receipt
	err := c.do("POST", "/api/v1/kernel/approve", req, &out)
	return &out, err
}

// ListSessions calls GET /api/v1/proofgraph/sessions.
func (c *HelmClient) ListSessions(limit, offset int) ([]Session, error) {
	var out []Session
	err := c.do("GET", fmt.Sprintf("/api/v1/proofgraph/sessions?limit=%d&offset=%d", limit, offset), nil, &out)
	return out, err
}

// GetReceipts calls GET /api/v1/proofgraph/sessions/{id}/receipts.
func (c *HelmClient) GetReceipts(sessionID string) ([]Receipt, error) {
	var out []Receipt
	err := c.do("GET", "/api/v1/proofgraph/sessions/"+sessionID+"/receipts", nil, &out)
	return out, err
}

// ExportEvidence calls POST /api/v1/evidence/export and returns raw bytes.
func (c *HelmClient) ExportEvidence(sessionID string) ([]byte, error) {
	body, _ := json.Marshal(ExportRequest{SessionID: sessionID, Format: "tar.gz"})
	req, err := http.NewRequest("POST", c.BaseURL+"/api/v1/evidence/export", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// VerifyEvidence calls POST /api/v1/evidence/verify.
func (c *HelmClient) VerifyEvidence(bundle []byte) (*VerificationResult, error) {
	var out VerificationResult
	// Simplified: send as JSON with base64-encoded bundle
	err := c.do("POST", "/api/v1/evidence/verify", map[string]any{"bundle_b64": bundle}, &out)
	return &out, err
}

// ReplayVerify calls POST /api/v1/replay/verify.
func (c *HelmClient) ReplayVerify(bundle []byte) (*VerificationResult, error) {
	var out VerificationResult
	err := c.do("POST", "/api/v1/replay/verify", map[string]any{"bundle_b64": bundle}, &out)
	return &out, err
}

// GetReceipt calls GET /api/v1/proofgraph/receipts/{hash}.
func (c *HelmClient) GetReceipt(receiptHash string) (*Receipt, error) {
	var out Receipt
	err := c.do("GET", "/api/v1/proofgraph/receipts/"+receiptHash, nil, &out)
	return &out, err
}

// ConformanceRun calls POST /api/v1/conformance/run.
func (c *HelmClient) ConformanceRun(req ConformanceRequest) (*ConformanceResult, error) {
	var out ConformanceResult
	err := c.do("POST", "/api/v1/conformance/run", req, &out)
	return &out, err
}

// GetConformanceReport calls GET /api/v1/conformance/reports/{id}.
func (c *HelmClient) GetConformanceReport(reportID string) (*ConformanceResult, error) {
	var out ConformanceResult
	err := c.do("GET", "/api/v1/conformance/reports/"+reportID, nil, &out)
	return &out, err
}

// Health calls GET /healthz.
func (c *HelmClient) Health() (map[string]string, error) {
	var out map[string]string
	err := c.do("GET", "/healthz", nil, &out)
	return out, err
}

// Version calls GET /version.
func (c *HelmClient) Version() (*VersionInfo, error) {
	var out VersionInfo
	err := c.do("GET", "/version", nil, &out)
	return &out, err
}
