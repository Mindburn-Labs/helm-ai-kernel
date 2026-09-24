// Package client provides a typed Go client for the HELM kernel API.
// Zero external dependencies — uses net/http and encoding/json only.
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// HelmApiError is returned when the API responds with a non-2xx status.
type HelmApiError struct {
	Status  int
	Message string
	// ReasonCode is the registered reason code from the error's
	// helm.errors.v1.ErrorDetail: an open string, empty when there is none.
	ReasonCode ReasonCode
	// Code is the Connect error code, such as "not_found" or "unavailable".
	Code string
	// Retryable reports whether repeating the same request can succeed.
	Retryable bool
}

func (e *HelmApiError) Error() string {
	return fmt.Sprintf("helm api %d: %s (%s)", e.Status, e.Message, e.ReasonCode)
}

// HelmClient is a typed client for the HELM kernel API.
type HelmClient struct {
	BaseURL     string
	APIKey      string
	TenantID    string
	PrincipalID string
	HTTPClient  *http.Client
}

// GovernanceMetadata captures kernel-issued X-Helm-* response headers.
type GovernanceMetadata struct {
	ReceiptID      string `json:"receipt_id"`
	Status         string `json:"status"`
	OutputHash     string `json:"output_hash"`
	LamportClock   int    `json:"lamport_clock"`
	ReasonCode     string `json:"reason_code"`
	DecisionID     string `json:"decision_id"`
	ProofGraphNode string `json:"proofgraph_node"`
	Signature      string `json:"signature"`
	ToolCalls      int    `json:"tool_calls"`
}

// ChatCompletionWithReceipt returns the OpenAI-compatible response plus HELM governance headers.
type ChatCompletionWithReceipt struct {
	Response   ChatCompletionResponse `json:"response"`
	Governance GovernanceMetadata     `json:"governance"`
}

type DemoRunResult = map[string]any
type DemoReceiptVerification = map[string]any

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

// WithTenantID sets the X-Helm-Tenant-ID header.
func WithTenantID(tenantID string) Option {
	return func(c *HelmClient) { c.TenantID = tenantID }
}

// WithPrincipalID sets the X-Helm-Principal-ID header.
func WithPrincipalID(principalID string) Option {
	return func(c *HelmClient) { c.PrincipalID = principalID }
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
	c.applyHeaders(req)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return helmAPIErrorFromResponse(resp)
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

// ChatCompletionsWithReceipt calls POST /v1/chat/completions and extracts X-Helm-* governance headers.
func (c *HelmClient) ChatCompletionsWithReceipt(req ChatCompletionRequest) (*ChatCompletionWithReceipt, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequest("POST", c.BaseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	c.applyHeaders(httpReq)
	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, helmAPIErrorFromResponse(resp)
	}
	var out ChatCompletionResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &ChatCompletionWithReceipt{
		Response: out,
		Governance: GovernanceMetadata{
			ReceiptID:      resp.Header.Get("X-Helm-Receipt-ID"),
			Status:         resp.Header.Get("X-Helm-Status"),
			OutputHash:     resp.Header.Get("X-Helm-Output-Hash"),
			LamportClock:   parseHeaderInt(resp.Header.Get("X-Helm-Lamport-Clock")),
			ReasonCode:     resp.Header.Get("X-Helm-Reason-Code"),
			DecisionID:     resp.Header.Get("X-Helm-Decision-ID"),
			ProofGraphNode: resp.Header.Get("X-Helm-ProofGraph-Node"),
			Signature:      resp.Header.Get("X-Helm-Signature"),
			ToolCalls:      parseHeaderInt(resp.Header.Get("X-Helm-Tool-Calls")),
		},
	}, nil
}

// EvaluateDecision calls POST /api/v1/evaluate with the legacy dynamic request and response.
// Deprecated: use EvaluateDecisionV5 for the typed V5 contract.
func (c *HelmClient) EvaluateDecision(req any) (map[string]any, error) {
	var out map[string]any
	err := c.do("POST", "/api/v1/evaluate", req, &out)
	return out, err
}

// EvaluateDecisionV5 calls POST /api/v1/evaluate with the canonical V5 request.
func (c *HelmClient) EvaluateDecisionV5(req EvaluateRequest) (*EvaluateResponse, error) {
	if strings.TrimSpace(req.GetTool()) == "" {
		return nil, fmt.Errorf("evaluate decision requires a non-blank tool")
	}
	if strings.TrimSpace(req.GetEffectLevel()) == "" {
		return nil, fmt.Errorf("evaluate decision requires a non-blank effect_level")
	}
	if strings.TrimSpace(req.GetSessionId()) == "" {
		return nil, fmt.Errorf("evaluate decision requires a non-blank session_id")
	}
	var out EvaluateResponse
	err := c.do("POST", "/api/v1/evaluate", req, &out)
	return &out, err
}

// RunPublicDemo calls POST /api/demo/run.
func (c *HelmClient) RunPublicDemo(actionID string, args SurfaceRecord) (*DemoRunResult, error) {
	if args == nil {
		args = SurfaceRecord{}
	}
	var out DemoRunResult
	err := c.do("POST", "/api/demo/run", map[string]any{
		"action_id": actionID,
		"policy_id": "agent_tool_call_boundary",
		"args":      args,
	}, &out)
	return &out, err
}

// VerifyPublicDemoReceipt calls POST /api/demo/verify.
func (c *HelmClient) VerifyPublicDemoReceipt(receipt SurfaceRecord, expectedReceiptHash string) (*DemoReceiptVerification, error) {
	var out DemoReceiptVerification
	err := c.do("POST", "/api/demo/verify", map[string]any{
		"receipt":               receipt,
		"expected_receipt_hash": expectedReceiptHash,
	}, &out)
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
	err := c.do("GET", "/api/v1/proofgraph/sessions/"+url.PathEscape(sessionID)+"/receipts", nil, &out)
	return out, err
}

// ExportEvidence calls POST /api/v1/evidence/export and returns raw bytes.
func (c *HelmClient) ExportEvidence(sessionID string) ([]byte, error) {
	format := "tar.gz"
	body, _ := json.Marshal(ExportRequest{SessionId: &sessionID, Format: &format})
	req, err := http.NewRequest("POST", c.BaseURL+"/api/v1/evidence/export", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	c.applyHeaders(req)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, helmAPIErrorFromResponse(resp)
	}
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
	err := c.do("GET", "/api/v1/proofgraph/receipts/"+url.PathEscape(receiptHash), nil, &out)
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

// errorBody is the HELM error model (core/pkg/httperr): an RFC 7807 problem
// whose extension members form a Connect error with one
// helm.errors.v1.ErrorDetail, plus the deprecated "error" member.
type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Detail  string `json:"detail"`
	Details []struct {
		Type  string `json:"type"`
		Debug struct {
			ReasonCode string `json:"reason_code"`
			Retryable  bool   `json:"retryable"`
		} `json:"debug"`
	} `json:"details"`
	Legacy *struct {
		Message    string `json:"message"`
		ReasonCode string `json:"reason_code"`
	} `json:"error"`
}

func helmAPIErrorFromResponse(resp *http.Response) error {
	var body errorBody
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || (body.Code == "" && body.Legacy == nil) {
		return &HelmApiError{Status: resp.StatusCode, Message: "unknown error", ReasonCode: ReasonErrorInternal}
	}
	out := &HelmApiError{Status: resp.StatusCode, Code: body.Code, Message: firstNonEmpty(body.Message, body.Detail)}
	for _, detail := range body.Details {
		if detail.Type == "helm.errors.v1.ErrorDetail" {
			out.ReasonCode, out.Retryable = detail.Debug.ReasonCode, detail.Debug.Retryable
			break
		}
	}
	if body.Legacy != nil {
		out.Message = firstNonEmpty(out.Message, body.Legacy.Message)
		out.ReasonCode = firstNonEmpty(out.ReasonCode, body.Legacy.ReasonCode)
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func parseHeaderInt(raw string) int {
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0
	}
	return value
}

func (c *HelmClient) applyHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	if c.TenantID != "" {
		req.Header.Set("X-Helm-Tenant-ID", c.TenantID)
	}
	if c.PrincipalID != "" {
		req.Header.Set("X-Helm-Principal-ID", c.PrincipalID)
	}
}
