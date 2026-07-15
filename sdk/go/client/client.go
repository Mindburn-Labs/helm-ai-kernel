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
	Status     int
	Message    string
	ReasonCode ReasonCode
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
	WorkspaceID string
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

// EvaluationScope is the authenticated identity binding for a governed
// evaluation. It is transported in headers and is never copied into the JSON
// DecisionRequest body.
type EvaluationScope struct {
	TenantID    string
	PrincipalID string
	SessionID   string
	WorkspaceID string
}

// EvaluationResult combines the signed decision with its durable receipt
// reference and the server's idempotency replay signal.
type EvaluationResult struct {
	Decision  DecisionRecord `json:"decision"`
	ReceiptID string         `json:"receipt_id"`
	Replayed  bool           `json:"replayed"`
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

// WithWorkspaceID sets the X-Helm-Workspace-ID header.
func WithWorkspaceID(workspaceID string) Option {
	return func(c *HelmClient) { c.WorkspaceID = workspaceID }
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

// EvaluateDecision is retained for source compatibility only.
//
// Deprecated: it intentionally fails locally so an arbitrary legacy payload
// cannot reach the public evaluator route. Use EvaluateDecisionWithScope.
func (c *HelmClient) EvaluateDecision(_ any) (map[string]any, error) {
	return nil, fmt.Errorf("EvaluateDecision is retired; use EvaluateDecisionWithScope with EvaluationScope")
}

// EvaluateDecisionWithScope calls the public, Guardian-backed
// POST /api/v1/evaluate contract. It sends only the canonical DecisionRequest
// fields, binds identity from EvaluationScope headers, and returns the signed
// decision plus the durable receipt reference issued by the server.
func (c *HelmClient) EvaluateDecisionWithScope(req DecisionRequest, scope EvaluationScope, idempotencyKey string) (*EvaluationResult, error) {
	if err := validateEvaluationScope(c, scope); err != nil {
		return nil, err
	}

	type sessionActionPayload struct {
		Action    string `json:"action"`
		Resource  string `json:"resource"`
		Verdict   string `json:"verdict"`
		Timestamp int64  `json:"timestamp"`
	}
	payload := struct {
		Action         string                 `json:"action"`
		Resource       string                 `json:"resource"`
		Context        map[string]interface{} `json:"context,omitempty"`
		SessionHistory []sessionActionPayload `json:"session_history,omitempty"`
	}{
		Action:   req.Action,
		Resource: req.Resource,
		Context:  req.Context,
	}
	if req.SessionHistory != nil {
		payload.SessionHistory = make([]sessionActionPayload, len(req.SessionHistory))
		for i, action := range req.SessionHistory {
			payload.SessionHistory[i] = sessionActionPayload{
				Action:    action.Action,
				Resource:  action.Resource,
				Verdict:   action.Verdict,
				Timestamp: action.Timestamp,
			}
		}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest(http.MethodPost, c.BaseURL+"/api/v1/evaluate", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	c.applyHeaders(httpReq)
	httpReq.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.APIKey))
	httpReq.Header.Set("X-Helm-Tenant-ID", strings.TrimSpace(scope.TenantID))
	httpReq.Header.Set("X-Helm-Principal-ID", strings.TrimSpace(scope.PrincipalID))
	httpReq.Header.Set("X-Helm-Session-ID", strings.TrimSpace(scope.SessionID))
	// EvaluationScope is authoritative for workspace binding; do not inherit a
	// client default when the scoped request intentionally omits it.
	httpReq.Header.Del("X-Helm-Workspace-ID")
	if workspaceID := strings.TrimSpace(scope.WorkspaceID); workspaceID != "" {
		httpReq.Header.Set("X-Helm-Workspace-ID", workspaceID)
	}
	if idempotencyKey = strings.TrimSpace(idempotencyKey); idempotencyKey != "" {
		httpReq.Header.Set("Idempotency-Key", idempotencyKey)
	}

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, helmAPIErrorFromResponse(resp)
	}

	var decision DecisionRecord
	if err := json.NewDecoder(resp.Body).Decode(&decision); err != nil {
		return nil, err
	}
	receiptID := strings.TrimSpace(resp.Header.Get("X-Helm-Receipt-ID"))
	if receiptID == "" {
		return nil, fmt.Errorf("evaluator response missing required X-Helm-Receipt-ID")
	}
	return &EvaluationResult{
		Decision:  decision,
		ReceiptID: receiptID,
		Replayed:  strings.EqualFold(resp.Header.Get("X-Helm-Idempotency-Replayed"), "true"),
	}, nil
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

// ConformanceRun calls POST /api/v1/conformance/run.
func (c *HelmClient) ConformanceRun(req ConformanceRequest) (*ConformanceResult, error) {
	var out ConformanceResult
	err := c.do("POST", "/api/v1/conformance/run", req, &out)
	return &out, err
}

// GetConformanceReport calls GET /api/v1/conformance/reports/{id}.
func (c *HelmClient) GetConformanceReport(reportID string) (*ConformanceResult, error) {
	var out ConformanceResult
	err := c.do("GET", "/api/v1/conformance/reports/"+url.PathEscape(reportID), nil, &out)
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

func helmAPIErrorFromResponse(resp *http.Response) error {
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
	if c.WorkspaceID != "" {
		req.Header.Set("X-Helm-Workspace-ID", c.WorkspaceID)
	}
}

func validateEvaluationScope(c *HelmClient, scope EvaluationScope) error {
	if c == nil || strings.TrimSpace(c.APIKey) == "" {
		return fmt.Errorf("governed evaluation requires an API key")
	}
	for name, value := range map[string]string{
		"tenant_id":    scope.TenantID,
		"principal_id": scope.PrincipalID,
		"session_id":   scope.SessionID,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("governed evaluation requires %s", name)
		}
	}
	return nil
}
