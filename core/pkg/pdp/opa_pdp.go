package pdp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

const BackendOPA Backend = "opa"

// OpaPDP implements PolicyDecisionPoint using an OPA REST API backend.
//
// OPA (Open Policy Agent) evaluates Rego policies remotely. This adapter
// maps HELM's DecisionRequest to OPA's input format and OPA's result
// back to HELM's DecisionResponse with deterministic hashing.
//
// Every call is fail-closed: network errors, timeouts, or unexpected
// responses all result in DENY.
type OpaPDP struct {
	endpoint    string // e.g., "http://localhost:8181/v1/data/helm/authz"
	client      *http.Client
	policyRef   string
	policyCache string // cached policy hash
}

// OpaConfig configures the OPA PDP backend.
type OpaConfig struct {
	// Endpoint is the OPA REST API URL for policy evaluation.
	// Example: "http://localhost:8181/v1/data/helm/authz"
	Endpoint string `json:"endpoint"`

	// PolicyRef is a stable reference to the active policy (e.g., git commit, bundle version).
	PolicyRef string `json:"policy_ref"`

	// TimeoutMs is the HTTP timeout in milliseconds. Default: 500ms.
	TimeoutMs int `json:"timeout_ms"`
}

// NewOpaPDP creates an OPA-backed PDP.
func NewOpaPDP(cfg OpaConfig) (*OpaPDP, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("pdp/opa: endpoint is required")
	}

	timeout := time.Duration(cfg.TimeoutMs) * time.Millisecond
	if timeout == 0 {
		timeout = 500 * time.Millisecond
	}

	pdp := &OpaPDP{
		endpoint:  cfg.Endpoint,
		client:    &http.Client{Timeout: timeout},
		policyRef: cfg.PolicyRef,
	}
	pdp.policyCache = pdp.computePolicyHash()
	return pdp, nil
}

// opaInput is the canonical input structure sent to OPA.
type opaInput struct {
	Principal   string            `json:"principal"`
	Action      string            `json:"action"`
	Resource    string            `json:"resource"`
	Context     map[string]any    `json:"context,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
}

// opaRequest wraps input for OPA REST API.
type opaRequest struct {
	Input opaInput `json:"input"`
}

// opaResponse is the OPA REST API response.
type opaResponse struct {
	Result *opaResult `json:"result"`
}

type opaResult struct {
	Allow      bool   `json:"allow"`
	ReasonCode string `json:"reason_code,omitempty"`
}

// Evaluate implements PolicyDecisionPoint. Fail-closed on all errors.
func (o *OpaPDP) Evaluate(ctx context.Context, req *DecisionRequest) (*DecisionResponse, error) {
	if req == nil {
		return o.denyResponse(string(contracts.ReasonSchemaViolation)), nil
	}

	// Map HELM request to OPA input.
	input := opaRequest{
		Input: opaInput{
			Principal:   req.Principal,
			Action:      req.Action,
			Resource:    req.Resource,
			Context:     req.Context,
			Environment: req.Environment,
		},
	}

	body, err := json.Marshal(input)
	if err != nil {
		return o.denyResponse(string(contracts.ReasonPDPError)), nil
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, o.endpoint, bytes.NewReader(body))
	if err != nil {
		return o.denyResponse(string(contracts.ReasonPDPError)), nil
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := o.client.Do(httpReq)
	if err != nil {
		// Fail-closed: network error → DENY
		return o.denyResponse(string(contracts.ReasonPDPError)), nil
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return o.denyResponse(string(contracts.ReasonPDPError)), nil
	}

	respBody, err := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20)) // 1MB max
	if err != nil {
		return o.denyResponse(string(contracts.ReasonPDPError)), nil
	}

	var opaResp opaResponse
	if err := json.Unmarshal(respBody, &opaResp); err != nil {
		return o.denyResponse(string(contracts.ReasonPDPError)), nil
	}

	if opaResp.Result == nil {
		// No result from OPA → fail-closed DENY
		return o.denyResponse(string(contracts.ReasonPDPDeny)), nil
	}

	reasonCode := normalizeDecisionReasonCode(opaResp.Result.Allow, opaResp.Result.ReasonCode)

	resp := &DecisionResponse{
		Allow:      opaResp.Result.Allow,
		ReasonCode: reasonCode,
		PolicyRef:  fmt.Sprintf("opa:%s", o.policyRef),
	}

	hash, err := ComputeDecisionHash(resp)
	if err != nil {
		return o.denyResponse(string(contracts.ReasonPDPError)), nil
	}
	resp.DecisionHash = hash

	return resp, nil
}

// Backend implements PolicyDecisionPoint.
func (o *OpaPDP) Backend() Backend { return BackendOPA }

// PolicyHash implements PolicyDecisionPoint.
func (o *OpaPDP) PolicyHash() string { return o.policyCache }

func (o *OpaPDP) denyResponse(reasonCode string) *DecisionResponse {
	resp := &DecisionResponse{
		Allow:      false,
		ReasonCode: reasonCode,
		PolicyRef:  fmt.Sprintf("opa:%s", o.policyRef),
	}
	resp.DecisionHash, _ = ComputeDecisionHash(resp)
	return resp
}

func (o *OpaPDP) computePolicyHash() string {
	input := struct {
		Backend   string `json:"backend"`
		Endpoint  string `json:"endpoint"`
		PolicyRef string `json:"policy_ref"`
	}{
		Backend:   "opa",
		Endpoint:  o.endpoint,
		PolicyRef: o.policyRef,
	}
	data, err := canonicalize.JCS(input)
	if err != nil {
		return "sha256:unknown"
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
