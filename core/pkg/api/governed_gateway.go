// Governed OpenAI-compatible inference gateway (MIN-468 / SPEND3).
//
// This handler set lets a user point an existing OpenAI-compatible client at
// Mindburn while keeping HELM spend policy in the execution path. Every chat /
// responses / embeddings call:
//
//  1. parses the HELM governance headers (workspace, agent, spend envelope,
//     idempotency, route policy);
//  2. asks the RouteQuote engine for an expiring quote BEFORE dispatch — a
//     non-ALLOW verdict (deny, escalate, stale price, terms block) returns
//     without ever calling a provider;
//  3. dispatches to the bound provider only under an ALLOW verdict;
//  4. settles actual cost against the quote ceiling (cap or escalate per
//     policy) and emits the usage + settlement receipts;
//  5. returns the standard OpenAI response body plus HELM response metadata
//     (verdict, route receipt, usage receipt, settlement receipt, quote,
//     actual cost, fallback status, EvidencePack ref).
//
// There is no unreceipted dispatch path here: dispatch is only reachable after
// an ALLOW quote, and the response is only written after settlement.
package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/inferencegateway"
)

// EnvelopeResolver loads the AgentSpendEnvelope referenced by the request
// headers for the authenticated scope. It returns false when no envelope exists
// so the gateway can fail closed.
type EnvelopeResolver func(tenantID, envelopeID string) (*economic.AgentSpendEnvelope, bool)

// ProviderDispatch performs the actual upstream inference once an ALLOW quote
// exists. It returns the OpenAI-shaped response body, the provider request id,
// actual provider cost in cents, and the actual token usage. Implementations
// must not be called unless the gateway authorized dispatch.
type ProviderDispatch func(r *http.Request, quote *economic.RouteQuote, body []byte) (DispatchOutcome, error)

// DispatchOutcome is the provider result the gateway settles against.
type DispatchOutcome struct {
	ResponseBody      json.RawMessage
	ProviderRequestID string
	ProviderCostCents int64
	InputTokens       int64
	OutputTokens      int64
}

// GovernedGateway wires the RouteQuote engine to OpenAI-compatible HTTP routes.
type GovernedGateway struct {
	engine   *inferencegateway.Engine
	resolver EnvelopeResolver
	dispatch ProviderDispatch
	tenantID func(*http.Request) string
	models   []GatewayModel
	maxBody  int64
}

// GatewayModel is one entry in the /v1/models listing.
type GatewayModel struct {
	ID       string `json:"id"`
	Object   string `json:"object"`
	OwnedBy  string `json:"owned_by"`
	Provider string `json:"provider,omitempty"`
}

// GovernedGatewayConfig configures the gateway.
type GovernedGatewayConfig struct {
	Engine   *inferencegateway.Engine
	Resolver EnvelopeResolver
	Dispatch ProviderDispatch
	// TenantID resolves the caller tenant. When nil the gateway cannot be built.
	TenantID func(*http.Request) string
	Models   []GatewayModel
}

// NewGovernedGateway validates configuration and returns the gateway.
func NewGovernedGateway(cfg GovernedGatewayConfig) (*GovernedGateway, error) {
	if cfg.Engine == nil {
		return nil, errors.New("api: governed gateway requires an engine")
	}
	if cfg.Resolver == nil {
		return nil, errors.New("api: governed gateway requires an envelope resolver")
	}
	if cfg.Dispatch == nil {
		return nil, errors.New("api: governed gateway requires a provider dispatch")
	}
	if cfg.TenantID == nil {
		return nil, errors.New("api: governed gateway requires a tenant resolver")
	}
	return &GovernedGateway{
		engine:   cfg.Engine,
		resolver: cfg.Resolver,
		dispatch: cfg.Dispatch,
		tenantID: cfg.TenantID,
		models:   cfg.Models,
		maxBody:  maxOpenAIRequestSize,
	}, nil
}

// Register attaches the OpenAI-compatible routes to a mux.
func (g *GovernedGateway) Register(mux *http.ServeMux) {
	mux.HandleFunc("/v1/chat/completions", g.handleInference)
	mux.HandleFunc("/v1/responses", g.handleInference)
	mux.HandleFunc("/v1/embeddings", g.handleInference)
	mux.HandleFunc("/v1/models", g.handleModels)
}

// inferenceBody is the minimal OpenAI-shaped request the gateway reads. The
// full body is forwarded to the provider untouched.
type inferenceBody struct {
	Model     string `json:"model"`
	MaxTokens *int   `json:"max_tokens,omitempty"`
}

// GatewayMetadata is the HELM receipt block attached to every governed response.
type GatewayMetadata struct {
	Governed          bool                           `json:"governed"`
	Verdict           economic.BudgetVerdict         `json:"verdict"`
	ReasonCode        economic.SpendReasonCode       `json:"reason_code"`
	Quote             *economic.RouteQuote           `json:"route_quote,omitempty"`
	RouteReceipt      *economic.BudgetVerdictReceipt `json:"route_receipt,omitempty"`
	UsageReceipt      *economic.UsageReceipt         `json:"usage_receipt,omitempty"`
	SettlementReceipt *economic.SettlementReceipt    `json:"settlement_receipt,omitempty"`
	QuotedAmountCents int64                          `json:"quoted_amount_cents,omitempty"`
	ActualAmountCents int64                          `json:"actual_amount_cents,omitempty"`
	BalanceAfterCents int64                          `json:"balance_after_cents,omitempty"`
	ModelSubstituted  bool                           `json:"model_substituted"`
	FallbackUsed      bool                           `json:"fallback_used"`
	Capped            bool                           `json:"cost_capped,omitempty"`
	Replayed          bool                           `json:"idempotent_replay,omitempty"`
	EvidencePackRef   string                         `json:"evidence_pack_ref,omitempty"`
}

// governedResponse is the envelope returned to the OpenAI-compatible client:
// the provider body under "response" plus the HELM receipt block under "helm".
type governedResponse struct {
	Response json.RawMessage `json:"response"`
	HELM     GatewayMetadata `json:"helm"`
}

func (g *GovernedGateway) handleInference(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteMethodNotAllowed(w)
		return
	}

	hdr, err := inferencegateway.ParseRequestHeaders(r.Header)
	if err != nil {
		WriteBadRequest(w, err.Error())
		return
	}
	tenantID := g.tenantID(r)
	if tenantID == "" {
		WriteUnauthorized(w, "tenant could not be resolved for request")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, g.maxBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		WriteBadRequest(w, "failed to read request body")
		return
	}
	var parsed inferenceBody
	if err := json.Unmarshal(body, &parsed); err != nil {
		WriteBadRequest(w, "invalid request body")
		return
	}
	if parsed.Model == "" {
		WriteBadRequest(w, "model is required")
		return
	}

	env, ok := g.resolver(tenantID, hdr.SpendEnvelope)
	if !ok {
		writeGatewayDenied(w, economic.BudgetVerdictDeny, economic.SpendReasonEnvelopeNotFound, "spend envelope not found")
		return
	}

	estInput, estOutput := estimateTokens(body, parsed.MaxTokens)
	quoteRes, qErr := g.engine.Quote(env, inferencegateway.RouteRequest{
		TenantID:              tenantID,
		WorkspaceID:           hdr.WorkspaceID,
		AgentID:               hdr.AgentID,
		PrincipalID:           hdr.PrincipalID,
		IdempotencyKey:        hdr.IdempotencyKey,
		RequestedModelID:      parsed.Model,
		EstimatedInputTokens:  estInput,
		EstimatedOutputTokens: estOutput,
	})
	if qErr != nil {
		// No dispatch happens on a non-ALLOW verdict. Surface the governed
		// verdict and (when present) the quote for the audit trail.
		g.writeQuoteRejection(w, quoteRes, qErr)
		return
	}

	outcome, derr := g.dispatch(r, quoteRes.Quote, body)
	if derr != nil {
		WriteError(w, http.StatusBadGateway, "provider dispatch failed", derr.Error())
		return
	}

	settleRes, serr := g.engine.Settle(
		quoteRes.Quote, outcome.ProviderRequestID, outcome.ProviderCostCents,
		outcome.InputTokens, outcome.OutputTokens,
	)
	if serr != nil {
		var qe *inferencegateway.QuoteError
		if errors.As(serr, &qe) {
			writeGatewayDenied(w, qe.Verdict, qe.ReasonCode, qe.Message)
			return
		}
		WriteInternal(w, serr)
		return
	}

	meta := GatewayMetadata{
		Governed:          true,
		Verdict:           economic.BudgetVerdictAllow,
		ReasonCode:        settleRes.ReasonCode,
		Quote:             quoteRes.Quote,
		RouteReceipt:      quoteRes.Receipt,
		UsageReceipt:      settleRes.UsageReceipt,
		SettlementReceipt: settleRes.SettlementReceipt,
		QuotedAmountCents: settleRes.QuotedAmountCents,
		ActualAmountCents: settleRes.ActualAmountCents,
		BalanceAfterCents: settleRes.BalanceAfterCents,
		ModelSubstituted:  quoteRes.ModelSubstituted,
		FallbackUsed:      quoteRes.FallbackUsed,
		Capped:            settleRes.Capped,
		Replayed:          settleRes.Replayed,
		EvidencePackRef:   settleRes.EvidencePackRef,
	}
	writeGatewayMetadataHeaders(w, meta)
	writeJSON(w, http.StatusOK, governedResponse{Response: outcome.ResponseBody, HELM: meta})
}

func (g *GovernedGateway) handleModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteMethodNotAllowed(w)
		return
	}
	models := g.models
	if models == nil {
		models = []GatewayModel{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": models})
}

func (g *GovernedGateway) writeQuoteRejection(w http.ResponseWriter, res *inferencegateway.QuoteResult, qErr error) {
	verdict := economic.BudgetVerdictDeny
	reason := economic.SpendReasonEvidenceMissing
	msg := qErr.Error()
	var qe *inferencegateway.QuoteError
	if errors.As(qErr, &qe) {
		verdict = qe.Verdict
		reason = qe.ReasonCode
		msg = qe.Message
	}
	status := statusForVerdict(verdict)
	meta := GatewayMetadata{Governed: true, Verdict: verdict, ReasonCode: reason}
	if res != nil {
		meta.Quote = res.Quote
		meta.ModelSubstituted = res.ModelSubstituted
		meta.FallbackUsed = res.FallbackUsed
		meta.EvidencePackRef = res.EvidencePackRef
	}
	writeGatewayMetadataHeaders(w, meta)
	writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"message":     msg,
			"type":        "helm_spend_authority_" + string(verdict),
			"reason_code": string(reason),
		},
		"helm": meta,
	})
}

func writeGatewayDenied(w http.ResponseWriter, verdict economic.BudgetVerdict, reason economic.SpendReasonCode, msg string) {
	meta := GatewayMetadata{Governed: true, Verdict: verdict, ReasonCode: reason}
	writeGatewayMetadataHeaders(w, meta)
	writeJSON(w, statusForVerdict(verdict), map[string]any{
		"error": map[string]any{
			"message":     msg,
			"type":        "helm_spend_authority_" + string(verdict),
			"reason_code": string(reason),
		},
		"helm": meta,
	})
}

func writeGatewayMetadataHeaders(w http.ResponseWriter, meta GatewayMetadata) {
	w.Header().Set("X-HELM-Governed", "true")
	w.Header().Set("X-HELM-Verdict", string(meta.Verdict))
	w.Header().Set("X-HELM-Reason-Code", string(meta.ReasonCode))
	if meta.Quote != nil {
		w.Header().Set("X-HELM-Route-Quote-Hash", meta.Quote.ContentHash)
	}
	if meta.UsageReceipt != nil {
		w.Header().Set("X-HELM-Usage-Receipt-Hash", meta.UsageReceipt.ContentHash)
	}
	if meta.SettlementReceipt != nil {
		w.Header().Set("X-HELM-Settlement-Receipt-Hash", meta.SettlementReceipt.ContentHash)
	}
	if meta.EvidencePackRef != "" {
		w.Header().Set("X-HELM-EvidencePack-Ref", meta.EvidencePackRef)
	}
}

func statusForVerdict(verdict economic.BudgetVerdict) int {
	switch verdict {
	case economic.BudgetVerdictEscalate:
		// 402 Payment Required: spend needs human approval before it can run.
		return http.StatusPaymentRequired
	case economic.BudgetVerdictDeny:
		return http.StatusForbidden
	default:
		return http.StatusOK
	}
}

// estimateTokens derives a pre-dispatch token estimate from the request body.
// Input is approximated from body size (~4 bytes/token); output is taken from
// max_tokens when the client set it, else a conservative default. The estimate
// only drives the quote ceiling — settlement always uses the provider's actual
// reported usage.
func estimateTokens(body []byte, maxTokens *int) (int64, int64) {
	in := int64(len(body)) / 4
	if in < 1 {
		in = 1
	}
	var out int64 = 256
	if maxTokens != nil && *maxTokens > 0 {
		out = int64(*maxTokens)
	}
	return in, out
}
