// Governed OpenAI-compatible inference gateway (MIN-468 / SPEND3).
//
// This handler set lets a user point an existing OpenAI-compatible client at
// Mindburn while keeping HELM spend policy in the execution path. Every chat /
// responses / embeddings call:
//
//  1. parses the HELM governance headers (workspace, agent, spend envelope,
//     idempotency, route policy) and the output-token ceiling (max_tokens,
//     max_completion_tokens or max_output_tokens), which is required on routes
//     that bill output tokens;
//  2. answers an already-settled idempotency key from the committed result,
//     without quoting or dispatching again;
//  3. asks the RouteQuote engine for an expiring quote BEFORE dispatch — a
//     non-ALLOW verdict (deny, escalate, stale price, terms block) returns
//     without ever calling a provider — with the output ceiling clamped to
//     what the spend envelope can pay for;
//  4. reserves the quote ceiling against the balance (exclusive per
//     idempotency key), then dispatches with the authorized output ceiling;
//  5. settles actual cost against the quote ceiling (per the engine's cost-cap
//     policy) and emits the usage + settlement receipts;
//  6. returns the standard OpenAI response body plus HELM response metadata
//     (verdict, route receipt, usage receipt, settlement receipt, quote,
//     actual cost, overage, fallback status, EvidencePack ref).
//
// There is no unreceipted dispatch path here: dispatch is only reachable after
// an ALLOW quote and a reservation, and the response is only written after
// settlement.
package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"sync"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/httperr"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/inferencegateway"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/privacy"
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
	engine       *inferencegateway.Engine
	resolver     EnvelopeResolver
	dispatch     ProviderDispatch
	tenantID     func(*http.Request) string
	models       []GatewayModel
	maxBody      int64
	onSettlement func(*GatewayMetadata)
	replays      *replayCache
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
	// OnSettlement receives the canonical in-process receipts before the public
	// response is projected and redacted.
	OnSettlement func(*GatewayMetadata)
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
		engine:       cfg.Engine,
		resolver:     cfg.Resolver,
		dispatch:     cfg.Dispatch,
		tenantID:     cfg.TenantID,
		models:       cfg.Models,
		maxBody:      maxOpenAIRequestSize,
		onSettlement: cfg.OnSettlement,
		replays:      &replayCache{items: make(map[string]retainedReplay)},
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
// full body is forwarded to the provider with only the output-token ceiling
// rewritten to the authorized value.
type inferenceBody struct {
	Model string `json:"model"`
}

// GatewayMetadata is the HELM receipt block attached to every governed response.
type GatewayMetadata struct {
	Governed          bool                           `json:"governed"`
	Verdict           economic.BudgetVerdict         `json:"verdict"`
	ReasonCode        economic.SpendReasonCode       `json:"reason_code"`
	Quote             *economic.RouteQuote           `json:"route_quote,omitempty"`
	RouteReceipt      *economic.BudgetVerdictReceipt `json:"route_receipt,omitempty"`
	UsageReceipt      *economic.UsageReceipt         `json:"-"`
	UsageReceiptView  *economic.UsageReceiptView     `json:"usage_receipt,omitempty"`
	SettlementReceipt *economic.SettlementReceipt    `json:"settlement_receipt,omitempty"`
	QuotedAmountCents int64                          `json:"quoted_amount_cents,omitempty"`
	ActualAmountCents int64                          `json:"actual_amount_cents,omitempty"`
	BalanceAfterCents int64                          `json:"balance_after_cents,omitempty"`
	ModelSubstituted  bool                           `json:"model_substituted"`
	FallbackUsed      bool                           `json:"fallback_used"`
	Capped            bool                           `json:"cost_capped,omitempty"`
	// OverageCents is actual cost debited above the quote ceiling.
	OverageCents int64 `json:"overage_cents,omitempty"`
	// SettleFailed marks a response where the provider was called but the
	// settlement could not commit; Quote identifies the unsettled dispatch.
	SettleFailed    bool   `json:"settle_failed,omitempty"`
	Replayed        bool   `json:"idempotent_replay,omitempty"`
	EvidencePackRef string `json:"evidence_pack_ref,omitempty"`
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
		httperr.WriteUnauthorized(w, "tenant could not be resolved for request")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, g.maxBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		WriteBadRequest(w, "failed to read request body")
		return
	}
	protectedBody, _, err := privacy.ProtectModelRequestJSON(r.Context(), json.RawMessage(body))
	if err != nil {
		if errors.Is(err, privacy.ErrDataEgressInvalid) {
			WriteBadRequest(w, "invalid request body")
			return
		}
		WriteForbidden(w, privacy.ErrDataEgressBlocked.Error())
		return
	}
	body = protectedBody
	var parsed inferenceBody
	if err := json.Unmarshal(body, &parsed); err != nil {
		WriteBadRequest(w, "invalid request body")
		return
	}
	if parsed.Model == "" {
		WriteBadRequest(w, "model is required")
		return
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		WriteBadRequest(w, "invalid request body")
		return
	}
	limitFields := outputLimitFields(r.URL.Path)
	outputLimit, err := requestedOutputLimit(fields, limitFields)
	if err != nil {
		WriteBadRequest(w, err.Error())
		return
	}

	env, ok := g.resolver(tenantID, hdr.SpendEnvelope)
	if !ok {
		writeGatewayDenied(w, economic.BudgetVerdictDeny, economic.SpendReasonEnvelopeNotFound, "spend envelope not found")
		return
	}

	// Idempotency is resolved before any quote, reservation or dispatch: a
	// settled key never reaches the provider again.
	replayKey := tenantID + "\x00" + hdr.IdempotencyKey
	scope := requestScope(tenantID, hdr, r.URL.Path, body)
	if settled, ok := g.engine.Lookup(tenantID, hdr.IdempotencyKey); ok {
		g.writeReplay(w, replayKey, scope, settled)
		return
	}

	estInput, estOutput := estimateTokens(body, outputLimit)
	quoteRes, qErr := g.engine.Quote(env, inferencegateway.RouteRequest{
		TenantID:              tenantID,
		WorkspaceID:           hdr.WorkspaceID,
		AgentID:               hdr.AgentID,
		PrincipalID:           hdr.PrincipalID,
		IdempotencyKey:        hdr.IdempotencyKey,
		RequestedModelID:      parsed.Model,
		EstimatedInputTokens:  estInput,
		EstimatedOutputTokens: estOutput,
		ClampOutputToMandate:  len(limitFields) > 0,
	})
	if qErr != nil {
		// No dispatch happens on a non-ALLOW verdict. Surface the governed
		// verdict and (when present) the quote for the audit trail.
		g.writeQuoteRejection(w, quoteRes, qErr)
		return
	}
	quote := quoteRes.Quote

	// Hold the quote ceiling before the provider sees the request. The hold
	// is exclusive per idempotency key, so a concurrent duplicate is refused.
	if _, rerr := g.engine.ReserveForDispatch(quote); rerr != nil {
		if errors.Is(rerr, inferencegateway.ErrDispatchConflict) {
			writeIdempotencyConflict(w, "a request with this idempotency key is already in flight or settled")
			return
		}
		g.writeQuoteRejection(w, quoteRes, &inferencegateway.QuoteError{
			Verdict: economic.BudgetVerdictDeny, ReasonCode: economic.SpendReasonBalanceInsufficient, Message: rerr.Error(),
		})
		return
	}

	dispatchBody, err := withOutputLimit(body, fields, limitFields, quote.OutputTokens)
	if err != nil {
		_, _ = g.engine.ReleaseReservation(quote)
		WriteInternal(w, err)
		return
	}
	outcome, derr := g.dispatch(r, quote, dispatchBody)
	if derr != nil {
		// Nothing settled: free the hold so a retry with the same key can run.
		_, _ = g.engine.ReleaseReservation(quote)
		WriteError(w, http.StatusBadGateway, "provider dispatch failed", "provider request failed")
		return
	}

	settleRes, serr := g.engine.Settle(
		quote, outcome.ProviderRequestID, outcome.ProviderCostCents,
		outcome.InputTokens, outcome.OutputTokens,
	)
	if serr != nil {
		writeSettleFailure(w, quote, settleRes, serr)
		return
	}

	meta := GatewayMetadata{
		Governed:          true,
		Verdict:           economic.BudgetVerdictAllow,
		ReasonCode:        settleRes.ReasonCode,
		Quote:             quoteRes.Quote,
		RouteReceipt:      quoteRes.Receipt,
		UsageReceipt:      settleRes.UsageReceipt,
		UsageReceiptView:  publicUsageReceiptView(settleRes.UsageReceipt),
		SettlementReceipt: settleRes.SettlementReceipt,
		QuotedAmountCents: settleRes.QuotedAmountCents,
		ActualAmountCents: settleRes.ActualAmountCents,
		BalanceAfterCents: settleRes.BalanceAfterCents,
		ModelSubstituted:  quoteRes.ModelSubstituted,
		FallbackUsed:      quoteRes.FallbackUsed,
		Capped:            settleRes.Capped,
		OverageCents:      settleRes.OverageCents,
		Replayed:          settleRes.Replayed,
		EvidencePackRef:   settleRes.EvidencePackRef,
	}
	if g.onSettlement != nil {
		g.onSettlement(&meta)
	}
	protectedResponse, _, responsePrivacyErr := privacy.ProtectModelResponseJSON(r.Context(), outcome.ResponseBody)
	if responsePrivacyErr == nil {
		outcome.ResponseBody = protectedResponse
	} else {
		outcome.ResponseBody = nil
	}
	writeGatewayMetadataHeaders(w, meta)
	if responsePrivacyErr != nil {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(struct {
			httperr.ProblemDetail
			HELM GatewayMetadata `json:"helm"`
		}{
			ProblemDetail: httperr.ProblemDetail{
				Type:   "https://helm.mindburn.run/errors/502",
				Title:  "provider response blocked",
				Status: http.StatusBadGateway,
				Detail: privacy.ErrDataEgressBlocked.Error(),
			},
			HELM: meta,
		})
		return
	}
	g.replays.put(replayKey, retainedReplay{scope: scope, response: outcome.ResponseBody})
	writeJSON(w, http.StatusOK, governedResponse{Response: outcome.ResponseBody, HELM: meta})
}

// writeReplay answers a settled idempotency key without dispatching. The
// retained response is returned only to the same request; any other use of the
// key, or a key whose response is no longer retained, gets 409.
func (g *GovernedGateway) writeReplay(w http.ResponseWriter, replayKey, scope string, settled *inferencegateway.SettleResult) {
	retained, ok := g.replays.get(replayKey)
	if !ok {
		writeIdempotencyConflict(w, "idempotency key already settled and its response is not retained; send a new idempotency key")
		return
	}
	if retained.scope != scope {
		writeIdempotencyConflict(w, "idempotency key was already used for a different request")
		return
	}
	meta := GatewayMetadata{
		Governed:          true,
		Verdict:           economic.BudgetVerdictAllow,
		ReasonCode:        settled.ReasonCode,
		UsageReceipt:      settled.UsageReceipt,
		UsageReceiptView:  publicUsageReceiptView(settled.UsageReceipt),
		SettlementReceipt: settled.SettlementReceipt,
		QuotedAmountCents: settled.QuotedAmountCents,
		ActualAmountCents: settled.ActualAmountCents,
		BalanceAfterCents: settled.BalanceAfterCents,
		Replayed:          true,
		EvidencePackRef:   settled.EvidencePackRef,
	}
	writeGatewayMetadataHeaders(w, meta)
	writeJSON(w, http.StatusOK, governedResponse{Response: retained.response, HELM: meta})
}

func writeIdempotencyConflict(w http.ResponseWriter, msg string) {
	writeGatewayMetadataHeaders(w, GatewayMetadata{
		Governed: true, Verdict: economic.BudgetVerdictDeny, ReasonCode: economic.SpendReasonReceiptMismatch,
	})
	WriteConflict(w, msg)
}

// writeSettleFailure reports a dispatch whose settlement did not commit. The
// provider has been called, so the metadata carries the quote and the actual
// cost for the caller's audit trail.
func writeSettleFailure(w http.ResponseWriter, quote *economic.RouteQuote, res *inferencegateway.SettleResult, err error) {
	verdict := economic.BudgetVerdictDeny
	reason := economic.SpendReasonSettlementMissing
	msg := "settlement failed after provider dispatch"
	status := http.StatusInternalServerError
	var qe *inferencegateway.QuoteError
	if errors.As(err, &qe) {
		verdict, reason, msg = qe.Verdict, qe.ReasonCode, qe.Message
		status = statusForVerdict(verdict)
	}
	meta := GatewayMetadata{Governed: true, Verdict: verdict, ReasonCode: reason, Quote: quote, SettleFailed: true}
	if res != nil {
		meta.QuotedAmountCents = res.QuotedAmountCents
		meta.ActualAmountCents = res.ActualAmountCents
		meta.OverageCents = res.OverageCents
	}
	writeGatewayMetadataHeaders(w, meta)
	writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"message":     msg,
			"type":        "helm_settlement_failed",
			"reason_code": string(reason),
		},
		"helm": meta,
	})
}

func publicUsageReceiptView(receipt *economic.UsageReceipt) *economic.UsageReceiptView {
	if receipt == nil {
		return nil
	}
	view := economic.NewUsageReceiptView(receipt, economic.DefaultRedactionProfile())
	protected, _, err := privacy.NewPrivacyManager().Protect(nil, receipt.ProviderRequestID)
	safe, ok := protected.(string)
	if err != nil || !ok || safe != receipt.ProviderRequestID {
		view.ProviderRequestID = ""
		view.RedactedFields = append(view.RedactedFields, "provider_request_id")
		sort.Strings(view.RedactedFields)
	}
	return &view
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
// Input is approximated from body size (~4 bytes/token); output is the
// client's output ceiling, which the gateway forwards so the provider cannot
// exceed it. Settlement always uses the provider's actual reported usage.
func estimateTokens(body []byte, outputLimit int64) (int64, int64) {
	in := int64(len(body)) / 4
	if in < 1 {
		in = 1
	}
	return in, outputLimit
}

// outputLimitFields names the request fields that cap billable output tokens
// on each route. Embeddings bill no output tokens.
func outputLimitFields(path string) []string {
	switch path {
	case "/v1/embeddings":
		return nil
	case "/v1/responses":
		return []string{"max_output_tokens"}
	default:
		return []string{"max_tokens", "max_completion_tokens"}
	}
}

// requestedOutputLimit reads the client's output-token ceiling: the smallest
// of the limit fields present. It is required wherever output is billed,
// because the quote, the reservation and the forwarded request all rest on it.
func requestedOutputLimit(fields map[string]json.RawMessage, names []string) (int64, error) {
	if len(names) == 0 {
		return 0, nil
	}
	var limit int64
	for _, name := range names {
		raw, ok := fields[name]
		if !ok || string(raw) == "null" {
			continue
		}
		var v int64
		if err := json.Unmarshal(raw, &v); err != nil || v <= 0 {
			return 0, fmt.Errorf("%s must be a positive integer", name)
		}
		if limit == 0 || v < limit {
			limit = v
		}
	}
	if limit == 0 {
		return 0, fmt.Errorf("%s is required: the governed gateway bounds output cost before dispatch", names[0])
	}
	return limit, nil
}

// withOutputLimit sets every output-limit field the client sent to the
// authorized ceiling, so the provider can bill no more than was quoted and
// reserved. The body is returned unchanged when it already carries that value.
func withOutputLimit(body []byte, fields map[string]json.RawMessage, names []string, limit int64) ([]byte, error) {
	value := json.RawMessage(strconv.FormatInt(limit, 10))
	changed := false
	for _, name := range names {
		if raw, ok := fields[name]; ok && string(raw) != "null" && string(raw) != string(value) {
			fields[name] = value
			changed = true
		}
	}
	if !changed {
		return body, nil
	}
	return json.Marshal(fields)
}

// requestScope fingerprints what an idempotency key was used for: tenant,
// governance headers, route and body. A replay must match it exactly.
func requestScope(tenantID string, hdr inferencegateway.RequestHeaders, path string, body []byte) string {
	h := sha256.New()
	for _, part := range []string{tenantID, hdr.WorkspaceID, hdr.AgentID, hdr.PrincipalID, hdr.SpendEnvelope, hdr.RoutePolicy, path} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// maxRetainedReplays bounds the in-memory replay cache.
//
// ponytail: responses are retained in memory only, for the last 1024 settled
// requests. After eviction or a restart a replay of a settled key gets 409 and
// never a second dispatch. Persist responses if clients need replays to
// survive restarts.
const maxRetainedReplays = 1024

type retainedReplay struct {
	scope    string
	response json.RawMessage
}

// replayCache retains the protected provider response of settled requests so
// an identical replay is answered without a second dispatch.
type replayCache struct {
	mu    sync.Mutex
	order []string
	items map[string]retainedReplay
}

func (c *replayCache) get(key string) (retainedReplay, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.items[key]
	return v, ok
}

func (c *replayCache) put(key string, v retainedReplay) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.items[key]; !ok {
		c.order = append(c.order, key)
		if len(c.order) > maxRetainedReplays {
			delete(c.items, c.order[0])
			c.order = c.order[1:]
		}
	}
	c.items[key] = v
}
