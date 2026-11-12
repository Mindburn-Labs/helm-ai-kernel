// Governed OpenAI-compatible inference gateway (MIN-468 / SPEND3).
//
// This handler set lets a user point an existing OpenAI-compatible client at
// Mindburn while keeping HELM spend policy in the execution path. Every chat /
// responses / embeddings call:
//
//  1. parses the HELM governance headers (workspace, agent, spend envelope,
//     idempotency, route policy), reads the body against the model gateway's
//     closed list for its route (core/pkg/gateway/modelbound: stored state,
//     remote media, hosted tools, routing members, unknown members and the
//     like are refused with 400), and reads the output-token ceiling
//     (max_tokens, max_completion_tokens or max_output_tokens), which is
//     required on routes that bill output tokens;
//  2. answers an already-settled idempotency key from the committed result,
//     without quoting or dispatching again;
//  3. asks the RouteQuote engine for an expiring quote BEFORE dispatch — a
//     non-ALLOW verdict (deny, escalate, stale price, terms block) returns
//     without ever calling a provider — on one input token per byte of the
//     request it forwards plus the image and tool floors, with the output
//     ceiling clamped to what the spend envelope can pay for;
//  4. reserves the quote ceiling against the spend envelope and the balance in
//     one step (exclusive per idempotency key), which issues the budget-verdict
//     receipt, then dispatches with the authorized output ceiling;
//  5. settles actual cost against the quote ceiling (per the engine's cost-cap
//     policy) and emits the usage + settlement receipts. A dispatch that may
//     have reached the provider is never released: without a usable usage
//     report it is debited at its hold, and its idempotency key is spent;
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
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/modelbound"
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
//
// An error means the call did not yield a response the gateway can settle on.
// It wraps ErrDispatchNotSent only when no byte of the request left the
// process; any other error is a dispatch that may have reached the provider,
// which the gateway debits at its hold and never releases.
type ProviderDispatch func(r *http.Request, quote *economic.RouteQuote, body []byte) (DispatchOutcome, error)

// ErrDispatchNotSent marks a dispatch error that happened before any byte of
// the request left the process, so the provider cannot have billed it. Only
// such an error releases the reservation.
var ErrDispatchNotSent = errors.New("the provider request was not sent")

// DispatchOutcome is the provider result the gateway settles against.
type DispatchOutcome struct {
	ResponseBody      json.RawMessage
	ProviderRequestID string
	ProviderCostCents int64
	InputTokens       int64
	OutputTokens      int64
	// UsageUnknown: the provider answered, but its usage could not be read or
	// priced, so the gateway settles the call at its hold.
	UsageUnknown bool
	// Notes are recorded on the usage receipt, such as the model the provider
	// answered with when it differs from the quoted one.
	Notes map[string]string
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
	SettleFailed bool `json:"settle_failed,omitempty"`
	// SettledAtHold marks a dispatch debited at its whole hold because the
	// provider may have billed it and its usage is not known.
	SettledAtHold   bool   `json:"settled_at_hold,omitempty"`
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
	// A key repeated at any depth is refused before the privacy scan rewrites
	// the body: the provider may read the other value than the one inspected.
	if err := modelbound.CheckNoDuplicateKeys(body); err != nil {
		WriteBadRequest(w, "the request body "+err.Error())
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
	// The request is read against the model gateway's closed list for its
	// route (core/pkg/gateway/modelbound): what the quote cannot price is
	// refused before any quote, hold or dispatch, naming it (helm-tracker#313).
	// The upstream speaks OpenAI's wire format for another account, so an auto
	// service tier is refused rather than named.
	fieldList, bound, refusal := modelbound.CheckBody(routeAPI(r.URL.Path), body, modelbound.Options{})
	if refusal != nil {
		WriteBadRequest(w, refusal.Message)
		return
	}
	model, _ := modelbound.String(fieldOf(fieldList, "model"))
	if model == "" {
		WriteBadRequest(w, "model is required")
		return
	}
	fields := make(map[string]json.RawMessage, len(fieldList))
	for _, f := range fieldList {
		fields[f.Key] = f.Raw
	}
	limitFields := outputLimitFields(r.URL.Path)
	outputLimit, err := requestedOutputLimit(fields, limitFields)
	if err != nil {
		WriteBadRequest(w, err.Error())
		return
	}
	// The members the closed list sets (store false on Responses) are part of
	// the request the hold is quoted on.
	set := map[string]json.RawMessage{}
	var setOrder []string
	for _, f := range bound.Set {
		set[f.Key] = f.Raw
		setOrder = append(setOrder, f.Key)
	}
	quoted := modelbound.Rebuild(fieldList, set, setOrder)

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

	estInput, estOutput := holdTokens(quoted, bound.ExtraInputTokens, outputLimit)
	quoteRes, qErr := g.engine.Quote(env, inferencegateway.RouteRequest{
		TenantID:              tenantID,
		WorkspaceID:           hdr.WorkspaceID,
		AgentID:               hdr.AgentID,
		PrincipalID:           hdr.PrincipalID,
		IdempotencyKey:        hdr.IdempotencyKey,
		RequestedModelID:      model,
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

	// Hold the quote ceiling against the envelope and the balance before the
	// provider sees the request, in one step that also issues the receipt.
	// The hold is exclusive per idempotency key, so a concurrent duplicate is
	// refused; a refused reservation rewrites quoteRes to the refusal.
	if _, rerr := g.engine.ReserveForDispatch(quoteRes); rerr != nil {
		if errors.Is(rerr, inferencegateway.ErrDispatchConflict) {
			writeIdempotencyConflict(w, "a request with this idempotency key is already in flight, settled, or held pending reconciliation")
			return
		}
		var qe *inferencegateway.QuoteError
		if !errors.As(rerr, &qe) {
			qe = &inferencegateway.QuoteError{Verdict: economic.BudgetVerdictDeny, ReasonCode: economic.SpendReasonBalanceInsufficient, Message: rerr.Error()}
		}
		g.writeQuoteRejection(w, quoteRes, qe)
		return
	}
	quote = quoteRes.Quote

	dispatchBody := withOutputLimit(fieldList, set, setOrder, limitFields, quote.OutputTokens)
	if len(dispatchBody) > len(quoted) {
		// The hold rests on the bytes it was quoted on; a larger forwarded
		// request could bill above it. Nothing has left the process.
		_, _ = g.engine.ReleaseReservation(quote)
		err = fmt.Errorf("api: the forwarded request is %d bytes, above the %d its hold was quoted on", len(dispatchBody), len(quoted))
		WriteInternalR(w, r, err)
		return
	}
	outcome, derr := g.dispatch(r, quote, dispatchBody)
	if derr != nil && errors.Is(derr, ErrDispatchNotSent) {
		// No byte of the request left the process: the provider cannot have
		// billed it, so the hold is freed and the key may be retried.
		_, _ = g.engine.ReleaseReservation(quote)
		WriteError(w, http.StatusBadGateway, "provider dispatch failed", "provider request failed")
		return
	}

	var settleRes *inferencegateway.SettleResult
	var serr error
	switch {
	case derr != nil || outcome.UsageUnknown:
		// The request may have reached the provider, which may have billed it
		// any amount up to the hold: debit the hold, so the key is spent and
		// the balance and the envelope carry what the call may have cost.
		reason := "the provider answered without usage the gateway could read"
		if derr != nil {
			reason = "the dispatch failed after the request may have reached the provider"
		}
		settleRes, serr = g.engine.SettleAtHold(quote, outcome.ProviderRequestID, reason, outcome.Notes)
	default:
		settleRes, serr = g.engine.SettleUsage(quote, inferencegateway.Usage{
			ProviderRequestID: outcome.ProviderRequestID, ProviderCostCents: outcome.ProviderCostCents,
			InputTokens: outcome.InputTokens, OutputTokens: outcome.OutputTokens, Notes: outcome.Notes,
		})
	}
	if serr != nil {
		// The hold stays: the provider was called and nothing was debited.
		writeSettleFailure(w, quote, settleRes, serr)
		return
	}

	// A settlement above the hold says so: its usage receipt carries
	// ESCALATE / ERR_SPEND_PER_REQUEST_LIMIT, not the reservation's ALLOW.
	verdict := economic.BudgetVerdictAllow
	if settleRes.UsageReceipt != nil && settleRes.UsageReceipt.BudgetVerdict != "" {
		verdict = settleRes.UsageReceipt.BudgetVerdict
	}
	meta := GatewayMetadata{
		Governed:          true,
		Verdict:           verdict,
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
		SettledAtHold:     settleRes.AtHold,
		Replayed:          settleRes.Replayed,
		EvidencePackRef:   settleRes.EvidencePackRef,
	}
	if g.onSettlement != nil {
		g.onSettlement(&meta)
	}
	if derr != nil {
		// Settled at the hold; the provider gave no response to return.
		writeGatewayMetadataHeaders(w, meta)
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"error": map[string]any{
				"message":     "provider dispatch failed after the request may have reached the provider; the call was debited at its hold",
				"type":        "helm_dispatch_failed",
				"reason_code": string(meta.ReasonCode),
			},
			"helm": meta,
		})
		return
	}
	protectedResponse, _, responsePrivacyErr := privacy.ProtectModelResponseJSON(r.Context(), outcome.ResponseBody)
	if responsePrivacyErr == nil {
		outcome.ResponseBody = protectedResponse
	} else {
		outcome.ResponseBody = nil
	}
	writeGatewayMetadataHeaders(w, meta)
	if responsePrivacyErr != nil {
		// A HELM error body with the gateway metadata as an extension member.
		w.Header().Set("Content-Type", httperr.ContentType)
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(struct {
			httperr.ProblemDetail
			HELM GatewayMetadata `json:"helm"`
		}{
			ProblemDetail: httperr.NewProblem(http.StatusBadGateway, "provider response blocked", privacy.ErrDataEgressBlocked.Error(), ""),
			HELM:          meta,
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

// holdTokens is the pre-dispatch bound the hold is quoted on: one input
// token per byte of the request the gateway forwards, which bounds the tokens
// of the text it carries, plus the floors of the inline images and hidden tool
// definitions bytes do not bound (modelbound), and the output ceiling the
// gateway forwards so the provider cannot exceed it. Settlement uses the
// provider's reported usage.
func holdTokens(body []byte, extraInput, outputLimit int64) (int64, int64) {
	return max(int64(len(body))+extraInput, 1), outputLimit
}

// routeAPI names the API a route's requests are read for.
func routeAPI(path string) string {
	switch path {
	case "/v1/responses":
		return modelbound.APIOpenAIResponses
	case "/v1/embeddings":
		return modelbound.APIOpenAIEmbeddings
	default:
		return modelbound.APIOpenAIChat
	}
}

func fieldOf(fields []modelbound.Field, key string) json.RawMessage {
	raw, _ := modelbound.Lookup(fields, key)
	return raw
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

// withOutputLimit builds the forwarded request: the client's members in
// their order, the members the closed list sets, and every output-limit field
// the client sent set to the authorized ceiling, so the provider can bill no
// more than was quoted and reserved. The authorized ceiling is at most the
// client's, so the forwarded request is no larger than the one quoted.
func withOutputLimit(fields []modelbound.Field, set map[string]json.RawMessage, setOrder, names []string, limit int64) []byte {
	edit := make(map[string]json.RawMessage, len(set)+len(names))
	for k, v := range set {
		edit[k] = v
	}
	value := json.RawMessage(strconv.FormatInt(limit, 10))
	for _, name := range names {
		if raw, ok := modelbound.Lookup(fields, name); ok && !modelbound.IsNull(raw) {
			edit[name] = value
		}
	}
	return modelbound.Rebuild(fields, edit, setOrder)
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
