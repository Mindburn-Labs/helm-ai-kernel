// quantum_posture: the server orchestrates classical Ed25519 signing of
// persisted receipt payloads through the issuer (issuer.go) and derives
// idempotency keys with SHA-256; no post-quantum primitives are used in this
// file.

package spendproxy

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/inferencegateway"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/privacy"
)

// maxRequestBody mirrors the governed gateway's privacy payload ceiling.
const maxRequestBody = privacy.MaxPayloadBytes

// ServerOptions wires a Server.
type ServerOptions struct {
	Config     *Config
	SourceHash string
	// ReceiptsDir holds the JSONL receipt log and the trusted-key registry.
	ReceiptsDir string
	// UpstreamBaseURL and UpstreamAPIKey configure the cloud provider dispatch.
	UpstreamBaseURL string
	UpstreamAPIKey  string
	// SigningSecret seeds the verdict issuer key; empty generates a fresh key.
	SigningSecret string
	Logf          func(format string, args ...any)
}

// Server is the runnable governed spend proxy: OpenAI-compatible routes over
// the SPEND3 engine with real upstream dispatch, signed verdicts, and durable
// receipts.
type Server struct {
	cfg        *Config
	sourceHash string
	engine     *inferencegateway.Engine
	ledger     *inferencegateway.BalanceLedger
	envelopes  map[string]*economic.AgentSpendEnvelope
	upstream   *Upstream
	store      *FileStore
	issuer     *Issuer
	keys       *TrustedKeys
	gatewayMux *http.ServeMux
	replay     *ReplaySummary
	logf       func(format string, args ...any)
}

// NewServer composes the full governed spend path. Startup replays the durable
// receipt log so the balance and the idempotency index survive restarts.
func NewServer(opts ServerOptions) (*Server, error) {
	if opts.Config == nil {
		return nil, errors.New("spendproxy: config is required")
	}
	if opts.SourceHash == "" {
		return nil, errors.New("spendproxy: config source hash is required")
	}
	if opts.ReceiptsDir == "" {
		return nil, errors.New("spendproxy: receipts dir is required")
	}
	logf := opts.Logf
	if logf == nil {
		logf = log.Printf
	}
	cfg := opts.Config
	now := time.Now().UTC()

	prices, terms, err := cfg.BuildBooks(now, opts.SourceHash)
	if err != nil {
		return nil, err
	}
	envelopes, err := cfg.BuildEnvelopes(opts.SourceHash)
	if err != nil {
		return nil, err
	}

	// Restart replay: the durable log is the source of truth for money already
	// spent against the configured opening balance.
	records, err := LoadRecords(receiptLogPath(opts.ReceiptsDir))
	if err != nil {
		return nil, err
	}
	debited := DebitedCents(records)
	opening := cfg.Balance.OpeningCents - debited
	if opening < 0 {
		return nil, fmt.Errorf(
			"spendproxy: receipt log shows %d cents already debited, exceeding the configured opening balance %d; refusing to start",
			debited, cfg.Balance.OpeningCents,
		)
	}
	account := economic.NewBalanceAccount(
		cfg.Balance.AccountID, cfg.TenantID, cfg.Currency, opening,
		"evidence://spend-proxy/"+cfg.Balance.AccountID,
	)
	ledger, err := inferencegateway.NewBalanceLedger(account)
	if err != nil {
		return nil, fmt.Errorf("spendproxy: balance ledger: %w", err)
	}
	replay, err := ReplayRecords(records, ledger)
	if err != nil {
		return nil, err
	}

	engine, err := inferencegateway.NewEngine(inferencegateway.EngineConfig{
		Prices:         prices,
		Terms:          terms,
		Ledger:         ledger,
		TreasuryID:     cfg.TreasuryID,
		RoutePolicyID:  cfg.RoutePolicyID,
		QuoteTTL:       time.Duration(cfg.QuoteTTLSeconds) * time.Second,
		StalePrice:     inferencegateway.StalePriceFailClosed,
		CostCap:        inferencegateway.CostCapClamp,
		PlatformFeeBps: cfg.PlatformFeeBps,
	})
	if err != nil {
		return nil, fmt.Errorf("spendproxy: engine: %w", err)
	}

	store, err := OpenFileStore(opts.ReceiptsDir)
	if err != nil {
		return nil, err
	}
	issuer, derivedFromPassphrase, err := NewIssuer(opts.SigningSecret)
	if err != nil {
		store.Close()
		return nil, err
	}
	if derivedFromPassphrase {
		logf("spend-proxy: WARNING: signing secret is not a 32-byte seed; derived one by hashing it")
	}
	keys, err := OpenTrustedKeys(opts.ReceiptsDir)
	if err != nil {
		store.Close()
		return nil, err
	}
	if err := keys.Register(issuer.KeyID(), issuer.PublicKey()); err != nil {
		store.Close()
		return nil, err
	}

	upstream, err := NewUpstream(opts.UpstreamBaseURL, opts.UpstreamAPIKey, prices)
	if err != nil {
		store.Close()
		return nil, err
	}

	s := &Server{
		cfg:        cfg,
		sourceHash: opts.SourceHash,
		engine:     engine,
		ledger:     ledger,
		envelopes:  envelopes,
		upstream:   upstream,
		store:      store,
		issuer:     issuer,
		keys:       keys,
		replay:     replay,
		logf:       logf,
	}

	gw, err := api.NewGovernedGateway(api.GovernedGatewayConfig{
		Engine:       engine,
		Resolver:     s.resolveEnvelope,
		Dispatch:     s.governedDispatch,
		TenantID:     func(*http.Request) string { return cfg.TenantID },
		Models:       s.modelList(),
		OnSettlement: s.persistOutcome,
	})
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("spendproxy: governed gateway: %w", err)
	}
	s.gatewayMux = http.NewServeMux()
	gw.Register(s.gatewayMux)
	return s, nil
}

// Close releases the receipt store.
func (s *Server) Close() error { return s.store.Close() }

// ReplaySummary reports what startup recovered from the durable log.
func (s *Server) ReplaySummary() ReplaySummary { return *s.replay }

// BalanceCents exposes the current governed balance.
func (s *Server) BalanceCents() int64 { return s.ledger.BalanceCents() }

// SigningKeyID exposes the verdict issuer key id.
func (s *Server) SigningKeyID() string { return s.issuer.KeyID() }

// ReceiptLogPath exposes where receipts land.
func (s *Server) ReceiptLogPath() string { return s.store.Path() }

func receiptLogPath(dir string) string { return dir + "/" + ReceiptLogName }

func (s *Server) resolveEnvelope(tenantID, envelopeID string) (*economic.AgentSpendEnvelope, bool) {
	if tenantID != s.cfg.TenantID {
		return nil, false
	}
	env, ok := s.envelopes[envelopeID]
	return env, ok
}

func (s *Server) modelList() []api.GatewayModel {
	models := make([]api.GatewayModel, 0, len(s.cfg.Prices))
	for _, p := range s.cfg.Prices {
		models = append(models, api.GatewayModel{
			ID: p.ModelID, Object: "model", OwnedBy: "helm", Provider: p.ProviderID,
		})
	}
	sort.Slice(models, func(i, j int) bool { return models[i].ID < models[j].ID })
	return models
}

// governedDispatch is the ProviderDispatch handed to the governed gateway. The
// authorized quote is appended (and fsynced) to the durable log BEFORE the
// provider is called; a store failure refuses dispatch. This is the
// no-unreceipted-dispatch invariant in code.
func (s *Server) governedDispatch(r *http.Request, quote *economic.RouteQuote, body []byte) (api.DispatchOutcome, error) {
	rec := &ReceiptRecord{
		Kind:          RecordRouteQuote,
		TenantID:      quote.TenantID,
		SpendIntentID: quote.SpendIntentID,
		RouteQuote:    quote,
	}
	if err := s.signRecord(rec); err != nil {
		return api.DispatchOutcome{}, fmt.Errorf("receipt signing failed; refusing dispatch: %w", err)
	}
	if err := s.store.Append(rec); err != nil {
		return api.DispatchOutcome{}, fmt.Errorf("receipt store append failed; refusing dispatch: %w", err)
	}
	return s.upstream.Dispatch(r.Context(), r.URL.Path, quote, body)
}

// Handler returns the proxy's HTTP surface.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", s.handleInference)
	mux.HandleFunc("/v1/responses", s.handleInference)
	mux.HandleFunc("/v1/embeddings", s.handleInference)
	mux.HandleFunc("/v1/models", s.gatewayMux.ServeHTTP)
	mux.HandleFunc("/helm/spend/health", s.handleHealth)
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":             "ok",
		"mode":               "spend-proxy",
		"upstream":           s.upstream.BaseURL,
		"config_source_hash": s.sourceHash,
		"signing_key_id":     s.issuer.KeyID(),
		"balance_cents":      s.ledger.BalanceCents(),
		"receipt_log":        s.store.Path(),
	})
}

func (s *Server) handleInference(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to read request body", "invalid_request_error", "")
		return
	}
	s.applyHeaderDefaults(r, body)

	var probe struct {
		Stream bool `json:"stream"`
	}
	_ = json.Unmarshal(body, &probe)

	if probe.Stream {
		writeJSONError(w, http.StatusForbidden, privacy.ErrDataEgressBlocked.Error(), "helm_data_egress_blocked", "")
		return
	}
	s.handleBuffered(w, r, body)
}

// applyHeaderDefaults injects the configured default governance identity for
// requests that carry no X-HELM headers (a stock OpenAI client repointed via
// OPENAI_BASE_URL). Governance still runs in full against the default
// envelope; with no defaults configured, header-less requests fail closed in
// ParseRequestHeaders.
func (s *Server) applyHeaderDefaults(r *http.Request, body []byte) {
	if s.cfg.Defaults.EnvelopeID == "" {
		return
	}
	if r.Header.Get(inferencegateway.HeaderAgent) == "" &&
		r.Header.Get(inferencegateway.HeaderSpendEnvelope) == "" {
		r.Header.Set(inferencegateway.HeaderAgent, s.cfg.Defaults.AgentID)
		r.Header.Set(inferencegateway.HeaderSpendEnvelope, s.cfg.Defaults.EnvelopeID)
		if s.cfg.Defaults.PrincipalID != "" {
			r.Header.Set(inferencegateway.HeaderPrincipal, s.cfg.Defaults.PrincipalID)
		}
		if s.cfg.Defaults.WorkspaceID != "" {
			r.Header.Set(inferencegateway.HeaderWorkspace, s.cfg.Defaults.WorkspaceID)
		}
	}
	if r.Header.Get(inferencegateway.HeaderIdempotencyKey) == "" {
		r.Header.Set(inferencegateway.HeaderIdempotencyKey, mintIdempotencyKey(body))
	}
}

// mintIdempotencyKey derives a fresh idempotency key for header-less traffic.
// Each such request is genuinely a new spend, so the key must never collide.
func mintIdempotencyKey(body []byte) string {
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	h := sha256.New()
	h.Write(body)
	h.Write(nonce[:])
	h.Write([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
	return "auto-" + hex.EncodeToString(h.Sum(nil))[:24]
}

// handleBuffered routes the request through the protected GovernedGateway
// handler via an in-memory recorder, persists the receipt set, and unwraps the
// governed envelope so the client receives the raw OpenAI-shaped body.
func (s *Server) handleBuffered(w http.ResponseWriter, r *http.Request, body []byte) {
	r.Body = io.NopCloser(bytes.NewReader(body))
	rec := newBufferedResponse()
	s.gatewayMux.ServeHTTP(rec, r)

	if rec.status == http.StatusOK {
		var envl struct {
			Response json.RawMessage     `json:"response"`
			HELM     api.GatewayMetadata `json:"helm"`
		}
		if err := json.Unmarshal(rec.body.Bytes(), &envl); err == nil && envl.Response != nil {
			copyHeaders(w.Header(), rec.header)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Del("Content-Length")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(envl.Response)
			return
		}
		// An OK response that is not the governed envelope is a bug upstream of
		// us; pass it through untouched rather than guessing.
	} else {
		// Denials and errors: keep the gateway's OpenAI-style error body, and
		// give refused quotes a durable audit line when the engine issued one.
		var envl struct {
			HELM api.GatewayMetadata `json:"helm"`
		}
		if err := json.Unmarshal(rec.body.Bytes(), &envl); err == nil {
			if envl.HELM.SettlementReceipt == nil && envl.HELM.Quote != nil {
				s.appendOrLog(&ReceiptRecord{
					Kind:          RecordRouteQuote,
					TenantID:      envl.HELM.Quote.TenantID,
					SpendIntentID: envl.HELM.Quote.SpendIntentID,
					Note:          fmt.Sprintf("rejected: %s/%s", envl.HELM.Verdict, envl.HELM.ReasonCode),
					RouteQuote:    envl.HELM.Quote,
				})
			}
		}
	}
	copyHeaders(w.Header(), rec.header)
	w.WriteHeader(rec.status)
	_, _ = w.Write(rec.body.Bytes())
}

// persistOutcome signs the verdict receipt and appends the post-dispatch
// receipt set. Idempotent replays are skipped — their receipts were persisted
// when the original request committed.
func (s *Server) persistOutcome(meta *api.GatewayMetadata) {
	if meta.Replayed {
		return
	}
	if meta.RouteReceipt != nil {
		if err := s.issuer.Sign(meta.RouteReceipt); err != nil {
			s.logf("spend-proxy: ERROR signing budget verdict receipt %s: %v", meta.RouteReceipt.ID, err)
		} else {
			s.appendOrLog(&ReceiptRecord{
				Kind:          RecordBudgetVerdict,
				TenantID:      meta.RouteReceipt.TenantID,
				SpendIntentID: meta.RouteReceipt.SpendIntentID,
				BudgetVerdict: meta.RouteReceipt,
			})
		}
	}
	if meta.UsageReceipt != nil {
		s.appendOrLog(&ReceiptRecord{
			Kind:              RecordUsage,
			TenantID:          meta.UsageReceipt.TenantID,
			SpendIntentID:     meta.UsageReceipt.SpendIntentID,
			BalanceAfterCents: meta.BalanceAfterCents,
			Usage:             meta.UsageReceipt,
		})
	}
	if meta.SettlementReceipt != nil {
		intentID := ""
		if meta.UsageReceipt != nil {
			intentID = meta.UsageReceipt.SpendIntentID
		} else if meta.Quote != nil {
			intentID = meta.Quote.SpendIntentID
		}
		s.appendOrLog(&ReceiptRecord{
			Kind:          RecordSettlement,
			TenantID:      meta.SettlementReceipt.TenantID,
			SpendIntentID: intentID,
			Settlement:    meta.SettlementReceipt,
		})
	}
}

func (s *Server) appendOrLog(rec *ReceiptRecord) {
	if err := s.signRecord(rec); err != nil {
		s.logf("spend-proxy: ERROR signing %s record (persisting unsigned; savings export will refuse it): %v", rec.Kind, err)
	}
	if err := s.store.Append(rec); err != nil {
		s.logf("spend-proxy: ERROR persisting %s record: %v", rec.Kind, err)
	}
}

// signRecord attaches the issuer's detached Ed25519 signature over the JCS
// canonicalization of the record's receipt payload. Records without a payload
// pass through unsigned.
func (s *Server) signRecord(rec *ReceiptRecord) error {
	payload := rec.Payload()
	if payload == nil {
		return nil
	}
	keyID, sig, err := s.issuer.SignDetached(payload)
	if err != nil {
		return err
	}
	rec.PayloadSignature = sig
	rec.PayloadSignatureKeyID = keyID
	return nil
}

// handleStream is the streaming counterpart of the governed gateway's
// inference handler: same engine, same fail-closed order (quote → persist →
// dispatch → settle → persist), with the SSE bytes piped through to the
// client. Receipt hashes for the post-dispatch receipts land in the durable
// log rather than response headers, which are already sent when settlement
// happens.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request, body []byte) {
	hdr, err := inferencegateway.ParseRequestHeaders(r.Header)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error(), "invalid_request_error", "")
		return
	}
	env, ok := s.resolveEnvelope(s.cfg.TenantID, hdr.SpendEnvelope)
	if !ok {
		s.writeVerdictError(w, economic.BudgetVerdictDeny, economic.SpendReasonEnvelopeNotFound, "spend envelope not found", nil)
		return
	}
	var parsed struct {
		Model     string `json:"model"`
		MaxTokens *int   `json:"max_tokens,omitempty"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || parsed.Model == "" {
		writeJSONError(w, http.StatusBadRequest, "model is required", "invalid_request_error", "")
		return
	}
	estIn, estOut := estimateTokens(body, parsed.MaxTokens)

	quoteRes, qErr := s.engine.Quote(env, inferencegateway.RouteRequest{
		TenantID:              s.cfg.TenantID,
		WorkspaceID:           hdr.WorkspaceID,
		AgentID:               hdr.AgentID,
		PrincipalID:           hdr.PrincipalID,
		IdempotencyKey:        hdr.IdempotencyKey,
		RequestedModelID:      parsed.Model,
		EstimatedInputTokens:  estIn,
		EstimatedOutputTokens: estOut,
	})
	if qErr != nil {
		verdict, reason, msg := verdictFromError(qErr)
		if quoteRes != nil && quoteRes.Quote != nil {
			s.appendOrLog(&ReceiptRecord{
				Kind:          RecordRouteQuote,
				TenantID:      quoteRes.Quote.TenantID,
				SpendIntentID: quoteRes.Quote.SpendIntentID,
				Note:          fmt.Sprintf("rejected: %s/%s", verdict, reason),
				RouteQuote:    quoteRes.Quote,
			})
		}
		s.writeVerdictError(w, verdict, reason, msg, quoteRes)
		return
	}
	quote := quoteRes.Quote

	// Durable pre-dispatch trail: authorized quote plus the signed verdict
	// receipt, fsynced BEFORE the provider sees the request.
	if err := s.issuer.Sign(quoteRes.Receipt); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to sign budget verdict receipt", "helm_internal_error", "")
		return
	}
	for _, rec := range []*ReceiptRecord{
		{Kind: RecordRouteQuote, TenantID: quote.TenantID, SpendIntentID: quote.SpendIntentID, RouteQuote: quote},
		{Kind: RecordBudgetVerdict, TenantID: quote.TenantID, SpendIntentID: quote.SpendIntentID, BudgetVerdict: quoteRes.Receipt},
	} {
		if err := s.signRecord(rec); err != nil {
			writeJSONError(w, http.StatusBadGateway, "receipt signing failed; refusing dispatch", "helm_receipt_store_error", "")
			return
		}
		if err := s.store.Append(rec); err != nil {
			writeJSONError(w, http.StatusBadGateway, "receipt store append failed; refusing dispatch", "helm_receipt_store_error", "")
			return
		}
	}

	w.Header().Set("X-HELM-Governed", "true")
	w.Header().Set("X-HELM-Verdict", string(economic.BudgetVerdictAllow))
	w.Header().Set("X-HELM-Route-Quote-Hash", quote.ContentHash)

	outcome, dErr := s.upstream.DispatchStream(w, r, quote, body)
	if outcome == nil {
		// Upstream refused before any stream byte: nothing was spent. Close the
		// audit trail and surface the failure.
		reason := "unknown dispatch failure"
		if dErr != nil {
			reason = dErr.Error()
		}
		s.appendOrLog(&ReceiptRecord{
			Kind: RecordSettleFailed, TenantID: quote.TenantID, SpendIntentID: quote.SpendIntentID,
			Note: "dispatch failed before stream start: " + reason, RouteQuote: quote,
		})
		writeJSONError(w, http.StatusBadGateway, "provider dispatch failed: "+reason, "helm_upstream_error", "")
		return
	}
	if dErr != nil {
		s.logf("spend-proxy: stream for %s interrupted: %v", quote.SpendIntentID, dErr)
	}

	in, out := outcome.InputTokens, outcome.OutputTokens
	if !outcome.UsageSeen {
		// No usage chunk: settle conservatively at the quoted estimate.
		in, out = quote.InputTokens, quote.OutputTokens
	}
	cost, cErr := s.upstream.CostCents(quote, in, out)
	if cErr != nil {
		s.logf("spend-proxy: cost derivation failed for %s: %v; settling at quoted amount", quote.SpendIntentID, cErr)
		cost = quote.QuotedAmountCents
	}
	settleRes, sErr := s.engine.Settle(quote, outcome.ProviderRequestID, cost, in, out)
	if sErr != nil {
		// Money may be spent but the debit cannot commit — close the trail
		// loudly instead of leaving a silent gap.
		s.appendOrLog(&ReceiptRecord{
			Kind: RecordSettleFailed, TenantID: quote.TenantID, SpendIntentID: quote.SpendIntentID,
			Note: "settlement failed after stream: " + sErr.Error(), RouteQuote: quote,
		})
		s.logf("spend-proxy: ERROR settlement failed for %s: %v", quote.SpendIntentID, sErr)
		return
	}
	if !settleRes.Replayed {
		s.appendOrLog(&ReceiptRecord{
			Kind: RecordUsage, TenantID: quote.TenantID, SpendIntentID: quote.SpendIntentID,
			BalanceAfterCents: settleRes.BalanceAfterCents, Usage: settleRes.UsageReceipt,
		})
		s.appendOrLog(&ReceiptRecord{
			Kind: RecordSettlement, TenantID: quote.TenantID, SpendIntentID: quote.SpendIntentID,
			Settlement: settleRes.SettlementReceipt,
		})
	}
}

func (s *Server) writeVerdictError(w http.ResponseWriter, verdict economic.BudgetVerdict, reason economic.SpendReasonCode, msg string, res *inferencegateway.QuoteResult) {
	meta := api.GatewayMetadata{Governed: true, Verdict: verdict, ReasonCode: reason}
	if res != nil {
		meta.Quote = res.Quote
		meta.ModelSubstituted = res.ModelSubstituted
		meta.FallbackUsed = res.FallbackUsed
		meta.EvidencePackRef = res.EvidencePackRef
	}
	w.Header().Set("X-HELM-Governed", "true")
	w.Header().Set("X-HELM-Verdict", string(verdict))
	w.Header().Set("X-HELM-Reason-Code", string(reason))
	writeJSON(w, statusForVerdict(verdict), map[string]any{
		"error": map[string]any{
			"message":     msg,
			"type":        "helm_spend_authority_" + string(verdict),
			"reason_code": string(reason),
		},
		"helm": meta,
	})
}

func verdictFromError(err error) (economic.BudgetVerdict, economic.SpendReasonCode, string) {
	var qe *inferencegateway.QuoteError
	if errors.As(err, &qe) {
		return qe.Verdict, qe.ReasonCode, qe.Message
	}
	return economic.BudgetVerdictDeny, economic.SpendReasonEvidenceMissing, err.Error()
}

func statusForVerdict(verdict economic.BudgetVerdict) int {
	switch verdict {
	case economic.BudgetVerdictEscalate:
		return http.StatusPaymentRequired
	case economic.BudgetVerdictDeny:
		return http.StatusForbidden
	default:
		return http.StatusOK
	}
}

// estimateTokens mirrors the governed gateway's pre-dispatch estimate: input
// from body size (~4 bytes/token), output from max_tokens or a conservative
// default. Settlement always uses actual reported usage.
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

// bufferedResponse captures the governed gateway's response for unwrapping.
type bufferedResponse struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func newBufferedResponse() *bufferedResponse {
	return &bufferedResponse{header: make(http.Header), status: http.StatusOK}
}

func (b *bufferedResponse) Header() http.Header { return b.header }

func (b *bufferedResponse) WriteHeader(status int) { b.status = status }

func (b *bufferedResponse) Write(p []byte) (int, error) { return b.body.Write(p) }

func copyHeaders(dst, src http.Header) {
	for k, values := range src {
		for _, v := range values {
			dst.Add(k, v)
		}
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg, errType, code string) {
	body := map[string]any{"message": msg, "type": errType}
	if code != "" {
		body["code"] = code
	}
	writeJSON(w, status, map[string]any{"error": body})
}
