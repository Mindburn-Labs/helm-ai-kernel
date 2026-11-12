// quantum_posture: the server orchestrates classical Ed25519 signing of
// persisted receipt payloads through the issuer (issuer.go) and derives
// idempotency keys with SHA-256; no post-quantum primitives are used in this
// file.

package spendproxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
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
	"strconv"
	"strings"
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
	// SigningSecret seeds the verdict issuer key; empty signs with the seed
	// the proxy generated in ReceiptsDir (SigningSeedFileName), generating
	// it on the first start.
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
	prices     *inferencegateway.MemoryPriceBook
	pending    []PendingDispatch
	logf       func(format string, args ...any)
	// lock is the receipts directory's lock, held until Close; seedPath is
	// the generated seed the issuer key comes from, empty for a given seed.
	lock     *dirLock
	seedPath string
}

// NewServer composes the full governed spend path. Startup replays the durable
// receipt log so the balance and the idempotency index survive restarts.
func NewServer(opts ServerOptions) (*Server, error) {
	s, err := openServer(opts, true)
	if err != nil {
		return nil, err
	}
	if err := s.keys.Register(s.issuer.KeyID(), s.issuer.PublicKey()); err != nil {
		_ = s.Close()
		return nil, err
	}
	upstream, err := NewUpstream(opts.UpstreamBaseURL, opts.UpstreamAPIKey, s.prices)
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	s.upstream = upstream
	gw, err := api.NewGovernedGateway(api.GovernedGatewayConfig{
		Engine:       s.engine,
		Resolver:     s.resolveEnvelope,
		Dispatch:     s.governedDispatch,
		TenantID:     func(*http.Request) string { return s.cfg.TenantID },
		Models:       s.modelList(),
		OnSettlement: s.persistOutcome,
	})
	if err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("spendproxy: governed gateway: %w", err)
	}
	s.gatewayMux = http.NewServeMux()
	gw.Register(s.gatewayMux)
	return s, nil
}

// openServer takes the receipts directory's lock, resolves the signing key
// (generating the directory's seed when createSeed is set and no secret is
// given), rebuilds the proxy's state from its config and receipt log
// (rebuildState) and opens its receipt store. It serves nothing and calls no
// provider; NewServer and Reconcile build on it, and Close releases the lock.
func openServer(opts ServerOptions, createSeed bool) (s *Server, err error) {
	if err := checkServerOptions(opts); err != nil {
		return nil, err
	}
	lock, err := lockReceiptsDir(opts.ReceiptsDir)
	if err != nil {
		return nil, err
	}
	var store *FileStore
	defer func() {
		if err != nil {
			if store != nil {
				_ = store.Close()
			}
			lock.Unlock()
		}
	}()
	secret, seedPath, err := signingSeed(opts.ReceiptsDir, opts.SigningSecret, createSeed)
	if err != nil {
		return nil, err
	}
	issuer, derivedFromPassphrase, err := NewIssuer(secret)
	if err != nil {
		return nil, err
	}
	keys, err := OpenTrustedKeys(opts.ReceiptsDir)
	if err != nil {
		return nil, err
	}
	st, err := rebuildState(opts, trustedKeyResolver(keys, issuer))
	if err != nil {
		return nil, err
	}
	if derivedFromPassphrase {
		st.logf("spend-proxy: WARNING: signing secret is not a 32-byte seed; derived one by hashing it")
	}
	store, err = OpenFileStore(opts.ReceiptsDir)
	if err != nil {
		return nil, err
	}

	for _, p := range st.pending {
		st.logf("spend-proxy: ALERT: dispatch %s (intent %s) was journalled before its provider call and never settled; %d cents stay reserved until `spend-proxy reconcile --intent %s` settles or releases it",
			p.Key, p.Quote.SpendIntentID, p.AmountCents, p.Quote.SpendIntentID)
	}
	return &Server{
		cfg:        opts.Config,
		sourceHash: opts.SourceHash,
		engine:     st.engine,
		ledger:     st.ledger,
		envelopes:  st.envelopes,
		prices:     st.prices,
		store:      store,
		issuer:     issuer,
		keys:       keys,
		replay:     st.replay,
		pending:    st.pending,
		logf:       st.logf,
		lock:       lock,
		seedPath:   seedPath,
	}, nil
}

// checkServerOptions refuses options rebuildState cannot work from.
func checkServerOptions(opts ServerOptions) error {
	switch {
	case opts.Config == nil:
		return errors.New("spendproxy: config is required")
	case opts.SourceHash == "":
		return errors.New("spendproxy: config source hash is required")
	case opts.ReceiptsDir == "":
		return errors.New("spendproxy: receipts dir is required")
	}
	return nil
}

// trustedKeyResolver resolves the keys a start accepts on the lines it
// replays: the issuer's own and the keys of earlier runs in the receipts
// directory's registry.
func trustedKeyResolver(keys *TrustedKeys, issuer *Issuer) func(string) (ed25519.PublicKey, bool) {
	return func(keyID string) (ed25519.PublicKey, bool) {
		if issuer != nil && keyID == issuer.KeyID() {
			return issuer.PublicKey(), true
		}
		return keys.PublicKeyFor(keyID)
	}
}

// proxyState is what the receipt log and the config rebuild.
type proxyState struct {
	prices    *inferencegateway.MemoryPriceBook
	envelopes map[string]*economic.AgentSpendEnvelope
	ledger    *inferencegateway.BalanceLedger
	engine    *inferencegateway.Engine
	replay    *ReplaySummary
	pending   []PendingDispatch
	logf      func(format string, args ...any)
}

// rebuildState rebuilds the books, the ledger with what the log debited, the
// envelopes' use, the engine and the dispatches held again pending
// reconciliation. It writes nothing. Every line that debits or frees a hold
// must be signed by a key trusted resolves (verifyBookLines).
func rebuildState(opts ServerOptions, trusted func(string) (ed25519.PublicKey, bool)) (*proxyState, error) {
	if err := checkServerOptions(opts); err != nil {
		return nil, err
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
	if err := verifyBookLines(records, trusted); err != nil {
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
	restoreEnvelopeUse(records, ledger, envelopes)

	engine, err := inferencegateway.NewEngine(inferencegateway.EngineConfig{
		Prices:        prices,
		Terms:         terms,
		Ledger:        ledger,
		TreasuryID:    cfg.TreasuryID,
		RoutePolicyID: cfg.RoutePolicyID,
		QuoteTTL:      time.Duration(cfg.QuoteTTLSeconds) * time.Second,
		StalePrice:    inferencegateway.StalePriceFailClosed,
		// The provider has already been paid when settlement runs: debit the
		// actual cost. A cost above the hold is recorded on the usage receipt
		// (ESCALATE / ERR_SPEND_PER_REQUEST_LIMIT, overage_cents), alerted
		// on, and closes the envelope for the rest of its period.
		CostCap:        inferencegateway.CostCapDebitActual,
		PlatformFeeBps: cfg.PlatformFeeBps,
	})
	if err != nil {
		return nil, fmt.Errorf("spendproxy: engine: %w", err)
	}

	// A dispatch journalled before its provider call that never settled and
	// was never released may have been billed: hold it again, pending
	// reconciliation, so its cents stay spent and its key cannot dispatch
	// again (helm-tracker#313, audit M18).
	pending, err := RestorePendingDispatches(records, engine, envelopes)
	if err != nil {
		return nil, err
	}
	replay.PendingDispatches = len(pending)
	for _, p := range pending {
		replay.PendingCents += p.AmountCents
	}
	return &proxyState{prices: prices, envelopes: envelopes, ledger: ledger, engine: engine, replay: replay, pending: pending, logf: logf}, nil
}

// Close releases the receipt store and the receipts directory's lock.
func (s *Server) Close() error {
	err := s.store.Close()
	s.lock.Unlock()
	return err
}

// SigningSeedPath is the generated seed file the issuer key comes from, or ""
// when the proxy was given a seed.
func (s *Server) SigningSeedPath() string { return s.seedPath }

// ReplaySummary reports what startup recovered from the durable log.
func (s *Server) ReplaySummary() ReplaySummary { return *s.replay }

// BalanceCents exposes the current governed balance.
func (s *Server) BalanceCents() int64 { return s.ledger.BalanceCents() }

// SigningKeyID exposes the verdict issuer key id.
func (s *Server) SigningKeyID() string { return s.issuer.KeyID() }

// SigningPublicKey is the issuer's Ed25519 public key as "ed25519:<hex>", the
// value `spend-proxy export --public-key` takes.
func (s *Server) SigningPublicKey() string {
	return "ed25519:" + hex.EncodeToString(s.issuer.PublicKey())
}

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
// no-unreceipted-dispatch invariant in code. A restart that finds this journal
// line without a settlement or a release holds the dispatch again.
//
// The provider call does not end when the client leaves: it runs to its end
// (bounded by the upstream client's timeout) so it settles on what the
// provider reports instead of on an unknown.
func (s *Server) governedDispatch(r *http.Request, quote *economic.RouteQuote, body []byte) (api.DispatchOutcome, error) {
	rec := &ReceiptRecord{
		Kind:          RecordRouteQuote,
		TenantID:      quote.TenantID,
		SpendIntentID: quote.SpendIntentID,
		Note:          NoteDispatchJournal,
		RouteQuote:    quote,
	}
	if err := s.signRecord(rec); err != nil {
		return api.DispatchOutcome{}, fmt.Errorf("receipt signing failed; refusing dispatch: %w: %w", api.ErrDispatchNotSent, err)
	}
	if err := s.store.Append(rec); err != nil {
		return api.DispatchOutcome{}, fmt.Errorf("receipt store append failed; refusing dispatch: %w: %w", api.ErrDispatchNotSent, err)
	}
	outcome, err := s.upstream.Dispatch(context.WithoutCancel(r.Context()), r.URL.Path, quote, body)
	if err != nil && errors.Is(err, api.ErrDispatchNotSent) {
		// The gateway releases the hold; journal that, so a restart does not
		// hold it again.
		s.appendOrLog(releaseRecord(quote, "no byte of the request left the proxy"))
	}
	return outcome, err
}

// settleFailedRecord is the signed line of a dispatch whose settlement failed
// after the provider was called: the dispatch's route quote, whose metadata
// records what the provider billed (MetadataActualCents), the overage above
// the hold and the envelope windows it closed. A restart closes those windows
// again, and reconcile settles the dispatch at no less than the actual
// (helm-tracker#313 r2, findings 3 and 4).
func settleFailedRecord(meta *api.GatewayMetadata, note string) *ReceiptRecord {
	quote := meta.Quote
	failed := *quote
	failed.Metadata = make(map[string]string, len(quote.Metadata)+4)
	for k, v := range quote.Metadata {
		failed.Metadata[k] = v
	}
	if meta.ActualAmountCents > 0 {
		failed.Metadata[MetadataActualCents] = strconv.FormatInt(meta.ActualAmountCents, 10)
	}
	if meta.OverageCents > 0 {
		failed.Metadata[MetadataOverageCents] = strconv.FormatInt(meta.OverageCents, 10)
	}
	if meta.EnvelopeClosed != "" {
		failed.Metadata[inferencegateway.MetadataEnvelopeClosed] = meta.EnvelopeClosed
		failed.Metadata[inferencegateway.MetadataEnvelopeClosedWindows] = strings.Join(meta.EnvelopeClosedWindows, ",")
	}
	return &ReceiptRecord{
		Kind:          RecordSettleFailed,
		TenantID:      quote.TenantID,
		SpendIntentID: quote.SpendIntentID,
		Note:          note,
		RouteQuote:    &failed,
	}
}

// releaseRecord is the signed journal line of a released hold: the dispatch's
// route quote, whose metadata says why it was released.
func releaseRecord(quote *economic.RouteQuote, reason string) *ReceiptRecord {
	released := *quote
	released.Metadata = make(map[string]string, len(quote.Metadata)+1)
	for k, v := range quote.Metadata {
		released.Metadata[k] = v
	}
	released.Metadata[MetadataReleaseReason] = reason
	return &ReceiptRecord{
		Kind:          RecordDispatchReleased,
		TenantID:      quote.TenantID,
		SpendIntentID: quote.SpendIntentID,
		Note:          "released: " + reason,
		RouteQuote:    &released,
	}
}

// RegisterRoutes mounts the proxy's HTTP surface on mux.
func (s *Server) RegisterRoutes(mux interface {
	HandleFunc(string, func(http.ResponseWriter, *http.Request))
}) {
	mux.HandleFunc("/v1/chat/completions", s.handleInference)
	mux.HandleFunc("/v1/responses", s.handleInference)
	mux.HandleFunc("/v1/embeddings", s.handleInference)
	mux.HandleFunc("/v1/models", s.requireCaller(s.gatewayMux.ServeHTTP))
	mux.HandleFunc("/helm/spend/health", s.requireCaller(s.handleHealth))
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":             "ok",
		"mode":               "spend-proxy",
		"upstream":           s.upstream.BaseURL,
		"config_source_hash": s.sourceHash,
		"signing_key_id":     s.issuer.KeyID(),
		"signing_public_key": s.SigningPublicKey(),
		"balance_cents":      s.ledger.BalanceCents(),
		"receipt_log":        s.store.Path(),
	})
}

func (s *Server) handleInference(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "")
		return
	}
	caller, refused := s.bindCaller(r)
	if refused != nil {
		code := "helm_caller_scope"
		if refused.status == http.StatusUnauthorized {
			code = "helm_caller_credential"
			w.Header().Set("WWW-Authenticate", `Bearer realm="helm-spend-proxy"`)
		}
		writeJSONError(w, refused.status, refused.message, refused.errType, code)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to read request body", "invalid_request_error", "")
		return
	}
	s.applyHeaderDefaults(r, body)
	scopeIdempotencyKey(r.Header, caller)

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
// OPENAI_BASE_URL), and mints an idempotency key for any request that names
// none, with or without defaults: a stock client sends none, and each such
// request is a new spend (helm-tracker#313 r2, finding 7). Governance still
// runs in full against the default envelope; with no defaults and no caller
// credential, a request without agent and envelope headers fails closed in
// ParseRequestHeaders.
func (s *Server) applyHeaderDefaults(r *http.Request, body []byte) {
	if r.Header.Get(inferencegateway.HeaderIdempotencyKey) == "" {
		r.Header.Set(inferencegateway.HeaderIdempotencyKey, mintIdempotencyKey(body))
	}
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
			if envl.HELM.SettleFailed && envl.HELM.Quote != nil {
				// The provider was called but nothing was debited: close the
				// audit trail loudly.
				note := fmt.Sprintf("settlement failed after dispatch (%s/%s): actual %d cents not debited",
					envl.HELM.Verdict, envl.HELM.ReasonCode, envl.HELM.ActualAmountCents)
				if envl.HELM.EnvelopeClosed != "" {
					note += fmt.Sprintf("; the bill is %d cents above the hold and envelope %s takes no further dispatch in %s",
						envl.HELM.OverageCents, envl.HELM.EnvelopeClosed, strings.Join(envl.HELM.EnvelopeClosedWindows, ", "))
				}
				s.logf("spend-proxy: ALERT: %s for %s", note, envl.HELM.Quote.SpendIntentID)
				s.appendOrLog(settleFailedRecord(&envl.HELM, note))
			} else if envl.HELM.SettlementReceipt == nil && envl.HELM.Quote != nil {
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
		note := ""
		if meta.OverageCents > 0 {
			note = fmt.Sprintf("overage: actual %d cents exceeds the quote ceiling by %d cents",
				meta.ActualAmountCents, meta.OverageCents)
			if closed := meta.UsageReceipt.Metadata["envelope_closed"]; closed != "" {
				note += fmt.Sprintf("; envelope %s takes no further dispatch this period", closed)
			}
			s.logf("spend-proxy: ALERT: %s for %s", note, meta.UsageReceipt.SpendIntentID)
		}
		if meta.SettlementReceipt != nil {
			for _, rec := range settlementRecords(meta.UsageReceipt, meta.SettlementReceipt, meta.BalanceAfterCents, note) {
				s.appendOrLog(rec)
			}
		}
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
